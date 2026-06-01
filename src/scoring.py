"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
scoring.py - Scoring engine per aggregazione dei risultati
=============================================================================

Obiettivo:
    Aggregare i risultati di tutte le metriche di rilevamento in un unico
    punteggio S(h) per host, secondo la formula del "Piano_operativo.md":

        S(h) = min(100, sum_{i=1..N} Punti_i * M_i(h))

    e classificare ogni host in una delle tre fasce di rischio:

        Verde  -> 0-29  punti  (host sicuro)
        Giallo -> 30-59 punti  (host sospetto, da monitorare)
        Rosso  -> 60-100 punti (host compromesso, intervento immediato)

    Lo script calcola inoltre un indice di rete approssimato come
    "caso peggiore" (max S(h)) per dare una visione globale dello stato
    della rete monitorata.

Logica di esecuzione:
    1. Apertura di UNA sola connessione a ClickHouse condivisa da tutte le metriche.
    2. Esecuzione di ogni metrica in sequenza, con gestione degli
       errori. Se una metrica fallisce, lo script logga e continua con le
       altre (non vogliamo che un bug singolo spenga l'intero sistema di scoring).
    3. Aggregazione dei risultati per host.
    4. Calcolo dello score finale e classificazione in fasce.
    5. Stampa di un report leggibile per gli analisti.

Frequenza di esecuzione:
    Batch orario via cron o systemd timer. Tutte le metriche di base sono
    progettate per essere eseguite ogni ora.

Esecuzione:
    $ source venv/bin/activate
    $ python3 scoring.py
=============================================================================
"""

import sys
import traceback
from datetime import datetime, timezone

import clickhouse_connect

# Import delle funzioni di calcolo di ogni metrica
# Ogni modulo espone calcola_m_XXX(client) -> dict[host_ip -> dettagli]
from m_rep   import calcola_m_rep
from m_cert  import calcola_m_cert
from m_sni   import calcola_m_sni
from m_srv   import calcola_m_srv
from m_proto import calcola_m_proto
from m_scan  import calcola_m_scan
from m_vol   import calcola_m_vol
from m_fail  import calcola_m_fail


# =============================================================================
# CONFIGURAZIONE
# =============================================================================

# Parametri di connessione a ClickHouse
CLICKHOUSE_HOST     = "localhost"
CLICKHOUSE_PORT     = 8123
CLICKHOUSE_DATABASE = "ntopng"
CLICKHOUSE_USER     = "default"
CLICKHOUSE_PASSWORD = "0022"

# Massimo score per host ranggiugibile
SCORE_MAX = 100

# Soglie delle fasce di rischio
SOGLIA_GIALLO = 30   # >= 30 punti -> giallo
SOGLIA_ROSSO  = 60   # >= 60 punti -> rosso

# Registro delle metriche da eseguire.
# Lista di tuple (nome_chiave_dict, nome_metrica, funzione_calcolo).
# Aggiungere una nuova metrica significa SOLO aggiungere una riga qui sotto
# (il resto dello script è lo stesso rispetto al set di metriche).
METRICHE = [
    ("M_rep",   "Destination reputation",     calcola_m_rep),
    ("M_cert",  "TLS certificate anomalies",  calcola_m_cert),
    ("M_sni",   "SNI evasion",                calcola_m_sni),
    ("M_srv",   "Server role detection",      calcola_m_srv),
    ("M_proto", "Non-standard port/protocol", calcola_m_proto),
    ("M_scan",  "Network discovery",          calcola_m_scan),
    ("M_vol",   "Asimmetria volumetrica",     calcola_m_vol),
    ("M_fail",  "Connection failure rate",    calcola_m_fail),
]


# =============================================================================
# FUNZIONI DI SUPPORTO
# =============================================================================

def connetti_clickhouse():
    """
    Apre la connessione condivisa al database di ClickHouse.
    """
    return clickhouse_connect.get_client(
        host     = CLICKHOUSE_HOST,
        port     = CLICKHOUSE_PORT,
        database = CLICKHOUSE_DATABASE,
        username = CLICKHOUSE_USER,
        password = CLICKHOUSE_PASSWORD,
    )


def fascia_rischio(score: int) -> str:
    """
    Mappa un punteggio S(h) su una delle tre fasce di rischio definite.
    """
    if score >= SOGLIA_ROSSO:
        return "ROSSO"
    if score >= SOGLIA_GIALLO:
        return "GIALLO"
    return "VERDE"


def emoji_fascia(fascia: str) -> str:
    """
    Marker testuale per riconoscere visivamente la fascia nei report.
    """
    return {"ROSSO": "[!!]", "GIALLO": "[ !]", "VERDE": "[ok]"}.get(fascia, "[??]")


# =============================================================================
# ESECUZIONE DELLE METRICHE
# =============================================================================

def esegui_metrica(nome: str, etichetta: str, fn, client) -> dict:
    """
    Esegue una singola metrica con gestione degli errori.

    Restituisce sempre un dizionario (eventualmente vuoto) per non bloccare
    l'aggregazione finale. Se la metrica fallisce, viene loggato l'errore e
    si prosegue con le altre.
    """
    print(f"  [run] {nome:8s} ({etichetta})...", end=" ", flush=True)
    try:
        risultati = fn(client)
        n = len(risultati)
        print(f"OK ({n} host flaggati)")
        return risultati
    except Exception as e:
        # Stampa errore ma non blocca lo script.
        # Lo stack trace va a stderr per essere visibile nei log di cron senza inquinare
        # lo stdout principale.
        print(f"ERRORE: {e}")
        print(f"  [run] Stack trace di {nome}:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return {}


def esegui_tutte_le_metriche(client) -> dict:
    """
    Lancia tutte le metriche e restituisce un dizionario:
        { nome_metrica -> { host_ip -> dettagli } }
    """
    print("\n[fase 1] Esecuzione delle metriche di rilevamento\n")
    risultati_per_metrica = {}
    for nome, etichetta, fn in METRICHE:
        risultati_per_metrica[nome] = esegui_metrica(nome, etichetta, fn, client)
    return risultati_per_metrica


# =============================================================================
# AGGREGAZIONE PER HOST
# =============================================================================

def aggrega_per_host(risultati_per_metrica: dict) -> dict:
    """
    Costruisce un dizionario aggregato per host:

        {
          "192.168.1.45": {
            "score":            85,
            "fascia":           "ROSSO",
            "metriche_attive":  ["M_rep", "M_sni", "M_proto"],
            "penalita_totale":  150,   <- prima della saturazione
            "dettagli": {
                "M_rep":   { ... output completo della metrica ... },
                "M_sni":   { ... },
                "M_proto": { ... },
            }
          },
          ...
        }

    lo `score` è limitato a 100 (SCORE_MAX), mentre `penalita_totale` mostra
    la somma grezza prima della limitazione. utile per capire se l'host
    è "solo" in zona rossa o se l'ha superata di molto.
    """
    aggregato = {}

    # Per ogni metrica, scorro gli host che ha flaggato
    for nome_metrica, risultati in risultati_per_metrica.items():
        for host_ip, dettagli in risultati.items():
            # Inizializza il record dell'host se primo incontro
            if host_ip not in aggregato:
                aggregato[host_ip] = {
                    "score":           0,
                    "fascia":          "VERDE",
                    "metriche_attive": [],
                    "penalita_totale": 0,
                    "dettagli":        {},
                }

            # Aggiungo le info di questa metrica al record
            penalita = dettagli.get("penalita", 0)
            aggregato[host_ip]["penalita_totale"] += penalita
            aggregato[host_ip]["metriche_attive"].append(nome_metrica)
            aggregato[host_ip]["dettagli"][nome_metrica] = dettagli

    # Calcolo lo score limitato e la fascia per ciascun host
    for host_ip, rec in aggregato.items():
        rec["score"]  = min(SCORE_MAX, rec["penalita_totale"])
        rec["fascia"] = fascia_rischio(rec["score"])

    return aggregato


# =============================================================================
# CALCOLO IL RISCHIO DELLA RETE
# =============================================================================

def calcola_indice_rete(aggregato: dict) -> dict:
    """
    Calcola un indice dello stato di rete come "caso peggiore".
    """
    if not aggregato:
        return {
            "score_max":          0,
            "fascia_globale":     "VERDE",
            "host_verde":         0,
            "host_giallo":        0,
            "host_rosso":         0,
            "host_totali_visti":  0,
        }

    score_max = max(rec["score"] for rec in aggregato.values())
    n_verde   = sum(1 for r in aggregato.values() if r["fascia"] == "VERDE")
    n_giallo  = sum(1 for r in aggregato.values() if r["fascia"] == "GIALLO")
    n_rosso   = sum(1 for r in aggregato.values() if r["fascia"] == "ROSSO")

    return {
        "score_max":          score_max,
        "fascia_globale":     fascia_rischio(score_max),
        "host_verde":         n_verde,
        "host_giallo":        n_giallo,
        "host_rosso":         n_rosso,
        "host_totali_visti":  len(aggregato),
    }


# =============================================================================
# REPORT
# =============================================================================

def stampa_intestazione():
    """
    Banner iniziale dello script.
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 75)
    print(f"  SISTEMA DI RILEVAMENTO ANOMALIE - SCORING ORARIO")
    print(f"  Esecuzione: {ts} UTC")
    print(f"  Metriche attive: {len(METRICHE)}")
    print("=" * 75)


def stampa_indice_rete(indice: dict):
    """
    Riepilogo dello stato di rete.
    """
    print()
    print("=" * 75)
    print("  [fase 3] STATO DELLA RETE")
    print("=" * 75)
    print(f"  Host osservati con almeno 1 metrica attiva : "
          f"{indice['host_totali_visti']}")
    print()
    print(f"  Distribuzione per fascia:")
    print(f"    Verde   (0-29)  : {indice['host_verde']:3d}")
    print(f"    Giallo  (30-59) : {indice['host_giallo']:3d}")
    print(f"    Rosso   (60-100): {indice['host_rosso']:3d}")
    print()
    fascia = indice["fascia_globale"]
    marker = emoji_fascia(fascia)
    print(f"  Score massimo della rete : {indice['score_max']}")
    print(f"  Fascia globale           : {marker} {fascia}")

    if fascia == "ROSSO":
        print()
        print(f"  >> RETE COMPROMESSA: almeno un host ha superato la soglia")
        print(f"     di intervento. è richiesta verifica immediata.")
    elif fascia == "GIALLO":
        print()
        print(f"  >> RETE IN OSSERVAZIONE: almeno un host mostra comportamenti")
        print(f"     anomali. è opportuno monitorare l'evoluzione nelle")
        print(f"     prossime ore.")
    else:
        print()
        print(f"  >> RETE OK: nessun host ha superato la soglia di allarme.")


def stampa_tabella_host(aggregato: dict):
    """
    Tabella riassuntiva degli host che hanno almeno una metrica attiva,
    ordinati per score decrescente (i più gravi in alto).
    """
    if not aggregato:
        print()
        print("=" * 75)
        print("  Nessun host flaggato da nessuna metrica nell'ultima ora.")
        print("=" * 75)
        return

    # Ordino per score decrescente
    ordinati = sorted(aggregato.items(),
                      key=lambda kv: kv[1]["score"],
                      reverse=True)

    print()
    print("=" * 75)
    print("  TABELLA HOST FLAGGATI (ordinati per score decrescente)")
    print("=" * 75)
    print(f"  {'Host':<18} {'Score':>5}  {'Fascia':<7}  Metriche attive")
    print(f"  {'-'*18} {'-'*5}  {'-'*7}  {'-'*32}")
    for host_ip, rec in ordinati:
        marker      = emoji_fascia(rec["fascia"])
        metriche    = ", ".join(rec["metriche_attive"])
        # Se la lista delle metriche è troppo lunga, la taglio con "..."
        if len(metriche) > 40:
            metriche = metriche[:37] + "..."
        print(f"  {host_ip:<18} {rec['score']:>5}  "
              f"{marker} {rec['fascia']:<6} {metriche}")


def stampa_dettaglio_host_critici(aggregato: dict):
    """
    Per ogni host in zona giallo/rosso, stampa il dettaglio delle metriche
    che hanno contribuito al suo score. Gli host in zona verde non vengono espansi
    per non sporcare l'output.
    """
    critici = {ip: rec for ip, rec in aggregato.items()
               if rec["fascia"] in ("GIALLO", "ROSSO")}

    if not critici:
        return  # nessun dettaglio da stampare

    print()
    print("=" * 75)
    print("  DETTAGLIO HOST CRITICI (fascia giallo e rosso)")
    print("=" * 75)

    # Stampo dal più critico al meno critico
    ordinati = sorted(critici.items(),
                      key=lambda kv: kv[1]["score"],
                      reverse=True)

    for host_ip, rec in ordinati:
        print()
        marker = emoji_fascia(rec["fascia"])
        print("-" * 75)
        print(f"  {marker} HOST {host_ip}  ->  "
              f"Score: {rec['score']}/100  ({rec['fascia']})")
        if rec["penalita_totale"] > SCORE_MAX:
            print(f"      (penalità grezza pre-saturazione: "
                  f"{rec['penalita_totale']})")
        print("-" * 75)

        # Espando le metriche scattate, una per una
        for nome_metrica in rec["metriche_attive"]:
            dettagli  = rec["dettagli"][nome_metrica]
            penalita  = dettagli.get("penalita", 0)
            print(f"    > {nome_metrica:8s} (+{penalita} punti)")
            # Stampo le chiavi salienti specifiche della metrica, escludendo
            # quelle generiche di sistema che non aiutano la lettura
            chiavi_da_saltare = {"penalita", "timestamp", nome_metrica}
            for k, v in dettagli.items():
                if k in chiavi_da_saltare:
                    continue
                # Per dict annidati (es. breakdown di M_fail) li espando
                if isinstance(v, dict):
                    print(f"         {k}:")
                    for k2, v2 in v.items():
                        print(f"           {k2:<18}: {v2}")
                elif isinstance(v, float):
                    print(f"         {k:<22}: {v:.4f}")
                else:
                    print(f"         {k:<22}: {v}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    stampa_intestazione()

    # Apertura connessione condivisa
    print("\n[setup] Connessione a ClickHouse...", end=" ", flush=True)
    try:
        client = connetti_clickhouse()
        print("OK")
    except Exception as e:
        print(f"FALLITA: {e}")
        return 1

    # Esecuzione di tutte le metriche
    risultati_per_metrica = esegui_tutte_le_metriche(client)

    # Aggregazione per host e calcolo dello score
    print("\n[fase 2] Aggregazione dei risultati per host")
    aggregato = aggrega_per_host(risultati_per_metrica)
    print(f"  Host unici flaggati da almeno una metrica: {len(aggregato)}")

    # Calcolo dell'indice di rete e stampa dei report
    indice = calcola_indice_rete(aggregato)
    stampa_indice_rete(indice)
    stampa_tabella_host(aggregato)
    stampa_dettaglio_host_critici(aggregato)

    print()
    print("=" * 75)
    print("  FINE ESECUZIONE")
    print("=" * 75)
    print()

    # Codice di uscita per integrazione con cron/monitoring esterni:
    #   0 -> rete in stato Verde
    #   1 -> rete in stato Giallo (allerta)
    #   2 -> rete in stato Rosso  (critico)
    # In questo modo cron puo' inviare alert.
    return {"VERDE": 0, "GIALLO": 1, "ROSSO": 2}[indice["fascia_globale"]]


if __name__ == "__main__":
    sys.exit(main())
