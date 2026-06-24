"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
Metrica M_srv - Server port detected
=============================================================================

Obiettivo:
    Segnalare gli host interni che iniziano a contattare una porta server
    non presente nel loro profilo storico di contatti. ntopng costruisce,
    per ogni host, l'insieme delle porte server che l'host contatta
    abitualmente; quando, terminato il learning period, compare
    un contatto verso una nuova porta server, genera l'allarme nativo
    (alert_id = 29).

    È un segnale debole di comunicazione in uscita verso un
    servizio/porta non visto prima (possibile indizio di nuovo traffico
    anomalo, contatto C2 o movimento laterale), non una prova di
    compromissione. Una semplice query DNS verso un resolver mai usato
    prima è sufficiente a farlo scattare.

Logica:
    ntopng mantiene per ogni host un profilo delle porte server contattate.
    Dopo un periodo di apprendimento, se l'host contatta una nuova porta server
    rispetto a quelle del learning period, genera l'allarme "Server Port Detected"
    (alert_id = 29, host_alert_server_ports_contacts).

    Peso STATICO di +20 punti per qualsiasi nuova porta server contattata
    da un host della LAN interna. Il peso statico (invece di un peso
    proporzionale al numero di porte o di hit) limita l'impatto dei casi
    in cui il contatto verso una porta server nuova è del tutto legittimo.

Frequenza di esecuzione:
    Event-driven (metrica deterministica): lo script va eseguito ogni ora
    tramite cron o systemd timer.

Fonte dei dati:
    Tabella `host_alerts` di ntopng su ClickHouse.
    Filtro: alert_id = 29 (host_alert_server_ports_contacts).
    La porta server contattata è estratta dal campo JSON:
    JSONExtractInt(json, 'port').
    Il dettaglio delle porte è utile per il report, ma non influisce sul
    punteggio (peso statico).

Soglie di rischio dello score finale S(h):
    Verde  ->  0-29  punti  (host sicuro)
    Giallo -> 30-59  punti  (host sospetto, da monitorare)
    Rosso  -> 60-100 punti  (host compromesso, intervento immediato)
=============================================================================
"""

import argparse
from datetime import datetime, timezone

from readconfig import (
    connetti_clickhouse, costruisci_filtro_lan,
    M_SRV_ALERT_ID as ALERT_ID_SERVER_PORT,
    PESO_M_SRV, FINESTRA_MINUTI_DEFAULT,
)

# =============================================================================
# QUERY SQL
# =============================================================================

# La query SQL viene costruita dentro `calcola_m_srv()` perché dipende
# dal parametro `finestra_minuti`, che può essere passato dinamicamente
# (default = FINESTRA_MINUTI_DEFAULT).
#
# La query implementa la formula del piano operativo:
#   A_srv = True -> M_srv = 1
# con peso STATICO assegnato dallo script Python (PESO_M_SRV = 30)
# moltiplicato per M_srv. Niente più multiIf con liste di porte lato SQL.
#
# Strutturazione in due fasi tramite CTE (Common Table Expression):
# - FASE 1 (CTE "base_data"): applica i filtri WHERE ed estrae JSON
#   una sola volta (`JSONExtractInt(json, 'port')` -> `port_extracted`).
#   Evita di ripetere il parsing in tutte le aggregazioni della FASE 2.
# - FASE 2: aggregazione per host (count, distinct, lista porte).
#   Nessuna logica di pesatura: il peso lo applica Python.


# =============================================================================
# FUNZIONI
# =============================================================================

def calcola_m_srv(client, finestra_minuti: int = FINESTRA_MINUTI_DEFAULT):
    """
    Esegue la query su ClickHouse e restituisce un dizionario con i risultati.

    Parametri:
        finestra_minuti : ampiezza della finestra temporale di analisi in minuti.
                          Default = FINESTRA_MINUTI_DEFAULT (60 minuti, ovvero
                          l'ultima ora) per essere compatibili con lo
                          scoring.py esistente.
                          Valori piccoli (es. 5-10) servono per testare la
                          metrica su tabelle molto grandi (miliardi di
                          record) contenendo l'intervallo della query.

    Il formato di ritorno è SIMMETRICO alle altre metriche:
    chiave = IP dell'host, valore = dizionario con i dettagli.

    Struttura del dizionario restituito:
    {
        "192.168.1.45": {
            "M_srv":          1,
            "hits_totali":    3,        <- allarmi totali nel periodo
            "porte_distinte": 2,        <- numero di porte uniche
            "lista_porte":   [22, 8888],
            "penalita":      30,        <- peso statico (PESO_M_SRV)
            "timestamp":     "2026-05-15T18:00:00+00:00"
        },
        ...
    }
    """
    # Costruzione della query con il parametro `finestra_minuti`.
    # Il valore è un intero controllato (validato a monte da argparse
    # o passato esplicitamente come argomento di funzione), quindi è
    # sicuro inserirlo via f-string senza rischio di SQL injection.
    #
    # `filtro_lan` è costruito dal file di configurazione "config.ini":
    #  questo, limita l'analisi ai soli host della LAN interna (RFC 1918). In host_alerts
    # la colonna `ip` è già una stringa, quindi nessuna conversione.
    filtro_lan = costruisci_filtro_lan("ip")

    query = f"""

    -- FASE 1 - CTE "base_data"
    -- Filtro temporale + alert_id + filtro RFC1918, ed estrazione della
    -- porta dal JSON UNA SOLA volta per riga (port_extracted).
    -- Tutto ciò che è costante riga per riga è isolato qui per evitare
    -- ricomputazioni nelle aggregazioni della FASE 2.

    WITH base_data AS (
        SELECT
            ip AS host_ip,
            JSONExtractInt(json, 'port') AS port_extracted

        FROM host_alerts
        WHERE
            -- Filtro 1: finestra temporale parametrica (default 60 minuti)
            tstamp >= now() - INTERVAL {finestra_minuti} MINUTE

            -- Filtro 2: solo l'allarme "Server Port Detected"
            AND alert_id = {ALERT_ID_SERVER_PORT}

            -- Filtro 3: LAN interna (classifichiamo solo host della rete monitorata)
            AND {filtro_lan}
    )

    -- FASE 2 - Aggregazione finale per host
    -- Nessuna logica di pesatura: il peso lo applica Python (PESO_M_SRV).
    -- Restituiamo solo i campi informativi per il report.

    SELECT
        host_ip,

        -- Numero totale di allarmi Server Port Detected per l'host
        count() AS hits_totali,

        -- Numero di porte distinte rilevate
        uniqExact(port_extracted) AS porte_distinte,

        -- Lista delle porte (utile per il report, max 10)
        arraySlice(groupUniqArray(port_extracted), 1, 10) AS lista_porte,

        -- M_srv si attiva se l'aggregazione ha trovato almeno una riga
        -- (per costruzione: se l'host è in questo result-set, ha >= 1 hit)
        1 AS M_srv

    FROM base_data
    GROUP BY host_ip
    ORDER BY hits_totali DESC
    """

    risultati = {}

    # Esecuzione della query
    righe = client.query(query).result_rows

    # Ogni riga contiene:
    # (host_ip, hits_totali, porte_distinte, lista_porte, M_srv)
    for (host_ip, hits_totali, porte_distinte,
         lista_porte, m_srv) in righe:

        risultati[host_ip] = {
            "M_srv":          m_srv,
            "hits_totali":    hits_totali,
            "porte_distinte": porte_distinte,
            "lista_porte":    list(lista_porte),  # da ClickHouse Array a lista Python
            "penalita":       PESO_M_SRV * m_srv,  # 30 se M_srv=1, 0 altrimenti
            "timestamp":      datetime.now(timezone.utc).isoformat()
        }

    return risultati


def stampa_report(host_ip: str, dati: dict):
    """
    Stampa un report leggibile per ogni host flagged dalla sola metrica.
    Usato quando lo script è eseguito per testing.
    """
    print("=" * 70)
    print(f"  [ALLARME M_srv] {host_ip}")
    print("=" * 70)
    print(f"  Timestamp           : {dati['timestamp']}")
    print(f"  M_srv               : {dati['M_srv']} (attiva)")
    print(f"  Porte rilevate      : {dati['lista_porte']}")
    print(f"  Porte distinte      : {dati['porte_distinte']}")
    print(f"  Hit totali          : {dati['hits_totali']}")
    print(f"  Penalità M_srv      : +{dati['penalita']} punti")
    print()


# =============================================================================
# MAIN - Esecuzione per testing
# =============================================================================

def main():
    """
    Quando integreremo tutto in scoring.py, questa funzione NON verrà chiamata:
    scoring.py importerà direttamente `calcola_m_srv()` dalla funzione sopra.

    Esecuzione da CLI:
        python m_srv.py                          # usa il default (60 minuti)
        python m_srv.py --finestra-minuti 10     # finestra di 10 minuti
        python m_srv.py --finestra-minuti 1440   # finestra di 24 ore
    """
    # Parsing degli argomenti da riga di comando
    parser = argparse.ArgumentParser(
        description="Calcolo della metrica M_srv (Server Port Detected)."
    )
    parser.add_argument(
        "--finestra-minuti",
        type=int,
        default=FINESTRA_MINUTI_DEFAULT,
        help=(
            f"Ampiezza in minuti della finestra temporale di analisi. "
            f"Default: {FINESTRA_MINUTI_DEFAULT}. "
            f"Valori più piccoli sono utili per testare la metrica su "
            f"tabelle molto grandi (miliardi di record) limitando "
            f"l'intervallo della query."
        ),
    )
    args = parser.parse_args()

    # Validazione: finestra deve essere positiva
    if args.finestra_minuti <= 0:
        print(f"[ERRORE] --finestra-minuti deve essere > 0 (ricevuto: {args.finestra_minuti})")
        return

    print(f"\n{'='*70}")
    print(f"  Avvio analisi M_srv - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Finestra temporale: ultimi {args.finestra_minuti} minuto/i")
    print(f"  Peso statico: +{PESO_M_SRV} punti per qualsiasi nuova porta server rilevata")
    print(f"{'='*70}\n")

    # Connessione al database
    try:
        client = connetti_clickhouse()
        print("[OK] Connessione a ClickHouse stabilita.\n")
    except Exception as e:
        print(f"[ERRORE] Impossibile connettersi a ClickHouse: {e}")
        return

    # Calcolo della metrica M_srv con la finestra specificata
    try:
        host_flaggati = calcola_m_srv(client, finestra_minuti=args.finestra_minuti)
    except Exception as e:
        print(f"[ERRORE] Errore durante l'esecuzione della query: {e}")
        return

    # Report dei risultati
    if not host_flaggati:
        print(f"[OK] Nessun host flagged - nessun nuova porta server rilevata negli ultimi {args.finestra_minuti} minuto/i.\n")
        return

    print(f"[!] {len(host_flaggati)} host flagged dalla metrica M_srv:\n")

    for host_ip, dati in host_flaggati.items():
        stampa_report(host_ip, dati)

# Esegui questo solo se lanciato come script principale (non importato come modulo)
if __name__ == "__main__":
    main()
