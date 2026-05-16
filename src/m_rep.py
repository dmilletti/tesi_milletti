"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
Metrica M_rep - Destination Reputation
=============================================================================

Obiettivo:
    Rilevare comunicazioni tra host interni della LAN e indirizzi IP noti
    come malevoli (server C2, nodi Tor, domini di phishing) consultando
    le blacklist integrate di ntopng.

Classificazione su due livelli (rispetto al modello teorico base):

  (1) DIREZIONE del contatto:
      - SRV blacklisted = l'host ha contattato un IP malevolo
                          -> segnale di COMPROMISSIONE ATTIVA
      - CLI blacklisted = l'host è stato contattato da un IP malevolo
                          -> segnale di ESPOSIZIONE/scansione

  (2) INTENSITÀ del contatto (numero di hit):
      Il modello matematico originale prevedeva M_i ∈ {0,1} con peso fisso.
      La metrica resta binaria, ma il PESO scala con
      il numero di hit:
        - Pochi hit (1-2 verso server BL) possono essere falsi positivi
          (es. blacklist obsoleta). Peso ridotto.
        - Molti hit (3+ verso server BL) indicano comunicazione
          persistente con C2 attivo. Peso pieno.
      Importante: non azzeriamo mai il peso, per non perdere gli attacchi
      "low and slow" che fanno beacon ogni ora.

Tabella dei pesi applicati:

  Caso SRV blacklisted (host contatta IP malevolo):
    hits = 1-2  ->  +30 punti (contatto isolato - possibile beacon iniziale)
    hits = 3+   ->  +50 punti (comunicazione persistente - C2 attivo confermato)

  Caso CLI blacklisted (host è bersaglio di IP malevolo):
    hits = 1-10 ->  +5  punti (scansione rara - rumore di fondo Internet)
    hits = 11+  ->  +15 punti (scansione persistente - target mirato)

  Caso entrambi attivi: prevale il caso più grave (SRV blacklisted).

Soglie di rischio dello score finale S(h):
    Verde  ->  0-29  punti  (host sicuro)
    Giallo -> 30-59  punti  (host sospetto, da monitorare)
    Rosso  -> 60-100 punti  (host compromesso, intervento immediato)
=============================================================================
"""

import clickhouse_connect
from datetime import datetime, timezone


# =============================================================================
# CONFIGURAZIONE
# =============================================================================

# Parametri di connessione a ClickHouse
CLICKHOUSE_HOST     = "localhost"
CLICKHOUSE_PORT     = 8123          # porta HTTP di ClickHouse
CLICKHOUSE_DATABASE = "ntopng"
CLICKHOUSE_USER     = "default"
CLICKHOUSE_PASSWORD = "0022"

# Soglie di intensità
SOGLIA_SRV_PERSISTENTE = 3
SOGLIA_CLI_MIRATO      = 11

# Pesi differenziati per direzione e intensità
PESO_SRV_ISOLATO     = 30   # 1-2 hit verso server BL
PESO_SRV_PERSISTENTE = 50   # 3+ hit verso server BL
PESO_CLI_RARO   = 5    # 1-10 hit da client BL
PESO_CLI_MIRATO      = 15   # 11+ hit da client BL

# Finestra temporale di analisi: guardiamo i flussi dell'ultima ora
FINESTRA_ORE = 1


# =============================================================================
# QUERY SQL
# =============================================================================

# La query applica la differenziazione su entrambi i livelli (direzione e
# intensità) direttamente lato database, evitando di trasferire dati grezzi
# allo script Python.
#
# multiIf() implementa la catena di if/elif annidati:
#   - se hits_srv >= 3       -> +50 (persistente)
#   - altrimenti se hits_srv >= 1   -> +30 (isolato)
#   - altrimenti se hits_cli >= 11  -> +15 (mirato)
#   - altrimenti se hits_cli >= 1   -> +5  (raro)
#   - altrimenti                    -> 0
# Prima si valuta SRV, e solo se non si attiva si scende sul caso CLI.
#
# Filtro CLIENT_LOCATION = 1: consideriamo solo host della LAN interna (per ora commentato)

QUERY_M_REP = f"""
SELECT
    IPv4NumToString(IPV4_SRC_ADDR) AS host_ip,
    countIf(IS_SRV_BLACKLISTED = 1) AS hits_srv_blacklisted,
    countIf(IS_CLI_BLACKLISTED = 1) AS hits_cli_blacklisted,

    -- Hit totali (informativo, non usato per il peso)
    hits_srv_blacklisted + hits_cli_blacklisted AS hits_totali,

    -- Se condizione è vera (hits_totali > 0), restituisce 1; altrimenti 0
    if(hits_totali > 0, 1, 0) AS M_rep,

    -- Penalità DIFFERENZIATA su DIREZIONE e INTENSITÀ
    multiIf(
        hits_srv_blacklisted >= {SOGLIA_SRV_PERSISTENTE}, {PESO_SRV_PERSISTENTE},
        hits_srv_blacklisted >= 1,                        {PESO_SRV_ISOLATO},
        hits_cli_blacklisted >= {SOGLIA_CLI_MIRATO},      {PESO_CLI_MIRATO},
        hits_cli_blacklisted >= 1,                        {PESO_CLI_RARO},
        0
    ) AS penalita_calcolata,

    -- Scenario testuale per il report
    multiIf(
        hits_srv_blacklisted >= {SOGLIA_SRV_PERSISTENTE}, 'COMPROMISSIONE PERSISTENTE (C2 attivo - hits ripetuti)',
        hits_srv_blacklisted >= 1,                        'CONTATTO ISOLATO a server BL (possibile beacon iniziale)',
        hits_cli_blacklisted >= {SOGLIA_CLI_MIRATO},      'SCANSIONE MIRATA (target persistente)',
        hits_cli_blacklisted >= 1,                        'SCANSIONE RARA (rumore di fondo Internet)',
        'N/A'
    ) AS scenario

FROM flows
WHERE
    -- Finestra temporale: ultima ora di traffico
    FIRST_SEEN >= now() - INTERVAL {FINESTRA_ORE} HOUR

    -- Escludiamo i flussi IPv6 (IPV4_SRC_ADDR = 0 nei flussi IPv6 puri)
    AND IPV4_SRC_ADDR != 0

    -- Consideriamo SOLO host della LAN interna (per ora commentato)
    -- Per AND CLIENT_LOCATION = 1

GROUP BY host_ip

-- Mostriamo solo gli host che hanno effettivamente triggerato la metrica
HAVING M_rep = 1

-- Ordinamento: prima i casi più gravi (penalità maggiore),
-- poi a parità di gravità i più ripetitivi
ORDER BY penalita_calcolata DESC, hits_totali DESC
"""


# =============================================================================
# FUNZIONI
# =============================================================================

def connetti_clickhouse():
    """
    Apre e restituisce la connessione al database ClickHouse.
    """
    client = clickhouse_connect.get_client(
        host     = CLICKHOUSE_HOST,
        port     = CLICKHOUSE_PORT,
        database = CLICKHOUSE_DATABASE,
        username = CLICKHOUSE_USER,
        password = CLICKHOUSE_PASSWORD,
    )
    return client


def calcola_m_rep(client):
    """
    Esegue la query su ClickHouse e restituisce un dizionario con i risultati.

    Il formato del dizionario è simmetrico a quello delle altre metriche
    per permettere a scoring.py di trattare tutte le metriche uniformemente.

    Struttura del dizionario restituito:
    {
        "192.168.1.45": {
            "M_rep":         1,
            "hits_srv":      4,
            "hits_cli":      0,
            "hits_totali":   4,
            "scenario":      "COMPROMISSIONE PERSISTENTE (C2 attivo - hits ripetuti)",
            "penalita":      50,
            "timestamp":     "2026-05-14T17:00:00+00:00"
        },
        ...
    }
    """
    risultati = {}

    # Esecuzione della query
    righe = client.query(QUERY_M_REP).result_rows

    # Ogni riga contiene:
    # (host_ip, hits_srv, hits_cli, hits_totali, M_rep,
    #  penalita_calcolata, scenario)
    for (host_ip, hits_srv, hits_cli, hits_totali, m_rep,
         penalita, scenario) in righe:

        risultati[host_ip] = {
            "M_rep":       m_rep,
            "hits_srv":    hits_srv,
            "hits_cli":    hits_cli,
            "hits_totali": hits_totali,
            "scenario":    scenario,
            "penalita":    penalita,    # già differenziata dalla query
            "timestamp":   datetime.now(timezone.utc).isoformat()
        }

    return risultati


def stampa_report(host_ip: str, dati: dict):
    """
    Stampa un report leggibile per ogni host flagged dalla sola metrica.
    Usato quando lo script è eseguito per testing..
    """
    print("=" * 70)
    print(f"  [ALLARME M_rep] {host_ip}")
    print("=" * 70)
    print(f"  Timestamp         : {dati['timestamp']}")
    print(f"  M_rep             : {dati['M_rep']} (attiva)")
    print(f"  Scenario          : {dati['scenario']}")
    print(f"  Hit server BL     : {dati['hits_srv']}")
    print(f"  Hit client BL     : {dati['hits_cli']}")
    print(f"  Hit totali        : {dati['hits_totali']}")
    print(f"  Penalità M_rep    : +{dati['penalita']} punti")
    print()


# =============================================================================
# MAIN - Esecuzione per testing
# =============================================================================

def main():
    """
    Quando integreremo tutto in scoring.py, questa funzione NON verrà chiamata.
    scoring.py importerà direttamente `calcola_m_rep()` dalla funzione sopra.
    """
    print(f"\n{'='*70}")
    print(f"  Avvio analisi M_rep - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Finestra temporale: ultima {FINESTRA_ORE} ora")
    print(f"  Pesi differenziati su direzione e intensità:")
    print(f"    SRV isolato (1-{SOGLIA_SRV_PERSISTENTE-1}): +{PESO_SRV_ISOLATO}     "
          f"SRV persistente ({SOGLIA_SRV_PERSISTENTE}+): +{PESO_SRV_PERSISTENTE}")
    print(f"    CLI raro (1-{SOGLIA_CLI_MIRATO-1}): +{PESO_CLI_RARO}     "
          f"CLI mirato ({SOGLIA_CLI_MIRATO}+): +{PESO_CLI_MIRATO}")
    print(f"{'='*70}\n")

    # Connessione al database
    try:
        client = connetti_clickhouse()
        print("[OK] Connessione a ClickHouse stabilita.\n")
    except Exception as e:
        print(f"[ERRORE] Impossibile connettersi a ClickHouse: {e}")
        return

    # Calcolo della metrica M_rep
    try:
        flagged_host = calcola_m_rep(client)
    except Exception as e:
        print(f"[ERRORE] Errore durante l'esecuzione della query: {e}")
        return

    # Report dei risultati
    if not flagged_host:
        print("[OK] Nessun host flagged - rete pulita nell'ultima ora.\n")
        return

    print(f"[!] {len(flagged_host)} host flagged dalla metrica M_rep:\n")

    for host_ip, dati in flagged_host.items():
        stampa_report(host_ip, dati)

# Esegui questo solo se lanciato come script principale (non importato come modulo)
if __name__ == "__main__":
    main()
