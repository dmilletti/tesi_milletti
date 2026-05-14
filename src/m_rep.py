"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
Metrica M_rep - Destination Reputation
=============================================================================

Obiettivo:
    Rilevare comunicazioni tra host interni e indirizzi IP noti come
    malevoli (server C2, nodi Tor, domini di phishing) consultando
    le blacklist integrate di ntopng.

Logica differenziata in base alla direzione del contatto:
    Caso A - l'host interno ha contattato un server blacklistato:
            è un segnale di COMPROMISSIONE ATTIVA (probabile C2 o esfiltrazione) -> +50 punti
    Caso B - un client esterno blacklistato ha contattato il nostro host:
            è un segnale di esposizione/scansione, non compromissione -> +10 punti
    Caso C - entrambi (estremamente raro): prevale Caso A -> +50 punti

Frequenza di esecuzione:
    Event-driven (metrica deterministica): lo script va eseguito ogni ora
    tramite cron o systemd timer.

Fonte dei dati:
    Tabella `flows` di ntopng su ClickHouse.

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

# Pesi differenziati per la direzione del contatto:
# - SRV blacklisted = host ha contattato un IP malevolo (compromissione)
# - CLI blacklisted = host è stato contattato da un IP malevolo (scansione)
PESO_SRV_BLACKLISTED = 50   # Gravità critica
PESO_CLI_BLACKLISTED = 10   # Segnale debole

# Finestra temporale di analisi (ultima ora)
FINESTRA_ORE = 24


# =============================================================================
# QUERY SQL
# =============================================================================

# La query applica la differenziazione dei pesi a livello SQL.
#
# multiIf() è l'equivalente di una catena di if/elif:
#   - se hits_srv_blacklisted > 0    -> assegna PESO_SRV_BLACKLISTED
#   - altrimenti se hits_cli_blacklisted > 0 -> assegna PESO_CLI_BLACKLISTED
#   - altrimenti -> 0
# Se un host ha contattato un server BL, vale +50 anche se è stato anche contattato
# da un client BL (non sommiamo, evitiamo doppio peso).

QUERY_M_REP = f"""
SELECT
    IPv4NumToString(IPV4_SRC_ADDR) AS host_ip,
    countIf(IS_SRV_BLACKLISTED = 1) AS hits_srv_blacklisted,
    countIf(IS_CLI_BLACKLISTED = 1) AS hits_cli_blacklisted,

    -- Hit totali (puramente informativo, non usato per il peso)
    hits_srv_blacklisted + hits_cli_blacklisted AS hits_totali,

    -- Se condizione è vera M_rep si attiva (hits_totali > 0), restituisce 1; altrimenti 0
    if(hits_totali > 0, 1, 0) AS M_rep,

    -- Penalità DIFFERENZIATA in base alla direzione del contatto:
    --   - se ha contattato server BL: +50 (host probabilmente compromesso)
    --   - altrimenti se contattato da client BL: +10 (solo bersaglio)
    multiIf(
        hits_srv_blacklisted > 0, {PESO_SRV_BLACKLISTED},
        hits_cli_blacklisted > 0, {PESO_CLI_BLACKLISTED},
        0
    ) AS penalita_calcolata,

    -- Scenario testuale (utile per il report)
    multiIf(
        hits_srv_blacklisted > 0, 'COMPROMISSIONE ATTIVA (contatto a server BL)',
        hits_cli_blacklisted > 0, 'ESPOSIZIONE (contattato da client BL)',
        'N/A'
    ) AS scenario

FROM flows
WHERE
    -- Finestra temporale (ultima ora di traffico)
    FIRST_SEEN >= now() - INTERVAL {FINESTRA_ORE} HOUR

    -- Escludiamo i flussi IPv6 (IPV4_SRC_ADDR = 0 nei flussi IPv6 puri)
    AND IPV4_SRC_ADDR != 0
    AND CLIENT_LOCATION = 1   -- solo host della LAN interna

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
    Il formato del dizionario è identico a quello delle altre metriche.

    Struttura del dizionario restituito:
    {
        "192.168.1.45": {
            "M_rep":         1,
            "hits_srv":      2,    <- flussi verso server blacklistati
            "hits_cli":      0,    <- flussi da client blacklistati
            "hits_totali":   2,
            "scenario":      "COMPROMISSIONE ATTIVA (contatto a server BL)",
            "penalita":      50,   <- peso differenziato per direzione
            "timestamp":     "2026-05-13T17:00:00+00:00"
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
            "hits_srv":    hits_srv,      # contatti verso server BL
            "hits_cli":    hits_cli,      # contatti ricevuti da client BL
            "hits_totali": hits_totali,
            "scenario":    scenario,      # descrizione testuale del caso
            "penalita":    penalita,      # già differenziata dalla query
            "timestamp":   datetime.now(timezone.utc).isoformat()
        }

    return risultati


def stampa_report(host_ip: str, dati: dict):
    """
    Stampa un report leggibile per ogni host flaggato dalla sola metrica.
    Usato quando lo script è eseguito per testing isolato.
    """
    print("=" * 60)
    print(f"  [ALLARME M_rep] {host_ip}")
    print("=" * 60)
    print(f"  Timestamp         : {dati['timestamp']}")
    print(f"  M_rep             : {dati['M_rep']} (attiva)")
    print(f"  Scenario          : {dati['scenario']}")
    print(f"  Hit server BL     : {dati['hits_srv']}")
    print(f"  Hit client BL     : {dati['hits_cli']}")
    print(f"  Hit totali        : {dati['hits_totali']}")
    print(f"  Penalità M_rep    : +{dati['penalita']} punti")
    print()


# =============================================================================
# MAIN - Esecuzione per testing isolato della metrica
# =============================================================================

def main():
    """
    Quando integreremo tutto in scoring.py, questa funzione NON verrà chiamata:
    scoring.py importerà direttamente `calcola_m_rep()` dalla funzione sopra.
    """
    print(f"\n{'='*60}")
    print(f"  Avvio analisi M_rep - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Finestra temporale: ultima {FINESTRA_ORE} ora")
    print(f"  Pesi: SRV blacklisted=+{PESO_SRV_BLACKLISTED}, CLI blacklisted=+{PESO_CLI_BLACKLISTED}")
    print(f"{'='*60}\n")

    # Step 1: connessione al database
    try:
        client = connetti_clickhouse()
        print("[OK] Connessione a ClickHouse stabilita.\n")
    except Exception as e:
        print(f"[ERRORE] Impossibile connettersi a ClickHouse: {e}")
        return

    # Step 2: calcolo della metrica M_rep
    try:
        host_flaggati = calcola_m_rep(client)
    except Exception as e:
        print(f"[ERRORE] Errore durante l'esecuzione della query: {e}")
        return

    # Step 3: report dei risultati
    if not host_flaggati:
        print("[OK] Nessun host flaggato - rete pulita nell'ultima ora.\n")
        return

    print(f"[!] {len(host_flaggati)} host flaggato/i dalla metrica M_rep:\n")

    for host_ip, dati in host_flaggati.items():
        stampa_report(host_ip, dati)

# Esegui questo solo se lanciato come script principale (non importato come modulo)
if __name__ == "__main__":
    main()
