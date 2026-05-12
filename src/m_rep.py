"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
Metrica M_rep - Destination Reputation
=============================================================================

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

# Peso della metrica
PESO_M_REP = 50

# Finestra temporale di analisi: guardiamo i flussi dell'ultima ora (24 ore per test)
FINESTRA_ORE = 24


# =============================================================================
# QUERY SQL
# =============================================================================

# Questa query implementa direttamente la formula matematica del piano operativo:
#   A_rep = True  ->  M_rep = 1
#
# Per ogni host sorgente (IPV4_SRC_ADDR), conta quante volte ha contattato
# un server blacklistato (IS_SRV_BLACKLISTED = 1) o se è stato 
# identificato come client blacklistato (IS_CLI_BLACKLISTED = 1).
# La clausola HAVING filtra e restituisce solo gli host con almeno un hit.
#
# Colonne usate dello schema ClickHouse:
#   - IPV4_SRC_ADDR      -> IP sorgente del flusso (host monitorato)
#   - IS_SRV_BLACKLISTED -> 1 se il server di destinazione è in blacklist
#   - IS_CLI_BLACKLISTED -> 1 se il client è in blacklist
#   - FIRST_SEEN         -> timestamp di inizio flusso (usato per la finestra oraria)

QUERY_M_REP = f"""
SELECT
    IPv4NumToString(IPV4_SRC_ADDR)          AS host_ip,
    countIf(IS_SRV_BLACKLISTED = 1)         AS hits_srv_blacklisted,
    countIf(IS_CLI_BLACKLISTED = 1)         AS hits_cli_blacklisted,
    hits_srv_blacklisted + hits_cli_blacklisted AS hits_totali,

    -- Questo implementa la formula: A_rep = True -> M_rep = 1
    -- Se condizione è vera (hits_totali > 0), restituisce 1; altrimenti 0
    if(hits_totali > 0, 1, 0)               AS M_rep

FROM flows
WHERE
    -- Finestra temporale (ultima ora di traffico)
    FIRST_SEEN >= now() - INTERVAL {FINESTRA_ORE} HOUR

    -- Escludiamo i flussi IPv6 (IPV4_SRC_ADDR = 0 nei flussi IPv6 puri)
    AND IPV4_SRC_ADDR != 0

GROUP BY host_ip

-- Mostriamo solo gli host che hanno effettivamente triggerato la metrica
HAVING M_rep = 1

-- Ordiniamo per numero di contatti malevoli (i più pericolosi prima)
ORDER BY hits_totali DESC
"""


# =============================================================================
# FUNZIONI
# =============================================================================

def connetti_clickhouse():
    """
    Apre e restituisce la connessione al database ClickHouse.
    In caso di errore lancia un'eccezione
    che verrà catturata nel blocco principale.
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

    Struttura del dizionario restituito:
    {
        "192.168.1.45": {
            "M_rep":              1,
            "hits_srv":           2,   <- quante volte ha contattato server blacklistati
            "hits_cli":           0,   <- quante volte è stato lui stesso in blacklist
            "hits_totali":        2,
            "penalita":          50,   <- punti da sommare allo score dell'host
            "timestamp":         "2026-05-11T19:30:00"
        },
        ...
    }
    """
    risultati = {}

    # Esecuzione della query
    righe = client.query(QUERY_M_REP).result_rows

    # Ogni riga contiene: (host_ip, hits_srv, hits_cli, hits_totali, M_rep)
    for host_ip, hits_srv, hits_cli, hits_totali, m_rep in righe:

        risultati[host_ip] = {
            "M_rep":       m_rep,
            "hits_srv":    hits_srv,    # flussi verso server blacklistati
            "hits_cli":    hits_cli,    # flussi in cui l'host era esso stesso blacklistato
            "hits_totali": hits_totali,
            "penalita":    PESO_M_REP * m_rep,  # 50 se M_rep=1, 0 se M_rep=0
            "timestamp":   datetime.now(timezone.utc).isoformat()
        }

    return risultati


def calcola_score_finale(penalita_attive: dict) -> int:
    """
    Calcola lo score finale dell'host sommando le penalità di tutte le
    metriche attive, con un limite massimo a 100.

    Per ora riceviamo solo M_rep. Quando implementeremo le altre metriche,
    questo dizionario conterrà tutte le penalità attive dell'host.

    Esempio di input futuro:
    {
        "M_rep":   50,
        "M_cert":  40,
        "M_proto":  0,
        ...
    }
    """
    totale = sum(penalita_attive.values())

    # Il punteggio non può mai superare 100 (normalizzazione del modello)
    return min(100, totale)


def classifica_rischio(score: int) -> tuple[str, str]:
    """
    Mappa lo score numerico sulla fascia di rischio.

    Restituisce una tupla (colore, descrizione):
        Verde  ->  0-29  punti
        Giallo -> 30-59  punti
        Rosso  -> 60-100 punti
    """
    if score < 30:
        return ("VERDE",  "Host sicuro - nessun intervento richiesto")
    elif score < 60:
        return ("GIALLO", "Host sospetto - monitorare attentamente")
    else:
        return ("ROSSO",  "HOST COMPROMESSO - intervento immediato richiesto")


def stampa_report(host_ip: str, dati: dict, score: int, fascia: tuple):
    """
    Stampa un report leggibile con lo score per ogni host flaggato.
    """
    colore, descrizione = fascia
    print("=" * 60)
    print(f"  [ALLARME M_rep] {host_ip}")
    print("=" * 60)
    print(f"  Timestamp         : {dati['timestamp']}")
    print(f"  M_rep             : {dati['M_rep']} (attiva)")
    print(f"  Hit server BL     : {dati['hits_srv']}")
    print(f"  Hit client BL     : {dati['hits_cli']}")
    print(f"  Hit totali        : {dati['hits_totali']}")
    print(f"  Penalità M_rep    : +{dati['penalita']} punti")
    print(f"  Score S(h)        : {score}/100")
    print(f"  Fascia di rischio : [{colore}] {descrizione}")
    print()


# =============================================================================
# MAIN
# =============================================================================

def main():
    print(f"\n{'='*60}")
    print(f"  Avvio analisi M_rep - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Finestra temporale: ultima {FINESTRA_ORE} ora")
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
        # Nessun host ha contattato destinazioni blacklistate nell'ultima ora
        print("[OK] Nessun host flaggato - rete pulita nell'ultima ora.\n")
        return

    print(f"[!] {len(host_flaggati)} host flaggato/i dalla metrica M_rep:\n")

    for host_ip, dati in host_flaggati.items():

        # Costruiamo il dizionario delle penalità attive per questo host.
        # Ora contiene solo M_rep; le altre metriche verranno aggiunte qui.
        penalita_attive = {
            "M_rep": dati["penalita"],
            # "M_ja4":  0,  <- verrà aggiunto con la metrica successiva
            # "M_cert": 0,
            # ...
        }

        # Calcolo dello score finale con cap a 100
        score = calcola_score_finale(penalita_attive)

        # Classificazione nella fascia di rischio
        fascia = classifica_rischio(score)

        # Stampa del report per questo host
        stampa_report(host_ip, dati, score, fascia)

# Esegui questo solo se lanciato come script principale (non importato come modulo)
if __name__ == "__main__":
    main()
