"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
Metrica M_sni - SNI Evasion
=============================================================================

Obiettivo:
    Rilevare tentativi di mascheramento delle comunicazioni TLS verso
    l'esterno, identificando i flussi cifrati che non includono il
    parametro SNI (Server Name Indication) durante l'handshake.

    I browser e le applicazioni legittime includono SEMPRE il nome
    del dominio di destinazione nell'estensione SNI. L'assenza di
    questo parametro è un'anomalia strutturale tipica di:
      - malware che contatta direttamente un IP numerico per nascondersi
      - script malevoli che bypassano la risoluzione DNS
      - strumenti di hacking che non rispettano gli standard TLS

Logica:
    Se ntopng ha rilevato almeno un flusso TLS senza SNI
    nell'ultima ora, la metrica scatta -> M_sni = 1 -> +50 punti all'host.

Frequenza di esecuzione:
    Event-driven (metrica deterministica): lo script va eseguito ogni ora
    tramite cron o systemd timer.

Peso nel modello:
    +50 punti (Gravità critica - zero falsi positivi)

Fonte dei dati:
    Tabella `flow_alerts_view` di ntopng su ClickHouse.
    Il problema è codificato come bit 24 nel campo `flow_risk_bitmap`.

Mappa nDPI usata (verificata su nDPI):
    bit 24 -> NDPI_TLS_MISSING_SNI  ("SNI should always be present")

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

# Parametri di connessione a ClickHouse (identici alle altre metriche)
CLICKHOUSE_HOST     = "localhost"
CLICKHOUSE_PORT     = 8123          # porta HTTP di ClickHouse
CLICKHOUSE_DATABASE = "ntopng"
CLICKHOUSE_USER     = "default"
CLICKHOUSE_PASSWORD = "0022"

# Peso della metrica nel modello di scoring
PESO_M_SNI = 50

# Finestra temporale di analisi: guardiamo i flussi dell'ultima ora
FINESTRA_ORE = 1


# =============================================================================
# QUERY SQL
# =============================================================================

# Implementa la formula matematica del piano operativo:
#   A_sni = True -> M_sni = 1
#
# La logica è identica nello schema a M_cert: leggiamo dalla tabella
# `flow_alerts_view` e usiamo bitTest() per verificare il bit 24
# (NDPI_TLS_MISSING_SNI) del campo flow_risk_bitmap.
#
# A differenza di M_cert, qui controlliamo un SOLO bit specifico.

QUERY_M_SNI = f"""
SELECT
    cli_ip AS host_ip,

    -- Conteggio dei flussi senza SNI generati dall'host
    countIf(bitTest(flow_risk_bitmap, 24) = 1) AS hits_missing_sni,

    -- Se condizione è vera (hits_missing_sni > 0), restituisce 1; altrimenti 0
    if(hits_missing_sni > 0, 1, 0) AS M_sni

FROM flow_alerts_view
WHERE
    -- Finestra temporale: ultima ora di traffico
    tstamp >= now() - INTERVAL {FINESTRA_ORE} HOUR

    -- Pre-filtro: ci interessano solo i flussi con bit 24 attivo.
    -- Sfruttiamo l'efficienza colonnare di ClickHouse per scartare
    -- subito tutti gli altri flussi.
    AND bitTest(flow_risk_bitmap, 24) = 1

GROUP BY host_ip

-- Mostriamo solo gli host che hanno effettivamente triggerato la metrica
HAVING M_sni = 1

-- Ordiniamo per numero di violazioni (i più pericolosi prima)
ORDER BY hits_missing_sni DESC
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


def calcola_m_sni(client):
    """
    Esegue la query su ClickHouse e restituisce un dizionario con i risultati.

    Il formato di ritorno è SIMMETRICO alle altre metriche:
    chiave = IP dell'host, valore = dizionario con i dettagli.
    Questa simmetria è essenziale perché lo `scoring.py`, il quale
    chiamerà tutte le metriche aspettandosi lo stesso formato.

    Struttura del dizionario restituito:
    {
        "192.168.1.45": {
            "M_sni":           1,
            "hits_missing":    3,    <- flussi TLS senza SNI rilevati
            "penalita":       50,    <- punti da sommare allo score
            "timestamp":     "2026-05-14T15:30:00+00:00"
        },
        ...
    }
    """
    risultati = {}

    # Esecuzione della query
    righe = client.query(QUERY_M_SNI).result_rows

    # Ogni riga contiene: (host_ip, hits_missing_sni, M_sni)
    for host_ip, hits_missing_sni, m_sni in righe:

        risultati[host_ip] = {
            "M_sni":        m_sni,
            "hits_missing": hits_missing_sni,
            "penalita":     PESO_M_SNI * m_sni,  # 50 se M_sni=1, 0 altrimenti
            "timestamp":    datetime.now(timezone.utc).isoformat()
        }

    return risultati


def stampa_report(host_ip: str, dati: dict):
    """
    Stampa un report leggibile per ogni host flaggato dalla sola metrica.
    Usato quando lo script è eseguito per testing.
    """
    print("=" * 60)
    print(f"  [ALLARME M_sni] {host_ip}")
    print("=" * 60)
    print(f"  Timestamp           : {dati['timestamp']}")
    print(f"  M_sni               : {dati['M_sni']} (attiva)")
    print(f"  Hit Missing SNI     : {dati['hits_missing']}")
    print(f"  Penalità M_sni      : +{dati['penalita']} punti")
    print()


# =============================================================================
# MAIN - Esecuzione per testing
# =============================================================================

def main():
    """
    Quando integreremo tutto in scoring.py, questa funzione NON verrà chiamata:
    scoring.py importerà direttamente `calcola_m_sni()` dalla funzione sopra.
    """
    print(f"\n{'='*60}")
    print(f"  Avvio analisi M_sni - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Finestra temporale: ultima {FINESTRA_ORE} ora")
    print(f"{'='*60}\n")

    # Connessione al database
    try:
        client = connetti_clickhouse()
        print("[OK] Connessione a ClickHouse stabilita.\n")
    except Exception as e:
        print(f"[ERRORE] Impossibile connettersi a ClickHouse: {e}")
        return

    # Calcolo della metrica M_sni
    try:
        host_flaggati = calcola_m_sni(client)
    except Exception as e:
        print(f"[ERRORE] Errore durante l'esecuzione della query: {e}")
        return

    # Report dei risultati
    if not host_flaggati:
        print("[OK] Nessun host flaggato - nessuna violazione SNI nell'ultima ora.\n")
        return

    print(f"[!] {len(host_flaggati)} host flaggato/i dalla metrica M_sni:\n")

    for host_ip, dati in host_flaggati.items():
        stampa_report(host_ip, dati)

# Esegui questo solo se lanciato come script principale (non importato come modulo)
if __name__ == "__main__":
    main()
