"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
Metrica M_cert - TLS Certificate Anomalies
=============================================================================

Obiettivo:
    Rilevare comunicazioni verso server che presentano certificati TLS
    anomali (auto-firmati, scaduti, non corrispondenti al dominio,
    o con algoritmo di firma debole come SHA1).

Logica:
    Se ntopng ha rilevato almeno un flusso con certificato problematico
    nell'ultima ora, la metrica scatta -> M_cert = 1 -> +40 punti all'host.

Frequenza di esecuzione:
    Event-driven (metrica deterministica): lo script va eseguito ogni ora
    tramite cron o systemd timer.

Peso nel modello:
    +40 punti (Sospetto alto - anomalia strutturale grave ma da sola
    non basta a portare l'host in zona rossa, serve un'altra anomalia
    per superare la soglia 60)

Fonte dei dati:
    Tabella `flow_alerts_view` (vista) di ntopng su ClickHouse.
    Nella view viene fatta questa rinominazione: f.FLOW_RISK AS flow_risk_bitmap,
    usiamo questa perché filtra fin da subito i potenziali allarmi (WHERE f.STATUS != 0).
    A differenza di M_rep (che usava colonne booleane già pronte),
    qui i problemi di certificato sono codificati come bit nel campo
    `flow_risk_bitmap`. Ogni bit corrisponde a un rischio nDPI specifico.

Mappa dei bit nDPI usati (verificata su nDPI, vedere risk_info nel JSON):
    bit 6  -> NDPI_TLS_SELFSIGNED_CERTIFICATE   ("Self-signed Cert")
    bit 9  -> NDPI_TLS_CERTIFICATE_EXPIRED      ("TLS Cert Expired")
    bit 10 -> NDPI_TLS_CERTIFICATE_MISMATCH     ("TLS Cert Mismatch")
    bit 29 -> NDPI_MALICIOUS_SHA1_CERTIFICATE   ("Malicious SHA1 Cert")

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
    PESO_M_CERT, FINESTRA_MINUTI_DEFAULT,
)

# =============================================================================
# QUERY SQL
# =============================================================================

# La query SQL viene costruita dentro `calcola_m_cert()` perché dipende
# dal parametro `finestra_minuti`, che può essere passato dinamicamente
# (default = FINESTRA_MINUTI_DEFAULT).
#
# Implementa la formula matematica del piano operativo:
#   A_cert = True -> M_cert = 1
# dove A_cert è l'insieme degli allarmi nativi di ntopng sui certificati.
#
# A differenza di M_rep, qui non c'è una colonna booleana già pronta.
# I problemi di certificato sono codificati come bit in `flow_risk_bitmap`:
# ogni bit corrisponde a un rischio nDPI specifico. Usiamo bitTest() di
# ClickHouse per controllare i singoli bit.
#
# Colonne usate dello schema ClickHouse (tabella flow_alerts_view):
#   - cli_ip            -> IP del client (host monitorato)
#   - tstamp            -> timestamp del flusso
#   - flow_risk_bitmap  -> bitmap dei rischi nDPI rilevati sul flusso
#
# La clausola GROUP BY + HAVING aggrega per host e mantiene solo
# quelli con almeno un bit di certificato attivo.


# =============================================================================
# FUNZIONI
# =============================================================================

def calcola_m_cert(client, finestra_minuti: int = FINESTRA_MINUTI_DEFAULT):
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

    Il formato di ritorno è SIMMETRICO a calcola_m_rep() di m_rep.py:
    chiave = IP dell'host, valore = dizionario con i dettagli.
    Questa simmetria è essenziale perché lo `scoring.py`, il quale
    chiamerà tutte le metriche aspettandosi lo stesso formato.

    Struttura del dizionario restituito:
    {
        "192.168.1.45": {
            "M_cert":            1,
            "hits_self_signed":  1,   <- cert auto-firmati contattati
            "hits_expired":      2,   <- cert scaduti contattati
            "hits_mismatch":     0,   <- cert con dominio non corrispondente
            "hits_sha1":         0,   <- cert con SHA1 (debole)
            "hits_totali":       3,
            "penalita":         40,   <- punti da sommare allo score
            "timestamp":         "2026-05-13T16:50:00+00:00"
        },
        ...
    }
    """
    # Costruzione della query con il parametro `finestra_minuti`.
    # Il valore è un intero controllato (validato a monte da argparse
    # o passato esplicitamente come argomento di funzione), quindi è
    # sicuro inserirlo via f-string senza rischio di SQL injection.
    #
    # `filtro_lan` è costruito dal modulo condiviso network_config:
    #  limita l'analisi ai soli host della LAN interna (RFC 1918) sulla colonna
    #  cli_ip, che è il "soggetto" del flusso.
    filtro_lan = costruisci_filtro_lan("cli_ip")

    query = f"""
    SELECT
        cli_ip AS host_ip,

        -- Conteggio per ogni tipo di anomalia di certificato
        countIf(bitTest(flow_risk_bitmap, 6)  = 1) AS hits_self_signed,
        countIf(bitTest(flow_risk_bitmap, 9)  = 1) AS hits_expired,
        countIf(bitTest(flow_risk_bitmap, 10) = 1) AS hits_mismatch,
        countIf(bitTest(flow_risk_bitmap, 29) = 1) AS hits_sha1,

        -- Hit totali su qualsiasi bit di certificato
        hits_self_signed + hits_expired + hits_mismatch + hits_sha1 AS hits_totali,

        -- Se condizione è vera (hits_totali > 0), restituisce 1; altrimenti 0
        if(hits_totali > 0, 1, 0) AS M_cert

    FROM flow_alerts_view
    WHERE
        -- Finestra temporale parametrica (default 60 minuti)
        tstamp >= now() - INTERVAL {finestra_minuti} MINUTE

        -- Filtro LAN interna: classifichiamo solo host della rete monitorata
        AND {filtro_lan}

        -- Pre-filtro: ci interessano SOLO i flussi con almeno un bit di
        -- certificato attivo. Sfruttiamo l'efficienza colonnare di ClickHouse
        -- per scartare subito tutti gli altri flussi.
        AND (
            bitTest(flow_risk_bitmap, 6)  = 1
            OR bitTest(flow_risk_bitmap, 9)  = 1
            OR bitTest(flow_risk_bitmap, 10) = 1
            OR bitTest(flow_risk_bitmap, 29) = 1
        )

    GROUP BY host_ip

    -- Mostriamo solo gli host che hanno effettivamente triggerato la metrica
    HAVING M_cert = 1

    -- Ordiniamo per gravità (host con più anomalie cert prima)
    ORDER BY hits_totali DESC
    """

    risultati = {}

    # Esecuzione della query
    righe = client.query(query).result_rows

    # Ogni riga contiene:
    # (host_ip, hits_self_signed, hits_expired, hits_mismatch,
    #  hits_sha1, hits_totali, M_cert)
    for (host_ip, hits_self_signed, hits_expired, hits_mismatch,
         hits_sha1, hits_totali, m_cert) in righe:

        risultati[host_ip] = {
            "M_cert":           m_cert,
            "hits_self_signed": hits_self_signed,
            "hits_expired":     hits_expired,
            "hits_mismatch":    hits_mismatch,
            "hits_sha1":        hits_sha1,
            "hits_totali":      hits_totali,
            "penalita":         PESO_M_CERT * m_cert,  # 40 se M_cert=1, 0 altrimenti
            "timestamp":        datetime.now(timezone.utc).isoformat()
        }

    return risultati


def stampa_report(host_ip: str, dati: dict):
    """
    Stampa un report leggibile per ogni host flagged dalla sola metrica.
    Usato quando lanciamo questo script in modalità "test".
    Quando invece chiamato da `scoring.py`, sarà quello a stampare il
    report unificato che somma tutte le metriche.
    """
    print("=" * 60)
    print(f"  [ALLARME M_cert] {host_ip}")
    print("=" * 60)
    print(f"  Timestamp           : {dati['timestamp']}")
    print(f"  M_cert              : {dati['M_cert']} (attiva)")
    print(f"  Hit self-signed     : {dati['hits_self_signed']}")
    print(f"  Hit expired         : {dati['hits_expired']}")
    print(f"  Hit mismatch        : {dati['hits_mismatch']}")
    print(f"  Hit SHA1 weak       : {dati['hits_sha1']}")
    print(f"  Hit totali          : {dati['hits_totali']}")
    print(f"  Penalità M_cert     : +{dati['penalita']} punti")
    print()


# =============================================================================
# MAIN - Esecuzione per testing
# =============================================================================

def main():
    """
    Quando integreremo tutto in scoring.py, questa funzione NON verrà chiamata:
    scoring.py importerà direttamente `calcola_m_cert()` dalla funzione sopra.

    Esecuzione da CLI:
        python m_cert.py                          # usa il default (60 minuti)
        python m_cert.py --finestra-minuti 10     # finestra di 10 minuti
        python m_cert.py --finestra-minuti 1440   # finestra di 24 ore
    """
    # Parsing degli argomenti da riga di comando
    parser = argparse.ArgumentParser(
        description="Calcolo della metrica M_cert (TLS Certificate Anomalies)."
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

    print(f"\n{'='*60}")
    print(f"  Avvio analisi M_cert - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Finestra temporale: ultimi {args.finestra_minuti} minuto/i")
    print(f"{'='*60}\n")

    # Connessione al database
    try:
        client = connetti_clickhouse()
        print("[OK] Connessione a ClickHouse stabilita.\n")
    except Exception as e:
        print(f"[ERRORE] Impossibile connettersi a ClickHouse: {e}")
        return

    # Calcolo della metrica M_cert con la finestra specificata
    try:
        flagged_host = calcola_m_cert(client, finestra_minuti=args.finestra_minuti)
    except Exception as e:
        print(f"[ERRORE] Errore durante l'esecuzione della query: {e}")
        return

    # Report dei risultati
    if not flagged_host:
        print(f"[OK] Nessun host flagged - nessuna anomalia di certificato negli ultimi {args.finestra_minuti} minuto/i.\n")
        return

    print(f"[!] {len(flagged_host)} host flagged dalla metrica M_cert:\n")

    for host_ip, dati in flagged_host.items():
        stampa_report(host_ip, dati)

# Esegui questo solo se lanciato come script principale (non importato come modulo)
if __name__ == "__main__":
    main()
