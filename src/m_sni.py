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

import argparse
from datetime import datetime, timezone

from config import costruisci_filtro_lan, connetti_clickhouse


# =============================================================================
# CONFIGURAZIONE
# =============================================================================

# Peso della metrica nel modello di scoring
PESO_M_SNI = 50

# Finestra temporale di analisi (default): guardiamo i flussi degli ultimi 60 minuti.
# Può essere sovrascritta dall'argomento `--finestra-minuti` da CLI oppure
# passando un valore esplicito alla funzione `calcola_m_sni()`.
# Nel sistema finale, lo scoring.py chiama la funzione senza argomenti e usa
# questo default; il parametro serve a contenere il costo della query
# quando si testa su tabelle molto grandi (miliardi di record).
FINESTRA_MINUTI_DEFAULT = 60


# =============================================================================
# QUERY SQL
# =============================================================================

# La query SQL viene costruita dentro `calcola_m_sni()` perché dipende
# dal parametro `finestra_minuti`, che può essere passato dinamicamente
# (default = FINESTRA_MINUTI_DEFAULT).
#
# Implementa la formula matematica del piano operativo:
#   A_sni = True -> M_sni = 1
#
# La logica è identica nello schema a M_cert: leggiamo dalla tabella
# `flow_alerts_view` e usiamo bitTest() per verificare il bit 24
# (NDPI_TLS_MISSING_SNI) del campo flow_risk_bitmap.
#
# A differenza di M_cert, qui controlliamo un SOLO bit specifico.


# =============================================================================
# FUNZIONI
# =============================================================================

def calcola_m_sni(client, finestra_minuti: int = FINESTRA_MINUTI_DEFAULT):
    """
    Esegue la query su ClickHouse e restituisce un dizionario con i risultati.

    Parametri:
    --finestra_minuti : ampiezza della finestra temporale di analisi in minuti.
                        Default = FINESTRA_MINUTI_DEFAULT (60 minuti,)
                        per essere compatibili con lo scoring.py esistente.
                        Valori piccoli (es. 5-10) servono per testare la
                        metrica su tabelle molto grandi (miliardi di
                        record) contenendo l'intervallo della query.

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
    # Costruzione della query con il parametro `finestra_minuti`.
    # Il valore è un intero controllato (validato a monte da argparse
    # o passato esplicitamente come argomento di funzione), quindi è
    # sicuro inserirlo via f-string senza rischio di SQL injection.
    #
    # `filtro_lan` è costruito dal modulo condiviso network_config:
    # limita l'analisi ai soli host della LAN interna (RFC 1918) sulla colonna
    # cli_ip, che è il "soggetto" del flusso (il client che fa TLS senza SNI).
    filtro_lan = costruisci_filtro_lan("cli_ip")

    query = f"""
    SELECT
        cli_ip AS host_ip,

        -- Conteggio dei flussi senza SNI generati dall'host
        countIf(bitTest(flow_risk_bitmap, 24) = 1) AS hits_missing_sni,

        -- Se condizione è vera (hits_missing_sni > 0), restituisce 1; altrimenti 0
        if(hits_missing_sni > 0, 1, 0) AS M_sni

    FROM flow_alerts_view
    WHERE
        -- Finestra temporale parametrica (default 60 minuti)
        tstamp >= now() - INTERVAL {finestra_minuti} MINUTE

        -- Filtro LAN interna: valutiamo solo host della rete monitorata
        AND {filtro_lan}

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

    risultati = {}

    # Esecuzione della query
    righe = client.query(query).result_rows

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

    Esecuzione da CLI:
        python m_sni.py                          # usa il default (60 minuti)
        python m_sni.py --finestra-minuti 10     # finestra di 10 minuti
        python m_sni.py --finestra-minuti 1440   # finestra di 24 ore
    """
    # Parsing degli argomenti da riga di comando
    parser = argparse.ArgumentParser(
        description="Calcolo della metrica M_sni (SNI Evasion)."
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
    print(f"  Avvio analisi M_sni - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Finestra temporale: ultimi {args.finestra_minuti} minuto/i")
    print(f"{'='*60}\n")

    # Connessione al database
    try:
        client = connetti_clickhouse()
        print("[OK] Connessione a ClickHouse stabilita.\n")
    except Exception as e:
        print(f"[ERRORE] Impossibile connettersi a ClickHouse: {e}")
        return

    # Calcolo della metrica M_sni con la finestra specificata
    try:
        host_flaggati = calcola_m_sni(client, finestra_minuti=args.finestra_minuti)
    except Exception as e:
        print(f"[ERRORE] Errore durante l'esecuzione della query: {e}")
        return

    # Report dei risultati
    if not host_flaggati:
        print(f"[OK] Nessun host flaggato - nessuna violazione SNI negli ultimi {args.finestra_minuti} minuto/i.\n")
        return

    print(f"[!] {len(host_flaggati)} host flaggato/i dalla metrica M_sni:\n")

    for host_ip, dati in host_flaggati.items():
        stampa_report(host_ip, dati)

# Esegui questo solo se lanciato come script principale (non importato come modulo)
if __name__ == "__main__":
    main()
