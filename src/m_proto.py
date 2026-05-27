"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
Metrica M_proto - Non-standard Port/Protocol
=============================================================================

Obiettivo:
    Rilevare i tentativi di aggirare i firewall nascondendo traffico
    non autorizzato dentro canali considerati sicuri (es. SSH tunneled
    su porta 443, RDP su porta 80). Il motore nDPI di ntopng
    identifica il protocollo reale analizzando il contenuto del pacchetto,
    poi lo confronta con la porta utilizzata, se non corrisponde, scatta
    l'allarme.

Logica:
    Peso STATICO di +30 punti per qualsiasi mismatch protocollo/porta
    rilevato da nDPI (bit 5 di flow_risk_bitmap acceso).

    Mantenere il peso basso (+30) è coerente con il fatto che un
    mismatch protocollo/porta è un segnale strutturale debole: nDPI
    dice "c'è qualcosa di strano qui" ma non "è un attacco". La
    metrica da sola lascia l'host in zona gialla; per portarlo in
    rosso serve il concorso di un'altra metrica.

Frequenza di esecuzione:
    Event-driven (metrica deterministica): lo script va eseguito ogni ora
    tramite cron o systemd timer.

Fonte dei dati:
    Tabella `flow_alerts_view` di ntopng su ClickHouse.
    - Bit 5 del flow_risk_bitmap: NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT
    - Protocollo reale estratto dal JSON: alerts['30']['proto.ndpi']
      (report per dettaglio diagnostico)

Soglie di rischio dello score finale S(h):
    Verde  ->  0-29  punti  (host sicuro)
    Giallo -> 30-59  punti  (host sospetto, da monitorare)
    Rosso  -> 60-100 punti  (host compromesso, intervento immediato)
=============================================================================
"""

import argparse
import clickhouse_connect
from datetime import datetime, timezone

from network_config import costruisci_filtro_lan


# =============================================================================
# CONFIGURAZIONE
# =============================================================================

# Parametri di connessione a ClickHouse
CLICKHOUSE_HOST     = "localhost"
CLICKHOUSE_PORT     = 8123
CLICKHOUSE_DATABASE = "ntopng"
CLICKHOUSE_USER     = "default"
CLICKHOUSE_PASSWORD = "0022"

# Peso della metrica nel modello di scoring
# Statico: lo stesso per qualsiasi mismatch protocollo/porta rilevato da nDPI.
PESO_M_PROTO = 30

# Finestra temporale di analisi (default): guardiamo i flussi degli ultimi 60 minuti.
# Può essere sovrascritta dall'argomento `--finestra-minuti` da CLI oppure
# passando un valore esplicito alla funzione `calcola_m_proto()`.
# Nel sistema finale, lo scoring.py chiama la funzione senza argomenti e usa
# questo default; il parametro serve a contenere il costo della query
# quando si testa su tabelle molto grandi (miliardi di record).
FINESTRA_MINUTI_DEFAULT = 60


# =============================================================================
# QUERY SQL
# =============================================================================

# La query SQL viene costruita dentro `calcola_m_proto()` perché dipende
# dal parametro `finestra_minuti`, che può essere passato dinamicamente
# (default = FINESTRA_MINUTI_DEFAULT).
#
# La query implementa la formula del piano operativo originale:
#   A_proto = True -> M_proto = 1
# con peso STATICO assegnato dallo script Python (PESO_M_PROTO = 30)
# moltiplicato per M_proto.
#
# Logica:
# 1) Filtro su bit 5 di flow_risk_bitmap (NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT)
# 2) Estrazione del protocollo reale dal JSON (proto.ndpi nell'oggetto alerts[30])
#    per il REPORT.
# 3) Aggregazione per host: count(), uniqExact() sulle combinazioni
#
# Struttura in due fasi tramite CTE:
# - FASE 1: filtro + estrazione proto_ndpi dal JSON una sola volta per riga
# - FASE 2: aggregazione per host (count, distinct, lista mismatch)


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


def calcola_m_proto(client, finestra_minuti: int = FINESTRA_MINUTI_DEFAULT):
    """
    Esegue la query su ClickHouse e restituisce un dizionario con i risultati.

    Parametri:
        finestra_minuti : ampiezza della finestra temporale di analisi in minuti.
                          Default = FINESTRA_MINUTI_DEFAULT (60 minuti)
                          per essere compatibili con lo scoring.py esistente.
                          Valori piccoli (es. 5-10) servono per testare la
                          metrica su tabelle molto grandi (miliardi di
                          record) contenendo l'intervallo della query.

    Il formato di ritorno è SIMMETRICO alle altre metriche:
    chiave = IP dell'host, valore = dizionario con i dettagli.

    Struttura del dizionario restituito:
    {
        "192.168.1.45": {
            "M_proto":               1,
            "hits_totali":           5,
            "combinazioni_distinte": 2,
            "lista_mismatch":     ['SSH su porta 443', 'HTTP su porta 8888'],
            "penalita":           30,   <- peso statico (PESO_M_PROTO)
            "timestamp":          "2026-05-15T19:00:00+00:00"
        },
        ...
    }
    """
    # Costruzione della query con il parametro `finestra_minuti`.
    # Il valore è un intero controllato (validato a monte da argparse
    # o passato esplicitamente come argomento di funzione), quindi è
    # sicuro inserirlo via f-string senza rischio di SQL injection.
    #
    # `filtro_lan` è costruito dal modulo condiviso network_config: limita
    # l'analisi ai soli host della LAN interna (RFC 1918) sulla colonna
    # cli_ip, che è il "soggetto" del flusso. Applicato dentro la CTE
    # così la FASE 2 lavora già su un dataset filtrato.
    filtro_lan = costruisci_filtro_lan("cli_ip")

    query = f"""

    -- FASE 1 - CTE "dati_filtrati"
    -- Filtro temporale + bit 5 acceso (mismatch protocollo/porta),
    -- ed estrazione del protocollo reale dal JSON UNA SOLA volta per riga.

    WITH dati_filtrati AS (
        SELECT
            cli_ip AS host_ip,
            srv_port,

            -- Estrazione UNICA del protocollo reale rilevato da nDPI
            -- (usata solo per il REPORT, non più per pesare)
            JSONExtractString(json, 'alerts', '30', 'proto.ndpi') AS proto_ndpi

        FROM flow_alerts_view
        WHERE
            -- Filtro 1: finestra temporale parametrica (default 60 minuti)
            tstamp >= now() - INTERVAL {finestra_minuti} MINUTE

            -- Filtro 2: bit 5 di flow_risk_bitmap acceso
            -- (NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT)
            -- Operazione binaria O(1), efficientissima sul DB colonnare
            AND bitTest(flow_risk_bitmap, 5) = 1

            -- Filtro 3: LAN interna (classifichiamo solo host della rete monitorata)
            AND {filtro_lan}
    )

    -- FASE 2 - Aggregazione finale per host
    -- Nessuna logica di pesatura: il peso lo applica Python (PESO_M_PROTO).

    SELECT
        host_ip,

        -- Numero totale di mismatch rilevati per l'host
        count() AS hits_totali,

        -- Numero di combinazioni distinte (protocollo, porta) osservate
        uniqExact(concat(proto_ndpi, ':', toString(srv_port))) AS combinazioni_distinte,

        -- Lista delle combinazioni (max 10, per evitare report giganteschi)
        arraySlice(
            groupUniqArray(concat(proto_ndpi, ' su porta ', toString(srv_port))),
            1, 10
        ) AS lista_mismatch,

        -- M_proto si attiva se l'aggregazione ha trovato almeno una riga
        -- (per costruzione: se l'host è in questo result-set, ha >= 1 hit)
        1 AS M_proto

    FROM dati_filtrati
    GROUP BY host_ip
    ORDER BY hits_totali DESC
    """

    risultati = {}

    # Esecuzione della query
    righe = client.query(query).result_rows

    # Ogni riga contiene:
    # (host_ip, hits_totali, combinazioni_distinte, lista_mismatch, M_proto)
    for (host_ip, hits_totali, combinazioni_distinte,
         lista_mismatch, m_proto) in righe:

        risultati[host_ip] = {
            "M_proto":               m_proto,
            "hits_totali":           hits_totali,
            "combinazioni_distinte": combinazioni_distinte,
            "lista_mismatch":        list(lista_mismatch),
            "penalita":              PESO_M_PROTO * m_proto,  # 30 se M_proto=1, 0 altrimenti
            "timestamp":             datetime.now(timezone.utc).isoformat()
        }

    return risultati


def stampa_report(host_ip: str, dati: dict):
    """
    Stampa un report leggibile per ogni host flagged dalla sola metrica.
    Usato quando lo script è eseguito per testing.
    """
    print("=" * 70)
    print(f"  [ALLARME M_proto] {host_ip}")
    print("=" * 70)
    print(f"  Timestamp             : {dati['timestamp']}")
    print(f"  M_proto               : {dati['M_proto']} (attiva)")
    print(f"  Mismatch rilevati     : {dati['lista_mismatch']}")
    print(f"  Combinazioni distinte : {dati['combinazioni_distinte']}")
    print(f"  Hit totali            : {dati['hits_totali']}")
    print(f"  Penalità M_proto      : +{dati['penalita']} punti")
    print()


# =============================================================================
# MAIN - Esecuzione per testing
# =============================================================================

def main():
    """
    Quando integreremo tutto in scoring.py, questa funzione NON verrà chiamata:
    scoring.py importerà direttamente `calcola_m_proto()` dalla funzione sopra.

    Esecuzione da CLI:
        python m_proto.py                          # usa il default (60 minuti)
        python m_proto.py --finestra-minuti 10     # finestra di 10 minuti
        python m_proto.py --finestra-minuti 1440   # finestra di 24 ore
    """
    # Parsing degli argomenti da riga di comando
    parser = argparse.ArgumentParser(
        description="Calcolo della metrica M_proto (Non-standard Port/Protocol)."
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
    print(f"  Avvio analisi M_proto - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Finestra temporale: ultimi {args.finestra_minuti} minuto/i")
    print(f"  Peso statico: +{PESO_M_PROTO} punti per qualsiasi mismatch protocollo/porta")
    print(f"{'='*70}\n")

    # Connessione al database
    try:
        client = connetti_clickhouse()
        print("[OK] Connessione a ClickHouse stabilita.\n")
    except Exception as e:
        print(f"[ERRORE] Impossibile connettersi a ClickHouse: {e}")
        return

    # Calcolo della metrica M_proto con la finestra specificata
    try:
        host_flaggati = calcola_m_proto(client, finestra_minuti=args.finestra_minuti)
    except Exception as e:
        print(f"[ERRORE] Errore durante l'esecuzione della query: {e}")
        return

    # Report dei risultati
    if not host_flaggati:
        print(f"[OK] Nessun host flagged - nessun mismatch protocollo/porta negli ultimi {args.finestra_minuti} minuto/i.\n")
        return

    print(f"[!] {len(host_flaggati)} host flagged dalla metrica M_proto:\n")

    for host_ip, dati in host_flaggati.items():
        stampa_report(host_ip, dati)

# Esegui questo solo se lanciato come script principale (non importato come modulo)
if __name__ == "__main__":
    main()
