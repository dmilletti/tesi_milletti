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

Logica con DIFFERENZIAZIONE per (protocollo, categoria porta):
    Il piano operativo originale prevedeva peso fisso +30 punti.
    Estendiamo la metrica con una matrice di pesi che riflette
    il rischio di ogni combinazione (protocollo, porta):

      C2 MASCHERATO -> +50 punti
        Protocollo di amministrazione remota (SSH, RDP, VNC, Telnet)
        nascosto dentro porte web standard (80, 443, 8080, 8443).
        È la classica tecnica per bypassare i firewall perimetrali.

      TUNNEL CIFRATO SOSPETTO -> +40 punti
        TLS/SSL su porte non-web (non in 80/443/altri web alt).
        Tipico di tunnel VPN nascosti o protocolli di esfiltrazione.

      MISMATCH GENERICO -> +30 punti
        Qualsiasi altra discrepanza protocollo/porta non classificata
        nei due casi sopra.

      LIKELY DEV SERVER -> +15 punti
        HTTP su porte web alternative comuni (3000, 4200, 5000, 5173,
        8000, 8080, 8443, 8888). Non filtriamo questo caso (un attaccante
        potrebbe usare queste porte di proposito), ma abbassiamo il peso
        perché è statisticamente il più comune falso positivo in ambienti
        di sviluppo.

Frequenza di esecuzione:
    Event-driven (metrica deterministica): lo script va eseguito ogni ora
    tramite cron o systemd timer.

Fonte dei dati:
    Tabella `flow_alerts_view` di ntopng su ClickHouse.
    - Bit 5 del flow_risk_bitmap: NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT
    - Protocollo reale estratto dal JSON: alerts['30']['proto.ndpi']

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
CLICKHOUSE_PORT     = 8123
CLICKHOUSE_DATABASE = "ntopng"
CLICKHOUSE_USER     = "default"
CLICKHOUSE_PASSWORD = "0022"

# Pesi differenziati per categoria di mismatch
PESO_C2_MASCHERATO       = 50   # Protocollo remoto su porta web standard
PESO_TUNNEL_CIFRATO      = 40   # TLS su porte non-web
PESO_MISMATCH_GENERICO   = 30   # Altri casi
PESO_LIKELY_DEV_SERVER   = 15   # HTTP su porte web alternative

# Finestra temporale di analisi: ultima ora
FINESTRA_ORE = 1 # per test possiamo allargare a 24 ore


# =============================================================================
# QUERY SQL - Versione ottimizzata con CTE
# =============================================================================

# La query implementa la formula del piano operativo:
#   A_proto = True -> M_proto = 1
# estesa con differenziazione dei pesi per (protocollo reale, categoria porta).
#
# Logica:
# 1) Filtro su bit 5 di flow_risk_bitmap (NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT)
# 2) Estrazione del protocollo reale dal JSON (proto.ndpi nell'oggetto alerts[30])
# 3) multiIf() che classifica il caso e assegna il peso
# 4) Aggregazione per host: max(peso), se un host ha più mismatch, prevale il caso più grave
#
# Strutturazione in due fasi tramite CTE (Common Table Expression):
# - FASE 1 (CTE "dati_filtrati_e_classificati"): applica i filtri WHERE,
#   estrae proto.ndpi dal JSON e calcola peso/categoria una sola volta per riga
# - FASE 2 (SELECT esterno): aggrega per host i valori pre-calcolati,
#   senza più necessità di parsing JSON o di rivalutare multiIf

QUERY_M_PROTO = f"""

-- FASE 1 - CTE "dati_filtrati_e_classificati"
-- Per ogni riga filtrata:
-- - estrae proto.ndpi una SOLA volta dal JSON
-- - calcola il peso applicabile alla riga
-- - calcola la categoria testuale corrispondente

-- Il risultato è un dataset intermedio con tutti i valori già pronti
-- per l'aggregazione finale, senza più necessità di parsing JSON
-- o di rivalutare i multiIf.

WITH dati_filtrati_e_classificati AS (
    SELECT
        cli_ip AS host_ip,
        srv_port,

        -- Estrazione UNICA del protocollo reale rilevato da nDPI
        JSONExtractString(json, 'alerts', '30', 'proto.ndpi') AS proto_ndpi,

        -- Calcolo del peso per la singola riga (valutato 1 volta sola)
        -- multiIf è l'equivalente ClickHouse di if/elif/elif/else
        multiIf(
            -- Caso 1: C2 mascherato -> +50
            -- protocollo remoto (SSH/RDP/VNC/Telnet) nascosto su porta web
            proto_ndpi IN ('SSH', 'RDP', 'VNC', 'Telnet')
                AND srv_port IN (80, 443, 8080, 8443),
            {PESO_C2_MASCHERATO},

            -- Caso 2: tunnel cifrato -> +40
            -- TLS/SSL/QUIC su porte non-web (escluse le web alternative comuni)
            proto_ndpi IN ('TLS', 'SSL', 'QUIC')
                AND srv_port NOT IN (80, 443, 8080, 8443, 8888,
                                     3000, 4200, 5000, 5173, 8000),
            {PESO_TUNNEL_CIFRATO},

            -- Caso 3: likely dev server -> +15
            -- HTTP su porte alternative comuni (Vite, React, Django, ecc.)
            proto_ndpi = 'HTTP'
                AND srv_port IN (3000, 4200, 5000, 5173, 8000, 8080, 8443, 8888),
            {PESO_LIKELY_DEV_SERVER},

            -- Caso 4 (default): mismatch generico -> +30
            -- Qualsiasi altra combinazione protocollo/porta
            {PESO_MISMATCH_GENERICO}
        ) AS penalita_singola,

        -- Categoria testuale corrispondente alla riga (per il report)
        -- IMPORTANTE: la sequenza dei casi deve essere IDENTICA a quella
        -- del calcolo del peso sopra, altrimenti peso e categoria si disallineano.
        -- Da tenere sincronizzati.
        multiIf(
            proto_ndpi IN ('SSH', 'RDP', 'VNC', 'Telnet')
                AND srv_port IN (80, 443, 8080, 8443),
            'C2 MASCHERATO (protocollo remoto su porta web)',

            proto_ndpi IN ('TLS', 'SSL', 'QUIC')
                AND srv_port NOT IN (80, 443, 8080, 8443, 8888,
                                     3000, 4200, 5000, 5173, 8000),
            'TUNNEL CIFRATO SOSPETTO (TLS su porta non-web)',

            proto_ndpi = 'HTTP'
                AND srv_port IN (3000, 4200, 5000, 5173, 8000, 8080, 8443, 8888),
            'LIKELY DEV SERVER (HTTP su porta alternativa)',

            'MISMATCH GENERICO (altra combinazione protocollo/porta)'
        ) AS categoria_singola

    FROM flow_alerts_view
    WHERE
        -- Filtro 1: finestra temporale (ultima ora)
        tstamp >= now() - INTERVAL {FINESTRA_ORE} HOUR

        -- Filtro 2: bit 5 di flow_risk_bitmap acceso (NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT)
        -- Operazione binaria O(1), efficientissima sul DB colonnare
        AND bitTest(flow_risk_bitmap, 5) = 1

        -- Filtro 3: solo host della LAN interna (coerenza con altre metriche)
        -- AND cli_location = 1 (per ora commentato)
)

-- FASE 2 - Aggregazione finale per host

-- Opera sul risultato intermedio della CTE. Tutti i valori sono già
-- calcolati riga per riga, quindi qui si tratta solo di aggregarli.
-- Nessun JSONExtract, nessuna logica di classificazione duplicata.

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

    -- Peso massimo applicabile: prevale lo scenario peggiore per l'host
    max(penalita_singola) AS penalita_calcolata,

    -- Categoria corrispondente al peso massimo
    -- argMax(valore, ordinatore): restituisce il VALORE della riga che ha l'ORDINATORE più alto.
    -- Qui sono coerenti per costruzione perché peso e categoria sono pre-calcolati nella stessa riga della CTE.
    argMax(categoria_singola, penalita_singola) AS categoria_dominante,

    -- M_proto si attiva se l'aggregazione ha trovato almeno una riga
    -- per costruzione: se l'host è in questo insieme result, ha avuto >= 1 hit
    1 AS M_proto

FROM dati_filtrati_e_classificati
GROUP BY host_ip
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


def calcola_m_proto(client):
    """
    Esegue la query su ClickHouse e restituisce un dizionario con i risultati.

    Il formato di ritorno è SIMMETRICO alle altre metriche:
    chiave = IP dell'host, valore = dizionario con i dettagli.

    Struttura del dizionario restituito:
    {
        "192.168.1.45": {
            "M_proto":               1,
            "hits_totali":           5,
            "combinazioni_distinte": 2,
            "lista_mismatch":     ['SSH su porta 443', 'HTTP su porta 8888'],
            "categoria_dominante": 'C2 MASCHERATO (protocollo remoto su porta web)',
            "penalita":           50,
            "timestamp":          "2026-05-15T19:00:00+00:00"
        },
        ...
    }
    """
    risultati = {}

    # Esecuzione della query
    righe = client.query(QUERY_M_PROTO).result_rows

    # Ogni riga contiene:
    # (host_ip, hits_totali, combinazioni_distinte, lista_mismatch,
    #  penalita_calcolata, categoria_dominante, M_proto)
    for (host_ip, hits_totali, combinazioni_distinte, lista_mismatch,
         penalita, categoria, m_proto) in righe:

        risultati[host_ip] = {
            "M_proto":               m_proto,
            "hits_totali":           hits_totali,
            "combinazioni_distinte": combinazioni_distinte,
            "lista_mismatch":        list(lista_mismatch),
            "categoria_dominante":   categoria,
            "penalita":              penalita,
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
    print(f"  Categoria dominante   : {dati['categoria_dominante']}")
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
    """
    print(f"\n{'='*70}")
    print(f"  Avvio analisi M_proto - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Finestra temporale: ultima {FINESTRA_ORE} ora")
    print(f"  Pesi differenziati per categoria di mismatch:")
    print(f"    C2 MASCHERATO (SSH/RDP/VNC su 80/443/8080/8443):  +{PESO_C2_MASCHERATO}")
    print(f"    TUNNEL CIFRATO (TLS su porte non-web):            +{PESO_TUNNEL_CIFRATO}")
    print(f"    MISMATCH GENERICO (altri casi):                   +{PESO_MISMATCH_GENERICO}")
    print(f"    LIKELY DEV SERVER (HTTP su porte alternative):    +{PESO_LIKELY_DEV_SERVER}")
    print(f"{'='*70}\n")

    # Connessione al database
    try:
        client = connetti_clickhouse()
        print("[OK] Connessione a ClickHouse stabilita.\n")
    except Exception as e:
        print(f"[ERRORE] Impossibile connettersi a ClickHouse: {e}")
        return

    # Calcolo della metrica M_proto
    try:
        host_flaggati = calcola_m_proto(client)
    except Exception as e:
        print(f"[ERRORE] Errore durante l'esecuzione della query: {e}")
        return

    # Report dei risultati
    if not host_flaggati:
        print("[OK] Nessun host flagged - nessun mismatch protocollo/porta nell'ultima ora.\n")
        return

    print(f"[!] {len(host_flaggati)} host flagged dalla metrica M_proto:\n")

    for host_ip, dati in host_flaggati.items():
        stampa_report(host_ip, dati)

# Esegui questo solo se lanciato come script principale (non importato come modulo)
if __name__ == "__main__":
    main()
