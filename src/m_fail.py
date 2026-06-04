"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
Metrica M_fail - Connection Failure Rate
=============================================================================

Obiettivo:
    Rilevare host che improvvisamente cominciano a registrare un tasso
    anomalo di connessioni fallite. È la firma classica di:
      - malware con Domain Generation Algorithm (DGA), che tenta
        decine o centinaia di domini casuali ricevendo NXDOMAIN;
      - tool di scansione che provano porte chiuse ricevendo TCP RST
        o silenzio assoluto;
      - host che cercano alla cieca un server di Command & Control
        di riserva mentre quello primario è caduto.

    A differenza delle metriche deterministiche (M_rep, M_sni, ecc.),
    qui non c'è un singolo evento booleano da intercettare: un host
    può sempre avere QUALCHE connessione fallita per motivi legittimi
    (DNS lenti, server momentaneamente irraggiungibili, errori di
    digitazione dell'utente, ecc.). Quello che ci interessa è lo
    SCOSTAMENTO rispetto alla normalità dell'host stesso.

    Per questo motivo M_fail è una metrica STATISTICA, gemella di M_vol:
    confronta il rate corrente con la baseline contestuale dell'host
    sui 7 giorni precedenti, e scatta solo se lo scostamento è
    significativo sia statisticamente che operativamente.

Logica:
    Per ogni host della LAN, alla fine di ogni ora:

      1. Conta i flussi totali e i flussi falliti dell'ultima ora
         -> r_t = n_falliti / n_totali (rate corrente)
      2. Recupera la baseline contestuale (stessa categoria oraria,
         ultimi 7 giorni) -> r_mediano, MAD
      3. Calcola lo Z-score robusto con il limite sulla MAD
      4. Applica le 5 condizioni di scatto in AND.

Definizione operativa di "flusso fallito":
    Un flusso è considerato fallito se è vera ALMENO UNA fra:
      - DST2SRC_PACKETS = 0
            Il server non ha mai risposto: SYN nel vuoto, query DNS
            in timeout, host irraggiungibile.
      - bit 43 di FLOW_RISK (NDPI_ERROR_CODE_DETECTED)
            Errore esplicito nel protocollo applicativo: NXDOMAIN
            sul DNS, codici HTTP 4xx/5xx.
      - bit 46 di FLOW_RISK (NDPI_UNIDIRECTIONAL_TRAFFIC)
            Variante nDPI-marcata del flusso unidirezionale, esclude
            automaticamente multicast e broadcast.
      - bit 50 di FLOW_RISK (NDPI_TCP_ISSUES)
            Problemi TCP rilevanti: connection refused (RST), scan,
            probing.
      - bit 51 di FLOW_RISK (NDPI_UNRESOLVED_HOSTNAME)
            Hostname mai osservato in una risoluzione DNS precedente.
            Indicatore tipico di DGA.
      - bit 55 di FLOW_RISK (NDPI_PROBING_ATTEMPT)
            Connessione senza scambio di dati che ha l'aspetto di un
            tentativo di sondaggio.

    Mappa verificata su:
      - src/include/ndpi_typedefs.h (enum ndpi_risk_enum)
      - https://www.ntop.org/guides/nDPI/flow_risks.html

Formula matematica:
    Sia F_tot l'insieme dei flussi correnti dell'host e F_fail il
    sottoinsieme di quelli falliti. Il rate orario è:

        r_t = |F_fail| / |F_tot|

    Il limite sulla MAD evita la divisione per zero su host molto
    regolari:

        MAD_eff = max(MAD, MAD_MIN_ASSOLUTA)

    Lo Z-score robusto:

        Z = (r_t - r_mediano) / MAD_eff

    La metrica scatta se sono soddisfatte simultaneamente:

        M_fail = 1  <=>  Z > 3 -> oscillazione statisticamente significativa
                  AND  r_t > r_mediano -> ci interessa solo l'aumento, non la diminuzione
                  AND  r_t > R_MIN_OPERATIVO -> tasso fallimento maggiore del 30% in valore assoluto
                  AND  n_flussi_correnti >= MIN_FLUSSI_CORRENTE -> soglia minima di flussi
                  AND  bucket_baseline >= MIN_BASELINE_HOURS -> almeno 30 ore di dati registrati

    Note progettuali:
      - Lo Z-score non usa il valore assoluto: vogliamo segnalare solo
        gli AUMENTI di fallimenti, non le diminuzioni (host che migliora).
      - Il limite è SOLO assoluto (non c'è il termine proporzionale di
        M_vol), su un rate che vive in [0, 1], il termine proporzionale
        sarebbe quasi sempre dominato dal limite assoluto.
      - MIN_FLUSSI_CORRENTE protegge dal rumore statistico su sample
        size minuscoli (3 flussi totali, 1 fallito => 33% di rate è
        rumore, non un'anomalia).
      - R_MIN_OPERATIVO garantisce la significatività operativa, cioè anche
        un Z-score molto alto su un host che è passato dallo 0.1% al
        2% di fallimenti non è un host compromesso.

Frequenza di esecuzione:
    Batch orario (metrica statistica): lo script va eseguito ogni ora
    tramite cron o systemd timer.

Peso nel modello:
    +30 punti (categoria "Evasione e ricognizione").

Fonte dei dati:
    Tabella `flows` di ntopng su ClickHouse.

Soglie di rischio dello score finale S(h):
    Verde  ->  0-29  punti  (host sicuro)
    Giallo -> 30-59  punti  (host sospetto, da monitorare)
    Rosso  -> 60-100 punti  (host compromesso, intervento immediato)
=============================================================================
"""

from datetime import datetime, timezone
from config import connetti_clickhouse, costruisci_filtro_lan


# =============================================================================
# CONFIGURAZIONE
# =============================================================================
# Peso della metrica nel modello di scoring
PESO_M_FAIL = 30

# ---- Parametri statistici ---------------------------------------------------

# Soglia di anomalia statistica (regola empirica 68-95-99.7)
# Z > 3 significa che l'evento ha < 0.3% di probabilità di essere ordinario
SOGLIA_Z = 3

# Rate operativo minimo: 
# anche con Z alto, il rate corrente in valore assoluto
# deve essere almeno del 30% per essere considerato un host in palese
# sofferenza. Senza questa soglia, un host passato dallo 0.1% al 2% di
# fallimenti darebbe Z alto ma non sarebbe operativamente significativo.
R_MIN_OPERATIVO = 0.30

# Limite assoluto sulla MAD (5 punti percentuali). Evita la divisione per zero
# su host molto regolari ed elimina falsi positivi su scostamenti minuscoli
# in valore assoluto.
MAD_MIN_ASSOLUTA = 0.05

# Sample size minimo nell'ora corrente:
# sotto questa soglia di flussi totali il rate non è statisticamente significativo
# (es. 1 fallito su 3 = 33% e'rumore puro).
MIN_FLUSSI_CORRENTE = 50

# Minimo numero di bucket necessari per una baseline statisticamente valida
# Se l'host ha meno di 30 ore di osservazione nella categoria temporale
# corrente, viene escluso dal calcolo (cold start).
MIN_BASELINE_HOURS = 30

# ---- Finestre temporali -----------------------------------------------------

# Profondità della baseline
# 7 giorni per assorbire la stagionalità settimanale
FINESTRA_CORRENTE_ORE   = 1
# Finestra dell'ora corrente da valutare
FINESTRA_STORICO_GIORNI = 7

# ---- Categorie temporali ---------------------------

# Giorni della settimana considerati weekend
# toDayOfWeek() di ClickHouse (6=Sab, 7=Dom)
GIORNI_WEEKEND = (6, 7)

# Range orario considerato lavorativo per i feriali
# Format: (ora_inizio, ora_fine) inclusivi
ORE_LAVORATIVE = (9, 17)

# ---- Bit nDPI per la definizione di "flusso fallito" --------------------------

# Posizioni dei bit nell'enum ndpi_risk_enum 
# (verificate su src/include/ndpi_typedefs.h del repository ntop/nDPI).
# La numerazione dell'enum coincide con la posizione del bit nel
# FLOW_RISK bitmap (cfr. m_cert.py, m_sni.py per riferimento incrociato).

BIT_NDPI_ERROR_CODE      = 43   # NDPI_ERROR_CODE_DETECTED
BIT_NDPI_UNIDIRECTIONAL  = 46   # NDPI_UNIDIRECTIONAL_TRAFFIC
BIT_NDPI_TCP_ISSUES      = 50   # NDPI_TCP_ISSUES
BIT_NDPI_UNRESOLVED_HOST = 51   # NDPI_UNRESOLVED_HOSTNAME
BIT_NDPI_PROBING_ATTEMPT = 55   # NDPI_PROBING_ATTEMPT

# Bitmask compatta usata nella query SQL:
#  la useremo con bitAnd() per testare se ALMENO UNO dei bit di fallimento è settato.
FLOW_RISK_FAIL_BITMASK = (
    (1 << BIT_NDPI_ERROR_CODE)      |
    (1 << BIT_NDPI_UNIDIRECTIONAL)  |
    (1 << BIT_NDPI_TCP_ISSUES)      |
    (1 << BIT_NDPI_UNRESOLVED_HOST) |
    (1 << BIT_NDPI_PROBING_ATTEMPT)
)


# =============================================================================
# QUERY SQL
# =============================================================================

# La query implementa la formula matematica descritta in testa al file.
# La struttura è analoga a quella di M_vol, con l'adattamento dal volume
# (byte) al rate (frazione ∈ [0, 1]).
#
# Pipeline a CTE (Common Table Expressions):
#
#   categoria_corrente -> identifica la fascia oraria (weekend,
#                         feriale_lavorativo, feriale_fuoriorario).
#   flussi_storici     -> aggrega per host e bucket orario sui 7 giorni
#                         precedenti, calcola il rate per ogni bucket.
#   mediane            -> mediana del rate per host + filtro cold start.
#   statistiche_baseline -> aggiunge la MAD ai dati per host.
#   flussi_correnti    -> aggrega per host nell'ultima ora, calcola il
#                         rate corrente e impone MIN_FLUSSI_CORRENTE.
#
# La SELECT finale fa il JOIN (flussi_correnti e statistiche_baseline),
# calcola lo Z-score con limite sulla MAD, applica le 3 condizioni residue
# (Z, direzionalita, soglia operativa).
#
# Colonne usate dallo schema ClickHouse (tabella `flows`):
#   - FIRST_SEEN         -> timestamp di inizio flusso
#   - IPV4_SRC_ADDR      -> IP sorgente del flusso (host monitorato)
#   - IPV4_DST_ADDR      -> IP destinazione (per filtrare intra-LAN)
#   - SRC2DST_PACKETS    -> pacchetti inviati dall'host
#   - DST2SRC_PACKETS    -> pacchetti ricevuti dall'host (= 0 -> allora fallito)
#   - FLOW_RISK          -> bitmap dei rischi nDPI (UInt64)
#
# Nota: in m_cert.py si usa la view `flow_alerts_view` perché là interessano
# solo i flussi che HANNO già un alert (STATUS != 0). Qui invece servono
# TUTTI i flussi (sia falliti che riusciti, per calcolare il rate), quindi
# si va direttamente sulla tabella `flows`.

FILTRO_LAN_SRC = costruisci_filtro_lan("IPv4NumToString(IPV4_SRC_ADDR)")

QUERY_M_FAIL = f"""
-- =============================================================
-- CTE 0: categoria_corrente
-- Determo in quale fascia temporale ricade l'ora attuale.
-- Risultato: una solo stringa di queste: 
-- ('feriale_lavorativo', 'feriale_fuoriorario', oppure 'weekend')
-- riutilizzabile nel resto della query.
-- =============================================================
WITH (
    SELECT multiIf(
        -- Siamo nel weekend?
        toDayOfWeek(now()) IN ({GIORNI_WEEKEND[0]}, {GIORNI_WEEKEND[1]}),
            'weekend',
        -- Siamo in un'ora lavorativa dei feriali?
        toHour(now()) BETWEEN {ORE_LAVORATIVE[0]} AND {ORE_LAVORATIVE[1]},
            'feriale_lavorativo',
        -- Altrimenti, siamo in un'ora non lavorativa dei feriali
            'feriale_fuoriorario'
    )
) AS categoria_corrente,

-- =============================================================
-- CTE 1: aggregazione storica per host e bucket orario
-- Per ogni host e ogni ora dei 7 giorni precedenti, calcola:
--   - n_flussi_totali  = quanti flussi
--   - n_flussi_falliti = quanti di quelli sono falliti
--   - rate_bucket      = rapporto fallimenti / totali
-- Filtra solo gli host LAN che comunicano verso destinazioni esterne,
-- e solo bucket che cadono nella stessa categoria temporale di "ora".
-- =============================================================

flussi_storici AS (
    SELECT
        -- Conversione da numero a stringa IP per chiarezza nei risultati
        IPv4NumToString(IPV4_SRC_ADDR) AS host_ip,
        -- Bucket orario: arrotonda FIRST_SEEN all'inizio dell'ora (es. 14:23 -> 14:00)
        toStartOfHour(FIRST_SEEN)       AS bucket_orario,
        -- Conto totale dei flussi per host e bucket
        count() AS n_flussi_totali,

        -- Conto i flussi falliti
        countIf(
            DST2SRC_PACKETS = 0
            OR bitAnd(FLOW_RISK, {FLOW_RISK_FAIL_BITMASK}) != 0
        ) AS n_flussi_falliti,

        -- Cast esplicito a Float64 per evitare divisione intera
        toFloat64(n_flussi_falliti) / toFloat64(n_flussi_totali) AS rate_bucket

    FROM flows
    WHERE
        -- Finestra storica di 7 giorni
        FIRST_SEEN >= now() - INTERVAL {FINESTRA_STORICO_GIORNI} DAY
        -- Escludo l'ora corrente
        AND FIRST_SEEN <  now() - INTERVAL {FINESTRA_CORRENTE_ORE} HOUR

        -- Esclude flussi IPv6 puri (IPV4_SRC_ADDR = 0)
        AND IPV4_SRC_ADDR != 0

        -- Filtro: tengo bucket solo della stessa categoria temporale dell'ora corrente.
        -- IMPORTANTE: la sequenza dei casi DEVE essere identica a
        -- quella usata in CTE 1, altrimenti i bucket non vengono
        -- categorizzati allo stesso modo.
        AND multiIf(
            toDayOfWeek(FIRST_SEEN) IN ({GIORNI_WEEKEND[0]}, {GIORNI_WEEKEND[1]}),
                'weekend',
            toHour(FIRST_SEEN) BETWEEN {ORE_LAVORATIVE[0]} AND {ORE_LAVORATIVE[1]},
                'feriale_lavorativo',
                'feriale_fuoriorario'
        ) = categoria_corrente

        -- Solo host della LAN interna come sorgente (RFC 1918)
        AND {FILTRO_LAN_SRC}

        -- Escludiamo destinazioni intra-LAN: ci interessano i fallimenti
        -- verso server esterni, non il traffico interno (che ha pattern
        -- propri e tipicamente bassissimo rate di fallimento)
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '10.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '172.16.0.0/12')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '192.168.0.0/16')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '127.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '169.254.0.0/16')

    GROUP BY host_ip, bucket_orario

    -- Bucket con zero flussi sono inutili (causano NaN nel rate)
    HAVING n_flussi_totali > 0
),

-- =============================================================
-- CTE 2: mediana del rate per host + filtro cold start
-- Per ogni host, calcola la mediana dei volumi orari sui bucket
-- della baseline filtrata. Applica il filtro cold start; host con
-- meno di 30 bucket validi non hanno baseline statisticamente affidabile
-- e vengono esclusi dal calcolo.
-- Restituisce una tabella con host_ip, r_mediano, bucket_count.
-- =============================================================

mediane AS (
    SELECT
        host_ip,
        median(rate_bucket) AS r_mediano,
        count()             AS bucket_count
    FROM flussi_storici
    GROUP BY host_ip
    HAVING bucket_count >= {MIN_BASELINE_HOURS}
),

-- =============================================================
-- CTE 3: aggiunta della MAD alla baseline
-- La MAD è la mediana della distanza assoluta dalla mediana.
-- Si calcola facendo la JOIN fra flussi_storici e mediane (per avere r_mediano riga
-- per riga) e applicando median(abs(rate_bucket - r_mediano)).
-- =============================================================
statistiche_baseline AS (
    SELECT
        fs.host_ip,
        -- Prendo una qualsiasi riga per host da mediane, tanto r_mediano e bucket_count
        -- sono costanti per host_ip (grazie al GROUP BY), quindi non importa quale prendo.
        any(m.r_mediano)                          AS r_mediano,
        any(m.bucket_count)                       AS bucket_count,
        median(abs(fs.rate_bucket - m.r_mediano)) AS mad
    FROM flussi_storici AS fs
    INNER JOIN mediane AS m ON fs.host_ip = m.host_ip
    GROUP BY fs.host_ip
),

-- =============================================================
-- CTE 4: aggregazione corrente per host (ultima ora)
-- Calcola lo stesso rate sull'ora corrente, con il breakdown per
-- categoria di fallimento (utile per il report finale).
-- Impone MIN_FLUSSI_CORRENTE come filtro di sample size.
-- =============================================================

flussi_correnti AS (
    SELECT
        IPv4NumToString(IPV4_SRC_ADDR) AS host_ip,

        count() AS n_flussi_totali,

        countIf(
            DST2SRC_PACKETS = 0
            OR bitAnd(FLOW_RISK, {FLOW_RISK_FAIL_BITMASK}) != 0
        ) AS n_flussi_falliti,

        toFloat64(n_flussi_falliti) / toFloat64(n_flussi_totali) AS r_corrente,

        -- Breakdown per causa di fallimento (per il report)
        countIf(DST2SRC_PACKETS = 0)                                 AS n_dst2src_zero,
        countIf(bitTest(FLOW_RISK, {BIT_NDPI_ERROR_CODE}) = 1)       AS n_error_code,
        countIf(bitTest(FLOW_RISK, {BIT_NDPI_UNIDIRECTIONAL}) = 1)   AS n_unidirectional,
        countIf(bitTest(FLOW_RISK, {BIT_NDPI_TCP_ISSUES}) = 1)       AS n_tcp_issues,
        countIf(bitTest(FLOW_RISK, {BIT_NDPI_UNRESOLVED_HOST}) = 1)  AS n_unresolved,
        countIf(bitTest(FLOW_RISK, {BIT_NDPI_PROBING_ATTEMPT}) = 1)  AS n_probing

    FROM flows
    WHERE
        FIRST_SEEN >= now() - INTERVAL {FINESTRA_CORRENTE_ORE} HOUR

        AND IPV4_SRC_ADDR != 0
        
        -- Filtro LAN sul SOGGETTO: valuto solo host interni alla rete monitorata
        AND {FILTRO_LAN_SRC}

        -- Escludiamo destinazioni intra-LAN: ci interessano i fallimenti
        -- verso server esterni, non il traffico interno (che ha pattern
        -- propri e tipicamente bassissimo rate di fallimento)
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '10.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '172.16.0.0/12')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '192.168.0.0/16')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '127.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '169.254.0.0/16')

    GROUP BY host_ip

    -- Sample size minimo per significatività statistica
    HAVING n_flussi_totali >= {MIN_FLUSSI_CORRENTE}
)

-- =============================================================
-- SELECT finale: JOIN, Z-score con limiti, condizioni di scatto
-- =============================================================

SELECT
    fc.host_ip AS host_ip,

    fc.n_flussi_totali AS n_totali,
    fc.n_flussi_falliti AS n_falliti,
    fc.r_corrente AS r_corrente,

    sb.r_mediano AS r_mediano,
    sb.mad AS mad,
    greatest(sb.mad, {MAD_MIN_ASSOLUTA}) AS mad_eff,

    -- Z-score robusto senza valore assoluto (vogliamo solo aumenti)
    (fc.r_corrente - sb.r_mediano)
        / greatest(sb.mad, {MAD_MIN_ASSOLUTA}) AS z_robusto,

    sb.bucket_count AS bucket_count,
    categoria_corrente AS categoria_temporale,

    -- Breakdown per causa di fallimento (per il report)
    fc.n_dst2src_zero AS n_dst2src_zero,
    fc.n_error_code AS n_error_code,
    fc.n_unidirectional AS n_unidirectional,
    fc.n_tcp_issues AS n_tcp_issues,
    fc.n_unresolved AS n_unresolved,
    fc.n_probing AS n_probing,

    1 AS M_fail

FROM flussi_correnti AS fc
INNER JOIN statistiche_baseline AS sb ON fc.host_ip = sb.host_ip
WHERE
    -- Tripla condizione di scatto (le altre due, MIN_FLUSSI_CORRENTE e
    -- MIN_BASELINE_HOURS, sono già state applicate come HAVING nei CTE (4 e 2) flussi_correnti e mediane)
    fc.r_corrente > {R_MIN_OPERATIVO}
    AND fc.r_corrente > sb.r_mediano
    AND z_robusto > {SOGLIA_Z}

ORDER BY z_robusto DESC
"""


# =============================================================================
# FUNZIONI
# =============================================================================

def calcola_m_fail(client):
    """
    Esegue la query su ClickHouse e restituisce un dizionario con i risultati.

    Il formato di ritorno è SIMMETRICO alle altre metriche:
    chiave = IP dell'host, valore = dizionario con i dettagli.

    Struttura del dizionario restituito:
    {
        "192.168.1.45": {
            "M_fail":              1,
            "n_totali":            312,    <- flussi totali dell'ora
            "n_falliti":           287,    <- flussi falliti
            "r_corrente":          0.92,   <- rate corrente (92%)
            "r_mediano":           0.018,  <- rate mediano storico (1.8%)
            "mad":                 0.012,  <- MAD reale
            "mad_eff":             0.05,   <- MAD effettiva (limite attivo)
            "z_robusto":           18.04,  <- Z-score robusto
            "bucket_count":        38,     <- bucket validi nella baseline
            "categoria_temporale": "feriale_lavorativo",
            "breakdown": {                 <- causa dominante del fallimento
                "dst2src_zero":   12,
                "error_code":     250,
                "unidirectional": 12,
                "tcp_issues":      15,
                "unresolved":      230,
                "probing":           3,
            },
            "penalita":            30,
            "timestamp":           "2026-05-25T18:00:00+00:00"
        },
        ...
    }
    """
    risultati = {}

    righe = client.query(QUERY_M_FAIL).result_rows

    # Ogni riga contiene (in ordine):
    # host_ip, n_totali, n_falliti, r_corrente,
    # r_mediano, mad, mad_eff, z_robusto,
    # bucket_count, categoria_temporale,
    # n_dst2src_zero, n_error_code, n_unidirectional,
    # n_tcp_issues, n_unresolved, n_probing,
    # M_fail
    for (host_ip, n_totali, n_falliti, r_corrente,
         r_mediano, mad, mad_eff, z_robusto,
         bucket_count, categoria_temporale,
         n_dst2src_zero, n_error_code, n_unidirectional,
         n_tcp_issues, n_unresolved, n_probing,
         m_fail) in righe:

        risultati[host_ip] = {
            "M_fail":              m_fail,
            "n_totali":            n_totali,
            "n_falliti":           n_falliti,
            "r_corrente":          float(r_corrente),
            "r_mediano":           float(r_mediano),
            "mad":                 float(mad),
            "mad_eff":             float(mad_eff),
            "z_robusto":           float(z_robusto),
            "bucket_count":        bucket_count,
            "categoria_temporale": categoria_temporale,
            "breakdown": {
                "dst2src_zero":   n_dst2src_zero,
                "error_code":     n_error_code,
                "unidirectional": n_unidirectional,
                "tcp_issues":     n_tcp_issues,
                "unresolved":     n_unresolved,
                "probing":        n_probing,
            },
            "penalita":            PESO_M_FAIL * m_fail,
            "timestamp":           datetime.now(timezone.utc).isoformat()
        }

    return risultati


def causa_dominante(breakdown: dict) -> tuple[str, int]:
    """
    Restituisce la coppia (etichetta, conteggio) della causa di fallimento
    più frequente per quell'host. Utile per il report leggibile.
    """
    etichette = {
        "error_code":     "ERRORE PROTOCOLLO (NXDOMAIN/HTTP 4xx-5xx)",
        "unresolved":     "HOSTNAME NON RISOLTO (sospetto DGA)",
        "tcp_issues":     "TCP ISSUES (connection refused / scan)",
        "probing":        "PROBING ATTEMPT (sondaggio silenzioso)",
        "unidirectional": "TRAFFICO UNIDIREZIONALE",
        "dst2src_zero":   "SERVER MAI HA RISPOSTO (timeout)",
    }
    # argmax sul breakdown
    causa, conteggio = max(breakdown.items(), key=lambda kv: kv[1])
    return etichette.get(causa, causa), conteggio


def stampa_report(host_ip: str, dati: dict):
    """
    Stampa un report leggibile per ogni host flagged dalla sola metrica.
    Usato quando lo script è eseguito per testing.
    """
    causa, conteggio = causa_dominante(dati["breakdown"])

    print("=" * 70)
    print(f"  [ALLARME M_fail] {host_ip}")
    print("=" * 70)
    print(f"  Timestamp             : {dati['timestamp']}")
    print(f"  M_fail                : {dati['M_fail']} (attiva)")
    print(f"  Categoria temporale   : {dati['categoria_temporale']}")
    print(f"  Bucket di baseline    : {dati['bucket_count']}")
    print(f"  Flussi totali (ora)   : {dati['n_totali']}")
    print(f"  Flussi falliti (ora)  : {dati['n_falliti']}")
    print(f"  Rate corrente         : {dati['r_corrente']*100:6.2f}%")
    print(f"  Rate mediano storico  : {dati['r_mediano']*100:6.2f}%")
    print(f"  MAD reale             : {dati['mad']*100:6.2f}%")
    print(f"  MAD effettiva (floor) : {dati['mad_eff']*100:6.2f}%")
    print(f"  Z-score robusto       : {dati['z_robusto']:6.2f}")
    print(f"  Causa dominante       : {causa} ({conteggio} flussi)")
    print(f"  Breakdown per causa   :")
    print(f"    error_code          : {dati['breakdown']['error_code']}")
    print(f"    unresolved          : {dati['breakdown']['unresolved']}")
    print(f"    tcp_issues          : {dati['breakdown']['tcp_issues']}")
    print(f"    probing             : {dati['breakdown']['probing']}")
    print(f"    unidirectional      : {dati['breakdown']['unidirectional']}")
    print(f"    dst2src_zero        : {dati['breakdown']['dst2src_zero']}")
    print(f"  Penalità M_fail       : +{dati['penalita']} punti")
    print()


# =============================================================================
# MAIN - Esecuzione per testing
# =============================================================================

def main():
    """
    Quando integreremo tutto in scoring.py, questa funzione NON verrà chiamata:
    scoring.py importerà direttamente `calcola_m_fail()` dalla funzione sopra.
    """
    print(f"\n{'='*70}")
    print(f"  Avvio analisi M_fail - "
          f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Finestra corrente    : ultima {FINESTRA_CORRENTE_ORE} ora")
    print(f"  Baseline storica     : ultimi {FINESTRA_STORICO_GIORNI} giorni")
    print(f"  Soglie statistiche   :")
    print(f"    Z > {SOGLIA_Z}")
    print(f"    r_corrente > {R_MIN_OPERATIVO*100:.0f}% (soglia operativa)")
    print(f"    MAD floor = {MAD_MIN_ASSOLUTA*100:.0f} punti percentuali")
    print(f"    flussi minimi correnti = {MIN_FLUSSI_CORRENTE}")
    print(f"    bucket minimi baseline = {MIN_BASELINE_HOURS}")
    print(f"  Bit nDPI considerati :"
          f" {BIT_NDPI_ERROR_CODE}, {BIT_NDPI_UNIDIRECTIONAL},"
          f" {BIT_NDPI_TCP_ISSUES}, {BIT_NDPI_UNRESOLVED_HOST},"
          f" {BIT_NDPI_PROBING_ATTEMPT}")
    print(f"{'='*70}\n")

    # Connessione al database
    try:
        client = connetti_clickhouse()
        print("[OK] Connessione a ClickHouse stabilita.\n")
    except Exception as e:
        print(f"[ERRORE] Impossibile connettersi a ClickHouse: {e}")
        return

    # Calcolo della metrica M_fail
    try:
        host_flaggati = calcola_m_fail(client)
    except Exception as e:
        print(f"[ERRORE] Errore durante l'esecuzione della query: {e}")
        return

    # Report dei risultati
    if not host_flaggati:
        print("[OK] Nessun host flagged - "
              "nessuna anomalia di rate di fallimento nell'ultima ora.\n")
        return

    print(f"[!] {len(host_flaggati)} host flagged dalla metrica M_fail:\n")

    for host_ip, dati in host_flaggati.items():
        stampa_report(host_ip, dati)


# Esegui questo solo se lanciato come script principale (non importato come modulo)
if __name__ == "__main__":
    main()
