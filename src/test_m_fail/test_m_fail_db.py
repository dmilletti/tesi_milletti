"""
=============================================================================
TEST DI LIVELLO 2 - VALIDAZIONE TRAMITE PROFILI DI TEST
=============================================================================

Obiettivo:
    Verificare che la query SQL di M_fail produca i risultati attesi su
    dati controllati scritti in una tabella temporanea `flows_test`.

    Qui testiamo l'integrazione:
      1. Generazione dei dati nel formato dello schema ntopng
      2. Calcolo di mediana e MAD da parte di ClickHouse
      3. Filtro contestuale per categoria temporale
      4. JOIN tra baseline e ora corrente
      5. Applicazione della tripla condizione di scatto + filtri cold start
      6. Definizione di "fallito" via DST2SRC_PACKETS=0 e bit nDPI

Approccio pratico:
    - Crea tabella `flows_test` con schema identico a `flows`
    - Inserisce dati per 4 host con profili noti
    - Esegue la query di M_fail (versione adattata) sulla tabella di test
    - Confronta i risultati con le attese
    - Elimina la tabella

Profili dei 4 host di test:

    Host A (10.0.0.1) - "Office tranquillo"
        Baseline:  ~150 flussi/ora con 1-3% di fallimenti
                   (rate mediana ~2%, MAD ~1%)
        Corrente:  200 flussi, ~2% falliti (dentro la tolleranza)
        Attesa:    M_fail = 0 (NON deve scattare)

    Host B (10.0.0.2) - "DGA via DNS"
        Baseline:  identica ad A (rate ~2%)
        Corrente:  250 flussi, 85% falliti (mix di bit 51 UNRESOLVED_HOSTNAME
                   e bit 43 ERROR_CODE, classico pattern DGA)
        Attesa:    M_fail = 1, Z molto alto, penalita = 30,
                   causa dominante = "unresolved" o "error_code"

    Host C (10.0.0.3) - "Host iperregolare" (testa il limite MAD)
        Baseline:  rate esattamente 0% in ogni bucket (MAD reale = 0)
        Corrente:  200 flussi, 40% falliti (bit 50 TCP_ISSUES)
        Attesa:    M_fail = 1, MAD reale = 0, MAD_eff = 0.05 (limite attivato)

    Host D (10.0.0.4) - "Cold start"
        Baseline:  solo 10 bucket (sotto MIN_BASELINE_HOURS = 30)
        Corrente:  200 flussi, 90% falliti
        Attesa:    Assente dai risultati (escluso per via del cold start)

Note di implementazione:
    - L'inserimento usa INSERT INTO ... VALUES via client.command() invece di
      client.insert(), per bypassare il bug dei datetime naive in CET/CEST
      gia' diagnosticato in test_m_vol_db.py.
    - La colonna FLOW_RISK e' UInt64; viene serializzata come stringa nella
      INSERT per evitare problemi di precisione con valori >= 2^53.
    - Il bit 43 (ERROR_CODE) corrisponde al valore 8796093022208;
      il bit 51 (UNRESOLVED_HOSTNAME) a 2251799813685248;
      il bit 50 (TCP_ISSUES) a 1125899906842624.
=============================================================================
"""
import clickhouse_connect
from datetime import datetime, timedelta
import ipaddress
import random
import sys

# Seed fisso per riproducibilita' della generazione casuale
random.seed(42)


# =============================================================================
# CONFIGURAZIONE
# =============================================================================

# Parametri di connessione (utente tester dedicato al testing)
CLICKHOUSE_HOST     = "localhost"
CLICKHOUSE_PORT     = 8123
CLICKHOUSE_DATABASE = "ntopng"
CLICKHOUSE_USER     = "tester"
CLICKHOUSE_PASSWORD = "test_password"

# Tabella di test (isolata da `flows` di produzione)
TABLE_NAME = "flows_test"

# Parametri della formula (identici a m_fail.py)
SOGLIA_Z            = 3.0
R_MIN_OPERATIVO     = 0.30
MAD_MIN_ASSOLUTA    = 0.05
MIN_FLUSSI_CORRENTE = 50
MIN_BASELINE_HOURS  = 30
PESO_M_FAIL         = 30

# Categorie temporali (devono replicare il multiIf della query)
ORE_LAVORATIVE = (9, 17)
GIORNI_WEEKEND = (6, 7)

# Finestre temporali
FINESTRA_STORICO_GIORNI = 7
FINESTRA_CORRENTE_ORE   = 1

# Bit nDPI per la definizione di "fallito"
BIT_NDPI_ERROR_CODE      = 43   # NDPI_ERROR_CODE_DETECTED
BIT_NDPI_UNIDIRECTIONAL  = 46   # NDPI_UNIDIRECTIONAL_TRAFFIC
BIT_NDPI_TCP_ISSUES      = 50   # NDPI_TCP_ISSUES
BIT_NDPI_UNRESOLVED_HOST = 51   # NDPI_UNRESOLVED_HOSTNAME
BIT_NDPI_PROBING_ATTEMPT = 55   # NDPI_PROBING_ATTEMPT

FLOW_RISK_FAIL_BITMASK = (
    (1 << BIT_NDPI_ERROR_CODE)      |
    (1 << BIT_NDPI_UNIDIRECTIONAL)  |
    (1 << BIT_NDPI_TCP_ISSUES)      |
    (1 << BIT_NDPI_UNRESOLVED_HOST) |
    (1 << BIT_NDPI_PROBING_ATTEMPT)
)

# Valori pre-calcolati dei singoli bit (usati come FLOW_RISK nelle righe)
RISK_ERROR_CODE      = 1 << BIT_NDPI_ERROR_CODE       #     8 796 093 022 208
RISK_UNIDIRECTIONAL  = 1 << BIT_NDPI_UNIDIRECTIONAL   #    70 368 744 177 664
RISK_TCP_ISSUES      = 1 << BIT_NDPI_TCP_ISSUES       # 1 125 899 906 842 624
RISK_UNRESOLVED_HOST = 1 << BIT_NDPI_UNRESOLVED_HOST  # 2 251 799 813 685 248
RISK_PROBING_ATTEMPT = 1 << BIT_NDPI_PROBING_ATTEMPT  #36 028 797 018 963 968
RISK_NONE            = 0  # flusso senza problemi noti

# IP dei 4 host di test
HOST_A_IP = "10.0.0.1"   # Office tranquillo
HOST_B_IP = "10.0.0.2"   # DGA via DNS
HOST_C_IP = "10.0.0.3"   # Iperregolare (test limite MAD)
HOST_D_IP = "10.0.0.4"   # Cold start
DEST_IP   = "8.8.8.8"    # IP esterno (Google DNS, fuori RFC1918)


# =============================================================================
# UTILITY
# =============================================================================

def ip_to_uint32(ip_str: str) -> int:
    """Converte un IP string in UInt32, come da convenzione ntopng."""
    return int(ipaddress.IPv4Address(ip_str))


def categoria_temporale_python(dt: datetime) -> str:
    """
    Replica in Python la stessa logica del multiIf SQL.
    Usata per generare timestamp che cadano nella categoria corretta.
    Deve restare SINCRONIZZATA con il multiIf della query.
    """
    # toDayOfWeek di ClickHouse: 1=lun, ..., 7=dom
    # In Python, weekday(): 0=lun, ..., 6=dom -> sommo 1 per allineare
    dow = dt.weekday() + 1
    if dow in GIORNI_WEEKEND:
        return "weekend"
    if ORE_LAVORATIVE[0] <= dt.hour <= ORE_LAVORATIVE[1]:
        return "feriale_lavorativo"
    return "feriale_fuoriorario"


def genera_bucket_categoria(categoria_target: str,
                            ora_riferimento: datetime,
                            n_giorni: int = 7) -> list:
    """
    Restituisce la lista di datetime di tutti i bucket orari che ricadono
    nella categoria_target, negli ultimi n_giorni.

    Esclude l'ultimo bucket immediatamente precedente all'ora corrente.
    Motivo: la query SQL separa il "corrente" (>= now() - 1h) dallo
    "storico" (< now() - 1h). Se generiamo flussi nel bucket precedente
    all'ora corrente con offset random fino a 50 minuti, alcuni di questi
    sforerebbero in avanti e finirebbero a cavallo della soglia,
    contaminando flussi_correnti. Saltare l'ultimo bucket categorizzato
    elimina del tutto il problema.
    """
    bucket = []
    inizio = ora_riferimento - timedelta(days=n_giorni)
    # Buffer di 2 ore (anziche' 1): l'ultimo bucket utile termina prima
    # della finestra corrente con un margine ampio per qualunque offset
    fine   = ora_riferimento - timedelta(hours=FINESTRA_CORRENTE_ORE + 1)

    cursore = inizio.replace(minute=0, second=0, microsecond=0)
    while cursore <= fine:
        if categoria_temporale_python(cursore) == categoria_target:
            bucket.append(cursore)
        cursore += timedelta(hours=1)

    return bucket


# =============================================================================
# SETUP E ELIMINAZIONE DELLA TABELLA DI TEST
# =============================================================================

def crea_tabella_test(client):
    """
    Crea flows_test con schema identico a flows.
    Se la tabella esiste gia' (da run precedenti interrotti), la droppa prima.
    """
    print(f"[setup] Creazione tabella '{TABLE_NAME}' (replica di flows)...")
    client.command(f"DROP TABLE IF EXISTS {TABLE_NAME}")
    # MergeTree locale e indipendente per evitare l'effetto proxy
    sql_create = (f"CREATE TABLE {TABLE_NAME} ENGINE = MergeTree ORDER BY tuple() "
                  f"AS SELECT * FROM flows LIMIT 0")
    client.command(sql_create)
    print(f"[setup] Tabella '{TABLE_NAME}' creata.\n")


def cleanup_tabella_test(client):
    """Droppa la tabella di test alla fine del run."""
    print(f"\n[teardown] Rimozione tabella '{TABLE_NAME}'...")
    client.command(f"DROP TABLE IF EXISTS {TABLE_NAME}")
    print(f"[teardown] Tabella rimossa.\n")


# =============================================================================
# GENERAZIONE DEI DATI DI TEST
# =============================================================================

def costruisci_riga_flusso(flow_id: int, timestamp: datetime,
                           host_ip: str,
                           dst2src_packets: int,
                           flow_risk: int) -> tuple:
    """
    Costruisce una riga di flusso compatibile con lo schema ntopng,
    popolando solo le colonne necessarie alla query di M_fail.

    Colonne popolate:
        FLOW_ID             - identificatore univoco
        IP_PROTOCOL_VERSION - 4 (IPv4)
        FIRST_SEEN          - timestamp di inizio flusso
        LAST_SEEN           - inizio + 5 secondi
        IPV4_SRC_ADDR       - host monitorato (LAN interna)
        IPV4_DST_ADDR       - DEST_IP = 8.8.8.8 (esterno)
        SRC2DST_PACKETS     - 1 (l'host ha provato a inviare)
        DST2SRC_PACKETS     - 0 se il server non ha risposto, >0 altrimenti
        FLOW_RISK           - bitmap dei rischi nDPI (UInt64)
    """
    return (
        flow_id,                          # FLOW_ID
        4,                                # IP_PROTOCOL_VERSION
        timestamp,                        # FIRST_SEEN
        timestamp + timedelta(seconds=5), # LAST_SEEN
        ip_to_uint32(host_ip),            # IPV4_SRC_ADDR
        ip_to_uint32(DEST_IP),            # IPV4_DST_ADDR
        1,                                # SRC2DST_PACKETS
        dst2src_packets,                  # DST2SRC_PACKETS
        flow_risk,                        # FLOW_RISK
    )


# Ordine delle colonne usato per la INSERT
COLONNE_INSERT = [
    "FLOW_ID",
    "IP_PROTOCOL_VERSION",
    "FIRST_SEEN",
    "LAST_SEEN",
    "IPV4_SRC_ADDR",
    "IPV4_DST_ADDR",
    "SRC2DST_PACKETS",
    "DST2SRC_PACKETS",
    "FLOW_RISK",
]


def genera_flussi_bucket(bucket_start: datetime, host_ip: str,
                         n_totali: int, n_falliti: int,
                         tipo_fallimento: str,
                         flow_id_start: int) -> tuple[list, int]:
    """
    Genera n_totali flussi per un dato host in un dato bucket orario, di
    cui n_falliti contrassegnati come falliti secondo `tipo_fallimento`.

    tipo_fallimento:
        "dst2src_zero"  -> DST2SRC_PACKETS = 0 (server mai risposto)
        "error_code"    -> FLOW_RISK con bit 43 (NXDOMAIN/HTTP error)
        "unresolved"    -> FLOW_RISK con bit 51 (DGA via DNS)
        "tcp_issues"    -> FLOW_RISK con bit 50 (RST/refused)
        "mix_dga"       -> meta' unresolved + meta' error_code (DGA realistico)

    Restituisce (lista_righe, next_flow_id).
    """
    righe = []
    fid = flow_id_start

    # Indici dei flussi falliti dentro al bucket (random)
    indici_falliti = set(random.sample(range(n_totali), n_falliti))

    for i in range(n_totali):
        # Timestamp distribuito casualmente dentro il bucket orario, ma con un
        # buffer di 10 minuti rispetto al bucket successivo (max offset = 50
        # minuti). Questo evita che flussi della baseline vicini all'ora
        # corrente cadano accidentalmente dentro la finestra "now() - 1 HOUR",
        # contaminando la CTE flussi_correnti e diluendone il rate.
        # Esempio: bucket=15:00, offset max=50min -> ts max=15:50, che resta
        # prima di now() - 1 HOUR anche con now()=16:02.
        offset_secondi = random.randint(1, 3000)
        ts = bucket_start + timedelta(seconds=offset_secondi)

        if i in indici_falliti:
            if tipo_fallimento == "dst2src_zero":
                dst_pkts, risk = 0, RISK_NONE
            elif tipo_fallimento == "error_code":
                dst_pkts, risk = 2, RISK_ERROR_CODE
            elif tipo_fallimento == "unresolved":
                dst_pkts, risk = 1, RISK_UNRESOLVED_HOST
            elif tipo_fallimento == "tcp_issues":
                dst_pkts, risk = 1, RISK_TCP_ISSUES
            elif tipo_fallimento == "mix_dga":
                # Meta' falliti come unresolved (DNS DGA), meta' come error_code
                # (HTTP 4xx ricevuti dai pochi C2 raggiungibili)
                if i % 2 == 0:
                    dst_pkts, risk = 1, RISK_UNRESOLVED_HOST
                else:
                    dst_pkts, risk = 2, RISK_ERROR_CODE
            else:
                raise ValueError(f"tipo_fallimento sconosciuto: {tipo_fallimento}")
        else:
            # Flusso riuscito: server ha risposto, nessun bit di rischio
            dst_pkts, risk = 5, RISK_NONE

        righe.append(costruisci_riga_flusso(fid, ts, host_ip, dst_pkts, risk))
        fid += 1

    return righe, fid


def genera_dati_host_A(bucket_categoria: list, flow_id_start: int) -> tuple[list, int]:
    """
    Host A - office tranquillo.
    Baseline: ~150 flussi/ora, 1-3% falliti (rate mediana ~2%, MAD ~1%)
    Corrente: 200 flussi, ~2% falliti (dentro tolleranza)
    """
    righe = []
    fid = flow_id_start

    # Baseline: per ogni bucket della categoria genera ~150 flussi
    # con un rate di fallimento intorno al 2%
    for bucket_start in bucket_categoria:
        n_tot = random.randint(140, 160)
        # Rate di fallimento tra 1% e 3% -> 1-5 falliti su 150
        n_fail = random.randint(int(n_tot * 0.01), int(n_tot * 0.03))
        nuove, fid = genera_flussi_bucket(
            bucket_start, HOST_A_IP, n_tot, n_fail,
            tipo_fallimento="dst2src_zero",
            flow_id_start=fid
        )
        righe.extend(nuove)

    # Corrente: 200 flussi, 2% falliti (4 falliti)
    ts_corrente = datetime.now() - timedelta(minutes=30)
    nuove, fid = genera_flussi_bucket(
        ts_corrente, HOST_A_IP, 200, 4,
        tipo_fallimento="dst2src_zero",
        flow_id_start=fid
    )
    righe.extend(nuove)
    return righe, fid


def genera_dati_host_B(bucket_categoria: list, flow_id_start: int) -> tuple[list, int]:
    """
    Host B - DGA via DNS.
    Baseline: identica ad A (rate ~2%)
    Corrente: 250 flussi, 85% falliti (mix unresolved + error_code = DGA)
    """
    righe = []
    fid = flow_id_start

    # Baseline pulita (identica ad A)
    for bucket_start in bucket_categoria:
        n_tot = random.randint(140, 160)
        n_fail = random.randint(int(n_tot * 0.01), int(n_tot * 0.03))
        nuove, fid = genera_flussi_bucket(
            bucket_start, HOST_B_IP, n_tot, n_fail,
            tipo_fallimento="dst2src_zero",
            flow_id_start=fid
        )
        righe.extend(nuove)

    # Corrente: il malware sta cercando il C2 -> 85% falliti su 250 flussi
    # 213 falliti su 250 = 85.2%, mix di DNS NXDOMAIN e HTTP errors
    ts_corrente = datetime.now() - timedelta(minutes=30)
    nuove, fid = genera_flussi_bucket(
        ts_corrente, HOST_B_IP, 250, 213,
        tipo_fallimento="mix_dga",
        flow_id_start=fid
    )
    righe.extend(nuove)
    return righe, fid


def genera_dati_host_C(bucket_categoria: list, flow_id_start: int) -> tuple[list, int]:
    """
    Host C - iperregolare (test del floor MAD).
    Baseline: rate esattamente 0% in ogni bucket -> MAD reale = 0
    Corrente: 200 flussi, 40% falliti (TCP refused, plausibile scan)
    Atteso: MAD_eff = 0.05 (floor attivato)
    """
    righe = []
    fid = flow_id_start

    # Baseline: ogni bucket ha esattamente 100 flussi, ZERO falliti
    # In questo modo rate_bucket = 0 per ogni bucket, mediana = 0, MAD = 0
    for bucket_start in bucket_categoria:
        nuove, fid = genera_flussi_bucket(
            bucket_start, HOST_C_IP, 100, 0,
            tipo_fallimento="dst2src_zero",  # ininfluente, 0 falliti
            flow_id_start=fid
        )
        righe.extend(nuove)

    # Corrente: 200 flussi, 80 falliti = 40% (sopra R_MIN_OPERATIVO)
    ts_corrente = datetime.now() - timedelta(minutes=30)
    nuove, fid = genera_flussi_bucket(
        ts_corrente, HOST_C_IP, 200, 80,
        tipo_fallimento="tcp_issues",
        flow_id_start=fid
    )
    righe.extend(nuove)
    return righe, fid


def genera_dati_host_D(bucket_categoria: list, flow_id_start: int) -> tuple[list, int]:
    """
    Host D - cold start.
    Baseline: solo i primi 10 bucket disponibili
    Corrente: 200 flussi, 90% falliti
    Atteso: ASSENTE dai risultati (escluso da bucket_count < 30)
    """
    righe = []
    fid = flow_id_start

    # Solo i primi 10 bucket (sotto la soglia MIN_BASELINE_HOURS = 30)
    bucket_ridotti = bucket_categoria[:10]
    for bucket_start in bucket_ridotti:
        nuove, fid = genera_flussi_bucket(
            bucket_start, HOST_D_IP, 100, 2,
            tipo_fallimento="dst2src_zero",
            flow_id_start=fid
        )
        righe.extend(nuove)

    # Corrente: 200 flussi, 180 falliti (90%) - "scatterebbe" se non fosse cold start
    ts_corrente = datetime.now() - timedelta(minutes=30)
    nuove, fid = genera_flussi_bucket(
        ts_corrente, HOST_D_IP, 200, 180,
        tipo_fallimento="mix_dga",
        flow_id_start=fid
    )
    righe.extend(nuove)
    return righe, fid


def riga_to_sql_values(riga: tuple) -> str:
    """
    Converte una riga-tupla in stringa SQL VALUES.

    Bypassa il bug del driver clickhouse-connect sui datetime naive in CET/CEST
    (vedi test_m_vol_db.py per la diagnostica). Costruiamo una
    INSERT INTO ... VALUES (...) e la mandiamo come command().

    FLOW_RISK e' UInt64 e per valori >= 2^53 perde precisione se serializzato
    via JSON. Lo mandiamo come stringa numerica nella query SQL, ClickHouse
    lo parsa correttamente.

    Ordine: (FLOW_ID, IP_PROTOCOL_VERSION, FIRST_SEEN, LAST_SEEN,
             IPV4_SRC_ADDR, IPV4_DST_ADDR,
             SRC2DST_PACKETS, DST2SRC_PACKETS, FLOW_RISK)
    """
    (flow_id, ip_proto, first_seen, last_seen,
     src, dst, src_pkts, dst_pkts, flow_risk) = riga
    first_seen_str = first_seen.strftime("%Y-%m-%d %H:%M:%S")
    last_seen_str  = last_seen.strftime("%Y-%m-%d %H:%M:%S")
    return (f"({flow_id}, {ip_proto}, "
            f"'{first_seen_str}', '{last_seen_str}', "
            f"{src}, {dst}, "
            f"{src_pkts}, {dst_pkts}, {flow_risk})")


def inserisci_dati_test(client):
    """
    Genera e inserisce i dati per i 4 host di test.
    Restituisce un dizionario con le statistiche generative per il report.
    """
    print("[gen] Generazione dati sintetici...")

    # Determina la categoria temporale corrente (datetime.now() locale per
    # allinearsi all'interpretazione di ClickHouse dei DateTime inseriti)
    ora_corrente = datetime.now()
    categoria_corrente = categoria_temporale_python(ora_corrente)
    print(f"[gen] Ora corrente              : "
          f"{ora_corrente.strftime('%Y-%m-%d %H:%M:%S')} (ora locale)")
    print(f"[gen] Categoria temporale corr. : {categoria_corrente}")

    # Calcola i bucket della baseline contestuale
    bucket_baseline = genera_bucket_categoria(categoria_corrente, ora_corrente)
    print(f"[gen] Bucket baseline disponibili: {len(bucket_baseline)} "
          f"(categoria '{categoria_corrente}', ultimi 7 giorni)")

    if len(bucket_baseline) < MIN_BASELINE_HOURS:
        print(f"\n[!!] ATTENZIONE: bucket disponibili ({len(bucket_baseline)}) "
              f"< MIN_BASELINE_HOURS ({MIN_BASELINE_HOURS})")
        print(f"     Tutti gli host (compresi A, B, C) verranno esclusi.")
        print(f"     Riprova in un orario con piu' bucket della categoria.\n")

    # Genera le righe per ciascun host
    fid = 9_999_000_000  # FLOW_ID alto per non collidere con dati reali

    righe_a, fid = genera_dati_host_A(bucket_baseline, fid)
    fid += 100   # gap di sicurezza fra blocchi

    righe_b, fid = genera_dati_host_B(bucket_baseline, fid)
    fid += 100

    righe_c, fid = genera_dati_host_C(bucket_baseline, fid)
    fid += 100

    righe_d, fid = genera_dati_host_D(bucket_baseline, fid)

    righe = righe_a + righe_b + righe_c + righe_d

    print(f"[gen] Righe da inserire         : "
          f"A={len(righe_a)}, B={len(righe_b)}, "
          f"C={len(righe_c)}, D={len(righe_d)}, totale={len(righe)}")

    # Inserimento via INSERT INTO ... VALUES per bypassare il bug del driver
    # sui datetime naive in ambiente CET/CEST.
    # Batch di 200 righe per evitare URL troppo lunghe (qui le righe sono
    # piu' numerose di test_m_vol_db.py perche' generiamo 100-150 flussi/bucket
    # invece di 1).
    BATCH_SIZE = 200
    colonne_str = ", ".join(COLONNE_INSERT)
    for i in range(0, len(righe), BATCH_SIZE):
        batch = righe[i:i + BATCH_SIZE]
        values_str = ",\n".join(riga_to_sql_values(r) for r in batch)
        # async_insert=0 forza inserimento sincrono (visibilita' immediata)
        sql = (f"INSERT INTO {TABLE_NAME} ({colonne_str}) "
               f"SETTINGS async_insert=0 VALUES\n{values_str}")
        client.command(sql)

    # Verifica post-insert
    n_inserite = client.query(f"SELECT count() FROM {TABLE_NAME}").result_rows[0][0]
    print(f"[gen] Righe effettivamente in DB: {n_inserite}")

    if n_inserite != len(righe):
        print(f"\n[!!] ATTENZIONE: attese {len(righe)} righe, "
              f"ne risultano {n_inserite}!")
        print(f"     Possibile bug di inserimento.\n")

    print(f"[gen] Dati inseriti in '{TABLE_NAME}'.\n")

    return {
        "categoria_corrente": categoria_corrente,
        "bucket_baseline": len(bucket_baseline),
        "righe_per_host": {
            HOST_A_IP: len(righe_a),
            HOST_B_IP: len(righe_b),
            HOST_C_IP: len(righe_c),
            HOST_D_IP: len(righe_d),
        }
    }


# =============================================================================
# QUERY M_fail ADATTATA PER IL TEST
# =============================================================================

QUERY_M_FAIL_TEST = f"""
WITH (
    SELECT multiIf(
        toDayOfWeek(now()) IN ({GIORNI_WEEKEND[0]}, {GIORNI_WEEKEND[1]}),
            'weekend',
        toHour(now()) BETWEEN {ORE_LAVORATIVE[0]} AND {ORE_LAVORATIVE[1]},
            'feriale_lavorativo',
            'feriale_fuoriorario'
    )
) AS categoria_corrente,

flussi_storici AS (
    SELECT
        IPv4NumToString(IPV4_SRC_ADDR) AS host_ip,
        toStartOfHour(FIRST_SEEN)       AS bucket_orario,
        count() AS n_flussi_totali,
        countIf(
            DST2SRC_PACKETS = 0
            OR bitAnd(FLOW_RISK, {FLOW_RISK_FAIL_BITMASK}) != 0
        ) AS n_flussi_falliti,
        toFloat64(n_flussi_falliti) / toFloat64(n_flussi_totali) AS rate_bucket
    FROM {TABLE_NAME}
    WHERE
        FIRST_SEEN >= now() - INTERVAL {FINESTRA_STORICO_GIORNI} DAY
        AND FIRST_SEEN <  now() - INTERVAL {FINESTRA_CORRENTE_ORE} HOUR
        AND IPV4_SRC_ADDR != 0
        AND multiIf(
            toDayOfWeek(FIRST_SEEN) IN ({GIORNI_WEEKEND[0]}, {GIORNI_WEEKEND[1]}),
                'weekend',
            toHour(FIRST_SEEN) BETWEEN {ORE_LAVORATIVE[0]} AND {ORE_LAVORATIVE[1]},
                'feriale_lavorativo',
                'feriale_fuoriorario'
        ) = categoria_corrente
        AND (
            isIPAddressInRange(IPv4NumToString(IPV4_SRC_ADDR), '10.0.0.0/8')
            OR isIPAddressInRange(IPv4NumToString(IPV4_SRC_ADDR), '172.16.0.0/12')
            OR isIPAddressInRange(IPv4NumToString(IPV4_SRC_ADDR), '192.168.0.0/16')
        )
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '10.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '172.16.0.0/12')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '192.168.0.0/16')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '127.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '169.254.0.0/16')
    GROUP BY host_ip, bucket_orario
    HAVING n_flussi_totali > 0
),

mediane AS (
    SELECT
        host_ip,
        median(rate_bucket) AS r_mediana,
        count()             AS bucket_count
    FROM flussi_storici
    GROUP BY host_ip
    HAVING bucket_count >= {MIN_BASELINE_HOURS}
),

statistiche_baseline AS (
    SELECT
        fs.host_ip,
        any(m.r_mediana)                          AS r_mediana,
        any(m.bucket_count)                       AS bucket_count,
        median(abs(fs.rate_bucket - m.r_mediana)) AS mad
    FROM flussi_storici AS fs
    INNER JOIN mediane AS m ON fs.host_ip = m.host_ip
    GROUP BY fs.host_ip
),

flussi_correnti AS (
    SELECT
        IPv4NumToString(IPV4_SRC_ADDR) AS host_ip,
        count() AS n_flussi_totali,
        countIf(
            DST2SRC_PACKETS = 0
            OR bitAnd(FLOW_RISK, {FLOW_RISK_FAIL_BITMASK}) != 0
        ) AS n_flussi_falliti,
        toFloat64(n_flussi_falliti) / toFloat64(n_flussi_totali) AS r_corrente,
        countIf(DST2SRC_PACKETS = 0)                                 AS n_dst2src_zero,
        countIf(bitTest(FLOW_RISK, {BIT_NDPI_ERROR_CODE}) = 1)       AS n_error_code,
        countIf(bitTest(FLOW_RISK, {BIT_NDPI_UNIDIRECTIONAL}) = 1)   AS n_unidirectional,
        countIf(bitTest(FLOW_RISK, {BIT_NDPI_TCP_ISSUES}) = 1)       AS n_tcp_issues,
        countIf(bitTest(FLOW_RISK, {BIT_NDPI_UNRESOLVED_HOST}) = 1)  AS n_unresolved,
        countIf(bitTest(FLOW_RISK, {BIT_NDPI_PROBING_ATTEMPT}) = 1)  AS n_probing
    FROM {TABLE_NAME}
    WHERE
        FIRST_SEEN >= now() - INTERVAL {FINESTRA_CORRENTE_ORE} HOUR
        AND IPV4_SRC_ADDR != 0
        AND (
            isIPAddressInRange(IPv4NumToString(IPV4_SRC_ADDR), '10.0.0.0/8')
            OR isIPAddressInRange(IPv4NumToString(IPV4_SRC_ADDR), '172.16.0.0/12')
            OR isIPAddressInRange(IPv4NumToString(IPV4_SRC_ADDR), '192.168.0.0/16')
        )
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '10.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '172.16.0.0/12')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '192.168.0.0/16')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '127.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '169.254.0.0/16')
    GROUP BY host_ip
    HAVING n_flussi_totali >= {MIN_FLUSSI_CORRENTE}
)

SELECT
    fc.host_ip AS host_ip,
    fc.n_flussi_totali AS n_totali,
    fc.n_flussi_falliti AS n_falliti,
    fc.r_corrente AS r_corrente,
    sb.r_mediana AS r_mediana,
    sb.mad AS mad,
    greatest(sb.mad, {MAD_MIN_ASSOLUTA}) AS mad_eff,
    (fc.r_corrente - sb.r_mediana)
        / greatest(sb.mad, {MAD_MIN_ASSOLUTA}) AS z_modified,
    sb.bucket_count AS bucket_count,
    categoria_corrente AS categoria_temporale,
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
    fc.r_corrente > {R_MIN_OPERATIVO}
    AND fc.r_corrente > sb.r_mediana
    AND z_modified > {SOGLIA_Z}
ORDER BY z_modified DESC
"""


def esegui_query_m_fail(client) -> dict:
    """Esegue la query e restituisce un dizionario host_ip -> dettagli."""
    risultati = {}
    righe = client.query(QUERY_M_FAIL_TEST).result_rows
    for (host_ip, n_totali, n_falliti, r_corrente,
         r_mediana, mad, mad_eff, z_modified,
         bucket_count, categoria_temporale,
         n_dst2src_zero, n_error_code, n_unidirectional,
         n_tcp_issues, n_unresolved, n_probing,
         m_fail) in righe:
        risultati[host_ip] = {
            "M_fail":              m_fail,
            "n_totali":            n_totali,
            "n_falliti":           n_falliti,
            "r_corrente":          float(r_corrente),
            "r_mediana":           float(r_mediana),
            "mad":                 float(mad),
            "mad_eff":             float(mad_eff),
            "z_modified":           float(z_modified),
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
        }
    return risultati


# =============================================================================
# VERIFICA DEI RISULTATI
# =============================================================================

def verifica_risultati(risultati: dict) -> list:
    """
    Verifica che i risultati siano coerenti con le attese.
    Restituisce una lista di esiti, uno per ogni host.
    """
    esiti = []

    # ------ Host A: NON deve essere nei risultati (rate ~2% dentro tolleranza) ------
    if HOST_A_IP not in risultati:
        esiti.append({
            "host": HOST_A_IP, "profilo": "Office tranquillo",
            "esito": "PASS",
            "dettagli": "Correttamente assente (rate corrente dentro tolleranza)"
        })
    else:
        r = risultati[HOST_A_IP]
        esiti.append({
            "host": HOST_A_IP, "profilo": "Office tranquillo",
            "esito": "FAIL",
            "dettagli": (f"Presente con Z={r['z_modified']:.2f}, "
                         f"r_corrente={r['r_corrente']*100:.2f}%. "
                         f"Atteso: assente.")
        })

    # ------ Host B: DEVE essere nei risultati con penalita = 30 ------
    if HOST_B_IP in risultati:
        r = risultati[HOST_B_IP]
        problemi = []
        if r["M_fail"] != 1:
            problemi.append(f"M_fail={r['M_fail']} invece di 1")
        if r["penalita"] != 30:
            problemi.append(f"penalita={r['penalita']} invece di 30")
        if r["z_modified"] <= 3:
            problemi.append(f"z_modified={r['z_modified']:.2f} non > 3")
        if r["r_corrente"] <= 0.30:
            problemi.append(f"r_corrente={r['r_corrente']*100:.1f}% non > 30%")
        # Causa dominante deve essere unresolved o error_code (entrambe contano in mix_dga)
        breakdown = r["breakdown"]
        causa_top = max(breakdown.items(), key=lambda kv: kv[1])
        if causa_top[0] not in ("unresolved", "error_code"):
            problemi.append(f"causa dominante='{causa_top[0]}' "
                            f"(attesa: unresolved o error_code)")
        if problemi:
            esiti.append({
                "host": HOST_B_IP, "profilo": "DGA via DNS",
                "esito": "FAIL",
                "dettagli": "; ".join(problemi)
            })
        else:
            esiti.append({
                "host": HOST_B_IP, "profilo": "DGA via DNS",
                "esito": "PASS",
                "dettagli": (f"Rilevato: Z={r['z_modified']:.2f}, "
                             f"r_corrente={r['r_corrente']*100:.1f}%, "
                             f"causa={causa_top[0]}({causa_top[1]}), "
                             f"+{r['penalita']} punti")
            })
    else:
        esiti.append({
            "host": HOST_B_IP, "profilo": "DGA via DNS",
            "esito": "FAIL",
            "dettagli": "Assente dai risultati. Atteso: presente con M_fail=1."
        })

    # ------ Host C: DEVE essere nei risultati con MAD_eff = 0.05 (floor attivo) ------
    if HOST_C_IP in risultati:
        r = risultati[HOST_C_IP]
        problemi = []
        if r["M_fail"] != 1:
            problemi.append(f"M_fail={r['M_fail']} invece di 1")
        if r["penalita"] != 30:
            problemi.append(f"penalita={r['penalita']} invece di 30")
        # MAD reale = 0 attesa (tutti i bucket hanno rate=0)
        if r["mad"] != 0:
            problemi.append(f"mad={r['mad']:.4f} non zero (atteso 0)")
        # MAD_eff = max(0, 0.05) = 0.05 (floor)
        if abs(r["mad_eff"] - MAD_MIN_ASSOLUTA) > 1e-6:
            problemi.append(f"mad_eff={r['mad_eff']:.4f} invece di "
                            f"{MAD_MIN_ASSOLUTA} (floor non attivato)")
        if problemi:
            esiti.append({
                "host": HOST_C_IP, "profilo": "Iperregolare (floor MAD)",
                "esito": "FAIL",
                "dettagli": "; ".join(problemi)
            })
        else:
            esiti.append({
                "host": HOST_C_IP, "profilo": "Iperregolare (floor MAD)",
                "esito": "PASS",
                "dettagli": (f"Rilevato: MAD_reale={r['mad']:.4f} -> "
                             f"MAD_eff={r['mad_eff']:.4f} (floor attivo), "
                             f"Z={r['z_modified']:.2f}, "
                             f"r_corrente={r['r_corrente']*100:.1f}%, "
                             f"+{r['penalita']} punti")
            })
    else:
        esiti.append({
            "host": HOST_C_IP, "profilo": "Iperregolare (floor MAD)",
            "esito": "FAIL",
            "dettagli": "Assente dai risultati. Atteso: presente con floor attivo."
        })

    # ------ Host D: NON deve essere nei risultati (cold start) ------
    if HOST_D_IP not in risultati:
        esiti.append({
            "host": HOST_D_IP, "profilo": "Cold start",
            "esito": "PASS",
            "dettagli": (f"Correttamente assente (escluso da "
                         f"bucket_count >= {MIN_BASELINE_HOURS})")
        })
    else:
        r = risultati[HOST_D_IP]
        esiti.append({
            "host": HOST_D_IP, "profilo": "Cold start",
            "esito": "FAIL",
            "dettagli": (f"Presente con bucket_count={r['bucket_count']}. "
                         f"Atteso: assente per cold start.")
        })

    return esiti


# =============================================================================
# REPORT
# =============================================================================

def stampa_report_risultati(risultati: dict):
    """Stampa il dump dei risultati raw della query."""
    print("=" * 75)
    print("  RISULTATI RAW DELLA QUERY")
    print("=" * 75)
    if not risultati:
        print("  (nessun host nei risultati)")
        print()
        return

    for host_ip, r in risultati.items():
        print(f"\n  Host {host_ip}:")
        print(f"    M_fail              : {r['M_fail']}")
        print(f"    n_totali            : {r['n_totali']}")
        print(f"    n_falliti           : {r['n_falliti']}")
        print(f"    r_corrente          : {r['r_corrente']*100:.2f}%")
        print(f"    r_mediana           : {r['r_mediana']*100:.2f}%")
        print(f"    mad (reale)         : {r['mad']:.4f} ({r['mad']*100:.2f}%)")
        print(f"    mad_eff             : {r['mad_eff']:.4f} ({r['mad_eff']*100:.2f}%)")
        print(f"    z_modified          : {r['z_modified']:.2f}")
        print(f"    bucket_count        : {r['bucket_count']}")
        print(f"    categoria_temporale : {r['categoria_temporale']}")
        print(f"    breakdown           :")
        for k, v in r['breakdown'].items():
            print(f"      {k:18s}: {v}")
        print(f"    penalita            : +{r['penalita']}")
    print()


def stampa_report_esiti(esiti: list):
    """Stampa il report finale PASS/FAIL per ogni host."""
    print("=" * 75)
    print("  ESITI DEI TEST")
    print("=" * 75)
    for e in esiti:
        prefisso = "[PASS]" if e["esito"] == "PASS" else "[FAIL]"
        print(f"  {prefisso} {e['host']:14s} ({e['profilo']})")
        print(f"          {e['dettagli']}")
    print()


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("\n" + "=" * 75)
    print("  TEST DI LIVELLO 2 - VALIDAZIONE TRAMITE PROFILI DI TEST DELLA METRICA M_fail")
    print("=" * 75)
    print(f"  Tabella di test     : {TABLE_NAME}")
    print(f"  MIN_BASELINE_HOURS  : {MIN_BASELINE_HOURS}")
    print(f"  R_MIN_OPERATIVO     : {R_MIN_OPERATIVO*100:.0f}%")
    print(f"  MAD_MIN_ASSOLUTA    : {MAD_MIN_ASSOLUTA*100:.0f} pp")
    print(f"  MIN_FLUSSI_CORRENTE : {MIN_FLUSSI_CORRENTE}")
    print("=" * 75 + "\n")

    # Connessione
    try:
        client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
            database=CLICKHOUSE_DATABASE,
            username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
        )
        print("[setup] Connessione a ClickHouse stabilita.\n")
    except Exception as e:
        print(f"[ERRORE] Impossibile connettersi a ClickHouse: {e}")
        return 1

    try:
        # Setup
        crea_tabella_test(client)

        # Generazione e inserimento dei dati
        info_gen = inserisci_dati_test(client)

        # Esecuzione della query
        print("[run] Esecuzione della query M_fail...\n")
        risultati = esegui_query_m_fail(client)

        # Report dei risultati raw
        stampa_report_risultati(risultati)

        # Verifica delle attese
        esiti = verifica_risultati(risultati)
        stampa_report_esiti(esiti)

        # Riepilogo finale
        passati = sum(1 for e in esiti if e["esito"] == "PASS")
        falliti = sum(1 for e in esiti if e["esito"] == "FAIL")
        print("=" * 75)
        print("  RIEPILOGO")
        print("=" * 75)
        print(f"  Test eseguiti : {len(esiti)}")
        print(f"  Passati       : {passati}")
        print(f"  Falliti       : {falliti}")
        if falliti == 0:
            print("\n  [OK] Tutti i test sono passati. "
                  "La query M_fail funziona correttamente end-to-end.")
        else:
            print(f"\n  [!!] {falliti} test FALLITI. "
                  "Verificare i log sopra prima di procedere.")
        print("=" * 75)

        return 0 if falliti == 0 else 1

    finally:
        # Cleanup garantito anche in caso di errore
        cleanup_tabella_test(client)


if __name__ == "__main__":
    sys.exit(main())
