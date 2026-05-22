"""
=============================================================================
TEST DI LIVELLO 2 - VALIDAZIONE TRAMITE PROFILI DI TEST
=============================================================================

Obiettivo:
    Verificare che la query SQL di M_vol produca i risultati attesi su
    dati controllati scritti in una tabella temporanea `flows_test`.

    A differenza del Livello 1, qui testiamo l'integrazione:
      1. Generazione dei dati nel formato dello schema ntopng
      2. Calcolo di mediana e MAD da parte di ClickHouse
      3. Filtro contestuale per categoria temporale
      4. JOIN tra baseline e ora corrente
      5. Applicazione della tripla condizione

Approccio pratico:
    - Crea tabella `flows_test` con schema identico a `flows`
    - Inserisce dati per 4 host con profili noti
    - Esegue la query di M_vol (versione adattata) sulla tabella di test
    - Confronta i risultati con quelli attesi
    - Elimina la tabella

Profili dei 4 host di test:

    Host A (10.0.0.1) - "Office worker tranquillo"
        Baseline:  ~10 MB/ora con piccola variabilità (8-12 MB)
        Corrente:  12 MB (dentro la tolleranza)
        Attesa:    M_vol = 0 (NON deve scattare)

    Host B (10.0.0.2) - "Esfiltrazione"
        Baseline:  identica ad A
        Corrente:  200 MB (esfiltrazione)
        Attesa:    M_vol = 1, Z molto alto, penalita = 20

    Host C (10.0.0.3) - "Server costante con picco" (testa il floor MAD)
        Baseline:  esattamente 1 MB ogni bucket (MAD reale = 0)
        Corrente:  80 MB
        Attesa:    M_vol = 1, MAD_eff = 1 MB (limite assoluto attivato)

    Host D (10.0.0.4) - "Cold start"
        Baseline:  solo 10 bucket di dati
        Corrente:  100 MB
        Attesa:    Assente dai risultati (escluso da cold start)
=============================================================================
"""
import clickhouse_connect
from datetime import datetime, timedelta
import ipaddress
import random
import sys

# Seed fisso per generazione riproducibile dei volumi rumorosi
random.seed(42)


# =============================================================================
# CONFIGURAZIONE
# =============================================================================

# Parametri di connessione
# L'utente tester ha readonly=0 ed è dedicato esclusivamente al testing.
CLICKHOUSE_HOST     = "localhost"
CLICKHOUSE_PORT     = 8123
CLICKHOUSE_DATABASE = "ntopng"
CLICKHOUSE_USER     = "tester"
CLICKHOUSE_PASSWORD = "test_password"

# Tabella di test (isolata da `flows` di produzione)
TABLE_NAME = "flows_test"

# Minimo numero di bucket richiesti per includere un host nella baseline
MIN_BASELINE_HOURS = 30

# Parametri della formula (identici a m_vol.py)
SOGLIA_Z         = 3.0
MAD_MIN_FRAZIONE = 0.10
MAD_MIN_ASSOLUTO = 1024 * 1024       # 1 MB
V_MIN_OPERATIVO  = 50 * 1024 * 1024
PESO_M_VOL       = 20

# Categorie temporali
ORE_LAVORATIVE   = (9, 17)
GIORNI_WEEKEND   = (6, 7)

# Finestre temporali
FINESTRA_STORICO_GIORNI = 7
FINESTRA_CORRENTE_ORE   = 1

# IP dei 4 host di test
HOST_A_IP = "10.0.0.1"   # Office tranquillo
HOST_B_IP = "10.0.0.2"   # Esfiltrazione
HOST_C_IP = "10.0.0.3"   # Server costante con picco
HOST_D_IP = "10.0.0.4"   # Cold start
DEST_IP   = "8.8.8.8"    # IP esterno (fuori RFC1918)


# =============================================================================
# UTILITY
# =============================================================================

def ip_to_uint32(ip_str: str) -> int:
    """Converte un IP string in UInt32, come da convenzione ntopng."""
    return int(ipaddress.IPv4Address(ip_str))


def formatta_byte(b: float) -> str:
    """Converte byte in unità leggibili per il report."""
    if b >= 1024**3:
        return f"{b / 1024**3:.2f} GB"
    if b >= 1024**2:
        return f"{b / 1024**2:.2f} MB"
    if b >= 1024:
        return f"{b / 1024:.2f} KB"
    return f"{int(b)} B"


def categoria_temporale_python(dt: datetime) -> str:
    """
    Replica in Python la stessa logica del multiIf SQL.
    Usata per generare timestamp che cadano nella categoria corretta.
    Deve restare SINCRONIZZATA con il multiIf della query.
    """
    # toDayOfWeek di ClickHouse: 1=lun, 2=mar, ..., 7=dom
    # In Python, weekday(): 0=lun, ..., 6=dom -> quindi sommo 1 per allineare
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
    nella categoria_target, negli ultimi n_giorni, ESCLUDENDO il bucket
    dell'ora corrente .
    """
    bucket = []
    inizio = ora_riferimento - timedelta(days=n_giorni)
    fine   = ora_riferimento - timedelta(hours=FINESTRA_CORRENTE_ORE +1)

    # Allinea l'inizio al bucket orario
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
    Se la tabella esiste già (da run precedenti interrotti), la droppa prima.
    """
    print(f"[setup] Creazione tabella '{TABLE_NAME}' (replica di flows)...")
    client.command(f"DROP TABLE IF EXISTS {TABLE_NAME}")
    # NOVITÀ: Estraiamo solo le colonne (LIMIT 0) e forziamo un motore
    # MergeTree locale e indipendente per evitare l'effetto proxy.
    # Questo garantisce che i dati di test siano isolati e visibili immediatamente dopo l'inserimento.
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
                           host_ip: str, byte_inviati: int) -> tuple:
    """
    Costruisce una riga di flusso compatibile con lo schema ntopng,
    popolando solo le colonne necessarie alla query di M_vol. Le altre
    vanno a default.

    Colonne popolate:
        FLOW_ID            - identificatore univoco, alto per evitare collisioni
        FIRST_SEEN         - timestamp di inizio flusso
        LAST_SEEN          - inizio + 5 secondi
        IPV4_SRC_ADDR      - host monitorato (LAN interna)
        IPV4_DST_ADDR      - DEST_IP = 8.8.8.8 (esterno)
        SRC2DST_BYTES      - byte inviati dall'host (V_out della metrica)
        IP_PROTOCOL_VERSION- 4 (IPv4)
    """
    return (
        flow_id,                          # FLOW_ID
        4,                                # IP_PROTOCOL_VERSION
        timestamp,                        # FIRST_SEEN
        timestamp + timedelta(seconds=5), # LAST_SEEN
        ip_to_uint32(host_ip),            # IPV4_SRC_ADDR
        ip_to_uint32(DEST_IP),            # IPV4_DST_ADDR
        byte_inviati,                     # SRC2DST_BYTES
    )


# Colonne corrispondenti all'ordine delle tuple sopra
COLONNE_INSERT = [
    "FLOW_ID",
    "IP_PROTOCOL_VERSION",
    "FIRST_SEEN",
    "LAST_SEEN",
    "IPV4_SRC_ADDR",
    "IPV4_DST_ADDR",
    "SRC2DST_BYTES",
]


def genera_dati_host_A(bucket_categoria: list, flow_id_start: int) -> list:
    """
    Host A - office tranquillo.
    Baseline: rumore tra 8 e 12 MB (mediana ~10 MB, MAD ~1 MB)
    Corrente: 12 MB (variazione minima dalla mediana)
    """
    righe = []
    fid = flow_id_start

    # Bucket della baseline: timestamp sparso dentro ogni bucket orario
    for bucket_start in bucket_categoria:
        offset_minuti = random.randint(1, 58)
        ts = bucket_start + timedelta(minutes=offset_minuti)
        byte = random.randint(8 * 1024 * 1024, 12 * 1024 * 1024)
        righe.append(costruisci_riga_flusso(fid, ts, HOST_A_IP, byte))
        fid += 1

    # Bucket corrente: 30 minuti fa, 12 MB.
    # NOTA: si usa datetime.now() (ora locale del processo) e NON
    # datetime.now(timezone.utc), perché ClickHouse interpreta i DateTime
    # inseriti come "ora locale del server".
    # Usare UTC creerebbe disallineamento di 2 ore in CEST.
    ts_corrente = datetime.now() - timedelta(minutes=30)
    righe.append(costruisci_riga_flusso(fid, ts_corrente, HOST_A_IP,
                                         12 * 1024 * 1024))
    return righe


def genera_dati_host_B(bucket_categoria: list, flow_id_start: int) -> list:
    """
    Host B - esfiltrazione canonica.
    Baseline: identica ad A (rumore 8-12 MB)
    Corrente: 200 MB (esfiltrazione massiva)
    """
    righe = []
    fid = flow_id_start

    for bucket_start in bucket_categoria:
        offset_minuti = random.randint(1, 58)
        ts = bucket_start + timedelta(minutes=offset_minuti)
        byte = random.randint(8 * 1024 * 1024, 12 * 1024 * 1024)
        righe.append(costruisci_riga_flusso(fid, ts, HOST_B_IP, byte))
        fid += 1

    # Bucket corrente: 200 MB (vedi nota su datetime.now() in genera_dati_host_A)
    ts_corrente = datetime.now() - timedelta(minutes=30)
    righe.append(costruisci_riga_flusso(fid, ts_corrente, HOST_B_IP,
                                         200 * 1024 * 1024))
    return righe


def genera_dati_host_C(bucket_categoria: list, flow_id_start: int) -> list:
    """
    Host C - server costante con picco (testa il limite sulla MAD).
    Baseline: esattamente 1 MB ogni bucket -> MAD reale = 0
    Corrente: 80 MB
    Atteso: greatest(MAD=0, 0.10*mediana=100KB, ASSOLUTO=1MB) = 1 MB
            Il limite assoluto prevale sui primi due.
    """
    righe = []
    fid = flow_id_start

    for bucket_start in bucket_categoria:
        offset_minuti = random.randint(1, 58)
        ts = bucket_start + timedelta(minutes=offset_minuti)
        byte = 1 * 1024 * 1024   # ESATTAMENTE 1 MB ogni bucket
        righe.append(costruisci_riga_flusso(fid, ts, HOST_C_IP, byte))
        fid += 1

    # Bucket corrente: 80 MB (vedi nota su datetime.now() in genera_dati_host_A)
    ts_corrente = datetime.now() - timedelta(minutes=30)
    righe.append(costruisci_riga_flusso(fid, ts_corrente, HOST_C_IP,
                                         80 * 1024 * 1024))
    return righe


def genera_dati_host_D(bucket_categoria: list, flow_id_start: int) -> list:
    """
    Host D - cold start.
    Baseline: solo 10 bucket (sotto MIN_BASELINE_HOURS = 30)
    Corrente: 100 MB
    Atteso: ASSENTE dai risultati (escluso dal filtro cold start)
    """
    righe = []
    fid = flow_id_start

    # Prende solo i primi 10 bucket disponibili
    bucket_ridotti = bucket_categoria[:10]
    for bucket_start in bucket_ridotti:
        offset_minuti = random.randint(1, 58)
        ts = bucket_start + timedelta(minutes=offset_minuti)
        byte = random.randint(8 * 1024 * 1024, 12 * 1024 * 1024)
        righe.append(costruisci_riga_flusso(fid, ts, HOST_D_IP, byte))
        fid += 1

    # Bucket corrente: 100 MB (vedi nota su datetime.now() in genera_dati_host_A)
    ts_corrente = datetime.now() - timedelta(minutes=30)
    righe.append(costruisci_riga_flusso(fid, ts_corrente, HOST_D_IP,
                                         100 * 1024 * 1024))
    return righe


def riga_to_sql_values(riga: tuple) -> str:
    """
    Converte una riga-tupla in stringa SQL VALUES.

    Bypassa il bug del driver clickhouse-connect che, su questa versione di
    Python/sistema (CET/CEST), non serializza correttamente i datetime
    "naive" via insert(). Costruiamo invece una INSERT INTO ... VALUES (...)
    e la mandiamo come command(), che è immune al problema.

    Ordine: (FLOW_ID, IP_PROTOCOL_VERSION, FIRST_SEEN, LAST_SEEN,
             IPV4_SRC_ADDR, IPV4_DST_ADDR, SRC2DST_BYTES)
    """
    flow_id, ip_proto, first_seen, last_seen, src, dst, byte = riga
    first_seen_str = first_seen.strftime("%Y-%m-%d %H:%M:%S")
    last_seen_str  = last_seen.strftime("%Y-%m-%d %H:%M:%S")
    return (f"({flow_id}, {ip_proto}, "
            f"'{first_seen_str}', '{last_seen_str}', "
            f"{src}, {dst}, {byte})")


def inserisci_dati_test(client):
    """
    Genera e inserisce i dati per i 4 host di test.
    Restituisce un dizionario con le statistiche generative per il report.

    Per il problema dei datetime con clickhouse_connect su sistemi CET/CEST,
    l'insert NON usa client.insert(...) ma costruisce direttamente
    una INSERT INTO ... VALUES (...) e la manda via client.command().
    Questa forma è immune al bug perchè ClickHouse parsa direttamente
    le stringhe '2026-05-21 11:30:00' come DateTime senza ambiguità di fuso.
    """
    print("[gen] Generazione dati ...")

    # Determina la categoria temporale corrente
    # Usiamo datetime.now() locale per allinearci all'interpretazione che
    # ClickHouse fa dei DateTime inseriti (ora locale del server)
    ora_corrente = datetime.now()
    categoria_corrente = categoria_temporale_python(ora_corrente)
    print(f"[gen] Ora corrente              : {ora_corrente.strftime('%Y-%m-%d %H:%M:%S')} (ora locale)")
    print(f"[gen] Categoria temporale corr. : {categoria_corrente}")

    # Calcola i bucket della baseline contestuale
    bucket_baseline = genera_bucket_categoria(categoria_corrente, ora_corrente)
    print(f"[gen] Bucket baseline disponibili: {len(bucket_baseline)} "
          f"(categoria '{categoria_corrente}', ultimi 7 giorni)")

    if len(bucket_baseline) < MIN_BASELINE_HOURS:
        print(f"\n[!!] ATTENZIONE: bucket disponibili ({len(bucket_baseline)}) "
              f"< MIN_BASELINE_HOURS ({MIN_BASELINE_HOURS})")
        print(f"     Tutti gli host (compresi A, B, C) verranno esclusi "
              f"dalla baseline.")
        print(f"     Riprova in un orario con piu' bucket della categoria,"
              f" oppure abbassa MIN_BASELINE_HOURS.\n")

    # Genera le righe per ciascun host
    righe = []
    fid = 9_999_000_000  # FLOW_ID alto per non collidere con dati reali

    righe_a = genera_dati_host_A(bucket_baseline, fid)
    fid += len(righe_a) + 100

    righe_b = genera_dati_host_B(bucket_baseline, fid)
    fid += len(righe_b) + 100

    righe_c = genera_dati_host_C(bucket_baseline, fid)
    fid += len(righe_c) + 100

    righe_d = genera_dati_host_D(bucket_baseline, fid)

    righe.extend(righe_a)
    righe.extend(righe_b)
    righe.extend(righe_c)
    righe.extend(righe_d)

    print(f"[gen] Righe da inserire         : "
          f"A={len(righe_a)}, B={len(righe_b)}, "
          f"C={len(righe_c)}, D={len(righe_d)}, totale={len(righe)}")

    # Inserimento via INSERT INTO ... VALUES per bypassare il bug del driver
    # sui datetime naive in ambiente CET/CEST.
    # Costruiamo la query in batch di 50 righe per evitare URL troppo lunghe.
    BATCH_SIZE = 50
    colonne_str = ", ".join(COLONNE_INSERT)
    for i in range(0, len(righe), BATCH_SIZE):
        batch = righe[i:i + BATCH_SIZE]
        values_str = ",\n".join(riga_to_sql_values(r) for r in batch)
        # NOVITÀ: Aggiunto SETTINGS async_insert=0 prima di VALUES
        # Questo forza l'inserimento sincrono e previene problemi di visibilità dei dati
        sql = f"INSERT INTO {TABLE_NAME} ({colonne_str}) SETTINGS async_insert=0 VALUES\n{values_str}"
        client.command(sql)

    # Verifica post-insert: conta quante righe sono effettivamente nella tabella
    n_inserite = client.query(f"SELECT count() FROM {TABLE_NAME}").result_rows[0][0]
    print(f"[gen] Righe effettivamente in DB: {n_inserite}")

    if n_inserite != len(righe):
        print(f"\n[!!] ATTENZIONE: attese {len(righe)} righe, ne risultano {n_inserite}!")
        print(f"     Possibile bug di inserimento. Verificare il driver clickhouse-connect.\n")

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
# QUERY M_vol ADATTATA PER IL TEST
# =============================================================================

QUERY_M_VOL_TEST = f"""

WITH (
    SELECT multiIf(
        toDayOfWeek(now()) IN ({GIORNI_WEEKEND[0]}, {GIORNI_WEEKEND[1]}),
            'weekend',
        toHour(now()) BETWEEN {ORE_LAVORATIVE[0]} AND {ORE_LAVORATIVE[1]},
            'feriale_lavorativo',
            'feriale_fuoriorario'
    )
) AS categoria_corrente,

baseline_grezza AS (
    SELECT
        IPv4NumToString(IPV4_SRC_ADDR) AS host_ip,
        toStartOfHour(FIRST_SEEN) AS bucket_orario,
        sum(SRC2DST_BYTES) AS v_bucket
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
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '10.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '172.16.0.0/12')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '192.168.0.0/16')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '127.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '169.254.0.0/16')
    GROUP BY host_ip, bucket_orario
),

mediane AS (
    SELECT
        host_ip,
        median(v_bucket) AS v_mediano,
        count() AS bucket_count
    FROM baseline_grezza
    GROUP BY host_ip
    HAVING bucket_count >= {MIN_BASELINE_HOURS}
),

statistiche_baseline AS (
    SELECT
        bg.host_ip,
        any(m.v_mediano)    AS v_mediano,
        any(m.bucket_count) AS bucket_count,
        median(abs(bg.v_bucket - m.v_mediano)) AS mad
    FROM baseline_grezza AS bg
    INNER JOIN mediane AS m ON bg.host_ip = m.host_ip
    GROUP BY bg.host_ip
),

volume_corrente AS (
    SELECT
        IPv4NumToString(IPV4_SRC_ADDR) AS host_ip,
        sum(SRC2DST_BYTES) AS v_out
    FROM {TABLE_NAME}
    WHERE
        FIRST_SEEN >= now() - INTERVAL {FINESTRA_CORRENTE_ORE} HOUR
        AND IPV4_SRC_ADDR != 0
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '10.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '172.16.0.0/12')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '192.168.0.0/16')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '127.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '169.254.0.0/16')
    GROUP BY host_ip
)

SELECT
    vc.host_ip                                            AS host_ip,
    vc.v_out                                              AS v_out,
    sb.v_mediano                                          AS v_mediano,
    sb.mad                                                AS mad,
    greatest(sb.mad,
             sb.v_mediano * {MAD_MIN_FRAZIONE},
             {MAD_MIN_ASSOLUTO})                          AS mad_eff,
    (vc.v_out - sb.v_mediano)
        / greatest(sb.mad,
                   sb.v_mediano * {MAD_MIN_FRAZIONE},
                   {MAD_MIN_ASSOLUTO})                    AS z_robusto,
    sb.bucket_count                                       AS bucket_count,
    categoria_corrente                                    AS categoria_temporale,
    1 AS M_vol

FROM volume_corrente AS vc
INNER JOIN statistiche_baseline AS sb ON vc.host_ip = sb.host_ip
WHERE
    vc.v_out > {V_MIN_OPERATIVO}
    AND vc.v_out > sb.v_mediano
    AND z_robusto > {SOGLIA_Z}

ORDER BY z_robusto DESC
"""


def esegui_query_m_vol(client) -> dict:
    """Esegue la query e restituisce un dizionario host_ip -> dettagli."""
    risultati = {}
    righe = client.query(QUERY_M_VOL_TEST).result_rows
    for (host_ip, v_out, v_mediano, mad, mad_eff,
         z_robusto, bucket_count, categoria_temporale, m_vol) in righe:
        risultati[host_ip] = {
            "M_vol": m_vol,
            "v_out": int(v_out),
            "v_mediano": int(v_mediano),
            "mad": float(mad),
            "mad_eff": float(mad_eff),
            "z_robusto": float(z_robusto),
            "bucket_count": bucket_count,
            "categoria_temporale": categoria_temporale,
            "penalita": PESO_M_VOL * m_vol,
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

    # ------ Host A: NON deve essere nei risultati ------
    if HOST_A_IP not in risultati:
        esiti.append({
            "host": HOST_A_IP, "profilo": "Office tranquillo",
            "esito": "PASS",
            "dettagli": "Correttamente assente (variazione dentro tolleranza)"
        })
    else:
        r = risultati[HOST_A_IP]
        esiti.append({
            "host": HOST_A_IP, "profilo": "Office tranquillo",
            "esito": "FAIL",
            "dettagli": f"Presente con Z={r['z_robusto']:.2f}, "
                        f"v_out={formatta_byte(r['v_out'])}. "
                        f"Atteso: assente."
        })

    # ------ Host B: DEVE essere nei risultati con penalita = 20 ------
    if HOST_B_IP in risultati:
        r = risultati[HOST_B_IP]
        problemi = []
        if r["M_vol"] != 1:
            problemi.append(f"M_vol={r['M_vol']} invece di 1")
        if r["penalita"] != 20:
            problemi.append(f"penalita={r['penalita']} invece di 20")
        if r["z_robusto"] <= 3:
            problemi.append(f"z_robusto={r['z_robusto']:.2f} non > 3")
        if r["v_out"] != 200 * 1024 * 1024:
            problemi.append(f"v_out={formatta_byte(r['v_out'])} invece di 200 MB")
        if problemi:
            esiti.append({
                "host": HOST_B_IP, "profilo": "Esfiltrazione",
                "esito": "FAIL",
                "dettagli": "; ".join(problemi)
            })
        else:
            esiti.append({
                "host": HOST_B_IP, "profilo": "Esfiltrazione",
                "esito": "PASS",
                "dettagli": (f"Rilevato: Z={r['z_robusto']:.2f}, "
                             f"mediana={formatta_byte(r['v_mediano'])}, "
                             f"MAD={formatta_byte(r['mad'])}, "
                             f"+{r['penalita']} punti")
            })
    else:
        esiti.append({
            "host": HOST_B_IP, "profilo": "Esfiltrazione",
            "esito": "FAIL",
            "dettagli": "Assente dai risultati. Atteso: presente con M_vol=1."
        })

    # ------ Host C: DEVE essere nei risultati con MAD_eff = 100 KB ------
    if HOST_C_IP in risultati:
        r = risultati[HOST_C_IP]
        problemi = []
        if r["M_vol"] != 1:
            problemi.append(f"M_vol={r['M_vol']} invece di 1")
        if r["penalita"] != 20:
            problemi.append(f"penalita={r['penalita']} invece di 20")
        # MAD reale = 0 attesa (tutti i bucket sono esattamente 1 MB)
        if r["mad"] != 0:
            problemi.append(f"mad={r['mad']} non zero (atteso 0)")
        # MAD_eff dopo l'introduzione del floor assoluto (Livello 3):
        # Host C ha mediana=1 MB, MAD=0.
        # greatest(MAD=0, 0.10*mediana=100KB, ASSOLUTO=1MB) = 1 MB
        # Prevale il floor ASSOLUTO, non piu' il proporzionale.
        atteso_mad_eff = MAD_MIN_ASSOLUTO    # 1 MB
        if abs(r["mad_eff"] - atteso_mad_eff) > 1:
            problemi.append(f"mad_eff={r['mad_eff']:.0f} invece di "
                            f"{atteso_mad_eff:.0f} (floor assoluto non attivato)")
        if problemi:
            esiti.append({
                "host": HOST_C_IP, "profilo": "Server costante (floor MAD)",
                "esito": "FAIL",
                "dettagli": "; ".join(problemi)
            })
        else:
            esiti.append({
                "host": HOST_C_IP, "profilo": "Server costante (floor MAD)",
                "esito": "PASS",
                "dettagli": (f"Rilevato: MAD_grezza={r['mad']:.0f} -> "
                             f"MAD_eff={formatta_byte(r['mad_eff'])} "
                             f"(floor assoluto attivo), "
                             f"Z={r['z_robusto']:.2f}, +{r['penalita']} punti")
            })
    else:
        esiti.append({
            "host": HOST_C_IP, "profilo": "Server costante (floor MAD)",
            "esito": "FAIL",
            "dettagli": "Assente dai risultati. Atteso: presente con floor assoluto attivo."
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
        print(f"    M_vol               : {r['M_vol']}")
        print(f"    v_out               : {formatta_byte(r['v_out'])}")
        print(f"    v_mediano           : {formatta_byte(r['v_mediano'])}")
        print(f"    mad (grezza)        : {formatta_byte(r['mad'])}")
        print(f"    mad_eff             : {formatta_byte(r['mad_eff'])}")
        print(f"    z_robusto           : {r['z_robusto']:.2f}")
        print(f"    bucket_count        : {r['bucket_count']}")
        print(f"    categoria_temporale : {r['categoria_temporale']}")
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
    print("  TEST DI LIVELLO 2 - VALIDAZIONE TRAMITE PROFILI DI TEST DELLA METRICA M_vol")
    print("=" * 75)
    print(f"  Tabella di test     : {TABLE_NAME}")
    print(f"  MIN_BASELINE_HOURS  : {MIN_BASELINE_HOURS} (override per il test)")
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
        print("[run] Esecuzione della query M_vol...\n")
        risultati = esegui_query_m_vol(client)

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
                  "La query M_vol funziona correttamente.")
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
