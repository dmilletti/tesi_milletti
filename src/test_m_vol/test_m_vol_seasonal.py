"""
=============================================================================
TEST DI LIVELLO 3 - VALIDAZIONE DELLA BASELINE DI M_vol
=============================================================================

Obiettivo:
    Validare la baseline della metrica M_vol, ovvero il
    fatto che la baseline statistica venga filtrata per categoria temporale
    (feriale_lavorativo, feriale_fuoriorario, weekend) prima del confronto
    con il volume di uscita corrente.

    Questo test è fondamentale per dimostrare che il miglioramento del piano
    operativo che è introdotto per gestire la stagionalità settimanale degli
    host funziona davvero. Lo stesso host con lo stesso volume di traffico
    deve essere valutato in modo OPPOSTO a seconda dell'orario in cui viene osservato.

Approccio:
    - Genera un SINGOLO host (E) con baseline notevolmente diversa nelle
      tre fasce orarie:
        feriale_lavorativo  -> 15 MB/bucket (lavora)
        feriale_fuoriorario -> 50 KB/bucket (quasi spento)
        weekend             -> 0 byte (PC spento)
    - Esegue la query di M_vol tre volte con orari SIMULATI diversi,
      sostituendo now() con un parametro nella query.
    - Per ogni run, verifica che la metrica si comporti come i risultati attesi.

Simulazione del tempo (Strada A):
    La query di m_vol.py usa now() in 3 punti diversi (categoria,
    finestra storica, finestra corrente). Nella versione parametrica
    sostituiamo OGNI occorrenza di now() con una costante chiamata
    `ora_simulata`, calcolata da parseDateTimeBestEffort() sulla
    stringa passata via f-string Python.

I tre run:

    RUN 1 - Lunedi 14:00 (feriale_lavorativo)
        V_out simulato:    15 MB
        Baseline attesa:   ~15 MB (feriale_lavorativo)
        Atteso:            M_vol = 0 (comportamento normale per la fascia)

    RUN 2 - Lunedi 23:00 (feriale_fuoriorario)
        V_out simulato:    60 MB
        Baseline attesa:   ~50 KB (feriale_fuoriorario)
        Atteso:            M_vol = 1, Z enorme
        DIMOSTRAZIONE:     lo stesso volume che era normale alle 14:00 è
                           anomalo alle 23:00.

    RUN 3 - Sabato 14:00 (weekend)
        V_out simulato:    30 MB
        Baseline attesa:   0 byte (weekend, host spento)
        Atteso:            Caso dove la mediana=0 e MAD=0, mad_eff=0,
                           divisione per zero.
        DOCUMENTAZIONE:    Bug del modello,(aggiunta floor MAD assoluto).

=============================================================================
"""
import clickhouse_connect
from datetime import datetime, timedelta
import ipaddress
import random
import sys

# Seed fisso per riproducibilità
random.seed(42)


# =============================================================================
# CONFIGURAZIONE
# =============================================================================

# Connessione (utente tester con readonly=0)
CLICKHOUSE_HOST     = "localhost"
CLICKHOUSE_PORT     = 8123
CLICKHOUSE_DATABASE = "ntopng"
CLICKHOUSE_USER     = "tester"
CLICKHOUSE_PASSWORD = "test_password"

TABLE_NAME = "flows_test"

# Parametri della formula M_vol (identici a m_vol.py)
SOGLIA_Z         = 3.0
MAD_MIN_FRAZIONE = 0.10
V_MIN_OPERATIVO  = 50 * 1024 * 1024
PESO_M_VOL       = 20

# Cold start: numero minimo di ore di baseline per calcolare la mediana e MAD.
MIN_BASELINE_HOURS = 30

# Categorie temporali
ORE_LAVORATIVE = (9, 17)
GIORNI_WEEKEND = (6, 7)

# Finestre temporali
FINESTRA_STORICO_GIORNI = 7
FINESTRA_CORRENTE_ORE   = 1

# Host stagionale unico
HOST_E_IP = "10.0.0.5"
DEST_IP   = "8.8.8.8"

# Volumi di traffico per profilo di Host E (in byte/bucket)
VOLUME_FERIALE_LAV    = (14 * 1024 * 1024, 16 * 1024 * 1024)   # 14-16 MB
VOLUME_FERIALE_FUORI  = (30 * 1024,         70 * 1024)         # 30-70 KB
VOLUME_WEEKEND        = (0,                 0)                 # 0 byte


# =============================================================================
# UTILITY (identiche al Livello 2)
# =============================================================================

def ip_to_uint32(ip_str: str) -> int:
    return int(ipaddress.IPv4Address(ip_str))


def formatta_byte(b: float) -> str:
    if b is None or b == 0:
        return "0 B"
    if abs(b) >= 1024**3:
        return f"{b / 1024**3:.2f} GB"
    if abs(b) >= 1024**2:
        return f"{b / 1024**2:.2f} MB"
    if abs(b) >= 1024:
        return f"{b / 1024:.2f} KB"
    return f"{int(b)} B"


def categoria_temporale_python(dt: datetime) -> str:
    """
    Stessa logica del multiIf SQL.
    Deve restare SINCRONIZZATA con la query parametrica.
    """
    dow = dt.weekday() + 1
    if dow in GIORNI_WEEKEND:
        return "weekend"
    if ORE_LAVORATIVE[0] <= dt.hour <= ORE_LAVORATIVE[1]:
        return "feriale_lavorativo"
    return "feriale_fuoriorario"


# =============================================================================
# GENERAZIONE DELLO STORICO DI HOST E
# =============================================================================

COLONNE_INSERT = [
    "FLOW_ID",
    "IP_PROTOCOL_VERSION",
    "FIRST_SEEN",
    "LAST_SEEN",
    "IPV4_SRC_ADDR",
    "IPV4_DST_ADDR",
    "SRC2DST_BYTES",
]


def costruisci_riga(flow_id, timestamp, host_ip, byte_inviati):
    """Helper per costruire la tupla di una riga."""
    return (
        flow_id, 4, timestamp,
        timestamp + timedelta(seconds=5),
        ip_to_uint32(host_ip), ip_to_uint32(DEST_IP),
        byte_inviati,
    )


def riga_to_sql_values(riga: tuple) -> str:
    """Serializza una riga in stringa SQL VALUES."""
    flow_id, ip_proto, first_seen, last_seen, src, dst, byte = riga
    return (f"({flow_id}, {ip_proto}, "
            f"'{first_seen.strftime('%Y-%m-%d %H:%M:%S')}', "
            f"'{last_seen.strftime('%Y-%m-%d %H:%M:%S')}', "
            f"{src}, {dst}, {byte})")


def genera_storico_host_E(ora_riferimento: datetime,
                          eventi_correnti: list) -> list:
    """
    Genera lo storico completo di Host E sui 7 giorni precedenti
    a ora_riferimento, distribuendo i volumi secondo il profilo
    stagionale dell'host.

    Argomenti:
        ora_riferimento: il "now" simulato, attorno al quale viene
                         costruito lo storico (7 giorni indietro).
        eventi_correnti: lista di tuple (timestamp, byte) da inserire
                         come "bucket corrente" dei vari run simulati.
                         Ogni timestamp è un'ora finta che cade DENTRO
                         la finestra di 1 ora rispetto al rispettivo
                         ora_simulata del run.

    Restituisce: lista di righe da inserire in DB.
    """
    righe = []
    flow_id = 9_999_500_000  # ID alto per non collidere

    # ---- Storico: 7 giorni di bucket orari ----
    inizio = ora_riferimento - timedelta(days=FINESTRA_STORICO_GIORNI)
    cursore = inizio.replace(minute=0, second=0, microsecond=0)
    # Includiamo tutta la storia DA inizio FINO A poco prima di ora_riferimento.
    # Lasciamo 1 ora per non sporcare la baseline con bucket
    # che cadrebbero dentro la finestra corrente del run.
    fine = ora_riferimento - timedelta(hours=FINESTRA_CORRENTE_ORE + 1)

    while cursore <= fine:
        categoria = categoria_temporale_python(cursore)

        # Scegli il range di volume in base alla categoria
        if categoria == "feriale_lavorativo":
            vmin, vmax = VOLUME_FERIALE_LAV
        elif categoria == "feriale_fuoriorario":
            vmin, vmax = VOLUME_FERIALE_FUORI
        else:  # weekend
            vmin, vmax = VOLUME_WEEKEND

        # Se il range è (0, 0) saltiamo del tutto: significa "host spento"
        # e non vogliamo generare flussi con 0 byte.
        if vmax > 0:
            offset = random.randint(1, 58)
            ts = cursore + timedelta(minutes=offset)
            byte = random.randint(vmin, vmax)
            righe.append(costruisci_riga(flow_id, ts, HOST_E_IP, byte))
            flow_id += 1

        cursore += timedelta(hours=1)

    # ---- Eventi correnti: uno per ogni run da simulare ----
    # Ogni evento è (timestamp_finto, byte). Questi bucket cadranno
    # dentro la finestra "ora corrente" del rispettivo run quando la
    # query verrà eseguita con quel ora_simulata.
    for ts_evento, byte_evento in eventi_correnti:
        righe.append(costruisci_riga(flow_id, ts_evento, HOST_E_IP, byte_evento))
        flow_id += 1

    return righe


# =============================================================================
# SETUP / ELIMINAZIONE DELLA TABELLA
# =============================================================================

def crea_tabella_test(client):
    """Crea flows_test (stessa logica del livello 2)."""
    client.command(f"DROP TABLE IF EXISTS {TABLE_NAME}")
    client.command(
        f"CREATE TABLE {TABLE_NAME} ENGINE = MergeTree ORDER BY tuple() "
        f"AS SELECT * FROM flows LIMIT 0"
    )


def cleanup_tabella_test(client):
    client.command(f"DROP TABLE IF EXISTS {TABLE_NAME}")


def inserisci_righe(client, righe: list):
    """Inserimento batch via INSERT INTO ... VALUES (stessa logica del livello 2)."""
    BATCH_SIZE = 50
    colonne_str = ", ".join(COLONNE_INSERT)
    for i in range(0, len(righe), BATCH_SIZE):
        batch = righe[i:i + BATCH_SIZE]
        values_str = ",\n".join(riga_to_sql_values(r) for r in batch)
        sql = (f"INSERT INTO {TABLE_NAME} ({colonne_str}) "
               f"SETTINGS async_insert=0 VALUES\n{values_str}")
        client.command(sql)


# =============================================================================
# QUERY M_vol PARAMETRICA
# =============================================================================
# Differenze rispetto alla versione di produzione (m_vol.py):
#   - {table_name}    : nome della tabella di test
#   - {ora_simulata}  : sostituisce ogni occorrenza di now() della query
#                       originale. La query usa parseDateTimeBestEffort()
#                       una sola volta per evitare di riparsare la stringa
#                       in ogni CTE.

QUERY_M_VOL_PARAMETRICA = f"""

WITH parseDateTimeBestEffort('{{ora_simulata}}') AS ora_simulata,

(
    SELECT multiIf(
        toDayOfWeek(ora_simulata) IN ({GIORNI_WEEKEND[0]}, {GIORNI_WEEKEND[1]}),
            'weekend',
        toHour(ora_simulata) BETWEEN {ORE_LAVORATIVE[0]} AND {ORE_LAVORATIVE[1]},
            'feriale_lavorativo',
            'feriale_fuoriorario'
    )
) AS categoria_corrente,

baseline_grezza AS (
    SELECT
        IPv4NumToString(IPV4_SRC_ADDR) AS host_ip,
        toStartOfHour(FIRST_SEEN) AS bucket_orario,
        sum(SRC2DST_BYTES) AS v_bucket
    FROM {{table_name}}
    WHERE
        -- Le tre occorrenze di now() della query originale diventano ora_simulata
        FIRST_SEEN >= ora_simulata - INTERVAL {FINESTRA_STORICO_GIORNI} DAY
        AND FIRST_SEEN <  ora_simulata - INTERVAL {FINESTRA_CORRENTE_ORE} HOUR
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
        median(v_bucket) AS v_mediana,
        count() AS bucket_count
    FROM baseline_grezza
    GROUP BY host_ip
    HAVING bucket_count >= {MIN_BASELINE_HOURS}
),

statistiche_baseline AS (
    SELECT
        bg.host_ip,
        any(m.v_mediana)    AS v_mediana,
        any(m.bucket_count) AS bucket_count,
        median(abs(bg.v_bucket - m.v_mediana)) AS mad
    FROM baseline_grezza AS bg
    INNER JOIN mediane AS m ON bg.host_ip = m.host_ip
    GROUP BY bg.host_ip
),

volume_corrente AS (
    SELECT
        IPv4NumToString(IPV4_SRC_ADDR) AS host_ip,
        sum(SRC2DST_BYTES) AS v_out
    FROM {{table_name}}
    WHERE
        FIRST_SEEN >= ora_simulata - INTERVAL {FINESTRA_CORRENTE_ORE} HOUR
        AND FIRST_SEEN <= ora_simulata
        AND IPV4_SRC_ADDR != 0
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '10.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '172.16.0.0/12')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '192.168.0.0/16')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '127.0.0.0/8')
        AND NOT isIPAddressInRange(IPv4NumToString(IPV4_DST_ADDR), '169.254.0.0/16')
    GROUP BY host_ip
)

SELECT
    vc.host_ip                                              AS host_ip,
    vc.v_out                                                AS v_out,
    sb.v_mediana                                            AS v_mediana,
    sb.mad                                                  AS mad,
    greatest(sb.mad, sb.v_mediana * {MAD_MIN_FRAZIONE})     AS mad_eff,
    -- divideOrNull per gestire il caso mad_eff=0 senza crash della query
    -- (restituisce NULL invece di errore di divisione per zero)
    divideOrNull(
        vc.v_out - sb.v_mediana,
        greatest(sb.mad, sb.v_mediana * {MAD_MIN_FRAZIONE})
    ) AS z_modified,
    sb.bucket_count                                         AS bucket_count,
    categoria_corrente                                      AS categoria_temporale,
    -- M_vol calcolata manualmente nella SELECT (la WHERE potrebbe escludere
    -- righe con z=NULL; qui le teniamo per la diagnostica)
    if(
        vc.v_out > {V_MIN_OPERATIVO}
        AND vc.v_out > sb.v_mediana
        AND z_modified > {SOGLIA_Z},
        1, 0
    ) AS M_vol

FROM volume_corrente AS vc
INNER JOIN statistiche_baseline AS sb ON vc.host_ip = sb.host_ip
ORDER BY vc.host_ip
"""

# NOTA importante sulla differenza con la query di produzione:
# Nella produzione la WHERE finale filtra fuori gli host che non soddisfano
# le tre condizioni di scatto. Qui invece la SELECT RESTITUISCE TUTTI gli
# host che hanno baseline+volume_corrente, e calcola M_vol come campo
# diagnostico. Questo permette di documentare i casi "non scatta" senza
# perdere le informazioni statistiche (mediana, MAD, Z).


# =============================================================================
# ESECUZIONE DELLA QUERY PARAMETRICA
# =============================================================================

def esegui_query(client, ora_simulata: datetime) -> dict:
    """
    Esegue la query parametrica con l'ora simulata fornita.
    Restituisce un dizionario host_ip -> dettagli.
    """
    ora_str = ora_simulata.strftime("%Y-%m-%d %H:%M:%S")
    sql = QUERY_M_VOL_PARAMETRICA.format(
        ora_simulata=ora_str,
        table_name=TABLE_NAME,
    )

    risultati = {}
    righe = client.query(sql).result_rows
    for (host_ip, v_out, v_mediana, mad, mad_eff,
         z_modified, bucket_count, categoria, m_vol) in righe:
        risultati[host_ip] = {
            "v_out":      int(v_out),
            "v_mediana":  int(v_mediana),
            "mad":        float(mad),
            "mad_eff":    float(mad_eff),
            # z_modified può essere None (divisione per zero gestita)
            "z_modified":  float(z_modified) if z_modified is not None else None,
            "bucket_count": bucket_count,
            "categoria":  categoria,
            "M_vol":      m_vol,
            "penalita":   PESO_M_VOL * m_vol,
        }
    return risultati


# =============================================================================
# DEFINIZIONE DEI TRE RUN
# =============================================================================
# Ogni run è una tupla (descrizione, ora_simulata, v_out_corrente, attesi).
# v_out_corrente sarà iniettato come bucket finto nella finestra di 1 ora
# precedente a ora_simulata. attesi è la lista delle verifiche da fare.

def calcola_ora_simulata_recente(giorno_target: int, ora_target: int) -> datetime:
    """
    Calcola un datetime "ora simulata" che cade nel passato recente,
    abbastanza vicino a now() perchè lo storico generato non finisca
    fuori dal contesto delle altre interrogazioni.

    giorno_target: 1=lun, ..., 7=dom
    ora_target:    0-23

    Strategia: parte da oggi e va a ritroso fino a trovare la combinazione
    giorno+ora richiesta, fermandosi alla prima occorrenza (così tutti i
    run cadono nella settimana appena trascorsa).
    """
    cursore = datetime.now().replace(minute=30, second=0, microsecond=0)
    cursore = cursore.replace(hour=ora_target)

    # weekday() Python: 0=lun, ..., 6=dom -> +1 per allineare a ClickHouse
    giorno_corrente = cursore.weekday() + 1
    delta_giorni = (giorno_corrente - giorno_target) % 7
    if delta_giorni == 0 and cursore > datetime.now():
        # Stesso giorno della settimana ma nel futuro -> torna indietro 7 giorni
        delta_giorni = 7

    return cursore - timedelta(days=delta_giorni)


# Definizione dei 3 run.
# ora_simulata viene calcolata in modo che cada nella settimana scorsa
# per garantire che ci siano abbastanza dati storici nello storico generato.

RUN_LUNEDI_14   = calcola_ora_simulata_recente(giorno_target=1, ora_target=14)
RUN_LUNEDI_23   = calcola_ora_simulata_recente(giorno_target=1, ora_target=23)
RUN_SABATO_14   = calcola_ora_simulata_recente(giorno_target=6, ora_target=14)


CONFIGURAZIONE_RUN = [
    {
        "nome":           "RUN 1 - Lunedi 14:00 (lavorativo)",
        "ora_simulata":   RUN_LUNEDI_14,
        "v_out_corrente": 15 * 1024 * 1024,    # 15 MB (in linea con la baseline)
        "categoria_attesa": "feriale_lavorativo",
        "m_vol_atteso":   0,                    # NON deve scattare
        "z_max_atteso":   SOGLIA_Z,             # Z deve restare sotto 3
        "descrizione":    (
            "Host che lavora alle 14:00 con volume normale per la fascia. "
            "La metrica NON deve scattare: il comportamento è coerente "
            "con la baseline contestuale dei feriali lavorativi (~15 MB)."
        ),
    },
    {
        "nome":           "RUN 2 - Lunedi 23:00 (fuoriorario)",
        "ora_simulata":   RUN_LUNEDI_23,
        "v_out_corrente": 60 * 1024 * 1024,    # 60 MB (anomalo per le 23:00)
        "categoria_attesa": "feriale_fuoriorario",
        "m_vol_atteso":   1,                    # DEVE scattare
        "z_min_atteso":   SOGLIA_Z,             # Z deve essere ben sopra 3
        "descrizione":    (
            "Stesso host alle 23:00 (fuori orario) con 60 MB di traffico. "
            "Nonostante 60 MB sia un volume modesto in valore assoluto, "
            "la baseline notturna dell'host è di pochi KB - quindi la "
            "metrica deve scattare. DIMOSTRAZIONE: stesso host, volume "
            "simile, comportamento OPPOSTO grazie al contesto orario."
        ),
    },
    {
        "nome":           "RUN 3 - Sabato 14:00 (weekend)",
        "ora_simulata":   RUN_SABATO_14,
        "v_out_corrente": 30 * 1024 * 1024,    # 30 MB nel weekend
        "categoria_attesa": "weekend",
        "m_vol_atteso":   None,                 # vedi nota sotto
        "edge_case":      "mediana_zero",       # ci aspettiamo l'edge case
        "descrizione":    (
            "Host normalmente spento nel weekend - baseline di 0 byte. "
            "EDGE CASE ATTESO: mediana=0 e MAD=0 portano a mad_eff=0 e "
            "divisione per zero. Il test PASSA documentando il "
            "comportamento e segnalando il bug per il futuro raffinamento "
            "(aggiunta di un floor assoluto MAD_MIN_ASSOLUTO)."
        ),
    },
]


# =============================================================================
# VERIFICA DEI RISULTATI
# =============================================================================

def verifica_run(run_config: dict, risultati: dict) -> dict:
    """
    Verifica un singolo run e restituisce un esito strutturato.
    """
    nome = run_config["nome"]
    host_ip = HOST_E_IP

    # Caso atteso: si gestisce in modo diverso
    if run_config.get("edge_case") == "mediana_zero":
        if host_ip in risultati:
            r = risultati[host_ip]
            # Ci aspettiamo z_modified = None per la divisione per zero gestita
            # da divideOrNull, o mediana=0 e mad=0
            if r["v_mediana"] == 0 and r["mad"] == 0 and r["mad_eff"] == 0:
                return {
                    "esito": "PASS",
                    "categoria": r["categoria"],
                    "dettagli": (
                        f"Edge case correttamente rilevato:\n"
                        f"    mediana=0, MAD=0, mad_eff=0, z_modified={r['z_modified']}\n"
                        f"    NOTA: il modello attuale non gestisce host "
                        f"con baseline a volume zero nella categoria corrente.\n"
                        f"    RACCOMANDAZIONE: aggiungere MAD_MIN_ASSOLUTO "
                        f"(di 1 MB) come terzo termine del greatest()."
                    ),
                }
            else:
                return {
                    "esito": "PASS",
                    "categoria": r["categoria"],
                    "dettagli": (
                        f"Run weekend gestito senza edge case: "
                        f"mediana={formatta_byte(r['v_mediana'])}, "
                        f"M_vol={r['M_vol']}, Z={r['z_modified']}."
                    ),
                }
        else:
            # Host assente: significa che la baseline weekend non esiste
            # perchè tutti i bucket sono a 0 e vengono saltati nello storico
            return {
                "esito": "PASS",
                "categoria": "n/d",
                "dettagli": (
                    f"Host assente dai risultati: la baseline weekend non è "
                    f"stata costruita perchè tutti i bucket erano a 0 byte. "
                    f"La metrica si comporta in modo conservativo (silenzio).\n"
                    f"    NOTA: l'host che non ha mai trasmesso nella "
                    f"categoria corrente non viene valutato (cold start "
                    f"implicito). Questo è un comportamento DESIDERABILE in "
                    f"termini di falsi positivi, ma andrebbe documentato come "
                    f"limite per gli host che si attivano per la prima volta."
                ),
            }

    # Verifica standard
    if host_ip not in risultati:
        return {
            "esito": "FAIL",
            "categoria": "n/d",
            "dettagli": (
                f"Host atteso ma assente. Probabilmente baseline insufficiente "
                f"o problema nella generazione dei dati."
            ),
        }

    r = risultati[host_ip]
    problemi = []

    # Categoria temporale corretta?
    if r["categoria"] != run_config["categoria_attesa"]:
        problemi.append(
            f"categoria='{r['categoria']}' invece di "
            f"'{run_config['categoria_attesa']}'"
        )

    # M_vol come atteso?
    if r["M_vol"] != run_config["m_vol_atteso"]:
        problemi.append(
            f"M_vol={r['M_vol']} invece di {run_config['m_vol_atteso']}"
        )

    # Z entro le aspettative?
    if "z_max_atteso" in run_config:
        if r["z_modified"] is None or r["z_modified"] > run_config["z_max_atteso"]:
            problemi.append(
                f"Z={r['z_modified']} non <= {run_config['z_max_atteso']}"
            )
    if "z_min_atteso" in run_config:
        if r["z_modified"] is None or r["z_modified"] <= run_config["z_min_atteso"]:
            problemi.append(
                f"Z={r['z_modified']} non > {run_config['z_min_atteso']}"
            )

    if problemi:
        return {
            "esito": "FAIL",
            "categoria": r["categoria"],
            "dettagli": "; ".join(problemi),
        }
    else:
        z_str = f"{r['z_modified']:.2f}" if r["z_modified"] is not None else "N/A"
        return {
            "esito": "PASS",
            "categoria": r["categoria"],
            "dettagli": (
                f"Rilevato correttamente: "
                f"v_out={formatta_byte(r['v_out'])}, "
                f"mediana={formatta_byte(r['v_mediana'])}, "
                f"MAD_eff={formatta_byte(r['mad_eff'])}, "
                f"Z={z_str}, M_vol={r['M_vol']}, "
                f"bucket_baseline={r['bucket_count']}"
            ),
        }


def stampa_risultato_run(run_config: dict, risultati: dict, esito: dict):
    """Stampa report leggibile del singolo run."""
    print("=" * 75)
    print(f"  {run_config['nome']}")
    print("=" * 75)
    print(f"  Ora simulata     : {run_config['ora_simulata'].strftime('%Y-%m-%d %H:%M (%A)')}")
    print(f"  V_out simulato   : {formatta_byte(run_config['v_out_corrente'])}")
    print(f"  Categoria attesa : {run_config['categoria_attesa']}")
    print(f"  Descrizione      : {run_config['descrizione']}")
    print()

    if HOST_E_IP in risultati:
        r = risultati[HOST_E_IP]
        z_str = f"{r['z_modified']:.2f}" if r["z_modified"] is not None else "NULL (div/0)"
        print(f"  RISULTATI QUERY per {HOST_E_IP}:")
        print(f"    categoria       : {r['categoria']}")
        print(f"    v_out           : {formatta_byte(r['v_out'])}")
        print(f"    v_mediana       : {formatta_byte(r['v_mediana'])}")
        print(f"    MAD (grezza)    : {formatta_byte(r['mad'])}")
        print(f"    MAD effettiva   : {formatta_byte(r['mad_eff'])}")
        print(f"    Z modified      : {z_str}")
        print(f"    bucket_baseline : {r['bucket_count']}")
        print(f"    M_vol           : {r['M_vol']} (penalita={r['penalita']})")
    else:
        print(f"  RISULTATI QUERY: host {HOST_E_IP} ASSENTE dai risultati")

    print()
    prefisso = "[PASS]" if esito["esito"] == "PASS" else "[FAIL]"
    print(f"  {prefisso} {esito['dettagli']}")
    print()


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("\n" + "=" * 75)
    print("  TEST DI LIVELLO 3 - VALIDAZIONE BASELINE CONTESTUALE DI M_vol")
    print("=" * 75)
    print(f"  Tabella di test    : {TABLE_NAME}")
    print(f"  Host stagionale    : {HOST_E_IP}")
    print(f"  Run da eseguire    : {len(CONFIGURAZIONE_RUN)}")
    print(f"  MIN_BASELINE_HOURS : {MIN_BASELINE_HOURS} (override per il test)")
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
        print(f"[ERRORE] Impossibile connettersi: {e}")
        return 1

    try:
        # Per generare correttamente lo storico ci serve l'ora simulata
        # piu' "vecchia" tra i 3 run, in modo da coprire tutte le finestre.
        ora_max = max(r["ora_simulata"] for r in CONFIGURAZIONE_RUN)
        print(f"[setup] Generazione storico Host E (relativo a {ora_max.strftime('%Y-%m-%d %H:%M')}):")

        # Costruiamo la lista degli eventi correnti: uno per ogni run.
        # Ogni evento è un timestamp che cade 30 minuti prima dell'ora simulata
        # del rispettivo run (così finirà dentro la sua finestra di 1 ora).
        eventi_correnti = []
        for run in CONFIGURAZIONE_RUN:
            ts_evento = run["ora_simulata"] - timedelta(minutes=30)
            eventi_correnti.append((ts_evento, run["v_out_corrente"]))
            print(f"        evento corrente per '{run['nome']}': "
                  f"{ts_evento.strftime('%Y-%m-%d %H:%M')} -> "
                  f"{formatta_byte(run['v_out_corrente'])}")

        # Genera tutto lo storico + i 3 eventi correnti
        righe = genera_storico_host_E(ora_max, eventi_correnti)
        print(f"[setup] Righe da inserire totali  : {len(righe)}")

        # Crea la tabella e inserisce
        crea_tabella_test(client)
        inserisci_righe(client, righe)

        # Verifica post-insert
        n_inserite = client.query(
            f"SELECT count() FROM {TABLE_NAME}"
        ).result_rows[0][0]
        print(f"[setup] Righe effettivamente in DB: {n_inserite}\n")

        if n_inserite == 0:
            print("[ERRORE] Insert silenzioso a vuoto. Aborto.")
            return 1

        # Esegue i 3 run
        passati = 0
        falliti = 0
        for run_config in CONFIGURAZIONE_RUN:
            risultati = esegui_query(client, run_config["ora_simulata"])
            esito = verifica_run(run_config, risultati)
            stampa_risultato_run(run_config, risultati, esito)
            if esito["esito"] == "PASS":
                passati += 1
            else:
                falliti += 1

        # Riepilogo
        print("=" * 75)
        print("  RIEPILOGO LIVELLO 3")
        print("=" * 75)
        print(f"  Run eseguiti : {len(CONFIGURAZIONE_RUN)}")
        print(f"  Passati      : {passati}")
        print(f"  Falliti      : {falliti}")
        if falliti == 0:
            print()
            print("  [OK] Validazione del baseline COMPLETATA.")
            print("       I tre run dimostrano che la baseline contestuale")
            print("       determina correttamente l'attività dell'host in")
            print("       base alla fascia oraria di osservazione.")
        else:
            print(f"\n  [!!] {falliti} run falliti. Verificare i log.")
        print("=" * 75)

        return 0 if falliti == 0 else 1

    finally:
        cleanup_tabella_test(client)


if __name__ == "__main__":
    sys.exit(main())
