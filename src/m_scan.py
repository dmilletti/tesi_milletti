"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
Metrica M_scan - Network Scan Detection
=============================================================================

Obiettivo:
    Rilevare host della LAN che effettuano scansioni della rete (network
    discovery, port scanning, scansioni evasive).
    È il segnale più caratteristico delle fasi iniziali di un attacco:
    reconnaissance, movimento laterale, ricerca di vulnerabilità.

Unificazione M_scan + M_syn:
    Il piano operativo prevedeva due metriche distinte:
    M_scan (network discovery, peso +30) e M_syn (SYN scan, peso +30).
    L'analisi di ntopng ha rivelato che la fonte dati le rileva entrambe
    nello stesso allarme (host_alert_scan_realtime, alert_id=15), il quale
    include codici di sottotipo che distinguono SYN scan, FIN scan, RST scan
    e incomplete flows nell'array `alerts` del JSON.
    Si è scelto quindi di unificare le due metriche in M_scan con
    differenziazione interna dei pesi sui codici, per evitare:
      - doppia penalizzazione sullo stesso evento
      - query separate sulla stessa tabella con stessi filtri

Logica con DIFFERENZIAZIONE per tipo di scan rilevato:
    Estendiamo la metrica con una matrice di pesi basata sul codice di sottotipo
    rilevato da ntopng nell'array `alerts`:

      EVASIONE FIREWALL -> +50 punti
        L'array contiene codice 3 (FIN scan) o 4 (RST scan).
        Tecniche avanzate usate per bypassare firewall stateful.
        I pacchetti FIN/RST non aprono nuove connessioni e quindi sfuggono
        ai controlli che ispezionano solo i SYN. Tipiche di attaccanti
        esperti o tool di pentesting professionali (nmap -sF, -sX).

      SYN SCAN CLASSICO -> +40 punti
        L'array contiene codice 2 (SYN scan).
        Tecnica più comune (nmap -sS): invio di SYN senza completare
        l'handshake. È il più frequente nelle reconnaissance.

      INCOMPLETE FLOWS -> +30 punti
        L'array contiene solo codice 0 (incomplete flows).
        Sono le connessioni avviate ma non completate. Può anche
        derivare da scan blando o da problemi di rete legittimi.

      VITTIMA -> 0 punti (esclusa)
        L'array contiene codice 1 (rx_only_scan).
        Conferma esplicita nel codice sorgente di ntopng:
        [1] = { descr = "rx_only_scan", is_victim = true }
        L'host non è attaccante ma è bersaglio di uno scan altrui.
        Non penalizziamo le vittime.

Frequenza di esecuzione:
    Event-driven (metrica deterministica): lo script va eseguito ogni ora
    tramite cron o systemd timer.

Fonte dei dati:
    Tabella `host_alerts` di ntopng su ClickHouse.
    - Filtro: alert_id = 15 (host_alert_scan_realtime)
    - Tipo di scan: estratto dall'array JSON `alerts` come array di interi

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
CLICKHOUSE_PORT     = 8123         # porta HTTP di ClickHouse
CLICKHOUSE_DATABASE = "ntopng"
CLICKHOUSE_USER     = "default"
CLICKHOUSE_PASSWORD = "0022"

# Alert ID del check "Scan (Realtime)" in ntopng
# (verificato in /usr/share/ntopng/scripts/lua/modules/alert_keys/host_alert_keys.lua)
ALERT_ID_SCAN_REALTIME = 15

# Pesi differenziati per categoria di scan rilevato
PESO_EVASIONE_FIREWALL = 50   # FIN/RST scan (codici [3] o [4])
PESO_SYN_SCAN          = 40   # SYN scan classico (codice [2])
PESO_INCOMPLETE_FLOWS  = 30   # Flows incomplete (solo codice [0])

# Finestra temporale di analisi (default): guardiamo i flussi degli ultimi 60 minuti.
# Può essere sovrascritta dall'argomento `--finestra-minuti` da CLI oppure
# passando un valore esplicito alla funzione `calcola_m_scan()`.
# Nel sistema finale, lo scoring.py chiama la funzione senza argomenti e usa
# questo default; il parametro serve a contenere il costo della query
# quando si testa su tabelle molto grandi (miliardi di record).
FINESTRA_MINUTI_DEFAULT = 60


# =============================================================================
# QUERY SQL
# =============================================================================

# La query SQL viene costruita dentro `calcola_m_scan()` perché dipende
# dal parametro `finestra_minuti`, che può essere passato dinamicamente
# (default = FINESTRA_MINUTI_DEFAULT).
#
# La query implementa la formula del piano operativo:
#   A_scan = True -> M_scan = 1
# estesa con differenziazione dei pesi sui codici di sottotipo del JSON.
#
# Logica:
# 1) Filtro su alert_id = 15 (host_alert_scan_realtime)
# 2) Estrazione dell'array `alerts` dal JSON come Array(Int32)
# 3) Esclusione delle vittime: chi ha il codice 1 nell'array è escluso
# 4) multiIf() che classifica il caso e assegna il peso in base ai codici
# 5) Aggregazione per host: max(peso) per gestire host con scan ripetuti
#
# Strutturazione in due fasi tramite CTE (Common Table Expression):
# - FASE 1 (CTE "dati_filtrati_e_classificati"): applica i filtri WHERE,
#   estrae l'array `alerts` una sola volta per riga e calcola peso e
#   categoria pre-classificati
# - FASE 2 (SELECT esterno): aggrega per host i valori pre-calcolati,
#   senza più necessità di parsing JSON o di rivalutare multiIf


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


def traduci_codici(codici: list) -> list:
    """
    Traduce i codici numerici dei sottotipi scan in stringhe leggibili.
    Mapping derivato dal file Lua host_alert_scan_realtime.lua:
       0 = Incomplete Flows Scan
       1 = RX-only Scan (vittima)
       2 = SYN Scan
       3 = FIN Scan
       4 = RST Scan
    """
    mapping = {
        0: "Incomplete Flows",
        1: "RX-only (vittima)",
        2: "SYN Scan",
        3: "FIN Scan",
        4: "RST Scan",
    }
    return [mapping.get(c, f"Codice sconosciuto ({c})") for c in codici]


def calcola_m_scan(client, finestra_minuti: int = FINESTRA_MINUTI_DEFAULT):
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

    Il formato di ritorno è SIMMETRICO alle altre metriche:
    chiave = IP dell'host, valore = dizionario con
    i dettagli.

    Struttura del dizionario restituito:
    {
        "192.168.1.45": {
            "M_scan":              1,
            "hits_totali":         3,
            "codici_rilevati":     [2, 3],
            "codici_descritti":    ["SYN Scan", "FIN Scan"],
            "categoria_dominante": "EVASIONE FIREWALL (FIN/RST scan)",
            "penalita":            50,
            "timestamp":           "2026-05-18T16:30:00+00:00"
        },
        ...
    }
    """
    # Costruzione della query con il parametro `finestra_minuti`.
    # Il valore è un intero controllato (validato a monte da argparse
    # o passato esplicitamente come argomento di funzione), quindi è
    # sicuro inserirlo via f-string senza rischio di SQL injection.
    # Le altre costanti interpolate (PESO_*, ALERT_ID_SCAN_REALTIME) sono
    # valori di modulo accessibili in questo scope.
    # Le doppie graffe `{{...}}` negli esempi di JSON nei commenti SQL sono
    # l'escape f-string per stampare letteralmente `{...}`.
    #
    # `filtro_lan` è costruito dal modulo condiviso network_config: limita
    # l'analisi ai soli host della LAN interna (RFC 1918). In host_alerts
    # la colonna `ip` è già una stringa, quindi nessuna conversione.
    filtro_lan = costruisci_filtro_lan("ip")

    query = f"""

    -- FASE 1 - CTE "dati_filtrati_e_classificati"
    -- Per ogni allarme scan_realtime:
    -- - estrae l'array `alerts` come Array(Int32) una SOLA volta
    -- - identifica chi è VITTIMA (contiene codice 1) e lo esclude
    -- - poi calcola peso e categoria in base ai codici presenti

    -- Il risultato è un dataset in cui ogni riga rappresenta un allarme singolo allarme
    -- con il suo peso e con la sua descrizione.

    WITH dati_filtrati_e_classificati AS (
        SELECT
            ip AS host_ip,

            -- Estrazione UNICA dell'array dei codici di sottotipo scan.
            -- Il JSON contiene es. {{"alerts": [2]}} oppure {{"alerts": [0, 3]}}
            -- e li trasforma in un array di interi: [2] o [0, 3]
            JSONExtract(json, 'alerts', 'Array(Int32)') AS codici_scan,

            -- Calcolo del peso per la singola riga (valutato una volta sola).
            -- multiIf valuta i casi nell'ordine, restituisce il primo match.
            -- L'ordine è IMPORTANTE: prima i casi più gravi, così la
            -- gerarchia dei pesi è garantita anche se l'array contiene
            -- più codici contemporaneamente (es. [0, 3] -> evasione firewall).
            multiIf(
                -- Caso 1: vittima -> escluso (peso 0)
                -- Se ANCHE solo uno dei codici è 1 (rx_only_scan), l'host non è un attaccante. 
                -- has() verifica appartenenza.
                has(codici_scan, 1),
                0,

                -- Caso 2: evasione firewall -> +50
                -- Contiene FIN scan (3) o RST scan (4)
                has(codici_scan, 3) OR has(codici_scan, 4),
                {PESO_EVASIONE_FIREWALL},

                -- Caso 3: SYN scan classico -> +40
                has(codici_scan, 2),
                {PESO_SYN_SCAN},

                -- Caso 4 (default): incomplete flows -> +30
                -- Per costruzione l'array contiene almeno [0]
                -- (i casi 1, 3, 4, 2 sono già stati gestiti sopra)
                {PESO_INCOMPLETE_FLOWS}
            ) AS penalita_singola,

            -- Categoria testuale corrispondente alla riga (per il report).
            -- IMPORTANTE: la sequenza dei casi deve essere IDENTICA a quella
            -- del calcolo del peso sopra, per garantire coerenza.
            multiIf(
                has(codici_scan, 1),
                'VITTIMA (rx_only_scan) - esclusa',

                has(codici_scan, 3) OR has(codici_scan, 4),
                'EVASIONE FIREWALL (FIN/RST scan)',

                has(codici_scan, 2),
                'SYN SCAN CLASSICO',

                'INCOMPLETE FLOWS (scan base)'
            ) AS categoria_singola

        FROM host_alerts
        WHERE
            -- Filtro 1: finestra temporale parametrica (default 60 minuti)
            tstamp >= now() - INTERVAL {finestra_minuti} MINUTE

            -- Filtro 2: solo allarmi scan_realtime
            AND alert_id = {ALERT_ID_SCAN_REALTIME}

            -- Filtro 3: LAN interna (classifichiamo solo host della rete monitorata)
            AND {filtro_lan}
    )

    -- FASE 2 - Aggregazione finale per host

    -- Opera sul risultato intermedio della CTE. Esclude le vittime (penalita_singola = 0)
    -- e aggrega i valori pre-calcolati per host.

    SELECT
        host_ip,

        -- Numero totale di allarmi scan per l'host
        count() AS hits_totali,

        -- Lista dei codici scan rilevati (max 10, per il report)
        -- arrayFlatten: schiaccia la struttura in un elenco piatto (es. [[0], [2, 3]] -> [0, 2, 3])
        -- arrayDistinct: elimina i duplicati (es. [0, 2, 3, 2] -> [0, 2, 3])
        -- arraySlice: limita a 10 codici per evitare report troppo lunghi.
        arraySlice(
            -- groupArray: unisce tutti gli array in un unico grande array
            arrayDistinct(arrayFlatten(groupArray(codici_scan))),
            1, 10
        ) AS codici_rilevati,

        -- Peso massimo applicabile: prevale lo scenario peggiore per l'host
        -- Es: host con scan SYN (+40) e successivo FIN scan (+50) -> allora +50
        max(penalita_singola) AS penalita_calcolata,

        -- Categoria corrispondente al peso massimo
        -- argMax(valore, ordinatore): restituisce il VALORE della riga he ha l'ORDINATORE più alto.
        -- Coerenza garantita per costruzione.
        argMax(categoria_singola, penalita_singola) AS categoria_dominante,

        -- M_scan si attiva se l'host non è solo vittima
        1 AS M_scan

    FROM dati_filtrati_e_classificati
    WHERE
        -- Esclude le vittime (penalita_singola = 0)
        penalita_singola > 0

    GROUP BY host_ip
    ORDER BY penalita_calcolata DESC, hits_totali DESC
    """

    risultati = {}

    # Esecuzione della query
    righe = client.query(query).result_rows

    # Ogni riga contiene:
    # (host_ip, hits_totali, codici_rilevati, penalita_calcolata,
    #  categoria_dominante, M_scan)
    for (host_ip, hits_totali, codici_rilevati,
         penalita, categoria, m_scan) in righe:

        # Conversione codici numerici in stringhe leggibili
        codici_descritti = traduci_codici(list(codici_rilevati))

        risultati[host_ip] = {
            "M_scan":              m_scan,
            "hits_totali":         hits_totali,
            "codici_rilevati":     list(codici_rilevati),
            "codici_descritti":    codici_descritti,
            "categoria_dominante": categoria,
            "penalita":            penalita,
            "timestamp":           datetime.now(timezone.utc).isoformat()
        }

    return risultati


def stampa_report(host_ip: str, dati: dict):
    """
    Stampa un report leggibile per ogni host flagged dalla sola metrica.
    Usato quando lo script è eseguito per testing.
    """
    print("=" * 70)
    print(f"  [ALLARME M_scan] {host_ip}")
    print("=" * 70)
    print(f"  Timestamp           : {dati['timestamp']}")
    print(f"  M_scan              : {dati['M_scan']} (attiva)")
    print(f"  Categoria dominante : {dati['categoria_dominante']}")
    print(f"  Tipi scan rilevati  : {', '.join(dati['codici_descritti'])}")
    print(f"  Codici (raw)        : {dati['codici_rilevati']}")
    print(f"  Hit totali          : {dati['hits_totali']}")
    print(f"  Penalità M_scan     : +{dati['penalita']} punti")
    print()


# =============================================================================
# MAIN - Esecuzione per testing
# =============================================================================

def main():
    """
    Quando integreremo tutto in scoring.py, questa funzione NON verrà chiamata:
    scoring.py importerà direttamente `calcola_m_scan()` dalla funzione sopra.

    Esecuzione da CLI:
        python m_scan.py                          # usa il default (60 minuti)
        python m_scan.py --finestra-minuti 10     # finestra di 10 minuti
        python m_scan.py --finestra-minuti 1440   # finestra di 24 ore
    """
    # Parsing degli argomenti da riga di comando
    parser = argparse.ArgumentParser(
        description="Calcolo della metrica M_scan (Network Scan Detection)."
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
    print(f"  Avvio analisi M_scan - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Finestra temporale: ultimi {args.finestra_minuti} minuto/i")
    print(f"  Pesi differenziati per tipo di scan rilevato:")
    print(f"    EVASIONE FIREWALL (FIN/RST scan):     +{PESO_EVASIONE_FIREWALL}")
    print(f"    SYN SCAN CLASSICO:                    +{PESO_SYN_SCAN}")
    print(f"    INCOMPLETE FLOWS (scan base):         +{PESO_INCOMPLETE_FLOWS}")
    print(f"    VITTIMA (rx_only_scan):               escluso")
    print(f"{'='*70}\n")

    # Connessione al database
    try:
        client = connetti_clickhouse()
        print("[OK] Connessione a ClickHouse stabilita.\n")
    except Exception as e:
        print(f"[ERRORE] Impossibile connettersi a ClickHouse: {e}")
        return

    # Calcolo della metrica M_scan con la finestra specificata
    try:
        host_flaggati = calcola_m_scan(client, finestra_minuti=args.finestra_minuti)
    except Exception as e:
        print(f"[ERRORE] Errore durante l'esecuzione della query: {e}")
        return

    # Report dei risultati
    if not host_flaggati:
        print(f"[OK] Nessun host flagged - nessuna attività di scan rilevata negli ultimi {args.finestra_minuti} minuto/i.\n")
        return

    print(f"[!] {len(host_flaggati)} host flagged dalla metrica M_scan:\n")

    for host_ip, dati in host_flaggati.items():
        stampa_report(host_ip, dati)

# Esegui questo solo se lanciato come script principale (non importato come modulo)
if __name__ == "__main__":
    main()
