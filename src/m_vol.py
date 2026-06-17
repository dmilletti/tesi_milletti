"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
Metrica M_vol - Asimmetria Volumetrica in Uscita
=============================================================================

Obiettivo:
    Rilevare l'esfiltrazione di dati o l'invio non autorizzato di file
    verso server esterni. Un host aziendale tipicamente scarica molti
    più dati di quanti ne invii (download web, ricezione email, ecc.).
    Se improvvisamente la dinamica si inverte e l'host inizia a trasferire
    grandi quantità di byte verso l'esterno, si stabilisce un forte
    sospetto che un attaccante o un malware stia copiando informazioni
    sensibili verso un server di appoggio.

Formula operativa (vedere documento di decisioni progettuali per i dettagli):

    MAD_eff = max( MAD, 0.10 * mediana, 1 MB )    <- triplo limite per evitare div/0 e falsi positivi su host a baseline bassa:
                                                  - MAD reale
                                                  - 10% mediana (scala-relativo)
                                                  - 1 MB assoluto (anti-inattività)

    Z_modified = ( V_out - mediana ) / MAD_eff <- direzionale, senza valore assoluto

    M_vol = 1  se e solo se:
        Z_modified > 3              (regola 99.7%)
        AND V_out > mediana        (solo picchi in eccesso)
        AND V_out > 50 MB          (esfiltrazione)

Frequenza di esecuzione:
    Batch-driven (metrica statistica): lo script va eseguito ogni ora
    tramite cron o systemd timer.

Peso nel modello:
    +20 punti (Anomalie di profilo e di volume - peso ridotto per via
    della maggiore probabilità di falsi positivi rispetto alle metriche
    deterministiche)

Fonte dei dati:
    Tabella `flows` di ntopng su ClickHouse.
    Colonne usate:
      - IPV4_SRC_ADDR, IPV4_DST_ADDR: identificazione di host e destinazione
      - SRC2DST_BYTES: byte trasmessi dal client al server.
      - FIRST_SEEN: timestamp di inizio flusso, usato per i bucket orari

Soglie di rischio dello score finale S(h):
    Verde  ->  0-29  punti  (host sicuro)
    Giallo -> 30-59  punti  (host sospetto, da monitorare)
    Rosso  -> 60-100 punti  (host compromesso, intervento immediato)
=============================================================================
"""

from datetime import datetime, timezone
from readconfig import (
    connetti_clickhouse, costruisci_filtro_lan, costruisci_filtro_esterno,
    PESO_M_VOL,
    M_VOL_SOGLIA_Z as SOGLIA_Z,
    M_VOL_MAD_MIN_FRAZIONE as MAD_MIN_FRAZIONE,
    M_VOL_MAD_MIN_ASSOLUTO as MAD_MIN_ASSOLUTO,
    M_VOL_V_MIN_OPERATIVO as V_MIN_OPERATIVO,
    MIN_BASELINE_HOURS, FINESTRA_STORICO_GIORNI, FINESTRA_CORRENTE_ORE,
    ORE_LAVORATIVE, GIORNI_WEEKEND,
)



# =============================================================================
# QUERY SQL
# =============================================================================

# La query si articola in 5 CTE successive per separare le fasi logiche.
# Qui dobbiamo costruire la baseline, calcolare la statistica e confrontare
# il presente con la baseline, tutto in una sola passata sul database.
#
# Le 5 fasi:
#   1) categoria_corrente   -> in che fascia temporale ci troviamo adesso
#   2) baseline_grezza      -> aggrega flussi in bucket orari,
#                              filtrati per stessa categoria dell'ora corrente
#   3) mediane              -> per ogni host, calcola mediana e applica
#                              il filtro cold start (>= 48 bucket)
#   4) statistiche_baseline -> per ogni host, calcola la MAD usando le
#                              mediane della CTE precedente (necessario un JOIN)
#   5) volume_corrente      -> somma byte in uscita dell'ora corrente
#
# SELECT finale:
# JOIN tra volume_corrente e statistiche_baseline,
# calcolo di MAD_eff e Z_modified, applicazione tripla condizione di scatto.

FILTRO_LAN_SRC = costruisci_filtro_lan("IPv4NumToString(IPV4_SRC_ADDR)")

FILTRO_EXT_DST = costruisci_filtro_esterno("IPv4NumToString(IPV4_DST_ADDR)")

QUERY_M_VOL = f"""

-- =============================================================
-- CTE 1: categoria_corrente
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
-- CTE 2: baseline_grezza
-- Aggrego i flussi degli ultimi 7 giorni in bucket orari per host.
-- Applico due filtri chiave:
--   a) categoria temporale del bucket = categoria dell'ora corrente
--   b) destinazione esterna (esclude IP privati/loopback)
-- Escludo l'ora corrente.
-- Restituisce una tabella con tre colonne, host_ip, bucket_orario, v_bucket.
-- =============================================================
baseline_grezza AS (
    SELECT
        -- Conversione da numero a stringa IP per chiarezza nei risultati
        IPv4NumToString(IPV4_SRC_ADDR) AS host_ip,
        -- Bucket orario: arrotonda FIRST_SEEN all'inizio dell'ora (es. 14:23 -> 14:00)
        toStartOfHour(FIRST_SEEN) AS bucket_orario,
        -- Somma dei byte in uscita (client -> server) per ogni bucket orario
        sum(SRC2DST_BYTES) AS v_bucket
    FROM flows
    WHERE
        -- Finestra storica di 7 giorni
        FIRST_SEEN >= now() - INTERVAL {FINESTRA_STORICO_GIORNI} DAY
        -- Escludo l'ora corrente
        AND FIRST_SEEN <  now() - INTERVAL {FINESTRA_CORRENTE_ORE} HOUR

        -- Esclude flussi IPv6 puri (IPV4_SRC_ADDR = 0)
        AND IPV4_SRC_ADDR != 0

        -- Filtro LAN sul SOGGETTO: valuto solo host interni alla rete monitorata
        AND {FILTRO_LAN_SRC}

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

        -- Quindi non considero tutto il traffico interno della rete. 
        AND {FILTRO_EXT_DST}

    GROUP BY host_ip, bucket_orario
),

-- =============================================================
-- CTE 3: mediane
-- Per ogni host, calcola la mediana dei volumi orari sui bucket
-- della baseline filtrata. Applica il filtro cold start; host con
-- meno di 30 bucket validi non hanno baseline statisticamente affidabile
-- e vengono esclusi dal calcolo.
-- Restituisce una tabella con host_ip, v_mediano, bucket_count.
-- =============================================================
mediane AS (
    SELECT
        host_ip,
        -- Calcolo della mediana dei volumi orari (v_bucket) per ogni host
        median(v_bucket) AS v_mediano,
        -- Conteggio dei bucket orari validi per ogni host
        count() AS bucket_count
    FROM baseline_grezza
    GROUP BY host_ip
    -- Scarto gli host che hanno meno di 30 ore di baseline
    HAVING bucket_count >= {MIN_BASELINE_HOURS}
),

-- =============================================================
-- CTE 4: statistiche_baseline
-- Per ogni host con baseline valida, calcola la MAD.
-- MAD = median( |v_bucket - v_mediano| ), quindi serve un JOIN con
-- la CTE precedente per avere la mediana disponibile.
-- ClickHouse non ha una funzione MAD nativa quindi si calcola come mediana
-- delle distanze assolute, in una seconda passata.
-- Restituisce una tabella con host_ip, v_mediano, bucket_count, mad.
-- =============================================================

statistiche_baseline AS (
    SELECT
        bg.host_ip,
        -- Prendo una qualsiasi riga per host da mediane, tanto v_mediano e bucket_count
        -- sono costanti per host_ip (grazie al GROUP BY), quindi non importa quale prendo.
        any(m.v_mediano)   AS v_mediano,
        any(m.bucket_count) AS bucket_count,
        median(abs(bg.v_bucket - m.v_mediano)) AS mad
    FROM baseline_grezza AS bg
    INNER JOIN mediane AS m ON bg.host_ip = m.host_ip
    GROUP BY bg.host_ip
),

-- =============================================================
-- CTE 5: volume_corrente
-- Somma i byte in uscita dell'host nell'ultima ora.
-- Stessi filtri di direzionalità della CTE 2 per garantire
-- confronto omogeneo (presente vs passato sono la stessa cosa).
-- Restituisce una tabella con host_ip e v_out (volume in uscita dell'ora corrente).
-- =============================================================
volume_corrente AS (
    SELECT
        IPv4NumToString(IPV4_SRC_ADDR) AS host_ip,
        sum(SRC2DST_BYTES) AS v_out
    FROM flows
    WHERE
        FIRST_SEEN >= now() - INTERVAL {FINESTRA_CORRENTE_ORE} HOUR
        AND IPV4_SRC_ADDR != 0
        -- Filtro LAN sul SOGGETTO: valuto solo host interni alla rete monitorata
        AND {FILTRO_LAN_SRC}

        -- Non considero il traffico interno della rete
        AND {FILTRO_EXT_DST}

    GROUP BY host_ip
)

-- =============================================================
-- SELECT finale
-- JOIN tra volume corrente e baseline statistica.
-- Calcola MAD effettiva e Z modified, applica la tripla
-- condizione di scatto:
--   1) Z > 3                       -> significatività statistica
--   2) V_out > mediana             -> direzionalità (solo picchi)
--   3) V_out > V_MIN_OPERATIVO     -> significatività operativa
-- =============================================================
SELECT
    vc.host_ip AS host_ip,
    vc.v_out AS v_out,
    sb.v_mediano AS v_mediano,
    sb.mad AS mad,

    -- Calcolo della MAD effettiva, per evitare div/0
    -- greatest(a, b) = max(a, b) in ClickHouse
    greatest(sb.mad, sb.v_mediano * {MAD_MIN_FRAZIONE}, {MAD_MIN_ASSOLUTO}) AS mad_eff,

    -- Z modified direzionale: senza valore assoluto.
    -- Valori positivi -> traffico sopra mediana (potenziale esfiltrazione)
    -- Valori negativi -> traffico sotto mediana (host inattivo, non interessa)
    (vc.v_out - sb.v_mediano)
        / greatest(sb.mad, sb.v_mediano * {MAD_MIN_FRAZIONE}, {MAD_MIN_ASSOLUTO}) AS z_modified,

    sb.bucket_count AS bucket_count,
    categoria_corrente AS categoria_temporale,

    -- Se siamo qui, tutte e tre le condizioni sotto sono soddisfatte
    1 AS M_vol

FROM volume_corrente AS vc
INNER JOIN statistiche_baseline AS sb ON vc.host_ip = sb.host_ip
WHERE
    -- Condizione 3: significatività operativa
    -- (filtro a monte: scarta subito host con volumi piccoli, evita
    -- di calcolare Z su valori che non possono comunque scattare)
    vc.v_out > {V_MIN_OPERATIVO}

    -- Condizione 2: direzionalità (solo scostamenti in eccesso)
    AND vc.v_out > sb.v_mediano

    -- Condizione 1: significatività statistica
    AND z_modified > {SOGLIA_Z}

-- Ordino per Z modified decrescente, così da portare in cima i casi più anomali.
ORDER BY z_modified DESC
"""


# =============================================================================
# FUNZIONI
# =============================================================================

def calcola_m_vol(client):
    """
    Esegue la query su ClickHouse e restituisce un dizionario con i risultati.

    Il formato di ritorno è SIMMETRICO alle altre metriche:
    chiave = IP dell'host, valore = dizionario con i dettagli.

    Struttura del dizionario restituito:
    {
        "192.168.1.45": {
            "M_vol":                1,
            "v_out":                78_643_200,     # byte nell'ora corrente
            "v_mediano":            12_582_912,     # mediana baseline contestuale
            "mad":                  3_145_728,      # MAD grezza
            "mad_eff":              3_145_728,      # MAD effettiva
            "z_modified":           21.0,           # Z-score effettivo
            "categoria_temporale":  "feriale_lavorativo",
            "bucket_baseline":      44,             # campioni usati per la baseline
            "penalita":             20,
            "timestamp":            "2026-05-19T14:00:00+00:00"
        },
        ...
    }
    """
    risultati = {}

    # Esecuzione della query
    righe = client.query(QUERY_M_VOL).result_rows

    # Ogni riga contiene:
    # (host_ip, v_out, v_mediano, mad, mad_eff,
    #  z_modified, bucket_count, categoria_temporale, M_vol)
    for (host_ip, v_out, v_mediano, mad, mad_eff,
         z_modified, bucket_count, categoria_temporale, m_vol) in righe:

        risultati[host_ip] = {
            "M_vol":               m_vol,
            "v_out":               int(v_out),
            "v_mediano":           int(v_mediano),
            "mad":                 int(mad),
            "mad_eff":             int(mad_eff),
            "z_modified":          float(z_modified),
            "categoria_temporale": categoria_temporale,
            "bucket_baseline":     bucket_count,
            "penalita":            PESO_M_VOL * m_vol,  # 20 se M_vol=1, 0 altrimenti
            "timestamp":           datetime.now(timezone.utc).isoformat()
        }

    return risultati


def formatta_byte(b: int) -> str:
    """
    Helper di formattazione: converte byte in unità leggibili (KB/MB/GB).
    Usato solo per il report di stampa.
    """
    if b >= 1024**3:
        return f"{b / 1024**3:.2f} GB"
    if b >= 1024**2:
        return f"{b / 1024**2:.2f} MB"
    if b >= 1024:
        return f"{b / 1024:.2f} KB"
    return f"{b} B"


def stampa_report(host_ip: str, dati: dict):
    """
    Stampa un report leggibile per ogni host flaggato dalla sola metrica.
    Usato quando lo script è eseguito per testing.
    """
    print("=" * 70)
    print(f"  [ALLARME M_vol] {host_ip}")
    print("=" * 70)
    print(f"  Timestamp           : {dati['timestamp']}")
    print(f"  M_vol               : {dati['M_vol']} (attiva)")
    print(f"  Categoria temporale : {dati['categoria_temporale']}")
    print(f"  Bucket baseline     : {dati['bucket_baseline']}")
    print(f"  V_out (ora attuale) : {formatta_byte(dati['v_out'])}")
    print(f"  V_mediano (baseline): {formatta_byte(dati['v_mediano'])}")
    print(f"  MAD (grezza)        : {formatta_byte(dati['mad'])}")
    print(f"  MAD effettiva       : {formatta_byte(dati['mad_eff'])}")
    print(f"  Z modified           : {dati['z_modified']:.2f}")
    print(f"  Penalità M_vol     : +{dati['penalita']} punti")
    print()


# =============================================================================
# MAIN - Esecuzione per testing
# =============================================================================

def main():
    """
    Quando integreremo tutto in scoring.py, questa funzione NON verrà chiamata:
    scoring.py importerà direttamente `calcola_m_vol()` dalla funzione sopra.
    """
    print(f"\n{'='*70}")
    print(f"  Avvio analisi M_vol - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Finestra storica baseline : {FINESTRA_STORICO_GIORNI} giorni")
    print(f"  Finestra ora corrente     : {FINESTRA_CORRENTE_ORE} ora")
    print(f"  Soglia Z modified          : > {SOGLIA_Z}")
    print(f"  Soglia operativa V_min    : > {formatta_byte(V_MIN_OPERATIVO)}")
    print(f"  Floor MAD (frazione)      : {MAD_MIN_FRAZIONE * 100:.0f}% della mediana")
    print(f"  Min bucket baseline       : {MIN_BASELINE_HOURS}")
    print(f"{'='*70}\n")

    # Connessione al database
    try:
        client = connetti_clickhouse()
        print("[OK] Connessione a ClickHouse stabilita.\n")
    except Exception as e:
        print(f"[ERRORE] Impossibile connettersi a ClickHouse: {e}")
        return

    # Calcolo della metrica M_vol
    try:
        host_flaggati = calcola_m_vol(client)
    except Exception as e:
        print(f"[ERRORE] Errore durante l'esecuzione della query: {e}")
        return

    # Report dei risultati
    if not host_flaggati:
        print("[OK] Nessun host flagged - nessuna asimmetria volumetrica anomala nell'ultima ora.\n")
        return

    print(f"[!] {len(host_flaggati)} host flagged dalla metrica M_vol:\n")

    for host_ip, dati in host_flaggati.items():
        stampa_report(host_ip, dati)


# Esegui questo solo se lanciato come script principale (non importato come modulo)
if __name__ == "__main__":
    main()
