"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
readconfig.py - Lettore della configurazione + helper condivisi
=============================================================================
Obiettivo:
    Unico ponte tra il file di configurazione esterno (config.ini) e il resto
    del sistema. Questo modulo NON contiene valori di configurazione: legge
    tutto da config.ini a runtime ed espone i parametri come costanti.
=============================================================================
"""

import configparser
from pathlib import Path

import clickhouse_connect


# =============================================================================
# LETTURA DEL FILE DI CONFIGURAZIONE
# =============================================================================

_PERCORSO_INI = Path(__file__).resolve().parent / "config.ini"

_cfg = configparser.ConfigParser(inline_comment_prefixes=(";",))
_letti = _cfg.read(_PERCORSO_INI)
if not _letti:
    raise FileNotFoundError(
        f"File di configurazione non trovato: {_PERCORSO_INI}\n"
        f"Creare config.ini nella stessa cartella di config.py."
    )


def _lista_reti(sezione: str, chiave: str) -> list[str]:
    """Legge reti CIDR separate da virgola e le restituisce ripulite."""
    grezzo = _cfg.get(sezione, chiave, fallback="")
    return [r.strip() for r in grezzo.split(",") if r.strip()]


def _tupla_int(sezione: str, chiave: str) -> tuple[int, ...]:
    """Legge una tupla di interi separati da virgola (es. '9, 17' -> (9, 17))."""
    grezzo = _cfg.get(sezione, chiave)
    return tuple(int(x.strip()) for x in grezzo.split(",") if x.strip())


# =============================================================================
# CONNESSIONE A CLICKHOUSE
# =============================================================================

CLICKHOUSE_HOST     = _cfg.get("clickhouse", "host", fallback="localhost")
CLICKHOUSE_PORT     = _cfg.getint("clickhouse", "port", fallback=8123)
CLICKHOUSE_DATABASE = _cfg.get("clickhouse", "database", fallback="ntopng")
CLICKHOUSE_USER     = _cfg.get("clickhouse", "user", fallback="default")
CLICKHOUSE_PASSWORD = _cfg.get("clickhouse", "password", fallback="")


# =============================================================================
# RETI
# =============================================================================

RETI_LOCALI      = _lista_reti("reti", "locali")
RETI_NON_ESTERNE = _lista_reti("reti", "non_esterne")

if not RETI_LOCALI:
    raise ValueError(
        "La voce [reti] locali in config.ini è vuota: definire almeno una "
        "rete locale (es. locali = 192.168.0.0/16)."
    )


# =============================================================================
# SCORING GLOBALE
# =============================================================================

SCORE_MAX     = _cfg.getint("scoring", "score_max")
SOGLIA_GIALLO = _cfg.getint("scoring", "soglia_giallo")
SOGLIA_ROSSO  = _cfg.getint("scoring", "soglia_rosso")


# =============================================================================
# FINESTRE TEMPORALI (condivise)
# =============================================================================

FINESTRA_MINUTI_DEFAULT = _cfg.getint("finestre", "finestra_minuti_default")
FINESTRA_CORRENTE_ORE   = _cfg.getint("finestre", "finestra_corrente_ore")
FINESTRA_STORICO_GIORNI = _cfg.getint("finestre", "finestra_storico_giorni")
MIN_BASELINE_HOURS      = _cfg.getint("finestre", "min_baseline_hours")
ORE_LAVORATIVE          = _tupla_int("finestre", "ore_lavorative")
GIORNI_WEEKEND          = _tupla_int("finestre", "giorni_weekend")

# =============================================================================
# VALIDAZIONE (ancora temporale per il replay di pcap storici)
# =============================================================================

_epoch_raw = ""
if _cfg.has_section("validazione"):
    _epoch_raw = _cfg.get("validazione", "epoch_riferimento", fallback="").strip()
EPOCH_RIFERIMENTO = int(_epoch_raw) if _epoch_raw not in ("", "0") else None


# =============================================================================
# PESI DELLE METRICHE (con peso unico non variabile)
# =============================================================================

PESO_M_VOL   = _cfg.getint("pesi", "m_vol")
PESO_M_FAIL  = _cfg.getint("pesi", "m_fail")
PESO_M_SRV   = _cfg.getint("pesi", "m_srv")
PESO_M_SNI   = _cfg.getint("pesi", "m_sni")
PESO_M_CERT  = _cfg.getint("pesi", "m_cert")
PESO_M_PROTO = _cfg.getint("pesi", "m_proto")


# =============================================================================
# M_VOL
# =============================================================================

M_VOL_SOGLIA_Z         = _cfg.getfloat("m_vol", "soglia_z")
M_VOL_MAD_MIN_FRAZIONE = _cfg.getfloat("m_vol", "mad_min_frazione")
M_VOL_MAD_MIN_ASSOLUTO = _cfg.getint("m_vol", "mad_min_assoluto")
M_VOL_V_MIN_OPERATIVO  = _cfg.getint("m_vol", "v_min_operativo")


# =============================================================================
# M_FAIL
# =============================================================================

M_FAIL_SOGLIA_Z            = _cfg.getfloat("m_fail", "soglia_z")
M_FAIL_R_MIN_OPERATIVO     = _cfg.getfloat("m_fail", "r_min_operativo")
M_FAIL_MAD_MIN_ASSOLUTA    = _cfg.getfloat("m_fail", "mad_min_assoluta")
M_FAIL_MIN_FLUSSI_CORRENTE = _cfg.getint("m_fail", "min_flussi_corrente")

# Bit del flow_risk_bitmap nDPI.
M_FAIL_BIT_NDPI_ERROR_CODE      = _cfg.getint("m_fail", "bit_ndpi_error_code")
M_FAIL_BIT_NDPI_UNIDIRECTIONAL  = _cfg.getint("m_fail", "bit_ndpi_unidirectional")
M_FAIL_BIT_NDPI_TCP_ISSUES      = _cfg.getint("m_fail", "bit_ndpi_tcp_issues")
M_FAIL_BIT_NDPI_UNRESOLVED_HOST = _cfg.getint("m_fail", "bit_ndpi_unresolved_host")
M_FAIL_BIT_NDPI_PROBING_ATTEMPT = _cfg.getint("m_fail", "bit_ndpi_probing_attempt")


# =============================================================================
# M_SCAN
# =============================================================================

M_SCAN_ALERT_ID               = _cfg.getint("m_scan", "alert_id")
M_SCAN_PESO_EVASIONE_FIREWALL = _cfg.getint("m_scan", "peso_evasione_firewall")
M_SCAN_PESO_SYN_SCAN          = _cfg.getint("m_scan", "peso_syn_scan")
M_SCAN_PESO_INCOMPLETE_FLOWS  = _cfg.getint("m_scan", "peso_incomplete_flows")


# =============================================================================
# M_SRV
# =============================================================================

M_SRV_ALERT_ID = _cfg.getint("m_srv", "alert_id")


# =============================================================================
# M_SNI
# =============================================================================

# Bit del flow_risk_bitmap nDPI controllato da M_sni.
M_SNI_BIT_NDPI_MISSING_SNI = _cfg.getint("m_sni", "bit_ndpi_missing_sni")


# =============================================================================
# M_REP
# =============================================================================

M_REP_SOGLIA_SRV_PERSISTENTE = _cfg.getint("m_rep", "soglia_srv_persistente")
M_REP_SOGLIA_CLI_MIRATO      = _cfg.getint("m_rep", "soglia_cli_mirato")
M_REP_PESO_SRV_ISOLATO       = _cfg.getint("m_rep", "peso_srv_isolato")
M_REP_PESO_SRV_PERSISTENTE   = _cfg.getint("m_rep", "peso_srv_persistente")
M_REP_PESO_CLI_RARO          = _cfg.getint("m_rep", "peso_cli_raro")
M_REP_PESO_CLI_MIRATO        = _cfg.getint("m_rep", "peso_cli_mirato")


# =============================================================================
# HELPER CONDIVISI
# =============================================================================

def connetti_clickhouse():
    """Apre e restituisce la connessione a ClickHouse (parametri da config.ini)."""
    return clickhouse_connect.get_client(
        host     = CLICKHOUSE_HOST,
        port     = CLICKHOUSE_PORT,
        database = CLICKHOUSE_DATABASE,
        username = CLICKHOUSE_USER,
        password = CLICKHOUSE_PASSWORD,
    )


def costruisci_filtro_lan(colonna_ip: str) -> str:
    """
    Clausola SQL VERA quando colonna_ip appartiene a una rete locale
    (RETI_LOCALI). Filtra il SOGGETTO della metrica (l'host interno).
    """
    condizioni = [
        f"isIPAddressInRange({colonna_ip}, '{rete}')"
        for rete in RETI_LOCALI
    ]
    return "(" + " OR ".join(condizioni) + ")"


def costruisci_filtro_esterno(colonna_ip: str) -> str:
    """
    Clausola SQL VERA quando colonna_ip e' una destinazione realmente ESTERNA:
    ne' host interno (RETI_LOCALI) ne' rete non instradabile (RETI_NON_ESTERNE).
    """
    da_escludere = list(dict.fromkeys(RETI_LOCALI + RETI_NON_ESTERNE))
    condizioni = [
        f"NOT isIPAddressInRange({colonna_ip}, '{rete}')"
        for rete in da_escludere
    ]
    return "(" + " AND ".join(condizioni) + ")"

def espr_riferimento() -> str:
    """
    Espressione SQL dell'istante di riferimento delle metriche.
    Produzione (EPOCH_RIFERIMENTO=None) -> now().
    Replay -> toDateTime(epoch): istante ASSOLUTO, immune al fuso del server.
    """
    if EPOCH_RIFERIMENTO is None:
        return "now()"
    return f"toDateTime({EPOCH_RIFERIMENTO})"


# =============================================================================
# AUTO-TEST DI CONTROLLO CONFIGURAZIONE
# =============================================================================

if __name__ == "__main__":
    print(f"=== Configurazione letta da {_PERCORSO_INI} ===\n")

    print("--- ClickHouse ---")
    print(f"  {CLICKHOUSE_USER}@{CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}/{CLICKHOUSE_DATABASE}")
    print(f"  password = {'*' * len(CLICKHOUSE_PASSWORD) if CLICKHOUSE_PASSWORD else '(vuota)'}\n")

    print("--- Reti locali (host interni) ---")
    for r in RETI_LOCALI:
        print(f"  {r}")
    print("\n--- Reti non esterne (escluse come destinazione) ---")
    for r in RETI_NON_ESTERNE:
        print(f"  {r}")

    print("\n--- Scoring ---")
    print(f"  score_max={SCORE_MAX}  giallo>={SOGLIA_GIALLO}  rosso>={SOGLIA_ROSSO}")

    print("\n--- Finestre ---")
    print(f"  default={FINESTRA_MINUTI_DEFAULT}min  corrente={FINESTRA_CORRENTE_ORE}h"
          f"  storico={FINESTRA_STORICO_GIORNI}g  baseline_min={MIN_BASELINE_HOURS}h")
    print(f"  ore_lavorative={ORE_LAVORATIVE}  weekend={GIORNI_WEEKEND}")

    print("\n--- Pesi ---")
    print(f"  vol={PESO_M_VOL} fail={PESO_M_FAIL} srv={PESO_M_SRV} "
          f"sni={PESO_M_SNI} cert={PESO_M_CERT} proto={PESO_M_PROTO}")

    print("\n--- Bit nDPI ---")
    print(f"  M_fail: err={M_FAIL_BIT_NDPI_ERROR_CODE} uni={M_FAIL_BIT_NDPI_UNIDIRECTIONAL} "
          f"tcp={M_FAIL_BIT_NDPI_TCP_ISSUES} unres={M_FAIL_BIT_NDPI_UNRESOLVED_HOST} "
          f"probe={M_FAIL_BIT_NDPI_PROBING_ATTEMPT}")
    print(f"  M_sni : missing_sni={M_SNI_BIT_NDPI_MISSING_SNI}")

    print("\n=== Test filtri SQL ===")
    print(f"  LAN(cli_ip)     -> {costruisci_filtro_lan('cli_ip')}")
    print(f"  ESTERNO(dst)    -> {costruisci_filtro_esterno('IPv4NumToString(IPV4_DST_ADDR)')}")
