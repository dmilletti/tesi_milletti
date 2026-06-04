"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
config.py - File di configurazione centrale
=============================================================================

Obiettivo:
    Un UNICO punto da cui modificare tutti i parametri operativi del
    sistema, senza mai toccare il codice delle metriche.

    È possibile cambiare la configurazione dei parametri di connessione a ClickHouse
    e la definizione di "host interno" (reti locali).

Cosa si modifica e dove:
    -> SOLO la sezione "PARAMETRI MODIFICABILI" qui sotto.
       Tutto il resto del sistema (metriche, scoring) NON va mai toccato
       per cambiare la configurazione.
=============================================================================
"""

import clickhouse_connect


# =============================================================================
# ============================ PARAMETRI MODIFICABILI =========================
# =============================================================================
# QUESTA È L'UNICA SEZIONE CHE SI MODIFICA PER CAMBIARE LA CONFIGURAZIONE.
# =============================================================================

# ---- Connessione a ClickHouse ----------------------------------------------
#
# Per cambiare la configurazione, modificare direttamente questi valori.

CLICKHOUSE_HOST     = "localhost"
CLICKHOUSE_PORT     = 8123          # porta HTTP
CLICKHOUSE_DATABASE = "ntopng"
CLICKHOUSE_USER     = "default"
CLICKHOUSE_PASSWORD = "0022"


# ---- Reti locali (definizione di "host interno") ---------------------------
#
# Range RFC 1918 - reti private IPv4 standard.
# Un host con IP in uno di questi range è considerato interno e verrà
# classificato dalle metriche di sicurezza. Un IP esterno non appartiene
# allo "spazio degli host" del sistema: non ha baseline storica, non
# possiamo intervenire, non ha senso assegnargli uno score.
#
# Per estendere la definizione di interno (es. aggiunta di un blocco IPv4
# pubblico aziendale), basta aggiungere la rete a questa lista: tutte le
# metriche la useranno automaticamente.
#
# Nota su loopback e link-local: NON sono inclusi. Il filtro è sul SOGGETTO
# (l'host monitorato); loopback (127.0.0.0/8) e link-local (169.254.0.0/16)
# non sono "host della LAN" e nei flussi reali non comparirebbero comunque
# come IP soggetto.
RETI_LOCALI = [
    "192.168.0.0/16",   # classe C privata
    "10.0.0.0/8",       # classe A privata
    "172.16.0.0/12",    # classe B privata
]

# =============================================================================
# ========================== FINE PARAMETRI MODIFICABILI ======================
# =============================================================================


# =============================================================================
# HELPER CONDIVISI
# =============================================================================
# Da qui in giù è codice di supporto: NON serve modificarlo per cambiare la
# configurazione. Tutte le metriche e scoring.py importano queste due
# funzioni da questo modulo.
# =============================================================================

def connetti_clickhouse():
    """
    Apre e restituisce la connessione al database ClickHouse usando i
    parametri definiti nella sezione "PARAMETRI MODIFICABILI".
    """
    return clickhouse_connect.get_client(
        host     = CLICKHOUSE_HOST,
        port     = CLICKHOUSE_PORT,
        database = CLICKHOUSE_DATABASE,
        username = CLICKHOUSE_USER,
        password = CLICKHOUSE_PASSWORD,
    )


def costruisci_filtro_lan(colonna_ip: str) -> str:
    """
    Costruisce la clausola SQL (parentesi inclusa) che verifica se la
    colonna IP indicata appartiene a una delle reti locali definite in
    RETI_LOCALI.

    Parametri:
        colonna_ip : nome della colonna SQL contenente l'IP da verificare,
                     oppure un'espressione SQL che ritorna una stringa IP.
                     ATTENZIONE: deve essere un identificatore di colonna
                     SQL controllato dallo sviluppatore, NON input utente.
                     Il valore viene inserito direttamente nella stringa
                     SQL (è sicuro perché non arriva mai da utenti esterni:
                     sono nomi di colonne cablati negli script).

                     Esempi tipici:
                       "cli_ip"                          (flow_alerts_view)
                       "ip"                              (host_alerts)
                       "IPv4NumToString(IPV4_SRC_ADDR)"  (flows, perché
                                                          IPV4_SRC_ADDR è UInt32
                                                          e isIPAddressInRange
                                                          richiede una stringa)

    Restituisce:
        Una stringa SQL nella forma:
            (isIPAddressInRange(<colonna_ip>, '192.168.0.0/16')
             OR isIPAddressInRange(<colonna_ip>, '10.0.0.0/8')
             OR isIPAddressInRange(<colonna_ip>, '172.16.0.0/12'))
    """
    condizioni = [
        f"isIPAddressInRange({colonna_ip}, '{rete}')"
        for rete in RETI_LOCALI
    ]
    return "(" + " OR ".join(condizioni) + ")"


# =============================================================================
# AUTO-TEST DI CONTROLLO CONFIGURAZIONE
# =============================================================================

if __name__ == "__main__":
    # Stampa la configurazione effettiva (con password mascherata) e verifica
    # che il filtro LAN sia ben formato. Utile per controllare al volo che i
    # parametri impostati siano quelli attesi.
    print("=== Configurazione ClickHouse effettiva ===\n")
    print(f"  host     = {CLICKHOUSE_HOST}")
    print(f"  port     = {CLICKHOUSE_PORT}")
    print(f"  database = {CLICKHOUSE_DATABASE}")
    print(f"  user     = {CLICKHOUSE_USER}")
    # Non stampiamo mai la password in chiaro: mostriamo solo se è impostata.
    mascherata = "*" * len(CLICKHOUSE_PASSWORD) if CLICKHOUSE_PASSWORD else "(vuota)"
    print(f"  password = {mascherata}")
    print()

    print("=== Reti locali ===\n")
    for rete in RETI_LOCALI:
        print(f"  {rete}")
    print()

    print("=== Test costruisci_filtro_lan ===\n")
    for col in ["cli_ip", "ip", "IPv4NumToString(IPV4_SRC_ADDR)"]:
        print(f"colonna_ip = {col!r}")
        print(f"  -> {costruisci_filtro_lan(col)}")
        print()
