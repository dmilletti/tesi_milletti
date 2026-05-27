"""
=============================================================================
SISTEMA DI RILEVAMENTO ANOMALIE DI RETE
Configurazione di rete condivisa
=============================================================================

Singolo modulo per la definizione di "host della LAN interna".
Importato da tutti gli script delle metriche che non hanno una baseline
(m_sni, m_rep, m_cert, m_scan,m_proto, m_srv).

Tutte le metriche classificano solo gli host interni della rete monitorata.
Un IP esterno non appartiene allo "spazio degli host" del sistema:
non ha baseline storica, non possiamo intervenire, non ha senso
assegnargli uno score.

Definire qui le reti interne in un unico punto garantisce che, se in
futuro la rete cambia (es.un blocco IPv4 pubblico aziendale), basta
modificare la lista `RETI_LOCALI` qui sotto e tutte le metriche si aggiornano insieme.

Nota su loopback e link-local:
    NON sono inclusi nelle reti locali, anche se in `m_vol.py` venivano
    esclusi insieme alle RFC1918. Lì il filtro era sulla destinazione del
    flusso (per identificare il traffico in uscita); qui il filtro è sul
    SOGGETTO (l'host monitorato). Il loopback (127.0.0.0/8) e il link-local
    (169.254.0.0/16) non sono "host della LAN", sono concetti diversi
    e nei flussi reali non comparirebbero comunque come IP soggetto.
=============================================================================
"""


# =============================================================================
# RETI LOCALI
# =============================================================================

# Range RFC 1918 - reti private IPv4 standard.
# Un host con IP in uno di questi range è considerato interno e
# verrà classificato dalle metriche di sicurezza.
#
# Per estendere la definizione di interno (es. aggiunta di un blocco
# IPv4 pubblico aziendale), basta aggiungere la rete a questa lista.
# Tutte le metriche la useranno automaticamente.
RETI_LOCALI = [
    "192.168.0.0/16",   # classe C privata
    "10.0.0.0/8",       # classe A privata
    "172.16.0.0/12",    # classe B privata
]


# =============================================================================
# COSTRUZIONE FILTRO SQL
# =============================================================================

def costruisci_filtro_lan(colonna_ip: str) -> str:
    """
    Costruisce la clausola SQL (parentesi inclusa) che verifica se la
    colonna IP indicata appartiene a una delle reti locali definite.

    Parametri:
        colonna_ip : nome della colonna SQL contenente l'IP da verificare,
                     oppure un'espressione SQL che ritorna una stringa IP.
                     ATTENZIONE: deve essere un identificatore di colonna
                     SQL controllato dallo sviluppatore, NON input utente.
                     Il valore viene modificato direttamente nella
                     stringa SQL (è sicuro perché non arriva mai da utenti
                     esterni: sono nomi di colonne cablati negli script).

                     Esempi tipici:
                       "cli_ip"                       (flow_alerts_view)
                       "ip"                           (host_alerts)
                       "IPv4NumToString(IPV4_SRC_ADDR)" (flows, perché
                                                       IPV4_SRC_ADDR è UInt32
                                                       e isIPAddressInRange
                                                       richiede una stringa)

    Restituisce:
        Una stringa SQL nella forma:
            (isIPAddressInRange(<colonna_ip>, '192.168.0.0/16')
             OR isIPAddressInRange(<colonna_ip>, '10.0.0.0/8')
             OR isIPAddressInRange(<colonna_ip>, '172.16.0.0/12'))
        '''
    """
    condizioni = [
        f"isIPAddressInRange({colonna_ip}, '{rete}')"
        for rete in RETI_LOCALI
    ]
    return "(" + " OR ".join(condizioni) + ")"


# =============================================================================
# AUTO-TEST
# =============================================================================

if __name__ == "__main__":
    # Verifica che la funzione produca SQL ben formato per i
    # tre casi tipici (colonna stringa, colonna stringa diversa, espressione
    # con conversione UInt32 -> String).
    print("=== Test costruisci_filtro_lan ===\n")

    for col in ["cli_ip", "ip", "IPv4NumToString(IPV4_SRC_ADDR)"]:
        print(f"colonna_ip = {col!r}")
        print(f"  -> {costruisci_filtro_lan(col)}")
        print()
