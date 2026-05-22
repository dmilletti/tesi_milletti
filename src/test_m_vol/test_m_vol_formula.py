"""
=============================================================================
TEST DI LIVELLO 1 - VALIDAZIONE DELLA FORMULA M_vol
=============================================================================

Obiettivo:
    Verificare che la formula matematica di M_vol produca i valori attesi
    su input controllati.
    Serve a validare la logica della metrica indipendentemente da ClickHouse
    e da ntopng. Se la formula qui non funziona, nessun test successivo può funzionare.

Cosa viene testato:
    - Calcolo dello Z robusto direzionale
    - Applicazione del triplo limite sulla MAD:
        MAD_eff = max(MAD, 0.10 * mediana, MAD_MIN_ASSOLUTO)
    - Tripla condizione di scatto (Z > 3 AND v_out > mediana AND v_out > V_min)
    - Gestione dei casi (MAD=0, mediana=0, valori al limite)
    
=============================================================================
"""

# =============================================================================
# CONFIGURAZIONE (identica a m_vol.py)
# =============================================================================
# Manteniamo qui le costanti per non dover importare m_vol.py, che si
# connetterebbe automaticamente al database.

SOGLIA_Z         = 3.0
MAD_MIN_FRAZIONE = 0.10
MAD_MIN_ASSOLUTO = 1024 * 1024       # 1 MB in byte
V_MIN_OPERATIVO  = 50 * 1024 * 1024  # 50 MB in byte
PESO_M_VOL       = 20


# =============================================================================
# FUNZIONI SOTTO TEST
# =============================================================================
# Replichiamo qui la logica della formula come funzioni Python,
# che restituiscono gli stessi valori della query SQL.

def calcola_mad_effettiva(mad: float, v_mediano: float) -> float:
    """
    Implementa il limite sulla MAD con tre termini:
        MAD_eff = max( MAD, 0.10 * mediana, MAD_MIN_ASSOLUTO )
    """
    return max(mad, v_mediano * MAD_MIN_FRAZIONE, MAD_MIN_ASSOLUTO)


def calcola_z_robusto(v_out: float, v_mediano: float, mad: float) -> float:
    """
    Implementa lo Z robusto direzionale:
        Z = (V_out - mediana) / MAD_eff

    Nota: senza valore assoluto. Valori negativi sono consentiti (significano
    "host meno attivo del solito") ma non causeranno mai lo scatto della
    metrica per via della condizione di direzionalità nella formula finale.

    Con il limite assoluto da 1 MB, MAD_eff non può mai essere zero, quindi
    la divisione è sempre possibile effettuarla. La protezione contro mad_eff=0
    è mantenuta sicura per eventuali futuri scenari in cui MAD_MIN_ASSOLUTO
    venisse abbassato a zero in fase di sperimentazione.
    """
    mad_eff = calcola_mad_effettiva(mad, v_mediano)
    if mad_eff == 0:
        return float('inf') if v_out > v_mediano else float('-inf')
    return (v_out - v_mediano) / mad_eff


def valuta_m_vol(v_out: float, v_mediano: float, mad: float) -> dict:
    """
    Implementa la tripla condizione di scatto:
        M_vol = 1  <=>  Z > 3  AND  v_out > mediana  AND  v_out > V_min

    Restituisce un dizionario con tutti i valori intermedi, utile per
    verificare passo dopo passo cosa è successo nel calcolo.
    """
    mad_eff = calcola_mad_effettiva(mad, v_mediano)
    z_robusto = calcola_z_robusto(v_out, v_mediano, mad)

    cond_statistica  = z_robusto > SOGLIA_Z
    cond_direzione   = v_out > v_mediano
    cond_operativa   = v_out > V_MIN_OPERATIVO

    m_vol = 1 if (cond_statistica and cond_direzione and cond_operativa) else 0

    return {
        "v_out":            v_out,
        "v_mediano":        v_mediano,
        "mad":              mad,
        "mad_eff":          mad_eff,
        "z_robusto":        z_robusto,
        "cond_statistica":  cond_statistica,
        "cond_direzione":   cond_direzione,
        "cond_operativa":   cond_operativa,
        "M_vol":            m_vol,
        "penalita":         PESO_M_VOL * m_vol,
    }


# =============================================================================
# HELPER PER IL REPORT
# =============================================================================

def formatta_byte(b: float) -> str:
    """Converte byte in unità leggibili per il report."""
    if b == 0:
        return "0 B"
    if b == float('inf'):
        return "inf"
    if b >= 1024**3:
        return f"{b / 1024**3:.2f} GB"
    if b >= 1024**2:
        return f"{b / 1024**2:.2f} MB"
    if b >= 1024:
        return f"{b / 1024:.2f} KB"
    return f"{b:.0f} B"


def formatta_z(z: float) -> str:
    """Formatta Z gestendo i valori infiniti."""
    if z == float('inf'):
        return "+inf"
    if z == float('-inf'):
        return "-inf"
    return f"{z:.2f}"


# =============================================================================
# CASI DI TEST
# =============================================================================
# Ogni caso è una tupla (nome, descrizione, v_out, v_mediano, mad, attesi)
# dove "attesi" è il dizionario dei valori che ci aspettiamo dalla formula.

# Per ogni caso verifichiamo SOLO i campi presenti in "attesi": questo permette
# di testare solo le proprietà rilevanti senza dover specificare tutti i valori
# intermedi (es. su un caso che testa MAD=0, non ci interessa lo Z esatto).

CASI_DI_TEST = [
    # =========================================================================
    # GRUPPO 1: Casi base (la formula deve funzionare in scenari normali)
    # =========================================================================
    {
        "nome": "Esfiltrazione tipica - host office",
        "descrizione": (
            "Host con baseline normale (12.5 MB) che trasferisce 78 MB. "
            "Caso di esfiltrazione: tutti e tre i flag devono attivarsi."
        ),
        "v_out":     78  * 1024 * 1024,   # 78 MB
        "v_mediano": 12.5 * 1024 * 1024,  # 12.5 MB
        "mad":       2.8 * 1024 * 1024,   # 2.8 MB
        "attesi": {
            "M_vol": 1,
            "penalita": 20,
            "cond_statistica": True,
            "cond_direzione": True,
            "cond_operativa": True,
        },
    },

    {
        "nome": "Traffico normale - nessuno scatto",
        "descrizione": (
            "Host con baseline 12.5 MB che trasferisce 14 MB. "
            "Variazione del 12% rispetto alla mediana, ben dentro la tolleranza."
        ),
        "v_out":     14   * 1024 * 1024,
        "v_mediano": 12.5 * 1024 * 1024,
        "mad":       2.8  * 1024 * 1024,
        "attesi": {
            "M_vol": 0,
            "penalita": 0,
            "cond_statistica": False,  # Z piccolo, non scatta
        },
    },

    # =========================================================================
    # GRUPPO 2: soglia sulla MAD (verifica il comportamento del 10% della mediana)
    # =========================================================================
    {
        "nome": "MAD = 0 - server costante con picco",
        "descrizione": (
            "Server che trasferisce esattamente 1 MB ogni ora (MAD reale = 0). "
            "Tre termini del greatest: MAD=0, 0.10*mediana=100KB, ASSOLUTO=1MB. "
            "Prevale il limite ASSOLUTO (1 MB). Lo Z resta finito e calcolabile."
        ),
        "v_out":     80 * 1024 * 1024,
        "v_mediano":  1 * 1024 * 1024,
        "mad":       0,
        "attesi": {
            "M_vol": 1,
            "mad_eff": 1024 * 1024,         # 1 MB (limite assoluto prevale)
        },
    },

    {
        "nome": "MAD bassa ma non zero - limite proporzionale o assoluto",
        "descrizione": (
            "Host con mediana 10 MB e MAD reale 500 KB. "
            "Tre termini del greatest: MAD=500KB, 0.10*mediana=1MB, ASSOLUTO=1MB. "
            "Limite proporzionale e assoluto coincidono (1 MB), prevalgono "
            "entrambi sulla MAD reale. MAD_eff = 1 MB."
        ),
        "v_out":      100 * 1024 * 1024,
        "v_mediano":   10 * 1024 * 1024,
        "mad":        500 * 1024,         # 500 KB
        "attesi": {
            "M_vol": 1,
            "mad_eff": 1024 * 1024,       # 1 MB (proporzionale = assoluto)
        },
    },

    {
        "nome": "MAD alta - limite inattivo",
        "descrizione": (
            "Host con mediana 10 MB e MAD reale 5 MB. "
            "Il 10% della mediana sarebbe 1 MB, ma MAD reale (5 MB) è maggiore, "
            "quindi MAD_eff = MAD = 5 MB (il limite non si attiva)."
        ),
        "v_out":     100 * 1024 * 1024,
        "v_mediano":  10 * 1024 * 1024,
        "mad":         5 * 1024 * 1024,
        "attesi": {
            "M_vol": 1,
            "mad_eff": 5 * 1024 * 1024,   # MAD invariata
        },
    },

    {
        "nome": "Limite assoluto prevale - host inattivo medio-basso",
        "descrizione": (
            "Host con mediana 500 KB e MAD 50 KB. "
            "Tre termini del greatest: MAD=50KB, 0.10*mediana=50KB, ASSOLUTO=1MB. "
            "Prevale il limite ASSOLUTO (1 MB), perchè i primi due sono troppo "
            "piccoli per essere statisticamente significativi. "
            "Questo caso valida l'introduzione del terzo termine."
        ),
        "v_out":     80 * 1024 * 1024,
        "v_mediano": 500 * 1024,         # 500 KB
        "mad":        50 * 1024,         # 50 KB
        "attesi": {
            "M_vol": 1,
            "mad_eff": 1024 * 1024,      # 1 MB (limite assoluto)
        },
    },

    # =========================================================================
    # GRUPPO 3: Tripla condizione (verifica che ciascun filtro blocchi
    # autonomamente la metrica)
    # =========================================================================
    {
        "nome": "Sotto soglia operativa - traffico statisticamente anomalo ma piccolo",
        "descrizione": (
            "Host che invia 30 MB con mediana 5 MB e MAD 1 MB. "
            "Z robusto = 25 (significativamente anomalo) MA v_out=30 MB "
            "non supera V_MIN_OPERATIVO=50 MB. La metrica NON deve scattare: "
            "non è una vera esfiltrazione, è solo rumore statistico."
        ),
        "v_out":     30 * 1024 * 1024,
        "v_mediano":  5 * 1024 * 1024,
        "mad":        1 * 1024 * 1024,
        "attesi": {
            "M_vol": 0,                   # bloccato dalla soglia operativa
            "cond_statistica": True,      # Z passa
            "cond_direzione": True,       # direzione passa
            "cond_operativa": False,      # FALLISCE qui
        },
    },

    {
        "nome": "Direzionalità - host meno attivo del solito",
        "descrizione": (
            "Host con baseline alta (200 MB) che ora trasferisce solo 5 MB. "
            "|Z| sarebbe alto ma in direzione OPPOSTA (host meno attivo). "
            "La metrica NON deve scattare: M_vol rileva ESFILTRAZIONE, "
            "non riduzione di attività."
        ),
        "v_out":       5 * 1024 * 1024,
        "v_mediano": 200 * 1024 * 1024,
        "mad":        10 * 1024 * 1024,
        "attesi": {
            "M_vol": 0,                   # bloccato dalla direzionalità
            "cond_direzione": False,      # FALLISCE qui (v_out < mediana)
        },
    },

    {
        "nome": "Z sotto soglia - variazione modesta",
        "descrizione": (
            "Host che invia 60 MB con mediana 50 MB e MAD 10 MB. "
            "Z = 1.0, ben sotto la soglia di 3. La variazione è "
            "operativamente rilevante (>50 MB) ma statisticamente "
            "nella norma. La metrica NON deve scattare."
        ),
        "v_out":     60 * 1024 * 1024,
        "v_mediano": 50 * 1024 * 1024,
        "mad":       10 * 1024 * 1024,
        "attesi": {
            "M_vol": 0,                   # bloccato dalla soglia statistica
            "cond_statistica": False,     # FALLISCE qui (Z = 1.0)
            "cond_direzione": True,
            "cond_operativa": True,
        },
    },

    # =========================================================================
    # GRUPPO 4: Casi ai confini delle soglie
    # =========================================================================
    {
        "nome": "Z esattamente a 3 (al limite, non scatta)",
        "descrizione": (
            "Calibriamo i valori per ottenere Z = 3.0 esatto. "
            "La condizione è Z > 3 (strettamente maggiore), quindi NON deve scattare. "
            "Verifichiamo la corretta semantica del confronto."
        ),
        # Z = (v_out - mediana) / mad_eff = 3
        # Scegliamo mediana=10MB, MAD=2MB (sopra la soglia di 1MB), v_out = mediana + 3*MAD = 16 MB
        # Ma 16 MB < V_MIN_OPERATIVO. Allora scaliamo:
        # mediana=50MB, MAD=10MB, v_out = 50+30 = 80 MB
        "v_out":     80 * 1024 * 1024,
        "v_mediano": 50 * 1024 * 1024,
        "mad":       10 * 1024 * 1024,
        "attesi": {
            "M_vol": 0,                   # Z=3 non supera Z>3
            "cond_statistica": False,
            "z_robusto": 3.0,
        },
    },

    {
        "nome": "v_out esattamente a 50 MB (al limite, non scatta)",
        "descrizione": (
            "v_out = 50 MB esatti. La condizione è v_out > V_MIN_OPERATIVO "
            "(strettamente maggiore), quindi NON deve scattare."
        ),
        "v_out":     50 * 1024 * 1024,    # esattamente al limite
        "v_mediano":  5 * 1024 * 1024,
        "mad":        1 * 1024 * 1024,
        "attesi": {
            "M_vol": 0,
            "cond_operativa": False,
        },
    },

    # =========================================================================
    # GRUPPO 5: Casi particolari
    # =========================================================================
    {
        "nome": "Mediana = 0 e MAD = 0 - host completamente inattivo nella baseline",
        "descrizione": (
            "Caso patologico: host che non ha mai trasferito un byte nella "
            "baseline (es. host nuovo che si attiva per la prima volta). "
            "Sia mediana che MAD sono 0. Grazie al limite ASSOLUTO (1 MB), "
            "introdotto come raffinamento del Livello 3, MAD_eff vale 1 MB "
            "e la divisione non esplode piu' a infinito. Lo Z resta finito "
            "ma comunque enorme (~100), la metrica scatta correttamente. "
            "DOCUMENTA come l'introduzione del terzo termine abbia "
            "risolto un caso rilevato in fase di validazione."
        ),
        "v_out":     100 * 1024 * 1024,
        "v_mediano": 0,
        "mad":       0,
        "attesi": {
            "M_vol": 1,
            "mad_eff": 1024 * 1024,       # 1 MB (limite assoluto: anche con mediana=0)
            "z_robusto": 100.0,           # 100 MB / 1 MB = 100 (finito!)
            "cond_statistica": True,
            "cond_direzione": True,
            "cond_operativa": True,
        },
    },
]


# =============================================================================
# EXECUTOR DEI TEST
# =============================================================================

def confronta_valori(atteso, ottenuto, tolleranza_relativa=0.001):
    """
    Confronto robusto che gestisce:
    - bool: ==
    - int: ==
    - float: confronto con tolleranza relativa (per evitare problemi di
            precisione floating point su valori grandi come byte)
    - inf: uguaglianza esatta
    """
    if isinstance(atteso, bool) or isinstance(ottenuto, bool):
        return atteso == ottenuto
    if atteso == float('inf') or ottenuto == float('inf'):
        return atteso == ottenuto
    if atteso == float('-inf') or ottenuto == float('-inf'):
        return atteso == ottenuto
    if isinstance(atteso, (int, float)) and isinstance(ottenuto, (int, float)):
        if atteso == 0:
            return abs(ottenuto) < 1e-9
        return abs(atteso - ottenuto) / abs(atteso) < tolleranza_relativa
    return atteso == ottenuto


def esegui_test(caso):
    """
    Esegue un singolo caso di test e restituisce (passed, dettagli).
    """
    risultato = valuta_m_vol(caso["v_out"], caso["v_mediano"], caso["mad"])

    fallimenti = []
    for campo, valore_atteso in caso["attesi"].items():
        valore_ottenuto = risultato[campo]
        if not confronta_valori(valore_atteso, valore_ottenuto):
            fallimenti.append({
                "campo":    campo,
                "atteso":   valore_atteso,
                "ottenuto": valore_ottenuto,
            })

    return (len(fallimenti) == 0, risultato, fallimenti)


def stampa_risultato_test(numero, caso, passed, risultato, fallimenti):
    """
    Stampa un report leggibile del singolo caso di test.
    """
    stato = "[PASS]" if passed else "[FAIL]"
    print(f"{stato} Test {numero}: {caso['nome']}")
    print(f"       {caso['descrizione']}")
    print(f"       Input:    v_out={formatta_byte(caso['v_out'])}, "
          f"mediana={formatta_byte(caso['v_mediano'])}, "
          f"MAD={formatta_byte(caso['mad'])}")
    print(f"       Calcolo:  MAD_eff={formatta_byte(risultato['mad_eff'])}, "
          f"Z={formatta_z(risultato['z_robusto'])}")
    print(f"       Output:   M_vol={risultato['M_vol']}, "
          f"penalita={risultato['penalita']}")
    print(f"       Flags:    statistica={risultato['cond_statistica']}, "
          f"direzione={risultato['cond_direzione']}, "
          f"operativa={risultato['cond_operativa']}")

    if not passed:
        print(f"       FALLIMENTI:")
        for f in fallimenti:
            print(f"           campo '{f['campo']}': "
                  f"atteso {f['atteso']}, ottenuto {f['ottenuto']}")
    print()


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("\n" + "=" * 75)
    print("  TEST DI LIVELLO 1 - VALIDAZIONE FORMALE DELLA FORMULA M_vol")
    print("=" * 75)
    print(f"  Soglia Z robusto       : > {SOGLIA_Z}")
    print(f"  Soglia operativa V_min : > {formatta_byte(V_MIN_OPERATIVO)}")
    print(f"  Limite MAD (frazione)   : {MAD_MIN_FRAZIONE * 100:.0f}% della mediana")
    print(f"  Numero di casi di test : {len(CASI_DI_TEST)}")
    print("=" * 75 + "\n")

    passati = 0
    falliti = 0

    for i, caso in enumerate(CASI_DI_TEST, start=1):
        passed, risultato, fallimenti = esegui_test(caso)
        stampa_risultato_test(i, caso, passed, risultato, fallimenti)

        if passed:
            passati += 1
        else:
            falliti += 1

    # Report finale
    print("=" * 75)
    print("  RIEPILOGO")
    print("=" * 75)
    print(f"  Test eseguiti : {len(CASI_DI_TEST)}")
    print(f"  Passati       : {passati}")
    print(f"  Falliti       : {falliti}")
    if falliti == 0:
        print(f"\n  [OK] Tutti i test sono passati. La formula è formalmente valida.")
    else:
        print(f"\n  [!!] {falliti} test FALLITI. Verificare la formula prima "
              f"di procedere ai livelli successivi.")
    print("=" * 75 + "\n")

    return 0 if falliti == 0 else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
