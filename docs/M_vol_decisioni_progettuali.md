# $M_{vol}$ - Decisioni progettuali

Questo documento raccoglie le decisioni scelte per l'implementazione della metrica $M_{vol}$ (Asimmetria volumetrica in uscita). Rappresenta il ponte tra la formulazione astratta del piano operativo e l'implementazione SQL/Python che andrà a girare sui dati di ntopng.

---

## 1. Definizione operativa di $V_{out}$

Per un host interno che agisce come **client** del flusso:

* `SRC2DST_BYTES` rappresenta i byte trasmessi dal client al server (quindi inviati **dall'host monitorato**).
* `DST2SRC_BYTES` rappresenta i byte trasmessi dal server al client (quindi ricevuti **dall'host monitorato**).

Per questa metrica:

```math
V_{out}(h, t) = \sum_{f \in F_{out}(h, t)} \text{SRC2DST\_BYTES}(f)

```

dove $F_{out}(h, t)$ è l'insieme dei flussi originati dall'host $h$ verso destinazioni esterne nell'ora $t$.

---

## 2. Aggregazione in bucket orari

Come tipologia di analisi è stata scelta quella di **bucket orari**. Per ogni host, l'asse temporale viene partizionato in finestre da 60 minuti e tutti i flussi che ricadono in una stessa finestra vengono aggregati sommando i loro byte. Ogni bucket diventa così **un singolo campione** del dataset statistico.

Su 7 giorni di osservazione si ottengono 7 × 24 = 168 bucket per host.

* Bucket più piccoli (es. 5 minuti) generano ~2000 campioni, ma sono sensibili a picchi istantanei legittimi che inquinano la statistica.
* Bucket più grandi (es. 24 ore) generano ~7 campioni, troppo pochi per una buona stima della dispersione.

---

## 3. Baseline: multi filtro temporale

### Il problema della stagionalità settimanale

Calcolare una baseline sull'intero campione delle 168 ore presenta un problema legato alla **stagionalità settimanale** degli host aziendali (orario lavorativo vs notte, feriali vs weekend).". Su 168 bucket, un host tipico ha circa 45 ore di attività lavorativa e ~123 ore di traffico nullo. La mediana viene così dominata dalla maggioranza inattiva, tendendo a valori molto bassi.

La conseguenza è che il lunedì mattina, quando l'host riprende la normale attività lavorativa, $V_{out}$ (volume totale dei byte in uscita) può apparire come un picco anomalo rispetto a una mediana basata principalmente su notti e weekend. Questo è un falso positivo.

### Filtro prima dell'aggregazione

La baseline rimane di 7 giorni, ma nel confronto con il valore corrente vengono utilizzati **solo i bucket della stessa categoria temporale**. Vengono definite tre categorie:

| Categoria | Definizione | Bucket attesi (settimana tipo) |
| --- | --- | --- |
| `feriale_lavorativo` | lun-ven, ore 9-17 | ~45 |
| `feriale_fuoriorario` | lun-ven, ore 0-8 e 18-23 | ~75 |
| `weekend` | sab-dom, tutte le ore | ~48 |

Ogni categoria mantiene un numero di campioni statisticamente accettabile (> 30). L'ora corrente viene confrontata solo con bucket della baseline che condividono la stessa categoria, riducendo i falsi positivi.

---

## 4. MAD proporzionale alla mediana

### Il problema della MAD

La formula dello $Z$-score robusto contiene la MAD al denominatore:

```math
Z = \frac{|V_{out} - \tilde{V}|}{MAD}

```

Quando un host presenta traffico estremamente regolare, la MAD assume valori vicini a zero. La formula diventa instabile o esplode in $+\infty$.

Si introduce una **MAD effettiva** che impone un valore minimo proporzionale alla scala dell'host:

```math
MAD_{eff} = \max(MAD, 0.10 \cdot \tilde{V})

```

In questo modo:

* Per host con dispersione naturale ampia, $MAD_{eff} = MAD$ (la formula resta inalterata).
* Per host con dispersione naturale piccola o nulla, $MAD_{eff} = 0.10 \cdot \tilde{V}$, ovvero il **10%** della mediana stessa.

La scelta del fattore **0.10** è state scelta osservando che la dispersione del traffico in scenari reali raramente scende sotto il 10% della media o mediana.

Lo $Z$-score effettivamente utilizzato diventa quindi:

```math
Z_{robusto} = \frac{V_{out} - \tilde{V}}{MAD_{eff}}

```

*(Il valore assoluto viene rimosso per i motivi discussi nella sezione successiva).*

---

## 5. Soglia volumetrica minima

### Il problema dello Z-score

Lo $Z$-score è per costruzione una **metrica relativa**, infatti misura uno scostamento in unità di dispersione, senza alcuna nozione del valore assoluto in gioco. Questo apre due tipi di falsi positivi:

* **Host quasi inattivo**: mediana ≈ 100 byte/ora, $MAD_{eff}$ ≈ 10 byte; se l'host invia 50 KB (banale traffico web), $Z$ ≈ 5000. L'allarme scatterebbe per qualunque attività diversa dal traffico occasionale.
* **Auto-update/backup occasionale**: mediana 1 MB/ora, $MAD_{eff}$ ≈ 200 KB; se l'host trasferisce 20 MB (aggiornamento o sincronizzazione cloud), $Z$ ≈ 95. Lo scostamento statistico è reale, ma 20 MB non costituiscono un'esfiltrazione significativa.

In entrambi i casi, il volume coinvolto è irrilevante dal punto di vista del rischio operativo. L'esfiltrazione di un database aziendale o di un insieme di documenti richiede tipicamente volumi di grandezza di circa decina o centinaia di megabyte.

### Doppia soglia con AND

Si aggiunge una **soglia volumetrica assoluta** che $V_{out}$ deve comunque superare, indipendentemente dallo $Z$-score:

```math
V_{min} = 50 \text{ MB}

```

L'anomalia viene certificata solo se sono soddisfatte simultaneamente tre condizioni:

```math
M_{vol} = 1 \iff Z_{robusto} > 3 \land V_{out} > \tilde{V} \land V_{out} > V_{min}

```

dove:

1. **$Z_{robusto} > 3$** garantisce la significatività statistica dello scostamento (regola empirica del **99.7%**).
2. **$V_{out} > \tilde{V}$** garantisce la direzionalità, cioè la metrica scatta solo per scostamenti **in eccesso**, non per riduzioni del traffico.
3. **$V_{out} > V_{min}$** garantisce la significatività operativa, cioè il volume in uscita deve essere abbastanza grande da costituire una potenziale esfiltrazione.

La scelta di $V_{min} = 50$ MB rappresenta un compromesso tra sensibilità e tasso di falsi positivi; corrisponde all'ordine di grandezza di un database aziendale di medie dimensioni o di una collezione documentale rilevante.

### Limite noto: attacchi "low-and-slow"

Una soglia assoluta di 50 MB/ora non rileva esfiltrazioni distribuite su molte ore a basso rate (es. 5 MB/ora per 20 ore). Questa è la classe di attacchi *low-and-slow*, già identificata come limite strutturale del modello nel paragrafo dei limiti del README.

---

## 6. Gestione del cold start

Un host osservato da troppo poche ore non ha una baseline statisticamente significativa. Si stabilisce un **minimo di campioni** necessari per attivare la metrica:

**MIN_BASELINE_HOURS = 30**

Se la baseline contestuale dell'host contiene meno di 30 bucket validi (nella categoria temporale corrente, sui 7 giorni di storico), l'host viene escluso dal calcolo per quel ciclo. La metrica $M_{vol}$ rimane inattiva ($M_{vol} = 0$) fino a che non si accumula uno storico sufficiente.

In casi limite dove nuovi host sono stati osservati solo (per esempio) per due giorni feriali, la baseline *weekend* potrebbe essere vuota e quindi $M_{vol}$ non scatta durante il primo weekend di osservazione.

---

## 7. Formula finale di $M_{vol}$

Combinando tutti gli elementi sopra descritti, la formula implementata diventa:

```math
\begin{aligned}
MAD_{eff} &= \max(MAD, 0.10 \cdot \tilde{V}) \\
Z_{robusto} &= \frac{V_{out} - \tilde{V}}{MAD_{eff}} \\
M_{vol} &= 1 \iff Z_{robusto} > 3 \land V_{out} > \tilde{V} \land V_{out} > V_{min}
\end{aligned}

```

dove $\tilde{V}$ e $MAD$ sono calcolati sui bucket della **baseline contestuale** (cioè stessa categoria temporale dell'ora corrente, ultimi 7 giorni).

---

## 8. Output atteso dello script

Per garantire coerenza con le metriche precedenti e con il futuro modulo `scoring.py`, il dizionario di output di `calcola_m_vol()` rispetta lo stesso pattern delle altre metriche, esteso con i dettagli statistici utili per il report.

```python
{
    "192.168.1.45": {
        "M_vol":              1,
        "v_out_corrente":     78_643_200,    # byte nell'ora corrente
        "mediana_baseline":   12_582_912,    # x̃ della categoria temporale
        "mad_baseline":       3_145_728,     # MAD grezza
        "mad_effettiva":      3_145_728,     # MAD dopo floor
        "z_robusto":          21.0,          # Z-score effettivo
        "categoria_temporale": "feriale_lavorativo",
        "bucket_baseline":    44,            # campioni usati per la baseline
        "penalita":           20,
        "timestamp":          "2026-05-19T14:00:00+00:00"
    }
}

```
