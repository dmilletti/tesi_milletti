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

Calcolare una baseline sull'intero campione delle 168 ore presenta un problema legato alla stagionalità settimanale degli host aziendali (orario lavorativo vs notte, feriali vs weekend). Su 168 bucket, un host tipico ha circa 45 ore di attività lavorativa e ~123 ore di traffico nullo. La mediana viene così dominata dalla maggioranza inattiva, tendendo a valori molto bassi.

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

## 4. Soglia minima per la MAD: triplo termine

### Il problema della MAD

La formula dello $Z$-score robusto contiene la MAD al denominatore:

$$Z = \frac{|V_{out} - \tilde{V}|}{MAD}$$

Quando un host presenta traffico estremamente regolare, la MAD assume valori vicini a zero. La formula diventa instabile o esplode a $+\infty$.

### Prima formulazione: limite proporzionale alla mediana

La prima formulazione adotta un limite proporzionale alla mediana:

$$MAD_{eff} = \max(MAD, 0.10 \cdot \tilde{V})$$

In questo modo:

* Per host con dispersione naturale ampia, $MAD_{eff} = MAD$ (la formula resta inalterata).
* Per host con dispersione naturale piccola, $MAD_{eff} = 0.10 \cdot \tilde{V}$, ovvero il 10% della mediana stessa.

La scelta del fattore 0.10 è motivata osservando che la dispersione del traffico in scenari reali raramente scende sotto il 10% della media o mediana.

### Raffinamento: terzo termine

Sono stati effettuati diversi test per validare la metrica,nel test di Livello 3 (test stagionale) è stato evidenziato che la formula proporzionale è ancora vulnerabile in due scenari:

* **Host a baseline molto bassa**: un host con mediana di 10 KB ha valore minimo di 1 KB. Sufficiente per la divisione, ma molto piccolo in termini operativi; combinato con valori di $V_{out}$ medi, può ancora produrre $Z$ artificialmente alti.
* **Host a baseline nulla nella categoria corrente**: un host che non ha mai trasmesso nella fascia oraria corrente (es. ufficio nel weekend) ha mediana=0, quindi anche il limite inferiore è 0, e la divisione esplode comunque.

Per chiudere entrambi i casi viene introdotto un **terzo termine** come soglia minima:

$$MAD_{eff} = \max(MAD, 0.10 \cdot \tilde{V}, MAD_{min})$$

dove $MAD_{min} = 1 \text{ MB}$. Questo valore è un compromesso tra due esigenze:

* Abbastanza grande da rendere statisticamente non significativa qualunque variazione sotto il megabyte, neutralizzando host quasi inattivi.
* Abbastanza piccolo da non oscurare anomalie reali su host di volume medio alto; per esempio per un host con baseline 100 MB e MAD 20 MB, il termine resta dominato e non influisce.

In sintesi, il triplo limite opera così:

* Su host normali (alta varianza), prevale $MAD$ reale.
* Su host molto regolari (bassa varianza, mediana media), prevale il termine proporzionale $0.10 \cdot \tilde{V}$.
* Su host con baseline minima o nulla, prevale il termine assoluto $MAD_{min}$.

Lo $Z$-score effettivamente utilizzato diventa quindi:

$$Z_{robusto} = \frac{V_{out} - \tilde{V}}{MAD_{eff}}$$

*(Il valore assoluto viene rimosso per i motivi discussi nella sezione successiva).*

---

## 5. Soglia volumetrica minima

### Il problema dello Z-score

Lo $Z$-score è per costruzione una **metrica relativa**, infatti misura uno scostamento in unità di dispersione, senza alcuna nozione del valore assoluto in gioco. Questo apre due tipi di falsi positivi:

* **Host quasi inattivo**: mediana ≈ 100 byte/ora, $MAD_{eff}$ ≈ 10 byte; se l'host invia 50 KB (banale traffico web), $Z$ ≈ 5000. L'allarme scatterebbe per qualunque attività diversa dal traffico occasionale.
* **Auto-update/backup occasionale**: mediana 1 MB/ora, $MAD_{eff}$ ≈ 200 KB; se l'host trasferisce 20 MB (aggiornamento o sincronizzazione cloud), $Z$ ≈ 95. Lo scostamento statistico è reale, ma 20 MB non costituiscono un'esfiltrazione significativa.

In entrambi i casi, il volume coinvolto è irrilevante dal punto di vista del rischio. L'esfiltrazione di un database aziendale o di un insieme di documenti richiede tipicamente volumi di grandezza di circa decina o centinaia di megabyte.

### Doppia soglia con AND

Si aggiunge una **soglia volumetrica assoluta** che $V_{out}$ deve comunque superare, indipendentemente dallo $Z$-score:

$$V_{min} = 50 \text{ MB}$$

L'anomalia viene certificata solo se sono soddisfatte simultaneamente tre condizioni:

$$M_{vol} = 1 \iff Z_{robusto} > 3 \land V_{out} > \tilde{V} \land V_{out} > V_{min}$$

dove:

1. **$Z_{robusto} > 3$** garantisce la significatività statistica dello scostamento (regola empirica del 99.7%).
2. **$V_{out} > \tilde{V}$** garantisce la direzionalità, cioè la metrica scatta solo per scostamenti **in eccesso**, non per riduzioni del traffico.
3. **$V_{out} > V_{min}$** garantisce la significatività operativa, cioè il volume in uscita deve essere abbastanza grande da costituire una potenziale esfiltrazione.

La scelta di $V_{min} = 50$ MB rappresenta un compromesso tra sensibilità e tasso di falsi positivi, corrisponde all'ordine di grandezza di un database aziendale di medie dimensioni o di una collezione documentale rilevante.

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

$$
\begin{aligned}
MAD_{eff} &= \max(MAD, 0.10 \cdot \tilde{V}, MAD_{min}) \\
Z_{robusto} &= \frac{V_{out} - \tilde{V}}{MAD_{eff}} \\
M_{vol} &= 1 \iff Z_{robusto} > 3 \land V_{out} > \tilde{V} \land V_{out} > V_{min}
\end{aligned}
$$

dove $\tilde{V}$ e $MAD$ sono calcolati sui bucket della **baseline contestuale** (cioè stessa categoria temporale dell'ora corrente, ultimi 7 giorni), e $MAD_{min} = 1 \text{ MB}$ è la soglia minima introdotto come raffinamento dopo il test.

---

## 8. Test effettuati

La metrica è stata validata su tre livelli di test progressivi, ognuno dei quali ha permesso di scoprire problemi non visibili dalla lettura statica del codice e di migliorare il modello.

### 8.1 Livello 1 - Validazione della formula

L'obiettivo è verificare che la formula matematica produca i valori attesi su input controllati.

Sono stati effettuati 12 casi di test che esercitano in modo sistematico tutti i rami della formula:

* casi base con input normali
* tre comportamenti della soglia sulla MAD (proporzionale prevale, assoluto prevale, MAD reale prevale)
* tripla condizione di scatto, ognuna fatta fallire singolarmente
* casi ai limiti delle soglie ($Z = 3$ esatto, $V_{out} = 50$ MB esatto)
* caso particolare con $\tilde{V} = 0$ e $MAD = 0$

Tutti e 12 i casi sono passati. Per ulteriori dettagli, vedere lo script "test_m_vol_formula.py".

### 8.2 Livello 2 - Validazione tramite profili di test

L'obiettivo è verificare che la query SQL, eseguita su ClickHouse con dati controllati, produca i risultati attesi.

È stata costruita appositamente una tabella di test (`flows_test`), la quale viene popolata con quattro profili di host distinti:

| Host | Profilo | Attesa |
| --- | --- | --- |
| 10.0.0.1 | Office tranquillo (~10 MB/ora) | $M_{vol} = 0$ |
| 10.0.0.2 | Esfiltrazione (200 MB su 10 MB di baseline) | $M_{vol} = 1$, Z molto alto |
| 10.0.0.3 | Server costante a 1 MB con picco di 80 MB | $M_{vol} = 1$, limite inferiore attivo |
| 10.0.0.4 | Cold start (solo 10 bucket di storico) | escluso dal calcolo |

Tutti e quattro i profili sono stati gestiti correttamente. In particolare, l'host 10.0.0.3 ha attivato il limite inferiore come previsto, con $MAD_{eff} = 1 \text{ MB}$ e $Z$ ≈ 79. Per ulteriore dettagli vedere lo script "test_m_vol_db.py".

### 8.3 Livello 3 - Validazione della baseline

L'obiettivo è dimostrare che la baseline a tre categorie distingue correttamente lo stesso host in fasce orarie diverse.

Per testare la risposta del sistema, lo stesso host è stato osservato in tre scenari temporali distinti all'interno della settimana. Questo approccio ha permesso di lasciare intatto lo storico dei dati, andando a modificare soltanto sull'orario di riferimento della query. La funzione `now()` usata in produzione è stata infatti temporaneamente parametrizzata e sostituita con una variabile esterna denominata `ora_simulata`.

| Run | Orario | Categoria | $V_{out}$ | $\tilde{V}$ baseline | $Z$ | $M_{vol}$ |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Lunedì 14:00 | feriale_lavorativo | 15.00 MB | 14.99 MB | 0.01 | 0 |
| 2 | Lunedì 23:00 | feriale_fuoriorario | 60.00 MB | 46.94 KB | 6172.46 | 1 |
| 3 | Sabato 14:00 | weekend | 30.00 MB | (host assente) | n/d | 0 |

Tutti e tre i run passati. Il confronto tra "Run 1" e "Run 2" è significativo, infatti lo stesso host con un volume quattro volte superiore alle 23:00 viene correttamente identificato come anomalia, mentre alle 14:00 con 15 MB viene considerato normale. Per ulteriori dettagli vedere lo script "test_m_vol_seasonal.py".

### 8.4 Considerazioni sul metodo

Ogni livello di test ha fornito un contributo distinto, infatti il livello 1 valida la formula matematica, il livello 2 valida la query e l'integrazione con il database, il Livello 3 valida l'efficacia della scelta progettuale della baseline scelta.
