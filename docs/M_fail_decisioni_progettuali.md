# $M_{fail}$ - Decisioni progettuali

Questo documento raccoglie le decisioni scelte per l'implementazione della metrica $M_{fail}$ (Connection Failure Rate). Come per $M_{vol}$, rappresenta il ponte tra la formulazione astratta del piano operativo e l'implementazione SQL/Python che andrà a girare sui dati di ntopng.

A differenza delle metriche deterministiche (come $M_{rep}$, $M_{cert}$, $M_{sni}$), $M_{fail}$ è la **seconda metrica statistica** del progetto e condivide con $M_{vol}$ la struttura generale (baseline contestuale, $Z$-score robusto, MAD con limite inferiore, cold start). Le differenze nascono dal fatto che $M_{fail}$ lavora su un **rate** (frazione in $[0, 1]$) e non su un volume in byte, e questo richiede scelte numeriche diverse per le soglie.

---

## 1. Definizione di "flusso fallito"

Il primo problema di $M_{fail}$ è stabilire **quando** un flusso debba essere considerato fallito. I fallimenti di rete possono manifestarsi in modi diversi a seconda del protocollo, del tipo di guasto e del livello su cui intervergono.

### I tre tipi di fallimento

Si distinguono tre famiglie di comportamenti:

* **No response**: il server non risponde mai. Si tratta del caso più semplice da rilevare, perché nei dati osserviamo `SRC2DST_PACKETS > 0` ma `DST2SRC_PACKETS = 0`. È la firma di firewall che droppano i pacchetti senza rispondere, host spenti, oppure query DNS che vanno in timeout.

* **Rejection**: il server o un intermediario risponde con un errore. Il flusso è bidirezionale (`DST2SRC_PACKETS >= 1`), ma il contenuto della risposta è un rifiuto, per esempio un TCP RST, una risposta DNS `NXDOMAIN`, un HTTP 4xx/5xx, un ICMP "port unreachable". È particolarmente importante perché è la firma classica del **DGA** (Domain Generation Algorithm), dove il malware genera centinaia di domini casuali e riceve NXDOMAIN per quasi tutti.

* **Connection close**: l'handshake si completa ma il flusso si chiude con un RST anomalo invece che con un FIN pulito. Caso meno comune ma comunque importante.

### La scelta dei valori da analizzare

Una definizione basata solo su `DST2SRC_PACKETS = 0` catturerebbe solo il primo tipo e perderebbe completamente i DGA (che è il bersaglio principale della metrica). Per coprire tutte e tre i tipi vengono analizzati i bit della bitmap `FLOW_RISK` prodotta da nDPI.

I bit selezionati sono cinque, scelti consultando l'enum `ndpi_risk_enum` nel file `src/include/ndpi_typedefs.h` del repository ufficiale di nDPI:

| Bit | Nome simbolico | Cosa cattura |
| --- | --- | --- |
| 43 | `NDPI_ERROR_CODE_DETECTED` | NXDOMAIN sul DNS, codici di errori HTTP 4xx/5xx |
| 46 | `NDPI_UNIDIRECTIONAL_TRAFFIC` | Flussi unidirezionali, nDPI esclude automaticamente multicast e broadcast |
| 50 | `NDPI_TCP_ISSUES` | Problemi TCP come connection refused (RST), scan, mapping |
| 51 | `NDPI_UNRESOLVED_HOSTNAME` | Hostname mai osservato in una richiesta di risoluzione DNS precedente, indicatore tipico di DGA |
| 55 | `NDPI_PROBING_ATTEMPT` | Connessione senza scambio di dati con invio di pacchetti specifici per il probing |

Un flusso viene considerato fallito se è vera **almeno una** fra:

* `DST2SRC_PACKETS = 0`, oppure
* se uno dei cinque bit di `FLOW_RISK` è stato settato a 1.

In SQL la condizione viene espressa con una bitmask compatta, evitando di concatenare cinque controlli OR separati:

```sql
DST2SRC_PACKETS = 0
OR bitAnd(FLOW_RISK, FLOW_RISK_FAIL_BITMASK) != 0
```

dove `FLOW_RISK_FAIL_BITMASK` è il risultato dell'OR di $(1 \ll 43)$, $(1 \ll 46)$, $(1 \ll 50)$, $(1 \ll 51)$, $(1 \ll 55)$.

---

## 2. Definizione del rate e aggregazione in bucket orari

Una volta definito cosa significa "flusso fallito", la metrica calcola il **rapporto** tra flussi falliti e flussi totali per ogni host:

$$
r_t(h, t) = \frac{|F_{fail}(h, t)|}{|F_{tot}(h, t)|}
$$

dove $F_{tot}(h, t)$ è l'insieme dei flussi originati dall'host $h$ verso destinazioni esterne nell'ora $t$, e $F_{fail}(h, t) \subseteq F_{tot}(h, t)$ è il sottoinsieme di quelli falliti.

Come per $M_{vol}$, l'aggregazione avviene in **bucket orari**. L'asse temporale viene partizionato in finestre da 60 minuti e tutti i flussi che ricadono in una stessa finestra vengono usati per calcolare il rate di quel bucket. Su 7 giorni di osservazione si ottengono 7 × 24 = 168 bucket per host, ciascuno con il proprio valore di rate.

La scelta di un'ora come unità di aggregazione è la stessa di $M_{vol}$ e per le stesse motivazioni. Bucket più piccoli sono sensibili a fluttuazioni istantanee legittime invece bucket più grandi non hanno abbastanza campioni per stimare la dispersione.

---

## 3. Baseline contestuale

La struttura della baseline è **identica** a quella di $M_{vol}$. La motivazione infatti è la stessa, la stagionalità settimanale degli host aziendali (orario lavorativo vs notte, feriali vs weekend) inquina una baseline calcolata sull'intero campione delle 168 ore. Vengono quindi mantenute le tre categorie temporali:

| Categoria | Definizione | Bucket attesi (settimana tipo) |
| --- | --- | --- |
| `feriale_lavorativo` | lun-ven, ore 9-17 | ~45 |
| `feriale_fuoriorario` | lun-ven, ore 0-8 e 18-23 | ~75 |
| `weekend` | sab-dom, tutte le ore | ~48 |

Per ogni host, alla fine di ogni ora $t$, vengono recuperati i bucket della baseline appartenenti alla stessa categoria di $t$, e su questi vengono calcolate la mediana del rate ($\tilde{r}$) e la MAD.

---

## 4. Limite sulla MAD

### Il problema della MAD su un rate

La formula dello $Z$-score robusto contiene la MAD al denominatore:

$$
Z = \frac{r_t - \tilde{r}}{MAD}
$$

Come per $M_{vol}$, un host con comportamento estremamente regolare presenta MAD vicina a zero e la formula esplode. Su $M_{fail}$ il problema si manifesta in modo ancora più estremo perché molti host hanno baseline **esattamente** a zero, per esempio un server interno che parla solo con altri server raggiungibili, ha rate di fallimento sempre 0 nei suoi 168 bucket, quindi mediana = 0 e MAD = 0.

### Perché non si usa il triplo termine di $M_{vol}$

In $M_{vol}$ è stato adottato un triplo termine:

$$
MAD_{eff} = \max(MAD, 0.10 \cdot \tilde{V}, MAD_{min})
$$

Il termine proporzionale ($0.10 \cdot \tilde{V}$) ha senso sui volumi, perché variano su molti ordini di grandezza, da pochi KB a centinaia di MB. Un limite proporzionale scala con la grandezza dell'host.

Su un rate questa logica non si applica. Il rate vive sempre nell'intervallo $[0, 1]$, quindi non c'è una variabilità di scala da gestire. Il termine proporzionale diventerebbe quasi sempre dominato da quello assoluto:

* Mediana 1% -> termine proporzionale = $0.001$ (assolutamente trascurabile)
* Mediana 5% -> termine proporzionale = $0.005$
* Mediana 50% -> termine proporzionale = $0.05$ (qui inizia a competere con il limite assoluto)

Solo per host che operano già a un rate mediano del 50% il termine proporzionale eguaglia il limite assoluto, ma sono casi rari e non vale la pena complicare la formula.

### Scelta del limite assoluto

Viene quindi adottato **un solo termine**, assoluto:

$$
MAD_{eff} = \max(MAD, MAD_{min})
$$

con $MAD_{min} = 0.05$ (cinque punti percentuali).

La scelta del valore è un compromesso analogo a quello fatto per $V_{min}$ in $M_{vol}$:

* Abbastanza grande da neutralizzare il rumore, per esempio, se $MAD_{min}$ fosse 0.001, un host con storia "tutto a zero" che oggi sale all'1% darebbe $Z = 10$. Poco tollerante.
* Abbastanza piccolo da non oscurare anomalie reali, per esempio, se $MAD_{min}$ fosse 0.30, per far scattare $Z > 3$ servirebbe uno scostamento di almeno il 90%, intercettando solo host completamente compromessi.

Cinque punti percentuali significa che scostamenti dell'ordine del 15-20% in valore assoluto rispetto alla baseline possono far scattare la metrica, mentre fluttuazioni dell'1-3% ancora no.

Lo $Z$-score effettivamente utilizzato diventa quindi:

$$
Z_{robusto} = \frac{r_t - \tilde{r}}{MAD_{eff}}
$$

*(Anche qui il valore assoluto viene rimosso per i motivi discussi nella sezione successiva).*

---

## 5. Doppia soglia operativa

### Il problema dello Z-score su un rate

Come per $M_{vol}$, lo $Z$-score è una metrica relativa che misura uno scostamento in unità di dispersione, senza nozione del valore assoluto. Su un rate questa caratteristica apre falsi positivi specifici:

* **Host con baseline a rate molto basso**: mediana 0.1%, $MAD_{eff}$ = 0.05; se oggi il rate sale al 2%, $Z$ = 0.38, sembra protetto. Ma con $MAD$ reale di 0.001, lo $Z$ senza floor sarebbe stato 19, e la metrica sarebbe scattata per un cambiamento trascurabile (da 0.1% a 2%).
* **Sample size piccolo**: un host con 3 flussi totali e 1 fallito ha rate = 33%. È rumore statistico, non un'anomalia.

Entrambi i casi richiedono soglie esplicite, non solo statistiche.

### La doppia soglia su un rate

Su un rate non basta una soglia operativa singola come quella di $M_{vol}$ ($V_{min}$ = 50 MB), perché il rate è un *rapporto* e ha due punti deboli da proteggere separatamente:

* **Significatività del rate stesso**: il valore di $r_t$ in valore assoluto deve essere abbastanza alto da indicare un host in sofferenza reale.
* **Significatività del campione su cui il rate è calcolato**: il numero di flussi totali nell'ora corrente deve essere abbastanza grande perché il rate sia statisticamente affidabile.

Vengono quindi introdotte **due soglie**:

$$
\begin{aligned}
R_{min} &= 0.30 \quad \text{(rate minimo)} \\
N_{min} &= 50 \quad \text{(sample size minimo dell'ora corrente)}
\end{aligned}
$$

La scelta di $R_{min} = 0.30$ è motivata dall'osservazione che un host che fallisce il 30% delle sue connessioni in un'ora è già un host palesemente in difficoltà. Sotto questa soglia, anche uno $Z$-score elevato indica solo che l'host ha cambiato comportamento, non che sia compromesso.

La scelta di $N_{min} = 50$ è motivata dalla statistica di base. Con 50 osservazioni l'errore del rate è dell'ordine di alcuni punti percentuali per rate intorno al 50% (sufficiente per discriminare scostamenti del 20-30%); con sample size più piccoli il rate fluttuerebbe troppo per essere significativo.

### Tripla condizione di scatto

A queste due soglie operative si aggiunge la condizione di direzionalità (analoga a quella di $M_{vol}$). Qui ci interessano solo gli **aumenti** del rate di fallimento, non i miglioramenti., quindi la condizione finale diventa:

$$
M_{fail} = 1 \iff Z_{robusto} > 3 \land r_t > \tilde{r} \land r_t > R_{min} \land N_{tot} \geq N_{min} \land \text{bucket}_{baseline} \geq 30
$$

dove:

1. **$Z_{robusto} > 3$** garantisce la significatività statistica dello scostamento (regola empirica del 99.7%).
2. **$r_t > \tilde{r}$** garantisce la direzionalità, cioè la metrica scatta solo per aumenti del rate, non per riduzioni.
3. **$r_t > R_{min}$** garantisce la significatività operativa del rate.
4. **$N_{tot} \geq N_{min}$** garantisce la significatività statistica del campione corrente.
5. **$\text{bucket}_{baseline} \geq 30$** è il filtro cold start (sezione successiva).

Rispetto a $M_{vol}$, $M_{fail}$ ha **cinque condizioni in AND invece di tre**. Il motivo è strutturale, infatti generalmente un rate è intrinsecamente più "rumoroso" di un volume, perché basta poco per farlo schizzare in percentuale, mentre per spostare di molto un volume in byte servono davvero molti pacchetti. Le due condizioni in più (soglia operativa sul rate e sample size) servono a proteggere la metrica da questo rumore di fondo.

### Limite noto: attacchi "low-and-slow" per DGA

Una soglia di rate del 30% non rileva DGA che generano poche query a bassa frequenza, distribuite su molte ore. Per esempio, un malware che genera 5 query NXDOMAIN ogni ora (e per il resto fa traffico legittimo) rimarrebbe sotto la soglia. Questa è la versione DGA del problema *low-and-slow* già identificato come limite strutturale del modello.

---

## 6. Gestione del cold start

Il filtro cold start è **identico** a quello di $M_{vol}$. Un host osservato da troppe poche ore nella categoria temporale corrente viene escluso dal calcolo.

**MIN_BASELINE_HOURS = 30**

Se la baseline contestuale dell'host contiene meno di 30 bucket validi (nella categoria temporale corrente, sui 7 giorni di storico), l'host viene escluso dal calcolo per quel ciclo. La metrica $M_{fail}$ rimane inattiva ($M_{fail} = 0$) fino a che non si accumula uno storico sufficiente.

In caso in cui un host è stato osservato solo per due giorni feriali avrà baseline weekend vuota, quindi $M_{fail}$ non scatta durante il primo weekend di osservazione.

---

## 7. Formula finale di $M_{fail}$

Combinando tutti gli elementi sopra descritti, la formula implementata diventa:

$$
\begin{aligned}
r_t &= \frac{|F_{fail}|}{|F_{tot}|} \\
MAD_{eff} &= \max(MAD, MAD_{min}) \\
Z_{robusto} &= \frac{r_t - \tilde{r}}{MAD_{eff}} \\
M_{fail} &= 1 \iff Z_{robusto} > 3 \land r_t > \tilde{r} \land r_t > R_{min} \land N_{tot} \geq N_{min} \land \text{bucket}_{baseline} \geq 30
\end{aligned}
$$

dove:

* $\tilde{r}$ e $MAD$ sono calcolati sui bucket della baseline contestuale (cioè stessa categoria temporale dell'ora corrente, ultimi 7 giorni);
* $MAD_{min} = 0.05$ è il limite inferiore assoluto sulla MAD;
* $R_{min} = 0.30$ è la soglia sul rate;
* $N_{min} = 50$ è il sample size minimo dell'ora corrente;
* $F_{fail}$ è definito dalla bitmask sui cinque bit nDPI 43, 46, 50, 51, 55 in OR con `DST2SRC_PACKETS = 0`.

---

## 8. Test effettuati

La metrica è stata validata su due livelli di test, lo stesso approccio adottato per $M_{vol}$. Non è stato eseguito un livello 3 stagionale perché la baseline contestuale di $M_{fail}$ è identica a quella di $M_{vol}$ e la sua efficacia è già stata dimostrata dai test di $M_{vol}$ livello 3.

### 8.1 Livello 1 - Validazione della formula

L'obiettivo è verificare che la formula matematica produca i valori attesi su input controllati. Sono stati esaminati sei casi che coprono i rami principali della formula:

* caso base con $Z > 3$ e tutte le soglie superate (la metrica scatta)
* caso con $Z > 3$ ma $r_t < R_{min}$ (soglia operativa blocca lo scatto)
* caso con $r_t < \tilde{r}$ (direzionalità blocca lo scatto, host migliorato)
* caso con $N_{tot} < N_{min}$ (sample size insufficiente blocca lo scatto)
* caso con $MAD = 0$ e $\tilde{r} = 0$ (test del limite sulla MAD)
* caso ai limiti delle soglie ($Z = 3$ esatto, $r_t = 0.30$ esatto)

Tutti e sei i casi producono il valore atteso. La verifica è stata fatta calcolando a mano lo $Z$-score e confrontandolo con la quintupla condizione, senza necessità di uno script dedicato. La formula è abbastanza semplice da non richiedere una validazione automatizzata.

### 8.2 Livello 2 - Validazione tramite profili di test

L'obiettivo è verificare che la query SQL, eseguita su ClickHouse con dati controllati, produca i risultati attesi.

È stata costruita una tabella di test `flows_test` (replica dello schema della tabella `flows`), popolata con quattro profili di host distinti:

| Host | Profilo | Attesa |
| --- | --- | --- |
| 10.0.0.1 | Office tranquillo (~150 flussi/ora, 1-3% di fallimenti) | $M_{fail} = 0$ |
| 10.0.0.2 | DGA via DNS (85% di fallimenti con mix di bit 51 e 43) | $M_{fail} = 1$, Z molto alto |
| 10.0.0.3 | Host molto regolare (rate sempre 0% nella baseline) con picco al 40% | $M_{fail} = 1$, limite MAD attivo |
| 10.0.0.4 | Cold start (solo 10 bucket di storico) | escluso dal calcolo |

I dati storici di ciascun host vengono distribuiti su sette giorni con timestamp realistici, in modo che la query incontri esattamente la configurazione attesa. Lo script esegue poi la query reale di $M_{fail}$ sulla tabella `flows_test` e confronta i risultati con le attese per ciascun profilo.

Il profilo dell'host 10.0.0.2 (DGA) usa una distribuzione mista dei bit di fallimento, dove metà dei flussi falliti portano il bit 51 (`UNRESOLVED_HOSTNAME`) e metà il bit 43 (`ERROR_CODE_DETECTED`), per simulare il comportamento realistico in cui il malware riceve NXDOMAIN dal DNS per la maggior parte dei domini generati e HTTP 4xx dai pochi C2 raggiungibili. Il profilo dell'host 10.0.0.3 (test del limite MAD) usa il bit 50 (`TCP_ISSUES`) per generare i fallimenti correnti.

Tutti e quattro i profili sono stati gestiti correttamente. In particolare, l'host 10.0.0.3 ha attivato il limite inferiore come previsto, con $MAD_{eff} = 0.05$ a fronte di una $MAD$ reale di 0, e $Z = 8$. Per ulteriori dettagli vedere lo script `test_m_fail_db.py`.

### 8.3 Bug scoperto durante il livello 2

Durante la prima esecuzione del livello 2, l'host 10.0.0.3 risultava inaspettatamente assente dai risultati nonostante lo $Z$-score fosse ben sopra la soglia. L'analisi ha rivelato un bug nel **generatore di dati di test**, non nella metrica.

La funzione `genera_bucket_categoria` includeva tra i bucket della baseline anche quello immediatamente precedente all'ora corrente. I flussi generati al suo interno, distribuiti con offset random fino all'incirca 58 minuti rispetto all'inizio del bucket, finivano a cavallo della soglia `now() - 1 HOUR` usata dalla query per separare baseline e ora corrente. Una parte di questi flussi (generati come riusciti) finiva quindi a contaminare la CTE `flussi_correnti`, diluendo il rate.

Per l'host 10.0.0.3 questo riduceva il rate corrente da 40% atteso a circa il 27%, sotto la soglia $R_{min} = 0.30$, causando l'esclusione dalla SELECT finale. Per l'host 10.0.0.2 la stessa diluizione c'era ma il rate rimaneva sopra la soglia (54% effettivo invece di 85% atteso).

Per rimediare a questo problema, è stato esteso il buffer di esclusione a due ore invece di una nella funzione `genera_bucket_categoria`, e limitare l'offset random a 50 minuti invece di 58 (`random.randint(1, 3000)` invece di `random.randint(1, 3500)`). Questa scelta garantisce che nessun flusso della baseline possa sforare nella finestra corrente, mantenendo comunque 44 bucket utili per la categoria `feriale_lavorativo`, ampiamente sopra il `MIN_BASELINE_HOURS = 30`.

Il bug è interamente del generatore di test e non del codice di produzione. La query di $M_{fail}$ ha funzionato correttamente in entrambi i casi, escludendo l'host che non superava la soglia operativa.

### 8.4 Considerazioni sul metodo

Il livello 1 valida la formula matematica, il livello 2 valida la query e l'integrazione con il database. La copertura dei quattro profili è equivalente a quella di $M_{vol}$ e copre tutti i tipi di comportamento della metrica come il caso negativo standard, caso positivo (DGA), test del limite sulla MAD, filtro cold start.

Tre dei cinque bit nDPI sono testati nei profili (bit 43, 50, 51); i restanti (46 e 55) condividono lo stesso ramo della query, perché entrano tutti nella medesima operazione `bitAnd` con la bitmask, quindi la loro corretta gestione è garantita per costruzione.
