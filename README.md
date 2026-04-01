# Analisi Comportamentale degli Host e Valutazione del Rischio di Rete

**Obiettivo:** Definire formalmente un modello matematico in grado di valutare lo stato di sicurezza di un'infrastruttura IT e rispondere alla domanda principale: "La mia rete è sicura?". Attraverso un approccio non invasivo (l'analisi passiva del traffico), il modello valuta il profilo dei singoli host unendo metriche deterministiche e statistiche. Lo scopo è andare oltre la semplice ricerca di minacce già conosciute (il classico approccio "bianco o nero"), per identificare variazioni anomale di comportamento ed eventi mai visti prima nella cosiddetta "zona grigia". In questo modo è possibile misurare il livello di anomalia del singolo nodo e, di conseguenza, calcolare il rischio dell'intera rete.

---

## 1. L'Equazione Generale del Sospetto

Il grado di sospetto di un host $h$ in un dato istante è definito dallo *Score Globale* $S(h)$. Abbandonando le logiche binarie, il modello adotta un sistema di **punteggio di rischio additivo espresso in centesimi** (da 0 a 100). L'equazione è una somma delle penalità assegnate per ogni anomalia rilevata, limitata superiormente:

$$S(h) = \min\left(100, \sum_{i=1}^{n} p_i \cdot M_i(h)\right)$$

Dove:
* $M_i(h) \in \{0, 1\}$ è il valore booleano restituito dalla singola metrica valutata (es. anomalia volumetrica, automazione temporale, reputazione IP).
* $p_i$ rappresenta il punteggio di penalità o la gravità assegnata all'indicatore (es. 10, 30 o 50 punti a seconda della criticità dell'evento).

Le metriche appartengono a due classi logiche distinte: **Deterministiche** e **Statistiche**.

---

## 2. Calcolo delle Metriche Deterministiche

Queste metriche valutano eventi puntuali basati su logica booleana (es. corrispondenza di un hash crittografico JA3 con firme malware o contatti verso IP/domini in blacklist). Il calcolo non richiede uno storico: l'osservazione attuale viene confrontata in tempo reale con un set di dati noto.

* Rilevata corrispondenza (match positivo): $M_i(h) = 1$
* Assenza di corrispondenza: $M_i(h) = 0$

---

## 3. Calcolo delle Metriche Comportamentali (Analisi della "Zona Grigia")

Le metriche comportamentali non cercano minacce note, ma esplorano la cosiddetta **"zona grigia"**: traffico apparentemente legittimo che risulta sospetto perché eccessivo, fuori orario, troppo rigido o totalmente inedito per quello specifico host. 
Per valutare questa tipologia di anomalie, il modello utilizza due approcci matematici distinti: l'analisi degli **scostamenti statistici** (per le variazioni quantitative) e la **Novelty Detection** (rilevamento delle novità assolute).

### Fase 3.1: Profilazione Storica (Baseline Robusta)
Per le variabili continue (es. volume di byte, frequenza temporale delle connessioni), il comportamento normale dell'host è modellato calcolando due indicatori su una finestra temporale storica (es. 7 giorni):
* **Mediana ($\tilde{x}$):** Rappresenta il valore centrale e tipico del traffico per quell'host.
* **MAD (Median Absolute Deviation):** Quantifica la dispersione fisiologica dei dati rispetto alla mediana, calcolata come:

$$MAD = \text{Mediana}(|x_i - \tilde{x}|)$$

L'utilizzo di $\tilde{x}$ e $MAD$ risulta matematicamente più solido rispetto a Media e Deviazione Standard, in quanto intrinsecamente immune ai fisiologici outlier del traffico di rete (es. picchi legittimi dovuti a download occasionali).

### Fase 3.2: Misurazione dello Scostamento Statistico (Z-Score Robusto)
Per misurare formalmente una deviazione quantitativa, si calcola la distanza dell'osservazione attuale $x$ dalla baseline, utilizzando lo **Z-Score Robusto**:

$$Z_{robusto} = \frac{|x - \tilde{x}|}{MAD}$$

Questa equazione restituisce un valore standardizzato. Se $Z_{robusto}$ supera una soglia di tolleranza conservativa $\theta$ (es. $Z > 3$, per coprire il 99.7% dei casi normali), l'evento è classificato come un'anomalia statistica.

### Fase 3.3: Rilevamento delle Novità Assolute (Novelty Detection)
Per valutare gli eventi "mai visti prima" (variabili discrete come l'uso di nuovi protocolli applicativi o servizi logici inediti), l'approccio statistico non è applicabile. Si utilizza quindi la teoria degli insiemi abbinata alla *Deep Packet Inspection*.
Sia $P_{storico}$ l'insieme dei protocolli applicativi (es. HTTP, DNS) utilizzati dall'host nel periodo di profilazione, e $P_{oggi}$ l'insieme rilevato nell'osservazione odierna. La novità ($N$) è calcolata tramite l'insieme differenza:

$$N = P_{oggi} \setminus P_{storico}$$

Se l'insieme $N$ non è vuoto ($N \neq \emptyset$), significa che l'host sta esibendo un comportamento strutturalmente inedito, attivando la relativa metrica di anomalia.

### Fase 3.4: Le Tre Dimensioni dell'Anomalia
Combinando la statistica e la teoria degli insiemi, il modello analizza la "zona grigia" esplorando il traffico di rete attraverso tre dimensioni logiche fondamentali. Questo approccio generalista permette di classificare le anomalie senza dipendere da specifici software di monitoraggio:

* **Dimensione Quantitativa (Quanto comunica?):** Sfruttando lo $Z_{robusto}$, il sistema misura le variazioni di volume (es. quantità di byte trasferiti o numero di connessioni). Questo permette di rilevare picchi eccezionali che potrebbero indicare un'esfiltrazione di dati o un abuso delle risorse, anche se il traffico è diretto verso destinazioni apparentemente lecite.
* **Dimensione Strutturale (Come comunica?):** Attraverso la *Novelty Detection*, il modello rileva i comportamenti del tutto inediti. Identificare l'uso di nuovi protocolli applicativi o di servizi mai utilizzati prima dall'host è fondamentale per intercettare tentativi di ricognizione interna, aggiramenti dei firewall o l'apertura di canali di comunicazione nascosti.
* **Dimensione Temporale (Umano vs Macchina):** Analizzando la regolarità del traffico nel tempo, il sistema valuta il "ritmo" delle comunicazioni. Questo parametro è vitale per distinguere il comportamento naturale e irregolare di un utente umano, dalla precisione matematica, rigida e periodica, tipica dei malware e dei processi automatizzati (es. il *beaconing* di una macchina infetta verso il suo server di controllo).

---

## 4. Correlazione Multidimensionale: Quando un Host diventa "Sospetto"

Come evidenziato dall'equazione dello *Score Globale* $S(h)$, il modello non si basa sulla valutazione di una singola metrica isolata, bensì sulla loro aggregazione. 

Nelle reti moderne, un singolo evento anomalo (i cosiddetti "segnali deboli") è spesso insufficiente per classificare un host come critico. Ad esempio, un *port-scan* isolato verso la rete interna potrebbe essere l'azione legittima di un amministratore di sistema. 

Un host viene definito "sospetto" (o in stato critico) solo quando si verifica una **convergenza di più anomalie** su assi dimensionali diversi. Matematicamente, questa correlazione è gestita dalla somma dei punteggi di penalità:

* **Caso A (Segnale isolato):** Se l'host esegue unicamente una scansione di rete, si attiverà solo la relativa metrica. Lo *Score* finale $S(h)$ crescerà esclusivamente dei punti assegnati a tale anomalia (es. +30 punti), mantenendo l'host in una fascia di rischio "Gialla" (da monitorare) ma non critica.
* **Caso B (Eventi correlati):** Se il medesimo host esegue una scansione di rete (+30 punti), contestualmente inizia a utilizzare un protocollo mai visto prima (+20 punti nella *Novelty Detection*) e genera un **Eccesso Volumetrico** in uscita (+20 punti da $Z_{robusto} > 3$), l'equazione sommerà i pesi di tutte queste metriche. Lo *Score* $S(h)$ schizzerà a 70/100, superando la soglia di allarme rosso.

È esattamente questa **correlazione di deviazioni comportamentali** nella "zona grigia" che certifica il cambio di stato dell'host da "regolare" a "sospetto", permettendo di identificare pattern complessi senza fare affidamento su firme predefinite.

---

## 5. Dal Singolo Host alla Rete: Valutazione della Postura di Sicurezza

L'obiettivo finale del modello non si limita alla classificazione del singolo nodo, ma mira a rispondere al quesito architetturale primario: *"La mia rete è sicura?"*. 

Per perseguire questo obiettivo, lo *Score* individuale $S(h)$ funge da mattoncino fondamentale per calcolare l'**Indice di Rischio di Rete ($I_{rete}$)**.
Poiché in ambito di sicurezza informatica la robustezza di una rete è pari a quella del suo anello più debole, l'aggregazione non può basarsi sulla semplice media aritmetica degli host (che diluirebbe un allarme critico in mezzo a migliaia di macchine sane).

Il modello valuta la sicurezza globale della rete basandosi su due fattori derivati:

1. **Il Rischio di Picco (Worst-Case Scenario):**
   La rete è intrinsecamente insicura se anche un solo host supera una soglia critica $\tau$ (es. $\tau = 60/100$). Il primo indicatore è quindi il massimo punteggio registrato nell'intero insieme degli host $H$:
   $$\max_{h \in H} S(h)$$

2. **La Densità delle Anomalie (Systemic Spread):**
   Se viene superata la soglia critica $\tau$, è fondamentale capire se si tratta di un'anomalia isolata (es. un singolo utente che esegue operazioni non consentite) o di una minaccia estesa (es. un'infezione che si propaga). Si definisce l'insieme degli host critici $C = \{h \in H \mid S(h) \ge \tau\}$. 
   La dimensione di questo insieme ($|C|$) definisce lo stato della rete:
   * **$|C| = 0$ :** Rete sicura.
   * **$|C| \approx 1$ :** Anomalia localizzata.
   * **$|C| \gg 1$ :** Diffusione sistemica o movimento laterale in corso.

**Risultati Attesi:**
Il risultato atteso è un sistema di monitoraggio operativo che, partendo dalle metriche di basso livello, genera un **Ranking di Priorità** degli host. Questo approccio quantitativo permette agli analisti non solo di individuare tempestivamente i nodi "sospetti" nella zona grigia, ottimizzando i tempi di neutralizzazione degli attacchi (*Incident Response*), ma anche di avere una metrica matematica oggettiva per certificare la sicurezza e la stabilità dell'intera infrastruttura di rete nel tempo.

---

## 6. Limiti Teorici dell'Approccio

Il modello presenta limiti intrinseci derivanti dalla sua natura di analisi passiva:
1. **Payload Blindness:** Il modello correla i metadati (L3/L4, protocolli applicativi e intestazioni TLS) ma non decifra il contenuto dei pacchetti crittografati. Flussi malevoli perfettamente mimetizzati nei volumi, nelle frequenze e nei protocolli di un normale traffico legittimo non genereranno un $\Delta$ statistico rilevabile.
2. **Attacchi Low and Slow:** Tecniche di esfiltrazione o scansione a frequenza estremamente bassa non produrranno uno scostamento sufficiente a far scattare la soglia dello $Z_{robusto}$.
3. **Baseline Poisoning:** Se l'host è già compromesso all'inizio della fase di campionamento storico (Cold Start), il traffico malevolo verrà assorbito nel calcolo della Mediana ($\tilde{x}$), venendo matematicamente validato come comportamento legittimo.

---
