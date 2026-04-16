# Analisi degli host e valutazione del rischio di rete

**Obiettivo:** Definire formalmente un modello matematico in grado di valutare lo stato di sicurezza di un'infrastruttura IT e rispondere alla domanda principale: "La mia rete è sicura?". Attraverso un approccio non invasivo (l'analisi passiva del traffico), il modello valuta il profilo dei singoli host utilizzando metriche deterministiche e statistiche. Lo scopo è andare oltre la semplice ricerca di minacce già conosciute (il classico approccio "bianco o nero"), per identificare variazioni anomale di comportamento ed eventi mai visti prima nella cosiddetta "zona grigia". In questo modo, possiamo misurare quanto ogni nodo della rete si discosta dal comportamento normale e calcolare il rischio per l'intera rete. Il modello aiuta a capire se la nostra rete è sicura e se ci sono aree che richiedono attenzione.

---

## 1. L'Equazione generale del sospetto

Per capire il grado di sospetto di un host $h$ in un dato istante viene utilizzato uno *Score Globale* $S(h)$. Abbandonando le logiche binarie, il modello adotta un sistema di **punteggio di rischio additivo** (da 0 a 100). L'equazione è una somma delle penalità assegnate per ogni anomalia rilevata, con un limite massimo:

$$S(h) = \min\left(100, \sum_{i=1}^{n} p_i \cdot M_i(h)\right)$$

Dove:
* $p_i$ rappresenta il punteggio di penalità o la gravità assegnata a ciascuna metrica.
* $M_i(h) \in \{0, 1\}$ è il valore booleano restituito dalla singola metrica valutata.

Le metriche utilizzate sono suddivise in due classi logiche: **Deterministiche** e **Statistiche**.

---

## 2. Calcolo delle metriche deterministiche

Queste metriche valutano eventi che si verificano in un determinato momento e sono classificati con valori booleani. Il calcolo non richiede uno storico: l'osservazione attuale viene confrontata in tempo reale con un set di dati noto.

* Rilevata corrispondenza (match positivo): $M_i(h) = 1$
* Assenza di corrispondenza (match negativo): $M_i(h) = 0$

---

## 3. Calcolo delle metriche comportamentali/statistiche (Analisi della "zona grigia")

Le metriche comportamentali non cercano minacce note, ma esplorano la cosiddetta **"zona grigia"**: traffico apparentemente legittimo che risulta sospetto perché eccessivo, fuori orario, troppo rigido o totalmente inedito per quello specifico host. 
Per valutare questa tipologia di anomalie, il modello utilizza due approcci matematici distinti:
* **Scostamenti statistici**: si tratta di esaminare i cambiamenti nella quantità del traffico.  
* **Novelty detection**: il quale serve ad individuare qualcosa di completamente nuovo.

### Fase 3.1: Analisi del comportamento atteso
Per le variabili continue come volume di byte, frequenza temporale delle connessioni, dobbiamo capire cosa è considerato normale per un host. Per farlo, prendiamo una finestra di 7 giorni e calcoliamo due indicatori importanti:
* **Mediana ($\tilde{x}$):** rappresenta il valore centrale e tipico del traffico per quell'host.
* **MAD (Median Absolute Deviation):** misura quanto i si discostano dalla mediana. In pratica ci aiuta a capire quanto i dati sono dispersi rispetto il valore centrale ed è calcolata come:

$$MAD = \text{Mediana}(|x_i - \tilde{x}|)$$

L'utilizzo di $\tilde{x}$ e $MAD$ risulta matematicamente più solido rispetto a Media e Deviazione Standard. Questo perché la Mediana e la MAD sono meno influenzate dai valori anomali come picchi di traffico legittimi causati da download occasionali. In questo modo, otteniamo un'idea più precisa di cosa è normale per un host.

### Fase 3.2: Misurazione dello scostamento statistico (Z-Score Robusto)
Per capire quanto un valore sia diverso dalla norma, possiamo utilizzare lo Z-Score Robusto. Questo calcola la distanza tra il valore attuale e il valore medio, utilizzando la seguente formula:

$$Z_{robusto} = \frac{|x - \tilde{x}|}{MAD}$$

Il risultatto di questa equazione è un valore che ci dice quanto il valore attuale si discosta dalla media. Se questo valore è più alto di una certa soglia, significa che il valore attuale è molto diverso dalla norma. Ad esempio, se il valore è più alto di 3, significa che il 99,7% dei casi normali sono al di sotto di questo valore. In questo caso, il valore attuale è considerato un'anomalia statistica.

### Fase 3.3: Rilevamento delle novità assolute (Novelty detection)
Per valutare gli eventi mai visti prima come l'uso di nuovi protocolli applicativi o servizi logici inediti, l'approccio statistico non è applicabile. Si utilizza quindi la teoria degli insiemi abbinata alla **Deep Packet Inspection**.
Definiamo $P_{storico}$ come l'insieme dei servizi che l'host ha utilizzato nel periodo di profilazione e definiamo $P_{oggi}$ come l'insieme dei servizi rilevati ed utilizzati oggi. La novità, che chiameremo ($N$) è calcolata prendendo la differenza fra questi due insiemi:

$$N = P_{oggi} \setminus P_{storico}$$

Se l'insieme $N$ non è vuoto ($N \neq \emptyset$), significa che l'host sta avendo un comportamento strutturalmente diverso, attivando la relativa metrica di anomalia.

---

## 4. Quando un Host diventa "Sospetto"

Come evidenziato dall'equazione dello *Score Globale* $S(h)$, il modello non si basa sulla valutazione di una singola metrica isolata, ma considera diverse metriche insieme.  

Nelle reti moderne, di solito non basta un singolo evento strano per etichettare un host come critico. Per esempio, un *port-scan* verso la rete interna potrebbe essere fatto da un amministratore di sistema per motivi legittimi.

Un host è considerato "sospetto" solo quando ci sono diverse anomalie che si sovrappongono. In termini matematici, questa correlazione è rappresentata dalla somma dei punteggi di penalità:

* **Caso A (Segnale isolato):** Se l'host esegue unicamente una scansione di rete, si attiverà solo la relativa metrica. Lo *Score* finale $S(h)$ crescerà esclusivamente dei punti assegnati a tale anomalia, mantenendo l'host in una fascia "verde" i da monitorare, ma non critica.
* **Caso B (Eventi correlati):** Se il medesimo host esegue una scansione di rete, ma allo stesso tempo inizia a utilizzare un protocollo mai visto prima e genera un eccesso volumetrico in uscita , l'equazione sommerà i pesi di tutte queste metriche. Lo *Score* $S(h)$ schizzerà in alto, superando la soglia di allarme rosso.

È esattamente questa correlazione di deviazioni comportamentali nella "zona grigia" che certifica il cambio di stato dell'host da "regolare" a "sospetto", permettendo di identificare pattern complessi senza fare affidamento su firme predefinite.

---

## 5. Valutazione dell'intera rete

L'obiettivo finale del modello non si limita alla classificazione del singolo nodo, ma mira a rispondere alla domanda: *"La mia rete è sicura?"*. 

Per raggiungere questo obiettivo, lo *Score* individuale $S(h)$ è fondamentale per calcolare l'**Indice di rischio di rete ($I_{rete}$)**.
Poiché in ambito di sicurezza informatica la robustezza di una rete è pari a quella del suo anello più debole, non possiamo semplicemente prendere la media dei punteggi di tutti i nodi.

Per valutare la sicurezza globale della rete, il modello considera due fattori importanti:

1. **Il rischio di picco:**  
   La rete viene considerata insicura se anche un solo host supera una soglia critica che chiameremo $\tau$. Il primo fattore da considerare è quindi il punteggio massimo registrato tra tutti gli host della rete, che possiamo esprimere come $H$:
   
   $$\max_{h \in H} S(h)$$

3. **La densità delle anomalie:**  
   Se viene superata la soglia critica $\tau$, è fondamentale capire se si tratta di un'anomalia isolata o di una minaccia estesa. Si definisce l'insieme degli host critici $C = \{h \in H \mid S(h) \ge \tau\}$. 
   La dimensione di questo insieme ($|C|$) definisce lo stato della rete:
   * **$|C| = 0$ :** rete sicura.
   * **$|C| \approx 1$ :** anomalia localizzata.
   * **$|C| \gg 1$ :** diffusione sistemica o movimento laterale in corso.

**Risultati Attesi:**  
Il risultato atteso è un sistema di monitoraggio operativo che, partendo dalle metriche di basso livello, genera un **Ranking di Priorità** degli host. In questo modo, gli analisti possono identificare rapidamente i nodi sospetti e intervenire tempestivamente per neutralizzare gli attacchi. Questo approccio ci permette anche di avere una misura oggettiva e matematica per valutare la sicurezza e la stabilità dell'intera rete nel tempo. Ciò significa che potremo ottimizzare i tempi di risposta agli attacchi e avere una visione chiara della sicurezza della nostra infrastruttura di rete.

---

## 6. Limiti dell'approccio

Il nostro modello ha alcuni limiti importanti che derivano dal fatto che si basa su un'analisi passiva del traffico di rete:
1. **Payload Blindness:** il modello è in grado di analizzare i metadati (come i protocolli di rete e le intestazioni TLS), ma non può decifrare il contenuto dei pacchetti crittografati. Ciò significa che se ci sono flussi di dati dannosi che imitano perfettamente il traffico legittimo normale, non saranno rilevati.
2. **Attacchi Low and Slow:** gli attacchi che si verificano a una frequenza molto bassa, come alcune tecniche di esfiltrazione o scansione, potrebbero non essere rilevati perché non causano uno scostamento sufficiente per le soglie di rilevamento.
3. **Baseline Poisoning:** se il sistema è già stato compromesso, il traffico dannoso potrebbe essere considerato come traffico legittimo e quindi non verrà rilevato. Questo accade perché il modello utilizza la mediana dei dati storici come riferimento per il comportamento legittimo.

---
