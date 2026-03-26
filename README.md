# Classificazione host sospetti

**Obiettivo:** Definire formalmente il livello di "sospetto" di un host all'interno di una rete attraverso un approccio non invasivo (analisi passiva del traffico), utilizzando un sistema di scoring basato su metriche deterministiche e statistiche.

---

## 1. L'Equazione Generale del Sospetto

Il grado di sospetto di un host $h$ in un dato istante è definito dallo *Score Globale* $S(h)$. Questa equazione è una combinazione lineare pesata di $n$ metriche indipendenti:

$$S(h) = \sum_{i=1}^{n} w_i \cdot M_i(h)$$

Dove:
* $M_i(h) \in [0, 1]$ è il valore normalizzato restituito dalla singola metrica valutata (es. anomalia volumetrica, beaconing, reputazione IP).
* $w_i \in (0, 1)$ rappresenta il "peso" o la gravità assegnata all'indicatore, con il vincolo formale che $\sum w_i = 1$.

Le metriche appartengono a due classi logiche distinte: **Deterministiche** e **Statistiche**.

---

## 2. Calcolo delle Metriche Deterministiche

Queste metriche valutano eventi puntuali basati su logica booleana (es. corrispondenza di un hash JA3 con firme malware o contatti verso IP in blacklist). Il calcolo non richiede uno storico: l'osservazione attuale viene confrontata con un set di dati noto.

* Rilevata corrispondenza (match positivo): $M_i(h) = 1$
* Assenza di corrispondenza: $M_i(h) = 0$

---

## 3. Calcolo delle Metriche Comportamentali (Analisi della "Zona Grigia")

Le metriche comportamentali non cercano minacce note (logica bianco/nero), ma esplorano la cosiddetta **"zona grigia"**: traffico apparentemente legittimo che risulta sospetto perché eccessivo, fuori orario o totalmente inedito per quello specifico host. 
Per valutare questa tipologia di anomalie, il modello utilizza due approcci matematici distinti: l'analisi degli **scostamenti statistici** (per le variazioni quantitative) e la **Novelty Detection** (rilevamento delle novità).

### Fase 3.1: Profilazione Storica (Baseline Robusta)
Per le variabili continue (es. volume di byte, frequenza di connessioni), il comportamento normale dell'host è modellato calcolando due indicatori su una finestra temporale storica:
* **Mediana ($\tilde{x}$):** Rappresenta il valore centrale e tipico del traffico per quell'host.
* **MAD (Median Absolute Deviation):** Quantifica la dispersione fisiologica dei dati rispetto alla mediana, calcolata come:

$$MAD = \text{Mediana}(|x_i - \tilde{x}|)$$

L'utilizzo di $\tilde{x}$ e $MAD$ risulta matematicamente più solido rispetto a Media e Deviazione Standard, in quanto intrinsecamente immune ai fisiologici outlier del traffico di rete (es. picchi legittimi dovuti a download occasionali).

### Fase 3.2: Misurazione dello Scostamento Statistico (Z-Score Robusto)
Per misurare formalmente una variazione quantitativa, si calcola la distanza dell'osservazione attuale $x$ dalla baseline, utilizzando lo **Z-Score Robusto**:

$$Z_{robusto} = \frac{|x - \tilde{x}|}{MAD}$$

Questa equazione restituisce un valore numerico. Se $Z_{robusto}$ supera una soglia di tolleranza $\theta$ (es. $Z > 3$), l'evento è classificato come un'anomalia quantitativa.

### Fase 3.3: Rilevamento delle Novità Assolute (Novelty Detection)
Per valutare gli eventi "mai visti prima" (variabili discrete come nuovi IP contattati, porte o protocolli inediti), l'approccio statistico non è applicabile. Si utilizza quindi la teoria degli insiemi.
Sia $E_{storico}$ l'insieme degli elementi (es. porte di destinazione) contattati dall'host nel periodo di profilazione, e $E_{oggi}$ l'insieme degli elementi contattati nell'osservazione odierna. La novità ($N$) è calcolata tramite l'insieme differenza:

$$N = E_{oggi} \setminus E_{storico}$$

Se l'insieme $N$ non è vuoto ($N \neq \emptyset$), significa che l'host sta esibendo un comportamento totalmente inedito, attivando la relativa metrica di anomalia.

### Fase 3.4: Applicazione alle Specifiche Metriche (Esempi)
L'unione di questi approcci permette di coprire diverse dimensioni della zona grigia:
* **Eccesso Volumetrico ($M_{vol}$):** Valuta picchi di traffico verso destinazioni lecite (es. un dipendente che carica 50GB di backup su un server aziendale). Il volume è lecito, ma lo $Z_{robusto}$ elevato segnala un'anomalia rispetto alla consuetudine.
* **Novità di Servizio/Destinazione ($M_{new}$):** Valuta l'uso di nuove risorse tramite la **Novelty Detection**. Ad esempio, una stampante di rete che improvvisamente avvia una connessione verso Internet, o un PC che utilizza il protocollo FTP (porta 21) per la prima volta.
* **Variazione dei Pattern Temporali ($M_{time}$):** Valuta il cambio di abitudini. Ad esempio, un host tipicamente attivo in orari d'ufficio che inizia a generare traffico costante alle 3 del mattino.

---

## 4. Correlazione Multidimensionale: Quando un Host diventa "Sospetto"

Come evidenziato dall'equazione dello *Score Globale* $S(h)$, il modello non si basa sulla valutazione di una singola metrica isolata, bensì sulla loro aggregazione. 

Nelle reti moderne, un singolo evento anomalo (i cosiddetti "segnali deboli") è spesso insufficiente per classificare un host come critico. Ad esempio, un *port-scan* isolato verso la rete interna potrebbe essere l'azione legittima di un amministratore di sistema o un software di *network discovery*. 

Un host viene definito "sospetto" (o ad alto rischio) solo quando si verifica una **convergenza di più anomalie** su assi dimensionali diversi. Matematicamente, questa correlazione è gestita dalla somma pesata $\sum w_i \cdot M_i(h)$:

* **Caso A (Segnale isolato):** Se l'host esegue unicamente una scansione di rete, si attiverà solo la relativa metrica. Lo *Score* finale $S(h)$ crescerà esclusivamente del peso assegnato a tale metrica (es. $0.15$), mantenendo l'host in una fascia di rischio bassa o accettabile.
* **Caso B (Eventi correlati):** Se il medesimo host esegue una scansione di rete, contestualmente inizia a utilizzare una porta mai vista prima ($N \neq \emptyset$ nella *Novelty Detection*) e genera un **Eccesso Volumetrico** in uscita ($Z_{robusto} > 3$), l'equazione sommerà i pesi di tutte queste metriche. Lo *Score* $S(h)$ si avvicinerà rapidamente a $1$.

È esattamente questa **correlazione di comportamenti** nella "zona grigia" che certifica il cambio di stato dell'host da "regolare" a "sospetto", permettendo di identificare pattern complessi senza fare affidamento su firme predefinite.

---

## 5. Limiti Teorici dell'Approccio

Il modello presenta limiti intrinseci derivanti dalla sua natura di analisi passiva:
1. **Payload Blindness:** Il modello correla esclusivamente i metadati (L3/L4 e intestazioni TLS). Flussi malevoli perfettamente mimetizzati nei volumi e nelle frequenze di un normale traffico legittimo non genereranno un $\Delta$ statistico rilevabile.
2. **Attacchi Low and Slow:** Tecniche di esfiltrazione o scansione a frequenza estremamente bassa non produrranno uno scostamento sufficiente a far scattare la soglia dello $Z_{robusto}$.
3. **Baseline Poisoning:** Se l'host è già compromesso all'inizio della fase di campionamento storico, il traffico malevolo verrà assorbito nel calcolo della Mediana ($\tilde{x}$), venendo matematicamente validato come comportamento legittimo.

---

## 6. Obiettivi e Risultati Attesi

L'obiettivo del modello è superare i tradizionali sistemi di sicurezza basati su regole rigide (dove un evento è valutato solo come "lecito" o "illecito"), per fornire invece una valutazione quantitativa e progressiva del rischio. 

Il risultato atteso è la generazione di un **Ranking di Priorità**: ordinando gli host in base al loro Score $S(h)$, si fornisce agli analisti un elenco ordinato per livello di criticità, riducendo il problema dell'affaticamento da allarmi e ottimizzando i tempi di neutralizzazione degli attacchi.
