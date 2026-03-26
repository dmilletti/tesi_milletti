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

## 3. Calcolo delle Metriche Statistiche (Comportamento e Cambiamento)

Le metriche statistiche valutano se l'attività attuale sia un'anomalia rispetto alla consuetudine dell'host. Questo calcolo utilizza un unico "motore matematico" diviso in tre fasi formali.

### Fase 3.1: Definizione del "Comportamento" (Baseline Robusta)
Il comportamento normale dell'host per una data metrica è modellato calcolando due indicatori su una finestra temporale storica:
* **Mediana ($\tilde{x}$):** Rappresenta il valore centrale e tipico del traffico per quell'host.
* **MAD (Median Absolute Deviation):** Quantifica la dispersione fisiologica dei dati rispetto alla mediana, calcolata come:

$$MAD = \text{Mediana}(|x_i - \tilde{x}|)$$

L'utilizzo di $\tilde{x}$ e $MAD$ risulta matematicamente più solido rispetto a Media e Deviazione Standard, in quanto intrinsecamente immune ai fisiologici outlier del traffico di rete (es. picchi legittimi dovuti a download occasionali).

### Fase 3.2: Misurazione del "Cambiamento" (Z-Score Robusto)
Per misurare formalmente il cambiamento, si calcola lo scostamento dell'osservazione attuale $x$ dalla baseline, utilizzando lo **Z-Score Robusto**:

$$Z_{robusto} = \frac{|x - \tilde{x}|}{MAD}$$

Questa equazione restituisce un **valore numerico** che indica la distanza dell'evento attuale dalla normalità.

### Fase 3.3: Valutazione della Metrica ($M_i$)

L'ultimo passaggio collega il calcolo statistico all'equazione globale del sospetto. Il valore dello Z-Score viene confrontato con una soglia di tolleranza $\theta$ (es. $Z>3$, che indica un evento statisticamente rarissimo):

* Se $Z_{robusto} > \theta$, l'anomalia è confermata e la metrica si attiva: $M_i(h) = 1$.
* Se $Z_{robusto} <= \theta$, l'evento rientra nella normale fluttuazione: $M_i(h) = 0$. (Da valutare: $M_i$​ potrebbe anche assumere valori continui tra 0 e 1 in base all'entità del superamento della soglia).

---

## 4. Limiti Teorici dell'Approccio

Il modello presenta limiti intrinseci derivanti dalla sua natura di analisi passiva:
1. **Payload Blindness:** Il modello correla esclusivamente i metadati (L3/L4 e intestazioni TLS). Flussi malevoli perfettamente mimetizzati nei volumi e nelle frequenze di un normale traffico legittimo non genereranno un $\Delta$ statistico rilevabile.
2. **Attacchi Low and Slow:** Tecniche di esfiltrazione o scansione a frequenza estremamente bassa non produrranno uno scostamento sufficiente a far scattare la soglia dello $Z_{robusto}$.
3. **Baseline Poisoning:** Se l'host è già compromesso all'inizio della fase di campionamento storico, il traffico malevolo verrà assorbito nel calcolo della Mediana ($\tilde{x}$), venendo matematicamente validato come comportamento legittimo.

---

## 5. Obiettivi e Risultati Attesi

L'obiettivo del modello è superare i tradizionali sistemi di sicurezza basati su regole rigide (dove un evento è valutato solo come "lecito" o "illecito"), per fornire invece una valutazione quantitativa e progressiva del rischio. 

Il risultato atteso è la generazione di un **Ranking di Priorità**: ordinando gli host in base al loro Score $S(h)$, si fornisce agli analisti un elenco ordinato per livello di criticità, riducendo il problema dell'affaticamento da allarmi e ottimizzando i tempi di neutralizzazione degli attacchi.
