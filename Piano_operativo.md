# Piano Operativo e Specifica delle Metriche

Il presente documento traduce il modello logico-matematico in un piano di implementazione pratico. Per evitare un carico computazionale insostenibile e per permettere un'analisi statistica affidabile, il sistema adotta un approccio ibrido: elaborazione a **finestre temporali (batch orari)** per i comportamenti statistici ed elaborazione **guidata dagli eventi (event-driven)** per i controlli deterministici.

## 1. Definizione e Frequenza di Osservazione delle Metriche

Per valutare lo stato di un host, il sistema osserva 7 metriche specifiche, estraendo i dati dai log di rete. Le metriche sono divise in due macro-categorie.

### 1.A Metriche Deterministiche (In Tempo Reale)
Queste metriche operano **event-driven**: il controllo avviene non appena l'host instaura una connessione.

* **1. Reputazione IP/DNS ($M_{rep}$):**
  * **Parametro:** Indirizzi IP e domini richiesti.
  * **Valutazione:** $1$ se la destinazione è presente in una *blacklist* di Threat Intelligence, altrimenti $0$.
* **2. Fingerprinting del Traffico Cifrato ($M_{ja3}$):**
  * **Parametro:** Hash JA3 (impronta digitale del client TLS) estratto dall'handshake crittografico.
  * **Valutazione:** $1$ se l'hash JA3 corrisponde a quello di un client malevolo noto (es. un malware o un tool di esfiltrazione), altrimenti $0$. Questo permette di identificare minacce anche se il traffico è crittografato.

### 1.B Metriche Statistiche e Comportamentali (Finestra di 1 Ora)
Queste metriche valutano la "zona grigia" tramite lo Z-Score Robusto o la Novelty Detection. Il calcolo avviene allo scoccare di ogni ora, confrontando i dati con la *baseline* degli ultimi **7 giorni** (da valutare).

* **3. Scansione Interna / Fan-out ($M_{scan}$):**
  * **Parametro:** Il numero di IP interni (host della LAN) unici contattati.
  * **Valutazione:** $1$ se si registra un'impennata anomala di contatti verso macchine interne ($Z_{robusto} > 3$), tipica dei movimenti laterali o del *port-scanning*, altrimenti $0$.
* **4. Novità di Servizio/Destinazione ($M_{new}$):**
  * **Parametro:** L'insieme delle porte logiche (TCP/UDP) di destinazione.
  * **Valutazione:** $1$ se l'host utilizza porte logiche mai osservate nello storico (l'insieme differenza non è vuoto), altrimenti $0$.
* **5. Eccesso Volumetrico ($M_{vol}$):**
  * **Parametro:** La somma totale dei byte inviati dall'host verso l'esterno.
  * **Valutazione:** $1$ se lo scostamento del volume in uscita è eccezionale ($Z_{robusto} > 3$), altrimenti $0$.
* **6. DNS Tunneling / Esfiltrazione Occulta ($M_{dns}$):**
  * **Parametro:** La lunghezza media e l'entropia dei sottodomini richiesti nelle query DNS.
  * **Valutazione:** $1$ se la lunghezza o il volume delle richieste DNS supera drasticamente la norma ($Z_{robusto} > 3$), indicando un possibile incapsulamento di dati nel protocollo DNS, altrimenti $0$.
* **7. Anomalia di Periodicità / Jitter ($M_{time}$):**
  * **Parametro:** La varianza temporale tra connessioni ripetute.
  * **Valutazione:** Il traffico umano è irregolare. Se una macchina inizia a generare traffico automatizzato (*beaconing*), la varianza attuale $x$ crolla tendendo a zero. Questa caduta genera una distanza enorme dalla mediana storica, producendo uno scostamento eccezzionale ($Z_{robusto}>3$). Ritorna $1$ in caso di superamento della soglia, altrimenti $0$.

---

## 2. Combinazione e Assegnazione dei Pesi ($w_i$)

Allo scadere di ogni ora di monitoraggio, il sistema aggrega i valori delle 7 metriche. Per determinare l'impatto di ogni evento sul punteggio finale $S(h)$, i pesi operativi sono stati bilanciati secondo la gravità architetturale (somma totale = $1.0$):

* **Fascia Altissima (Indicatori di Compromissione certi):**
  * $w_{rep} = 0.25$ (Destinazione malevola)
  * $w_{ja3} = 0.25$ (Client TLS malevolo)
* **Fascia Alta (Comportamenti di Zona Grigia critici):**
  * $w_{scan} = 0.15$ (Movimento laterale sospetto)
  * $w_{new} = 0.15$ (Uso di protocolli inediti)
* **Fascia Media (Anomalie quantitative):**
  * $w_{vol} = 0.10$ (Picco di volume in uscita)
* **Fascia Bassa (Segnali deboli / Supporto):**
  * $w_{dns} = 0.05$ (Anomalia DNS)
  * $w_{time} = 0.05$ (Traffico automatizzato)

L'equazione finale calcolata per ogni host risulta quindi:
$$S(h) = 0.25(M_{rep} + M_{ja3}) + 0.15(M_{scan} + M_{new}) + 0.10(M_{vol}) + 0.05(M_{dns} + M_{time})$$

---

## 3. Verdetto: Classificazione dello Stato dell'Host

Il calcolo dell'equazione produce un valore compreso tra 0.0 e 1.0. Per rispondere operativamente alla necessità di definire se il comportamento di un host "va bene o va male", il sistema mappa il risultato su tre fasce di rischio predefinite:

* **Stato Regolare $\rightarrow [0.0 - 0.29]$ ("Va bene")**
  L'host svolge le sue normali attività. Anche se dovesse verificarsi un isolato picco di traffico ($0.20$), il punteggio rimane sotto la soglia di allarme. Nessun intervento richiesto.

* **Zona Grigia $\rightarrow [0.30 - 0.59]$ ("Da monitorare")**
  L'host mostra variazioni anomale di comportamento. Ad esempio, potrebbe aver iniziato a usare un protocollo inedito ($0.30$), magari associato a un traffico meccanico e automatizzato ($+0.10 = 0.40$). Non vi è certezza di compromissione, ma l'host scala posizioni nel sistema di monitoraggio degli analisti.

* **Stato Critico $\rightarrow [0.60 - 1.0]$ ("Va male")**
  Il superamento di questa soglia matematica certifica la convergenza di anomalie gravi. Per raggiungere o superare lo 0.60, l'host deve necessariamente aver contattato un IP malevolo, oppure aver generato *contemporaneamente* un picco volumetrico su protocolli mai usati in precedenza. L'analista riceve un allarme ad alta priorità per avviare le procedure di indagine e contenimento.
---
