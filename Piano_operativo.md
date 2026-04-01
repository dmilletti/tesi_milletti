# Piano Operativo e Specifica delle Metriche

Il presente documento traduce il modello logico-matematico in un piano di implementazione pratico. Per evitare un carico computazionale insostenibile e per permettere un'analisi statistica affidabile, il sistema adotta un approccio ibrido: elaborazione a **finestre temporali (batch orari)** per i comportamenti statistici ed elaborazione **guidata dagli eventi (event-driven)** per i controlli deterministici.

## 1. Definizione Logica e Teorica delle Metriche di Sicurezza

Il modello si compone di **dieci metriche indipendenti**, selezionate per coprire l'intero spettro delle anomalie di rete. Ciascuna metrica astrae uno specifico comportamento dell'host e lo traduce in un valore normalizzato $M_i \in \{0, 1\}$. Le metriche sono raggruppate in base all'approccio logico utilizzato per la loro valutazione.

### 1.A Metriche Deterministiche (In tempo reale)
Queste metriche operano secondo una logica booleana e non necessitano di un periodo di apprendimento. Valutano la natura intrinseca di una singola connessione confrontandola con insiemi di dati noti a priori.

* **1. Reputazione Logica delle Destinazioni ($M_{rep}$)**
  * **Razionale Teorico:** Valuta il livello di affidabilità degli *endpoint* esterni con cui l'host tenta di comunicare. Una connessione verso un nodo di rete la cui maliziosità è già certificata (es. server di Comando e Controllo noti) compromette istantaneamente lo stato di sicurezza dell'host interno.
  * **Formalizzazione:** Sia $\mathcal{B}$ l'insieme degli indirizzi IP e dei domini globalmente riconosciuti come malevoli (Threat Intelligence). Se la destinazione $d$ della connessione appartiene a tale insieme ($d \in \mathcal{B}$), l'evento viene marcato come compromissione certa, restituendo $M_{rep} = 1$.

* **2. Fingerprinting Crittografico del Client ($M_{ja3}$)**
  * **Razionale Teorico:** La crittografia rende illeggibile il contenuto dei pacchetti, limitando le analisi tradizionali. Questa metrica supera tale limite analizzando la firma strutturale (l'impronta digitale) della fase di negoziazione della connessione (*handshake*). Tool malevoli e malware utilizzano librerie crittografiche specifiche che generano firme uniche.
  * **Formalizzazione:** Il sistema estrae l'impronta crittografica del client. Se tale impronta coincide con lo spazio delle firme associate a software d'attacco, la metrica certifica l'anomalia strutturale restituendo $M_{ja3} = 1$.

* **3. Anomalie nei Certificati TLS ($M_{cert}$)**
  * **Razionale Teorico:** I siti web e i servizi cloud legittimi utilizzano certificati emessi da Autorità di Certificazione (CA) riconosciute. Le infrastrutture di attacco improvvisate impiegano frequentemente certificati auto-firmati (*Self-Signed*) o con parametri di validità errati (es. durate secolari).
  * **Formalizzazione:** L'analizzatore verifica la catena di fiducia del certificato presentato dal server. In presenza di certificati auto-firmati o palesemente non conformi agli standard di sicurezza, si fissa $M_{cert} = 1$.

### 1.B Metriche Statistiche e Comportamentali (Finestra di 1 ora)
Queste metriche esplorano la "zona grigia", valutando variazioni anomale rispetto allo stato di quiete dell'host. Sfruttano l'ispezione profonda, la teoria degli insiemi (Novelty Detection) e lo scostamento statistico standardizzato ($Z_{robusto}$). Il calcolo avviene allo scoccare di ogni ora, confrontando i dati con la *baseline* degli ultimi **7 giorni**.

* **4. Rilevamento Funzionalità Server ($M_{srv}$)**
  * **Razionale Teorico:** In una rete aziendale, una normale *workstation* opera tipicamente come "Client", originando traffico verso l'esterno. L'apertura improvvisa di una porta in ascolto che accetta connessioni in ingresso indica un'inversione di ruolo, sintomo critico dell'installazione di una *backdoor* o di un accesso remoto non autorizzato.
  * **Formalizzazione:** Se l'host, storicamente noto come client, accetta con successo connessioni logiche in ingresso agendo da ricevitore, si attiva $M_{srv} = 1$.

* **5. Protocollo su Porta Non Standard ($M_{proto}$)**
  * **Razionale Teorico:** Per eludere i firewall perimetrali, le minacce instradano traffico anomalo (es. protocolli di amministrazione remota come SSH o tunnel VPN) su porte logiche tipicamente consentite e riservate ad altri scopi (es. porta 80 o 443 per il web).
  * **Formalizzazione:** Tramite ispezione profonda dei pacchetti, se l'applicativo rilevato non corrisponde al protocollo standard atteso per quella specifica porta logica (tentativo di evasione), si fissa $M_{proto} = 1$.

* **6. Scansione interna o Fan-out ($M_{scan}$)**
  * **Razionale Teorico:** Un host standard comunica regolarmente con un numero stabile di nodi interni. Un incremento improvviso del numero di macchine interne contattate è il sintomo primario di una fase di ricognizione (*Network Discovery*) o del tentativo di propagazione di un'infezione (Movimento Laterale).
  * **Formalizzazione:** La variabile analizzata è la cardinalità degli IP interni contattati. Se il valore attuale si discosta in modo eccezionale dalla Mediana storica ($Z_{robusto} > 3$), si attiva $M_{scan} = 1$.

* **7. Esplorazione di Protocolli Inediti ($M_{new}$)**
  * **Razionale Teorico:** Limitarsi all'analisi delle porte logiche (Livello 4) espone al rumore generato dalle porte effimere. Questa metrica eleva il controllo al Livello Applicativo (Livello 7) tramite *Deep Packet Inspection* (DPI). Un host aziendale utilizza tipicamente un set ristretto di protocolli (es. HTTP/S, DNS, IMAP). L'esordio improvviso di protocolli mai utilizzati prima (es. traffico *Peer-to-Peer* come BitTorrent, routing anonimo come Tor o protocolli di desktop remoto come RDP) è un indicatore primario di compromissione o di *Shadow IT*.
  * **Formalizzazione:** Applicando la *Novelty Detection* ai metadati L7, sia $P_{storico}$ l'insieme dei protocolli applicativi storicamente noti per l'host e $P_{oggi}$ l'insieme dei protocolli attualmente rilevati. Se l'insieme differenza non è vuoto ($P_{oggi} \setminus P_{storico} \neq \emptyset$), il comportamento è inedito e si fissa $M_{new} = 1$.

* **8. Asimmetria Volumetrica in Uscita ($M_{vol}$)**
  * **Razionale Teorico:** Un ribaltamento improvviso della dinamica di rete, caratterizzato da un trasferimento massivo di dati dall'host verso l'esterno, astrae il concetto di esfiltrazione di dati sensibili.
  * **Formalizzazione:** La variabile monitorata è la somma dei byte in uscita. Un picco estremo rispetto alla varianza abituale genera un valore di $Z_{robusto} > 3$, attivando $M_{vol} = 1$.

* **9. Anomalie nel Protocollo di Risoluzione Nomi ($M_{dns}$)**
  * **Razionale Teorico:** Tecniche avanzate di elusione (come il *DNS Tunneling* o gli algoritmi DGA) abusano del protocollo DNS incapsulando dati rubati o richieste malevole all'interno di stringhe lunghissime e apparentemente casuali. 
  * **Formalizzazione:** Se l'host inizia a generare query con un grado di entropia o lunghezza statisticamente incompatibile con la sua norma ($Z_{robusto} > 3$), si registra un abuso del canale e $M_{dns} = 1$.

* **10. Rigidità Temporale e Automazione ($M_{time}$)**
  * **Razionale Teorico:** I processi infetti (come le *botnet*) sono implementati tramite cicli algoritmici rigidi, generando comunicazioni periodiche estremamente precise, contrariamente all'elevata varianza che caratterizza la navigazione umana.
  * **Formalizzazione:** La metrica analizza la varianza del tempo di inter-arrivo dei pacchetti. Un crollo della varianza verso lo zero innesca lo $Z_{robusto} > 3$, portando $M_{time} = 1$.

---

## 2. Sistema di Scoring Additivo (0-100)

Allo scadere di ogni ora di monitoraggio, il sistema aggrega i valori delle 10 metriche. Ogni anomalia rilevata ($M_i = 1$) aggiunge un punteggio di penalità predefinito in base alla sua gravità intrinseca:

* **Gravità Critica (Compromissione certa):**
  * Reputazione Destinazione ($M_{rep}$): **+50 punti**
  * Fingerprinting JA3 ($M_{ja3}$): **+50 punti**
* **Sospetto Alto (Cambiamenti strutturali):**
  * Anomalie Certificati TLS ($M_{cert}$): **+40 punti**
  * Funzionalità Server Rilevata ($M_{srv}$): **+40 punti**
* **Evasione e Ricognizione:**
  * Protocollo su Porta Non Standard ($M_{proto}$): **+30 punti**
  * Scansione interna / Fan-out ($M_{scan}$): **+30 punti**
* **Zona Grigia (Anomalie quantitative e novità):**
  * Esplorazione Inedita ($M_{new}$): **+20 punti**
  * Asimmetria Volumetrica ($M_{vol}$): **+20 punti**
* **Segnali Deboli (Indicatori di supporto):**
  * Anomalie DNS ($M_{dns}$): **+10 punti**
  * Automazione Temporale ($M_{time}$): **+10 punti**

L'equazione finale per il calcolo dello *Score Globale* dell'host risulta limitata a un massimo di 100:
$$S(h) = \min\left(100, \sum_{i=1}^{10} \text{Punti}_i \cdot M_i\right)$$

---

## 3. Verdetto Operativo: Dall'Host all'Intera Rete

Il calcolo dell'equazione produce un valore intero compreso tra 0 e 100. Per rispondere operativamente alla necessità di definire se il comportamento di un nodo "va bene o va male", il sistema mappa il risultato $S(h)$ su tre fasce di rischio predefinite. 

Allo stesso tempo, per valutare la postura di sicurezza dell'intera infrastruttura, la *dashboard* degli analisti applica una logica basata sul caso peggiore (*Worst-Case Scenario*). Lo stato globale della rete è determinato dal punteggio massimo registrato tra tutti gli host attivi ( max $S(h)$ ), mappandosi direttamente sulle stesse tre fasce:

* **Stato Regolare / Rete Sicura (Verde) $\rightarrow$ [0 - 29 punti]**
  * **Singolo Host:** Svolge le sue normali attività. Anche in presenza di un isolato picco volumetrico (20 punti) o di un leggero traffico automatizzato (10 punti), il punteggio cumulativo rimane sotto la soglia di allarme. 
  * **Intera Rete:** Se nessun host supera i 29 punti, l'infrastruttura è considerata integra e non è richiesto alcun intervento.

* **Zona Grigia / Rete in Osservazione (Giallo) $\rightarrow$ [30 - 59 punti]**
  * **Singolo Host:** Mostra variazioni anomale. Ad esempio, potrebbe aver iniziato a usare porte logiche inedite (20 punti) associato a un traffico meccanico (10 punti) per un totale di 30 punti. Non vi è certezza matematica di compromissione, ma l'host scala le priorità nel sistema di monitoraggio.
  * **Intera Rete:** La rete è tecnicamente intatta, ma la presenza di host in questa fascia richiede attenzione per prevenire deviazioni comportamentali o minacce silenziose (*Low and Slow*).

* **Stato Critico / Rete Compromessa (Rosso) $\rightarrow$ [60 - 100 punti]**
  * **Singolo Host:** Il superamento di quota 60 certifica la convergenza di anomalie gravi. L'host deve necessariamente aver contattato una destinazione malevola nota (50 punti) supportata da un'altra anomalia, oppure aver esibito un accumulo massiccio di comportamenti evasivi contemporanei.
  * **Intera Rete:** Poiché in *Cybersecurity* una rete è forte quanto il suo anello più debole, un solo host in stato critico (max $S(h) \ge 60$) dichiara l'intero perimetro compromesso, innescando l'immediata *Incident Response*.
  
---

## 4. Giustificazione dei Parametri Statistici e Temporali

La solidità di un modello di *Anomaly Detection* non risiede solo nelle formule matematiche adottate, ma anche nel corretto dimensionamento dei parametri operativi. La scelta della soglia di anomalia, della finestra di osservazione e della profondità dello storico risponde a precise necessità statistiche e architetturali.

### 4.1 La Soglia di Anomalia ($Z_{robusto} > 3$)
L'impostazione della soglia di tolleranza $\theta = 3$ non è arbitraria, ma deriva direttamente dalla "Regola Empirica" della statistica descrittiva (nota anche come regola del 68-95-99.7). 

Assumendo che il traffico di rete tenda a distribuirsi attorno a un valore centrale (la Mediana), la dispersione misurata tramite la MAD ci permette di standardizzare le distanze:
* Uno Z-Score pari a **1** copre circa il **68%** delle normali fluttuazioni comportamentali.
* Uno Z-Score pari a **2** copre circa il **95%** della varianza regolare.
* Uno Z-Score pari a **3** ingloba il **99.7%** dei comportamenti ordinari dell'host.

Scegliere di attivare le metriche di allarme solo quando $Z_{robusto} > 3$ significa matematicamente che un evento ha meno dello **0.3%** di probabilità di essere un comportamento regolare casuale. Questa soglia estremamente conservativa è fondamentale in ambito *Cybersecurity* per abbattere drasticamente i falsi positivi e prevenire il fenomeno dell'affaticamento da allarmi.

### 4.2 La Finestra di Osservazione (Batch di 1 Ora)
Le metriche statistiche richiedono l'accumulo di un *set* di dati sufficiente per calcolare indicatori validi. Il sistema utilizza una finestra temporale di osservazione di **1 ora** (rispetto a un'analisi al minuto o giornaliera) come compromesso architetturale ottimale:
* **Contro il micro-batch (es. 5 minuti):** Finestre troppo brevi sono sensibili ai "micro-burst" (picchi istantanei legittimi, come il download di un file), che invaliderebbero la statistica generando continuo "rumore".
* **Contro il macro-batch (es. 24 ore):** Un'osservazione giornaliera creerebbe distribuzioni statisticamente perfette, ma risulterebbe totalmente inefficace per la neutralizzazione degli attacchi (*Incident Response*). La finestra oraria garantisce un volume di campioni statisticamente rilevante, mantenendo un tempo di reazione compatibile con le dinamiche di contenimento di un attacco.

### 4.3 La Profondità dello Storico (Baseline di 7 Giorni)
Il calcolo della Mediana $\tilde{x}$ e della $MAD$ avviene su una finestra storica di **7 giorni**. Questa scelta è dettata dalla necessità di assorbire la naturale **stagionalità settimanale** delle reti aziendali, intrinsecamente legata agli orari lavorativi e ai giorni di riposo. La profondità di 7 giorni assicura che il comportamento attuale venga confrontato con una baseline che ha già "imparato" i pattern dell'intera settimana, rendendo il modello consapevole dei cicli aziendali.

---
