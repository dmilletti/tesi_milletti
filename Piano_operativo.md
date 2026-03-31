# Piano Operativo e Specifica delle Metriche

Il presente documento traduce il modello logico-matematico in un piano di implementazione pratico. Per evitare un carico computazionale insostenibile e per permettere un'analisi statistica affidabile, il sistema adotta un approccio ibrido: elaborazione a **finestre temporali (batch orari)** per i comportamenti statistici ed elaborazione **guidata dagli eventi (event-driven)** per i controlli deterministici.

## 1. Definizione Logica e Teorica delle Metriche di Sicurezza

Il modello si compone di sette metriche indipendenti, selezionate per coprire l'intero spettro delle anomalie di rete. Ciascuna metrica astrae uno specifico comportamento dell'host e lo traduce in un valore normalizzato $M_i \in \{0, 1\}$. Le metriche sono raggruppate in base all'approccio logico utilizzato per la loro valutazione.

### 1.A Metriche Deterministiche (In tempo reale)
Queste metriche operano secondo una logica booleana e non necessitano di un periodo di apprendimento. Valutano la natura intrinseca di una singola connessione confrontandola con insiemi di dati noti a priori.

* **1. Reputazione Logica delle Destinazioni ($M_{rep}$)**
  * **Razionale Teorico:** Questa metrica valuta il livello di affidabilità degli *endpoint* esterni con cui l'host tenta di comunicare. L'astrazione logica si basa sul principio che una connessione verso un nodo di rete la cui maliziosità è già certificata (es. server di Comando e Controllo noti) compromette istantaneamente lo stato di sicurezza dell'host interno.
  * **Formalizzazione:** Sia $\mathcal{B}$ l'insieme degli indirizzi IP e dei domini globalmente riconosciuti come malevoli (Threat Intelligence). Se la destinazione $d$ della connessione appartiene a tale insieme ($d \in \mathcal{B}$), l'evento viene marcato come compromissione certa, restituendo $M_{rep} = 1$.

* **2. Fingerprinting Crittografico del Client ($M_{ja3}$)**
  * **Razionale Teorico:** La crittografia (TLS/SSL) rende illeggibile il contenuto dei pacchetti (Payload), rendendo inefficaci le analisi tradizionali. Questa metrica supera il limite della "cecità al contenuto" analizzando la firma strutturale (l'impronta digitale) della fase di negoziazione della connessione (*handshake*). Tool malevoli e malware utilizzano librerie crittografiche specifiche che generano firme uniche e distinguibili dai normali browser web.
  * **Formalizzazione:** Il sistema estrae l'impronta crittografica del client. Se tale impronta coincide con lo spazio delle firme associate a software d'attacco, la metrica certifica l'anomalia strutturale restituendo $M_{ja3} = 1$.

### 1.B Metriche Statistiche e Comportamentali (Finestra di 1 ora)
Queste metriche esplorano la "zona grigia", valutando variazioni anomale rispetto allo stato di quiete dell'host. Sfruttano la teoria degli insiemi (Novelty Detection) e lo scostamento statistico standardizzato ($Z_{robusto}$). Il calcolo avviene allo scoccare di ogni ora, confrontando i dati con la *baseline* degli ultimi **7 giorni**.

* **3. Scansione interna o Fan-out ($M_{scan}$)**
  * **Razionale Teorico:** In una rete ben strutturata, un host standard comunica regolarmente con un numero ristretto e stabile di nodi interni (es. gateway, server DNS, stampanti). Un incremento improvviso del numero di macchine interne contattate è il sintomo primario di una fase di ricognizione (*Network Discovery*) o del tentativo di propagazione di un'infezione (Movimento Laterale).
  * **Formalizzazione:** La variabile analizzata è la cardinalità degli IP interni contattati. Se il valore attuale si discosta in modo eccezionale dalla Mediana storica calcolata per quell'host ($Z_{robusto} > 3$), si attiva $M_{scan} = 1$.
* **4. Esplorazione Inedita di Rete ($M_{new}$)**
  * **Razionale Teorico:** Un host tradizionale tende a utilizzare un set circoscritto di protocolli e porte logiche legate alla sua funzione aziendale. L'apertura di connessioni verso porte logiche mai utilizzate in precedenza rappresenta un forte indicatore di cambiamento comportamentale, tipico dell'esfiltrazione dati tramite canali non convenzionali o dello sfruttamento di nuove vulnerabilità.
  * **Formalizzazione:** Applicando la *Novelty Detection*, sia $P_{storico}$ l'insieme delle porte logiche storicamente note e $P_{oggi}$ l'insieme delle porte attuali. Se l'insieme differenza non è vuoto ($P_{oggi} \setminus P_{storico} \neq \emptyset$), il comportamento è inedito e si fissa $M_{new} = 1$.
* **5. Asimmetria Volumetrica in Uscita ($M_{vol}$)**
  * **Razionale Teorico:** I flussi di rete client-server tradizionali sono tipicamente asimmetrici a favore del traffico in ingresso (download). Un ribaltamento improvviso di questa dinamica, caratterizzato da un trasferimento massivo di dati dall'host verso l'esterno, astrae il concetto di esfiltrazione di dati sensibili o di invio di materiale non autorizzato.
  * **Formalizzazione:** La variabile monitorata è la somma dei byte in uscita. Un picco estremo rispetto alla varianza abituale (MAD) genera un valore di $Z_{robusto} > 3$, attivando $M_{vol} = 1$.
* **6. Anomalie nel Protocollo di Risoluzione Nomi ($M_{dns}$)**
  * **Razionale Teorico:** Il DNS è un protocollo nato esclusivamente per tradurre nomi in indirizzi IP, caratterizzato da query brevi e leggibili. Tecniche avanzate di elusione (come il *DNS Tunneling*) abusano di questo protocollo incapsulando dati rubati all'interno di stringhe lunghissime e apparentemente casuali (es. `x8f9q...z1.dominio.com`). 
  * **Formalizzazione:** La metrica analizza le proprietà testuali delle richieste, come la lunghezza media o l'entropia della stringa. Se l'host inizia a generare query con un grado di entropia o lunghezza statisticamente incompatibile con la sua norma ($Z_{robusto} > 3$), si registra un abuso del canale e $M_{dns} = 1$.
* **7. Rigidità Temporale e Automazione ($M_{time}$)**
  * **Razionale Teorico:** L'interazione umana con le interfacce di rete è guidata da logiche stocastiche: il tempo tra un click e l'altro (o tra una richiesta e l'altra) presenta una varianza naturale molto elevata. Al contrario, i processi infetti (come le *botnet* che comunicano con il proprio creatore) sono implementati tramite cicli algoritmici rigidi, generando comunicazioni periodiche estremamente precise.
  * **Formalizzazione:** La metrica analizza la varianza del tempo di inter-arrivo (Inter-Arrival Time) dei pacchetti. L'anomalia si verifica non per un picco verso l'alto, ma per un crollo della varianza verso lo zero. Questa assenza di casualità genera un'enorme distanza matematica dalla mediana storica (umana), innescando lo $Z_{robusto} > 3$ e portando $M_{time} = 1$.

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

## 4 Giustificazione dei Parametri Statistici e Temporali

La solidità di un modello di *Anomaly Detection* non risiede solo nelle formule matematiche adottate, ma anche nel corretto dimensionamento dei parametri operativi. La scelta della soglia di anomalia, della finestra di osservazione e della profondità dello storico risponde a precise necessità statistiche e architetturali.

### 4.1. La Soglia di Anomalia ($Z_{robusto} > 3$)
L'impostazione della soglia di tolleranza $\theta = 3$ non è arbitraria, ma deriva direttamente dalla "Regola Empirica" della statistica descrittiva (nota anche come regola del 68-95-99.7). 



Assumendo che il traffico di rete tenda a distribuirsi attorno a un valore centrale (la Mediana), la dispersione misurata tramite la MAD ci permette di standardizzare le distanze:
* Uno Z-Score pari a **1** copre circa il **68%** delle normali fluttuazioni comportamentali.
* Uno Z-Score pari a **2** copre circa il **95%** della varianza regolare.
* Uno Z-Score pari a **3** ingloba il **99.7%** dei comportamenti ordinari dell'host.

Scegliere di attivare le metriche di allarme ($M_i = 1$) solo quando $Z_{robusto} > 3$ significa matematicamente che un evento ha meno dello **0.3%** di probabilità di essere un comportamento regolare casuale. Questa soglia estremamente conservativa è fondamentale in ambito *Cybersecurity* per abbattere drasticamente i falsi positivi e prevenire il fenomeno dell'affaticamento da allarmi.

### 4.2. La Finestra di Osservazione (Batch di 1 Ora)
Le metriche statistiche richiedono l'accumulo di un *set* di dati sufficiente per calcolare indicatori validi. Il sistema utilizza una finestra temporale di osservazione di **1 ora** (rispetto a un'analisi al minuto o giornaliera) come compromesso architetturale ottimale:
* **Contro il micro-batch (es. 5 minuti):** Finestre troppo brevi sono sensibili ai "micro-burst" (picchi istantanei legittimi, come il download di un file o l'apertura di una pagina web pesante), che invaliderebbero la statistica generando continuo "rumore".
* **Contro il macro-batch (es. 24 ore):** Un'osservazione giornaliera creerebbe distribuzioni statisticamente perfette, ma risulterebbe totalmente inefficace per la neutralizzazione degli attacchi (*Incident Response*). Se l'allarme per un'esfiltrazione dati o un movimento laterale scattasse solo a mezzanotte, il danno architetturale sarebbe già stato ampiamente consumato.
La finestra oraria garantisce quindi un volume di campioni statisticamente rilevante, mantenendo un tempo di reazione compatibile con le dinamiche di contenimento di un attacco.

### 4.3 La Profondità dello Storico (Baseline di 7 Giorni)
Per definire cosa sia "normale" per un dato host, il calcolo della Mediana $\tilde{x}$ e della $MAD$ avviene su una finestra storica di **7 giorni**. 
Questa scelta è dettata dalla necessità di assorbire la naturale **stagionalità settimanale** delle reti aziendali. Il traffico di una rete IT segue pattern ciclici legati agli orari e ai giorni lavorativi. 

Se il sistema utilizzasse uno storico di sole 24 ore, il traffico registrato un lunedì mattina verrebbe erroneamente classificato come un'anomalia estrema rispetto alla quiete della domenica precedente. La profondità di 7 giorni assicura che il comportamento attuale (es. martedì alle ore 10:00) venga confrontato con una baseline che ha già "imparato" e inglobato i pattern dell'intera settimana lavorativa e del weekend, rendendo il modello intrinsecamente consapevole dei cicli aziendali.

---
