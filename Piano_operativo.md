# Piano Operativo e Specifica delle Metriche

Il presente documento traduce il modello logico-matematico in un piano di implementazione pratico. Per evitare un carico computazionale insostenibile e per permettere un'analisi statistica affidabile, il sistema adotta un approccio ibrido: elaborazione a **finestre temporali (batch orari)** per i comportamenti statistici ed elaborazione **guidata dagli eventi (event-driven)** per i controlli deterministici.

## 1. Definizione Logica e Teorica delle Metriche di Sicurezza

Il modello si compone di **dieci metriche indipendenti**, selezionate per coprire l'intero spettro delle anomalie di rete. Ciascuna metrica astrae uno specifico comportamento dell'host e lo traduce in un valore normalizzato $M_i \in \{0, 1\}$. Le metriche sono raggruppate in base all'approccio logico utilizzato per la loro valutazione.

### 1.A Metriche Deterministiche (In tempo reale)
Queste metriche operano secondo una logica booleana e non necessitano di un periodo di apprendimento. Valutano la natura intrinseca di una singola connessione confrontandola con insiemi di dati noti a priori.

* **1. Reputazione Logica delle Destinazioni ($M_{rep}$)**
  * **Razionale Teorico:** Valuta il livello di affidabilità degli *endpoint* esterni con cui l'host tenta di comunicare. Una connessione verso un nodo di rete la cui maliziosità è già certificata (es. server di Comando e Controllo noti, nodi di uscita Tor, o domini di *phishing*) compromette istantaneamente lo stato di sicurezza dell'host interno, configurando una certezza di infezione o esfiltrazione.
  * **Implementazione Tecnica:** L'analizzatore estrae in tempo reale gli indirizzi IP di destinazione dai log di flusso (es. NetFlow) e i nomi a dominio estratti dalle query DNS. Questi indicatori di compromissione estratti dal traffico vengono confrontati in modo deterministico con piattaforme di *Threat Intelligence* aziendali (es. MISP) o *blacklist* pubbliche costantemente aggiornate.
  * **Formalizzazione:** Sia $\mathcal{B}$ l'insieme dinamico degli Indicatori di Compromissione, che include tutti gli indirizzi IP e i domini globalmente riconosciuti come malevoli in un dato istante temporale. Sia $d$ l'indirizzo IP di destinazione di un flusso di rete generato e $q$ l'eventuale dominio interrogato dall'host $h$. Se l'host tenta di contattare una destinazione presente nella lista nera:

    $$d \in \mathcal{B} \lor q \in \mathcal{B}$$

    l'evento viene immediatamente marcato come compromissione certa, restituendo $M_{rep} = 1$.

* **2. Fingerprinting Crittografico del Client ($M_{ja3}$)**
  * **Razionale Teorico:** La crittografia (TLS/SSL) rende illeggibile il contenuto dei pacchetti, impedendo le analisi tradizionali. Tuttavia, ogni software (browser, script Python, o malware) esegue la fase di handshake in modo unico, dichiarando quali algoritmi e versioni supporta. Questa "firma" permette di identificare il tipo di applicazione che ha originato il traffico, distinguendo un browser legittimo da un tool d'attacco o da un ransomware.
  * **Implementazione Tecnica:** Il sistema utilizza sonde di ispezione profonda (DPI come Zeek o Suricata) per estrarre cinque parametri specifici dal pacchetto *TLS Client Hello*. Questi parametri vengono concatenati e trasformati in un'impronta digitale univoca di 32 caratteri (Hash MD5), denominata **JA3**. Tale impronta viene confrontata in tempo reale con un database di firme associate a strumenti malevoli (es. Cobalt Strike, Metasploit, o diverse famiglie di malware).
  * **Formalizzazione:** Sia $\mathcal{J}$ l'insieme delle firme JA3 censite come malevole nelle banche dati di *Threat Intelligence*. Sia $j$ l'impronta JA3 estratta dalla connessione corrente dell'host $h$. Se l'impronta calcolata appartiene all'insieme delle firme note per software d'attacco:

    $$j \in \mathcal{J}$$

    la metrica certifica l'uso di software non autorizzato o malevolo, restituendo $M_{ja3} = 1$.

* **3. Anomalie nei Certificati TLS ($M_{cert}$)**
  * **Razionale Teorico:** I siti web e i servizi cloud legittimi utilizzano certificati crittografici emessi da Autorità di Certificazione (CA) pubblicamente riconosciute e attendibili. Le infrastrutture d'attacco o i server C2 (*Command and Control*) improvvisati impiegano frequentemente certificati auto-firmati (*Self-Signed*), scaduti, o generati con parametri di validità palesemente anomali per risparmiare tempo o eludere i controlli di base.
  * **Implementazione Tecnica:** Il sistema sfrutta sonde di *Deep Packet Inspection* per analizzare il pacchetto *TLS Certificate* inviato dal server al client durante l'handshake. Estrae i metadati del certificato X.509 (in particolare i campi *Issuer*, *Subject*, *Not Before* e *Not After*). Successivamente, verifica se la CA emittente appartiene al *Trust Store* aziendale (l'elenco delle autorità di cui ci si fida) e valuta la coerenza temporale delle date di validità.
  * **Formalizzazione:** Sia $c$ il certificato TLS presentato dal server di destinazione. Definiamo $\mathcal{T}$ come l'insieme delle Autorità di Certificazione (CA) globalmente attendibili. Definiamo inoltre la funzione booleana $SelfSigned(c)$ (vera se il certificato è auto-firmato, ovvero se l'emittente coincide con il soggetto) e la funzione $Invalid(c)$ (vera se il certificato risulta scaduto o con date di validità non conformi). Se si verifica almeno una di queste condizioni anomale:

    $$Issuer(c) \notin \mathcal{T} \lor SelfSigned(c) \lor Invalid(c)$$

    il canale di comunicazione viene marcato come inaffidabile o potenzialmente compromesso, attivando $M_{cert} = 1$.

### 1.B Metriche Statistiche e Comportamentali (Finestra di 1 ora)
Queste metriche esplorano la "zona grigia", valutando variazioni anomale rispetto allo stato di quiete dell'host. Sfruttano l'ispezione profonda, la teoria degli insiemi (Novelty Detection) e lo scostamento statistico standardizzato ($Z_{robusto}$). Il calcolo avviene allo scoccare di ogni ora, confrontando i dati con la *baseline* degli ultimi **7 giorni**.

* **4. Rilevamento Funzionalità Server ($M_{srv}$)**
  * **Razionale Teorico:** In una rete aziendale standard, una normale *workstation* opera tipicamente come "Client", originando traffico verso l'esterno. L'apertura improvvisa di una porta locale in ascolto (socket) che accetta con successo connessioni in ingresso indica un'inversione di ruolo, sintomo critico dell'installazione di una *backdoor* o di un movimento laterale. Il sistema adotta un approccio **Zero Trust**: ogni inversione di ruolo genera un'anomalia. Si esclude deliberatamente l'uso di "Whitelist" per gli IP di amministrazione IT, poiché la compromissione di un nodo autorizzato permetterebbe all'attaccante di muoversi lateralmente eludendo la metrica.
  * **Implementazione Tecnica:** Il monitoraggio si basa sull'analisi deterministica dei flussi di rete (tramite sonde come NetFlow o Zeek) a livello di trasporto (L4). Per il protocollo TCP, un host interno agisce da server se invia pacchetti con flag `SYN-ACK` in risposta a un `SYN`. Nei log di flusso, ciò si traduce nell'osservare l'host monitorato con il ruolo di *Responder* in una sessione contrassegnata come stabilita.
  * **Formalizzazione:** Sia $F$ l'insieme dei flussi di rete bidirezionali stabiliti con successo. Un singolo flusso $f \in F$ è definito dalla tupla $(o, r)$, dove $o$ è l'host *Originator* (chi inizia la connessione) e $r$ è l'host *Responder* (chi accetta la connessione). Se per l'host monitorato $h$ esiste almeno un flusso $f$ in cui esso compare come ricevitore ($h = r$), si certifica l'inversione di ruolo e si impone $M_{srv} = 1$.

* **5. Protocollo su Porta Non Standard ($M_{proto}$)**
  * **Razionale Teorico:** I firewall perimetrali tradizionali bloccano il traffico basandosi sulle porte logiche (Livello 4). Per eludere queste restrizioni, gli attaccanti instradano traffico anomalo (es. protocolli di amministrazione remota come SSH, o tunnel VPN) su porte tipicamente sempre aperte e riservate al traffico web (come la porta 80 o 443).
  * **Implementazione Tecnica:** La misurazione richiede l'impiego di sonde di *Deep Packet Inspection* (DPI), come Zeek o librerie come nDPI. Questi strumenti analizzano la firma strutturale del *payload* del pacchetto per identificare il reale protocollo applicativo (Livello 7), indipendentemente dalla porta utilizzata. Il sistema estrae il metadato L7 e lo confronta con lo standard IANA atteso per la porta di destinazione (L4) del flusso.
  * **Formalizzazione:** Sia $p$ la porta logica di destinazione di un flusso di rete. Sia $\mathcal{M}(p)$ la funzione che mappa la porta $p$ al suo protocollo applicativo standard atteso (ad esempio, $\mathcal{M}(443) = \text{TLS}$). Sia $L7_{DPI}$ il reale protocollo applicativo identificato dalla sonda tramite ispezione profonda. Se l'analizzatore identifica con certezza un protocollo che diverge dallo standard atteso ( $L7_{DPI} \neq \mathcal{M}(p)$ ), viene certificato un tentativo di evasione o un mascheramento del traffico, fissando $M_{proto} = 1$.

* **6. Scansione Interna o Fan-out ($M_{scan}$)**
  * **Razionale Teorico:** Un host standard all'interno di un'architettura di rete comunica tipicamente con un numero stabile e limitato di nodi interni (es. domain controller, file server, stampanti). Un incremento improvviso e massiccio del "Fan-out" (il numero di host distinti contattati) è il sintomo primario di una fase di ricognizione automatizzata (*Network Discovery*) o del tentativo di propagazione di un'infezione (Movimento Laterale).
  * **Implementazione Tecnica:** Il calcolo viene effettuato aggregando i log di flusso direzionali (es. NetFlow) alla chiusura della finestra oraria (batch). Il sistema filtra esclusivamente i flussi in cui l'host monitorato agisce come *Originator* e in cui l'indirizzo IP di destinazione appartiene allo spazio di indirizzamento interno dell'organizzazione (es. subnet RFC 1918). Viene quindi estratto il numero di indirizzi IP di destinazione unici.
  * **Formalizzazione:** Sia $D_{int}$ l'insieme degli IP interni univoci contattati dall'host $h$ nella finestra oraria corrente $t$. La variabile osservata è la cardinalità dell'insieme: $x_t = |D_{int}|$. Siano $\tilde{x}$ e $MAD$ rispettivamente la Mediana e la *Median Absolute Deviation* calcolate sulla distribuzione storica della stessa variabile $x$ per l'host $h$ negli ultimi 7 giorni. Il sistema calcola lo scostamento statistico standardizzato:

    $$Z_{robusto} = \frac{|x_t - \tilde{x}|}{MAD}$$

    Se il valore risultante indica un picco eccezionale ($Z_{robusto} > 3$), l'anomalia esplorativa è certificata e si impone $M_{scan} = 1$.

* **7. Esplorazione di Protocolli Inediti ($M_{new}$)**
  * **Razionale Teorico:** Un host aziendale standard possiede una "firma comportamentale" applicativa ben definita e ripetitiva (es. navigazione web via HTTP/TLS, risoluzione nomi via DNS, protocolli di posta). L'esordio improvviso di protocolli di Livello 7 mai utilizzati in precedenza dalla macchina (come traffico *Peer-to-Peer* per l'esfiltrazione, *routing* anonimo tramite Tor, o protocolli di amministrazione remota come RDP/SSH) è un indicatore primario dell'esecuzione di un *payload* malevolo o della compromissione del nodo.
  * **Implementazione Tecnica:** L'analisi si affida ai log generati da un motore di *Deep Packet Inspection* (DPI, es. Zeek o nDPI), che estrae con precisione l'identificativo del protocollo applicativo incapsulato nel *payload*, ignorando la porta L4. Al termine di ogni batch orario, il sistema aggrega tutti i protocolli L7 identificati per l'host e li confronta con il "profilo applicativo" appreso dinamicamente (la *baseline* ricavata dai log degli ultimi 7 giorni).
  * **Formalizzazione:** Applicando i principi della *Novelty Detection* tramite la teoria degli insiemi, sia $P_{storico}$ l'insieme di tutti i protocolli applicativi (L7) univoci generati dall'host $h$ nella finestra di apprendimento mobile di 7 giorni. Sia $P_{batch}$ l'insieme dei protocolli applicativi estratti dal traffico dell'host $h$ nell'ultima ora di monitoraggio. Se l'insieme differenza tra i due non risulta vuoto:

    $$P_{batch} \setminus P_{storico} \neq \emptyset$$
    
    significa che è comparso almeno un protocollo totalmente inedito per la storicità del nodo. In tal caso, si fissa $M_{new} = 1$.

* **8. Asimmetria Volumetrica in Uscita ($M_{vol}$)**
  * **Razionale Teorico:** Nella normale operatività aziendale, una postazione di lavoro ha un profilo di traffico asimmetrico sbilanciato verso il *download* (scaricamento di file, navigazione web, ricezione posta). Un ribaltamento improvviso di questa dinamica, caratterizzato da un trasferimento massivo di dati dall'host verso l'esterno (*upload*), astrae il concetto critico di esfiltrazione di dati sensibili o di invio di archivi verso un server *Drop point* controllato da un attaccante.
  * **Implementazione Tecnica:** Il calcolo aggrega la telemetria di base dei flussi di rete direzionali (NetFlow o log del Firewall) alla chiusura del batch orario. Il sistema filtra i flussi uscenti (dove l'host monitorato è *Originator* e la destinazione è un IP esterno) e somma il valore del campo "Byte trasmessi" (o `bytes_out`).
  * **Formalizzazione:** Sia $V_{out}$ il volume totale in byte trasmessi verso l'esterno dall'host $h$ nella finestra oraria corrente $t$. Siano $\tilde{V}$ e $MAD$ la Mediana e la *Median Absolute Deviation* dei volumi in uscita storici (finestra di 7 giorni). Il sistema calcola lo Z-Score robusto per quantificare l'anomalia volumetrica:
    
    $$Z_{robusto} = \frac{|V_{out} - \tilde{V}|}{MAD}$$
    
    Se il picco di trasferimento genera uno scostamento eccezionale rispetto alla varianza abituale ($Z_{robusto} > 3$), l'esfiltrazione o l'asimmetria anomala viene certificata, portando $M_{vol} = 1$.
    
* **9. Anomalie nel Protocollo di Risoluzione Nomi ($M_{dns}$)**
  * **Razionale Teorico:** Alcuni attacchi avanzati (come il *DNS Tunneling* o i malware DGA) sfruttano il normale traffico DNS per nascondere informazioni. Invece di chiedere alla rete di tradurre nomi a dominio legittimi, gli attaccanti incapsulano dati esfiltrati o comandi all'interno di stringhe lunghissime e generate in modo pseudo-casuale (es. `x9k2js8...malicious.com`).
  * **Implementazione Tecnica:** L'analizzatore estrae i nomi a dominio completi (FQDN) direttamente dalle richieste registrate nei log del server DNS aziendale o tramite sonde di traffico passivo. Su ogni stringa estratta viene calcolata l'Entropia di Shannon, un indicatore matematico che ne misura il "livello di disordine" o casualità dei caratteri. Al termine della finestra oraria, si calcola l'entropia aggregata delle richieste e la si confronta con il profilo abituale dell'host.
  * **Formalizzazione:** Sia $q$ la stringa del dominio interrogato e $p_i$ la frequenza con cui compare l'i-esimo carattere nella parola. L'Entropia di Shannon per la singola richiesta è calcolata come:

    $$E(q) = - \sum_{i} p_i \log_2(p_i)$$

    Sia $E_{batch}$ il valore di entropia tipico registrato dall'host $h$ nell'ora corrente. Confrontandolo con la Mediana $\tilde{E}$ e la $MAD$ storiche (calcolate su 7 giorni), si ottiene lo scostamento statistico:

    $$Z_{robusto} = \frac{|E_{batch} - \tilde{E}|}{MAD}$$

    Se il livello di disordine delle stringhe genera uno scostamento incompatibile con le normali abitudini dell'host ($Z_{robusto} > 3$), si registra un abuso del protocollo e si fissa $M_{dns} = 1$.

* **10. Rigidità Temporale e Automazione ($M_{time}$)**
  * **Razionale Teorico:** I processi infetti (come le *botnet*) comunicano con i server esterni di Comando e Controllo (C2) utilizzando cicli algoritmici preimpostati. Questo genera comunicazioni periodiche estremamente precise (effetto *heartbeat* o battito cardiaco), in netto contrasto con l'elevata variabilità temporale che caratterizza la normale navigazione umana.
  * **Implementazione Tecnica:** Il sistema analizza i *timestamp* di inizio dei flussi di rete verso destinazioni esterne (es. log NetFlow). Viene calcolato il tempo di inter-arrivo, ovvero l'intervallo temporale che trascorre tra la generazione di un flusso e il successivo. Alla fine del batch orario, si valuta la varianza di questi intervalli. Una varianza che crolla verso lo zero indica una forte automazione meccanica e innaturale.
  * **Formalizzazione:** Sia $\Delta t_i$ il tempo trascorso tra l'inizio di un flusso di rete e il successivo. Sia $V_{batch}$ la varianza di questi intervalli temporali registrata nell'ora corrente per l'host $h$. Confrontandola con la Mediana storica $\tilde{V}$ e la $MAD$, si calcola lo scostamento:

    $$Z_{robusto} = \frac{|V_{batch} - \tilde{V}|}{MAD}$$

    Se lo scostamento statistico è eccezionale ($Z_{robusto} > 3$) e, contestualmente, la varianza attuale è nettamente inferiore a quella storica (cioè $V_{batch} \ll \tilde{V}$, indicando un crollo della variabilità temporale), si certifica la presenza di un automatismo informatico e si impone $M_{time} = 1$.

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
