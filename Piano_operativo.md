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

* **2. Fingerprinting Crittografico del Client ($M_{ja4}$)**
    * **Razionale Teorico:** L'uso diffuso della crittografia (TLS/SSL) protegge la privacy oscurando il contenuto dei pacchetti, ma al contempo nasconde le attività malevole ai tradizionali sistemi di ispezione. Tuttavia, la fase iniziale di negoziazione (*TLS Client Hello*), che avviene in chiaro, rivela il comportamento del software. Ogni applicazione (browser, script automatizzato o malware) negozia la connessione in modo unico, richiedendo specifici algoritmi, versioni e supporti. L'impronta JA4 cattura questa "firma comportamentale", permettendo di distinguere, ad esempio, un browser aziendale legittimo da uno strumento d'attacco o da un malware, indipendentemente dall'IP contattato.
    * **Implementazione Tecnica:** Il sistema sfrutta le capacità di ispezione profonda dei NIDS (es. Suricata 7+) per estrarre le caratteristiche della connessione TLS e calcolare l'impronta JA4. Questa impronta (es. `t13d1516h2_8daaf6152771_a56c5b993250`) è modulare e divisa in tre sezioni: un prefisso in chiaro che descrive il protocollo e il numero di estensioni, un hash degli algoritmi crittografici supportati e un hash delle estensioni stesse. Questa firma viene confrontata in tempo reale con i database di *Threat Intelligence* (es. repository FoxIO) contenenti le impronte associate a strumenti malevoli (come Cobalt Strike, Metasploit o script elusivi).
    * **Formalizzazione:** Sia $\mathcal{J}$ l'insieme delle impronte crittografiche JA4 classificate come malevole o sospette dalle fonti di *Threat Intelligence*. Sia $j$ l'impronta JA4 estratta dal pacchetto *Client Hello* generato dall'host $h$. Se l'impronta calcolata appartiene all'insieme delle firme malevole note:

        $$j \in \mathcal{J}$$

        la metrica certifica l'impiego di software di rete non autorizzato o malevolo, attivandosi e restituendo $M_{ja4} = 1$.

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

* **11. Tasso di Connessioni Fallite ($M_{fail}$)**
  * **Razionale Teorico:** Nella normale operatività aziendale, la stragrande maggioranza dei tentativi di connessione (es. *handshake* TCP o richieste DNS) avviati da un client legittimo si conclude con successo. Al contrario, un software malevolo impegnato in attività di ricognizione silenziosa della rete interna (*stealth scanning*) o nella ricerca di un server di Comando e Controllo di riserva (tramite DGA), genererà inevitabilmente una vasta mole di tentativi di connessione a vuoto (esitanti in pacchetti *RST* o *Timeout*). Un'impennata improvvisa del tasso di fallimento astrae perfettamente questo comportamento anomalo di "ricerca alla cieca".
  * **Implementazione Tecnica:** Il NIDS (Suricata) tiene traccia dello stato di terminazione di ogni connessione bidirezionale, registrando se un flusso è stato stabilito correttamente o se è fallito/rifiutato. Al termine del batch orario, il sistema aggrega tutti i flussi originati dall'host monitorato e calcola il rapporto percentuale tra le connessioni fallite e il totale dei tentativi effettuati, confrontandolo poi con la tolleranza storica dell'host.
  * **Formalizzazione:** Sia $F_{tot}$ l'insieme di tutti i flussi di rete originati dall'host $h$ nella finestra oraria corrente $t$. Sia $F_{fail} \subseteq F_{tot}$ il sottoinsieme dei flussi terminati con esito anomalo. Il tasso di fallimento orario è definito come:

    $$r_t = \frac{|F_{fail}|}{|F_{tot}|}$$

    Siano $\tilde{r}$ e $MAD$ rispettivamente la Mediana e la *Median Absolute Deviation* dei tassi di fallimento storici (finestra mobile di 7 giorni). Il sistema calcola lo scostamento statistico standardizzato:

    $$Z_{robusto} = \frac{|r_t - \tilde{r}|}{MAD}$$

    Se il tasso di errore subisce un incremento eccezionale rispetto alla consuetudine dell'host ($Z_{robusto} > 3$), l'anomalia esplorativa viene certificata, portando $M_{fail} = 1$.

* **12. Anomalie di Durata della Sessione / Reverse Shell ($M_{dur}$)**
  * **Razionale Teorico:** Il traffico web generato da un utente umano è intrinsecamente "a raffiche" (*bursty*): le connessioni vengono aperte per scaricare risorse e chiuse rapidamente. Al contrario, un attaccante che stabilisce una *Reverse Shell* o un tunnel persistente necessita di mantenere la sessione aperta per ore o giorni per inviare comandi interattivi o esfiltrare dati. Questa metrica identifica i flussi che rimangono attivi per tempi sproporzionati rispetto alla norma statistica dell'host.
  * **Implementazione Tecnica:** Il sistema analizza il campo `flow.age` nei log di Suricata, che indica la durata in secondi di ogni sessione. Allo scadere del batch orario, si estrae il valore massimo di durata osservato tra tutti i flussi attivi o chiusi nell'ora. Questo dato viene confrontato con la distribuzione storica (ultimi 7 giorni) delle durate massime registrate dall'host.
  * **Formalizzazione:** Sia $T$ l'insieme delle durate (in secondi) dei flussi originati dall'host $h$ nell'ora $t$. Sia $x_t = \max(T)$ il valore di persistenza massima. Siano $\tilde{x}$ e $MAD$ la Mediana e la *Median Absolute Deviation* storiche. Lo scostamento standardizzato è:
    
    $$Z_{robusto} = \frac{|x_t - \tilde{x}|}{MAD}$$
    
    Se $Z_{robusto} > 3$ e la durata osservata è superiore alla mediana ($x_t > \tilde{x}$), si identifica una persistenza anomala e si impone $M_{dur} = 1$.

---

## 2. Sistema di Scoring Additivo e Normalizzazione (0-100)

Il modello operativo non valuta i singoli pacchetti in modo isolato, ma aggrega le anomalie per definire lo stato di salute generale del nodo. Per garantire un'analisi consistente e limitare l'esplosione combinatoria dei dati, il sistema di *scoring* si basa su regole precise di temporizzazione e normalizzazione.

### 2.1 Frequenza di Calcolo e Normalizzazione Matematica
Per rispondere all'esigenza di correlare gli eventi senza sovraccaricare il sistema, lo *Score Globale* dell'host viene calcolato (o ricalcolato) in due scenari:
1. **Event-driven (In tempo reale):** Immediatamente, non appena si attiva una metrica deterministica (es. $M_{rep}$ o $M_{ja4}$).
2. **Time-driven (A fine batch):** Allo scadere di ogni finestra oraria (1 ora), aggregando i risultati delle metriche statistiche.


Per prevenire un'esplosione incontrollata del punteggio, il sistema implementa una **normalizzazione intrinseca basata sulla finestra temporale anziché sui singoli eventi**. 

È fondamentale chiarire che il punteggio **non è cumulativo per ogni singolo flusso di rete anomalo**. La trasformazione di ogni metrica in una variabile booleana ($M_i \in \{0, 1\}$) garantisce che la penalità venga assegnata esclusivamente per la *presenza* di quel comportamento nell'arco dell'ora monitorata, indipendentemente dalla sua frequenza di ripetizione. 

Ad esempio, se un host genera 1.000 connessioni evasive verso una porta non standard all'interno dello stesso batch orario, la metrica non assegnerà 1.000 penalità consecutive, ma "scatterà" una sola volta per quell'ora ($M_{proto} = 1$). L'intensità e il volume dell'attacco non vengono ignorati dal modello, ma sono già valutati e assorbiti a monte dal calcolo dello $Z_{robusto}$, il quale funge da interruttore per attivare o meno la metrica. Questo meccanismo garantisce che lo score finale rimanga confinato e proporzionato all'interno della scala 0-100.

### 2.2 Ponderazione delle Soglie di Rischio
I "pesi" assegnati alle singole metriche non sono casuali, ma derivano da un'analisi del rischio basata su due fattori: l'**impatto** dell'anomalia (es. esfiltrazione vs ricognizione) e la **probabilità di falsi positivi**. Ogni anomalia rilevata ($M_i = 1$) aggiunge un punteggio predefinito:

* **Gravità Critica (+50 punti):** Assegnati a comportamenti con un livello di confidenza quasi assoluto e falsi positivi prossimi allo zero. Una singola violazione (es. contattare una destinazione malevola nota) compromette per metà l'affidabilità del nodo. Due violazioni critiche saturate portano subito lo score a 100.
  * Reputazione Destinazione ($M_{rep}$)
  * Fingerprinting crittografico JA4 ($M_{ja4}$)
* **Sospetto Alto (+40 punti):** Anomalie strutturali gravi, ma che richiedono almeno un'altra anomalia secondaria per certificare la compromissione totale (superamento soglia 60).
  * Anomalie Certificati TLS ($M_{cert}$)
  * Funzionalità Server Rilevata ($M_{srv}$)
* **Evasione e Ricognizione (+30 punti):** Comportamenti tipici delle fasi intermedie di un attacco (es. movimenti laterali), che potrebbero però coincidere con rari interventi di amministrazione IT.
  * Protocollo su Porta Non Standard ($M_{proto}$)
  * Scansione interna / Fan-out ($M_{scan}$)
  * Tasso di Connessioni Fallite ($M_{fail}$)
  * Anomalie di Durata Sessione ($M_{dur}$)
* **Anomalie di profilo e di volume (+20 punti):** Assegnati ad anomalie puramente quantitative. Hanno un'alta probabilità di falsi positivi (es. un dipendente che usa WeTransfer genera un'asimmetria volumetrica), pertanto il peso ridotto garantisce che l'host rimanga in "zona verde/sicura" se l'evento è isolato.
  * Esplorazione Inedita ($M_{new}$)
  * Asimmetria Volumetrica ($M_{vol}$)
* **Segnali Deboli (+10 punti):** Anomalie che, prese singolarmente, non sono sufficienti per destare allarme, ma fungono da "moltiplicatori" per confermare altre minacce.
  * Anomalie DNS ($M_{dns}$)
  * Automazione Temporale ($M_{time}$)

L'equazione finale per il calcolo dello *Score Globale* dell'host risulta matematicamente limitata a un valore massimo di 100 tramite la funzione minimo:

$$S(h) = \min\left(100, \sum_{i=1}^{12} \text{Punti}_i \cdot M_i\right)$$

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

## 4. Analisi Comparativa e Architettura del Sistema

La progettazione di questo modello operativo nasce da un'analisi critica delle più recenti evoluzioni nella letteratura scientifica in ambito *Cybersecurity* (2024-2025). La solidità del sistema non risiede solo nelle formule matematiche adottate, ma nella scelta deliberata di un'architettura che superi gli attuali limiti operativi dell'Intelligenza Artificiale, unita a un rigoroso dimensionamento dei parametri statistici e temporali.

### 4.1 L'Uso della Statistica Robusta per superare il "Rumore" di Rete
L'applicazione di modelli statistici classici per la *Network Anomaly Detection* sconta storicamente il limite della sensibilità agli *outlier*: i normali (e legittimi) picchi di traffico aziendale alterano la media aritmetica e la deviazione standard, generando cecità statistica o falsi positivi.

Per risolvere questo problema, la letteratura più recente ha validato l'efficacia della statistica robusta applicata al traffico di rete. Romo-Chavero et al. [1] (2025) propongono un framework in cui la MAD (*Median Absolute Deviation*) viene impiegata per rilevare le anomalie del protocollo BGP, dimostrando che il calcolo delle deviazioni basato sulla Mediana garantisce un'elevata resistenza ai picchi di traffico non malevoli. 

Il modello proposto in questa tesi condivide l'assunto teorico validato da Romo-Chavero et al., adottando la MAD e lo $Z_{robusto}$ come motore statistico per le metriche comportamentali. Tuttavia, se ne distacca per l'efficienza applicativa: mentre nella letteratura accademica la MAD viene spesso usata solo come fase di preparazione dati (*labeling*) per addestrare successivi e pesanti modelli di Machine Learning, il nostro sistema utilizza i superamenti della soglia dello $Z_{robusto}$ per alimentare direttamente il sistema di *scoring*. Questa scelta mantiene intatta la resilienza statistica, ma azzera i costi di addestramento computazionale.

### 4.2 Rilevamento su Traffico Cifrato: Efficienza vs. Complessità

Oggi oltre il 90% del traffico web è protetto da protocolli crittografici (come TLS/HTTPS). Questo ha reso largamente inefficace la tradizionale *Deep Packet Inspection* (DPI), originariamente progettata per leggere il contenuto in chiaro dei pacchetti. Tuttavia, studi recenti come quello di Muttaqien et al. (2025) dimostrano che è possibile identificare le minacce analizzando i metadati non cifrati scambiati durante la fase iniziale di *handshake*. Tra questi indicatori spiccano le caratteristiche dei certificati TLS e le impronte crittografiche del client (storicamente basate sullo standard JA3).

Nel loro studio, Muttaqien et al. estraggono proprio le vecchie impronte JA3 e le classificano impiegando complesse architetture di *Deep Learning* (modelli ibridi Random Forest e LSTM). Pur garantendo un'elevata accuratezza, queste reti neurali risultano estremamente onerose dal punto di vista computazionale: per addestrare il modello è stato necessario elaborare un dataset di ben 30 milioni di sessioni.

Il nostro modello operativo compie un doppio salto evolutivo rispetto a questo approccio. In primo luogo, aggiorna il set di estrazione adottando il più moderno e robusto standard **JA4** (metrica $M_{ja4}$), che supera i limiti strutturali e le vulnerabilità di collisione del suo predecessore. In secondo luogo, abbandona le pesanti architetture predittive in favore di una strategia deterministica. Invece di delegare l'analisi a una rete neurale, il sistema valida l'impronta JA4 e i Certificati confrontandoli in tempo reale con fonti di *Threat Intelligence* (firme malevole note) ed eseguendo controlli logici formali. Questo approccio garantisce un blocco immediato e privo di falsi positivi per le minacce conosciute, risultando molto più leggero, rapido e facilmente implementabile rispetto alle architetture basate su *Deep Learning*.

### 4.3 Vantaggi Operativi del Risk Scoring Deterministico rispetto all'AI

Sebbene l'Intelligenza Artificiale (AI) sia molto popolare nella ricerca accademica per rilevare le intrusioni di rete, la sua applicazione pratica nel mondo reale sconta diverse criticità. Gli stessi ricercatori che sviluppano questi modelli ammettono spesso la necessità di approcci più snelli e gestibili.

Il primo grande ostacolo riguarda i **costi computazionali e il cosiddetto *Concept Drift***. Come evidenziato dallo studio di Talukder et al. [3] (2025), i modelli di *Machine Learning* richiedono un'enorme potenza di calcolo, rendendoli difficili da usare su reti ad alto traffico. Inoltre, l'AI impara esclusivamente dai dati passati: se gli attaccanti inventano una nuova tecnica per eludere le difese, il modello diventa subito obsoleto (subisce una "deriva del concetto" o *Concept Drift*) e deve essere faticosamente riaddestrato con nuovi dati.

Il secondo problema riguarda le **nuove vulnerabilità e l'effetto "scatola nera" (*Explainability*)**. Acharjya et al. [4] (2025) sottolineano come gli hacker utilizzino già tecniche mirate (*Adversarial Machine Learning*) per inquinare i dati di addestramento e ingannare deliberatamente l'Intelligenza Artificiale. A questo si aggiunge un forte limite operativo intrinseco alle reti neurali: la mancanza di **interpretabilità** (il cosiddetto effetto *Black-Box*). Questo impedisce agli analisti di estrarre la catena logica che ha innescato un allarme, costringendoli a lunghe indagini manuali per validare l'effettiva presenza di una minaccia.

Per superare questi limiti, il nostro modello adotta una strategia di **Risk Scoring statico e deterministico (*White-Box*)**. Invece di affidarsi a previsioni basate sui dati storici, il sistema assegna punteggi di rischio precisi ogni volta che rileva una violazione evidente e oggettiva delle regole di rete (come una scansione interna o l'uso di un protocollo anomalo). Questo approccio algoritmico garantisce tre vantaggi fondamentali:
1. **Immunità all'inganno (*Adversarial ML*):** Basandosi su regole logiche fisse, il sistema non può essere manipolato o "avvelenato" dall'attaccante.
2. **Nessun riaddestramento (*Zero-Training*):** Il modello non ha bisogno di imparare costantemente le nuove tattiche d'attacco, perché si concentra sul rilevare le violazioni dei principi di base della rete, che restano sempre invariati.
3. **Trasparenza Immediata:** L'analista capisce in un istante perché è scattato l'allarme (es. "L'host ha 70 punti: 50 per un certificato falso + 20 per traffico anomalo"), velocizzando drasticamente la risposta all'incidente (*Incident Response*).

### 4.4 Giustificazione dei Parametri Statistici e Temporali
Una volta definita e validata l'architettura deterministica rispetto allo Stato dell'Arte, è fondamentale dimensionare correttamente i parametri operativi affinché il modello si adatti al traffico reale senza generare *Alert Fatigue*.
* **La Soglia di Anomalia ($Z_{robusto} > 3$):** L'impostazione della soglia di tolleranza $\theta = 3$ non è arbitraria, ma deriva direttamente dalla "Regola Empirica" della statistica descrittiva (nota anche come regola del 68-95-99.7). 

Assumendo che il traffico di rete tenda a distribuirsi attorno a un valore centrale (la Mediana), la dispersione misurata tramite la MAD ci permette di standardizzare le distanze:
* Uno Z-Score pari a **1** copre circa il **68%** delle normali fluttuazioni comportamentali.
* Uno Z-Score pari a **2** copre circa il **95%** della varianza regolare.
* Uno Z-Score pari a **3** ingloba il **99.7%** dei comportamenti ordinari dell'host.

Scegliere di attivare le metriche di allarme solo quando $Z_{robusto} > 3$ significa matematicamente che un evento ha meno dello **0.3%** di probabilità di essere un comportamento regolare casuale. Questa soglia estremamente conservativa è fondamentale in ambito *Cybersecurity* per abbattere drasticamente i falsi positivi e prevenire il fenomeno dell'affaticamento da allarmi.
* **La Finestra di Osservazione (Batch di 1 Ora):** Le metriche statistiche richiedono l'accumulo di un *set* di dati sufficiente per calcolare indicatori validi. Il sistema utilizza una finestra temporale di osservazione di **1 ora** (rispetto a un'analisi al minuto o giornaliera) come compromesso architetturale ottimale:
* **Contro il micro-batch (es. 5 minuti):** Finestre troppo brevi sono sensibili ai "micro-burst" (picchi istantanei legittimi, come il download di un file), che invaliderebbero la statistica generando continuo "rumore".
* **Contro il macro-batch (es. 24 ore):** Un'osservazione giornaliera creerebbe distribuzioni statisticamente perfette, ma risulterebbe totalmente inefficace per la neutralizzazione degli attacchi (*Incident Response*). La finestra oraria garantisce un volume di campioni statisticamente rilevante, mantenendo un tempo di reazione compatibile con le dinamiche di contenimento di un attacco.
* **La Profondità dello Storico (Baseline di 7 Giorni):** Il calcolo della Mediana $\tilde{x}$ e della $MAD$ avviene su una finestra storica di **7 giorni**. Questa scelta è dettata dalla necessità di assorbire la naturale **stagionalità settimanale** delle reti aziendali, intrinsecamente legata agli orari lavorativi e ai giorni di riposo. La profondità di 7 giorni assicura che il comportamento attuale venga confrontato con una baseline che ha già "imparato" i pattern dell'intera settimana, rendendo il modello consapevole dei cicli aziendali.

---

## 5. Riferimenti Bibliografici

[1] M. A. Romo-Chavero, G. de los Ríos Alatorre, J. A. Cantoral-Ceballos, J. A. Pérez-Díaz, and C. Martinez-Cagnazzo, *"A Hybrid Model for BGP Anomaly Detection Using Median Absolute Deviation and Machine Learning"*, IEEE Open Journal of the Communications Society, vol. 6, 2025. [DOI: 10.1109/OJCOMS.2025.3550010](https://doi.org/10.1109/OJCOMS.2025.3550010)

[2] H. Muttaqien, M. Niswar, Z. Zainuddin, and S. Syarif, *"Efficient Identification of Malicious Traffic in TLS Networks Using Machine Learning"*, 2025 IEEE International Conference on Artificial Intelligence and Mechatronics Systems (AIMS), 2025. [DOI: 10.1109/AIMS66189.2025.11229622](https://doi.org/10.1109/AIMS66189.2025.11229622)

[3] A. Talukder and A. Rahman, *"Evaluating the Efficacy of Explainable Machine Learning Algorithms for the Detection and Classification of Network Intrusions"*, 2025 IEEE 2nd International Conference on Computing, Applications and Systems (COMPAS), 2025. [DOI: 10.1109/COMPAS67506.2025.11381867](https://doi.org/10.1109/COMPAS67506.2025.11381867)

[4] K. Acharjya, M. Arora, M. Grover, and M. Eti, *"Application of Artificial Intelligence and Machine Learning Techniques for Network Intrusion Detection and Prevention"*, 2025 International Conference on Networks and Cryptology (NETCRYPT), 2025. [DOI: 10.1109/NETCRYPT65877.2025.11102769](https://doi.org/10.1109/NETCRYPT65877.2025.11102769)

---
