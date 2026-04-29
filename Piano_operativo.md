# Piano operativo e specifica delle metriche

Questo documento traduce il modello teorico in un piano operativo e concreto. Per evitare di sovraccaricare il sistema con calcoli continui e garantire risultati precisi, adottiamo un approccio "ibrido" che struttura l'analisi su due livelli distinti:
* **Analisi in tempo reale (Event-driven):** dedicata ai controlli deterministici, interviene istantaneamente non appena viene rilevato un segnale di pericolo noto.
* **Analisi a intervalli regolari (Batch orari):** dedicata ai controlli statistici e comportamentali, raccoglie e valuta i dati ogni ora per studiare le abitudini dell'host e individuare eventuali anomalie nel tempo.

## 1. Definizione logica e teorica delle metriche di sicurezza

Il modello è composto da **15 metriche indipendenti**, selezionate per coprire l'intero spettro delle anomalie di rete. Ciascuna metrica esamina uno specifico comportamento dell'host e lo traduce in un valore normalizzato $M_i \in \{0, 1\}$. Le metriche sono raggruppate in base all'approccio logico utilizzato per la loro valutazione.

### 1.A Metriche deterministiche (In tempo reale)
Queste metriche operano secondo una logica booleana e non necessitano di un periodo di apprendimento. Valutano la natura intrinseca di una singola connessione confrontandola con insiemi di dati noti a priori.

### 1. Destination reputation ($M_{rep}$)

* **Obiettivo:** Monitorare e validare il grado di affidabilità degli endpoint esterni con cui gli host della rete interna tentano di stabilire una connessione. L'identificazione di comunicazioni verso nodi già censiti come malevoli (ad esempio server di Command & Control, nodi di uscita Tor o domini di phishing) permette di rilevare tempestivamente uno stato di compromissione, prevenendo attività di esfiltrazione dati o persistenza dell'attacco.
* **Metodologia di estrazione:** La raccolta dei dati viene effettuata tramite **ntopng**, configurato come sonda di monitoraggio passivo del traffico di rete. Lo strumento analizza in tempo reale i flussi NetFlow/IPFIX per estrarre gli indirizzi IP di destinazione e ispeziona il traffico DNS per ricavare i nomi di dominio (FQDN). Questi metadati vengono confrontati automaticamente con feed di *threat intelligence* e *blacklist* integrate nativamente o caricate esternamente nel sistema.
* **Modello matematico:** Sia $\mathcal{B}$ l'insieme dinamico degli Indicatori di Compromissione (IoC) aggiornati. Se per un dato host $h$, l'indirizzo IP di destinazione $d$ o il dominio richiesto $q$ appartengono all'insieme malevolo, la metrica viene attivata:

    $$d \in \mathcal{B} \lor q \in \mathcal{B} \implies M_{rep} = 1$$

### 2. Client Fingerprinting ($M_{ja4}$)

* **Obiettivo:** Identificare e classificare la natura del software che genera traffico di rete analizzando il suo fingerprinting durante la negoziazione dei protocolli cifrati (TLS). Poiché ogni applicazione (sia un browser legittimo o un malware) negozia la connessione in modo unico, questa metrica permette di distinguere strumenti autorizzati da software malevoli o non autorizzati, indipendentemente dalla destinazione contattata.
* **Metodologia di estrazione:** L'estrazione dei dati avviene tramite **ntopng**, che agisce ispezionando la fase iniziale della connessione cifrata, nota come *TLS Client Hello*. **ntopng** analizza i parametri in chiaro inviati dal client (algoritmi supportati, versioni del protocollo ed estensioni) e calcola l'impronta **JA4**, una stringa modulare che rappresenta univocamente il comportamento del software di rete. Questa firma viene poi confrontata in tempo reale con database di *Threat Intelligence* che catalogano le impronte associate a strumenti d'attacco noti, come Cobalt Strike o Metasploit.
* **Modello matematico:** Sia $\mathcal{J}$ l'insieme delle impronte JA4 classificate come malevole o sospette dalle fonti di intelligence. Sia $j$ l'impronta specifica calcolata da ntopng per l'host monitorato $h$. Se l'impronta appartiene all'insieme delle firme note per essere pericolose, la metrica certifica l'uso di software non autorizzato:
  
    $$j \in \mathcal{J} \implies M_{ja4} = 1$$

### 3. TLS Certificate Anomalies ($M_{cert}$)

* **Obiettivo:** Individuare canali di comunicazione potenzialmente pericolosi analizzando la validità e l'origine dei certificati crittografici utilizzati dai server esterni. Poiché gli attaccanti utilizzano spesso infrastrutture improvvisate con certificati auto-firmati, scaduti o emessi da autorità non riconosciute per risparmiare tempo o eludere i controlli, questa metrica funge da filtro critico per identificare server di Comando e Controllo (C2) o siti di phishing.
* **Metodologia di estrazione:** L'analisi dei certificati viene effettuata tramite **ntopng**, che esegue una *Deep Packet Inspection* (DPI) durante lo scambio del pacchetto *TLS Certificate* nell'handshake. ntopng isola il certificato X.509 presentato dal server ed estrae automaticamente i metadati essenziali, tra cui l'autorità di certificazione emittente (Issuer), il soggetto (Subject) e le date di validità. Lo strumento verifica poi se l'ente emittente è presente nell'elenco delle autorità attendibili (Trust store) e se il certificato rispetta i vincoli temporali di validità.
* **Modello matematico:** Sia $c$ il certificato TLS presentato dal server di destinazione. Definiamo $\mathcal{T}$ come l'insieme delle autorità di certificazione (CA) globalmente attendibili. La metrica valuta tre condizioni critiche: se l'emittente non è attendibile ( $Issuer(c) \notin \mathcal{T}$ ), se il certificato è auto-firmato ( $SelfSigned(c)$ ) o se è temporalmente non valido ( $Invalid(c)$ ). Se almeno una di queste condizioni è vera, la metrica si attiva:

    $$Issuer(c) \notin \mathcal{T} \lor SelfSigned(c) \lor Invalid(c) \implies M_{cert} = 1$$

### 4. SNI Evasion ($M_{sni}$)

* **Obiettivo:** Rilevare tentativi di mascheramento delle comunicazioni verso l'esterno, verificando la presenza del parametro SNI (Server Name Indication) nelle connessioni cifrate. Poiché i browser e le applicazioni legittime includono sempre il nome del sito di destinazione in chiaro durante la connessione iniziale, l'assenza volontaria di questo dato (ad esempio, quando un malware tenta di contattare direttamente un indirizzo IP numerico per nascondersi) rivela un'evidente anomalia strutturale, tipica di script malevoli o strumenti di hacking.
* **Metodologia di estrazione:** L'ispezione viene affidata a **ntopng**, che monitora passivamente il traffico di rete in uscita. Durante l'handshake del protocollo TLS (ovvero l'istante in cui client e server si accordano prima di cifrare i dati), lo strumento analizza l'estensione dedicata all'SNI. ntopng verifica in tempo reale se il campo `tls.sni` risulta popolato con un nome a dominio valido, intercettando immediatamente le connessioni in cui tale campo risulta completamente vuoto o mancante.
* **Modello matematico:** Sia $f$ un flusso di rete crittografato (TLS) originato da un host $h$ verso un indirizzo IP pubblico. Definiamo la funzione $SNI(f)$ come l'operazione che estrae la stringa del SNI dal pacchetto analizzato. Se la funzione restituisce un valore vuoto, il sistema certifica un'evasione e attiva la penalità:

    $$SNI(f) = \emptyset \implies M_{sni} = 1$$

### 1.B Metriche statistiche e comportamentali (Finestra di 1 ora)
Questa sezione descrive le metriche dedicate all'analisi della cosiddetta **"zona grigia"**, ovvero quell'area del traffico di rete che non contiene minacce evidenti, ma che risulta sospetta perché si discosta dalle normali abitudini dell'host. Invece di cercare virus già noti, il sistema identifica la comparsa di attività totalmente inedite o cambiamenti insoliti nella quantità di dati scambiati. Il calcolo viene eseguito automaticamente ogni ora, confrontando i dati recenti con la sua *baseline*, costruita analizzando la sua attività negli ultimi **7 giorni**.

### 5. Server role detection ($M_{srv}$)

* **Obiettivo**: Rilevare inversioni di ruolo sospette in cui un computer aziendale, che solitamente agisce come **client**, inizia improvvisamente ad accettare connessioni dall'esterno come se fosse un **server**. Questo cambio di comportamento è un segnale di allarme critico: indica spesso la presenza di una *backdoor* o il tentativo di un attaccante di muoversi lateralmente all'interno della rete dopo aver compromesso un nodo.
* **Metodologia di estrazione**: Il monitoraggio viene effettuato tramite **ntopng**, che analizza la dinamica delle sessioni a livello di trasporto (TCP/UDP). Lo strumento osserva il modo in cui vengono stabiliti i flussi: se l'host monitorato risponde a chiamate in arrivo (ad esempio inviando un segnale di conferma `SYN-ACK` in risposta a una richiesta di connessione `SYN`), ntopng lo classifica come "Responder". Se ntopng registra anche una sola sessione stabilita con successo in cui l'host monitorato svolge il ruolo da **server**, l'evento viene segnalato come anomalia di ruolo.
* **Modello matematico**: Sia $F$ l'insieme delle connessioni bidirezionali stabilite correttamente. Ogni connessione $f \in F$ è definita dalla coppia $(o, r)$, dove $o$ rappresenta chi inizia la comunicazione (*Originator*) e $r$ chi la riceve (*Responder*). Se per l'host monitorato $h$ viene individuato un flusso in cui esso agisce come ricevente (server), la metrica si attiva:

    $$h = r \implies M_{srv} = 1$$

### 6. Non-standard Port/Protocol ($M_{proto}$)

* **Obiettivo**: Rilevare i tentativi di aggirare i sistemi di sicurezza (come i classici firewall) nascondendo traffico non autorizzato all'interno di canali solitamente considerati sicuri e lasciati aperti. Poiché le reti bloccano le porte non necessarie, gli attaccanti spesso incanalano traffico sospetto, come connessioni per il controllo remoto (SSH) o tunnel VPN su porte tipicamente riservate alla normale navigazione web (come la porta 80 o 443), sperando di passare inosservati.
* **Metodologia di estrazione**: L'analisi viene affidata alla *Deep Packet Inspection* (DPI) di **ntopng**. Invece di fidarsi del semplice numero di porta utilizzato per la connessione (che è facilmente falsificabile a livello superficiale), ntopng analizza la struttura interna del pacchetto di rete per identificare con certezza il vero protocollo in uso. Successivamente, lo strumento confronta il protocollo reale appena scoperto con lo standard internazionale atteso per quella specifica porta di destinazione.
* **Modello matematico**: Sia $p$ la porta di destinazione utilizzata da un flusso di rete e sia $\mathcal{M}(p)$ la regola che definisce quale protocollo ci si aspetta normalmente su quella porta (ad esempio, $\mathcal{M}(443) = \text{TLS}$). Definiamo $L7_{DPI}$ come il protocollo reale identificato da ntopng analizzando l'interno del pacchetto. Se l'analizzatore identifica un protocollo che è differente da quello atteso, la metrica si attiva per segnalare il mascheramento:

    $$L7_{DPI} \neq \mathcal{M}(p) \implies M_{proto} = 1$$

### 7. Internal scanning / Fan-out ($M_{scan}$)

* **Obiettivo:** Rilevare tentativi di esplorazione non autorizzata all'interno della rete locale, come le scansioni automatizzate o i movimenti laterali di un malware. Di norma, un computer aziendale comunica con un numero limitato e stabile di dispositivi interni (come file server o stampanti). Un improvviso e massiccio aumento del numero di dispositivi diversi contattati nell'arco di un'ora è un forte indicatore che un'infezione sta cercando nuove macchine vulnerabili a cui propagarsi.
* **Metodologia di estrazione:** La metrica viene gestita nativamente da **ntopng** tramite i suoi motori di analisi comportamentale (*Behavioural checks*). ntopng analizza in tempo reale i flussi di rete e, grazie agli algoritmi di *network discovery*, è in grado di identificare se un host sta tentando di mappare la rete interna. Nello specifico, il sistema monitora il numero di connessioni uniche verso IP interni e la velocità con cui vengono effettuate, innescando allarmi specifici come `Scan`, `SYN Scan` o `Network discovery`.
* **Modello matematico:** Definiamo $A_{scan}$ come l'insieme degli allarmi nativi di ntopng legati alle attività di scanning della rete. La metrica si attiva se viene registrato almeno un evento di questo tipo per l'host monitorato nell'intervallo di tempo (1 ora):

    $$A_{scan} \in \{\text{Scan, Network discovery, SYN Scan}\}$$

    Se ntopng rileva l'anomalia comportamentale, la metrica si attiva:

    $$A_{scan} = \text{True} \implies M_{scan} = 1$$

### 8. Novel protocol detection ($M_{new}$)

* **Obiettivo:** Individuare l'uso improvviso di protocolli applicativi mai utilizzati prima da uno specifico dispositivo. Poiché ogni computer aziendale possiede una routine di rete consolidata (ad esempio, navigazione web, risoluzione DNS e traffico mail), la comparsa inaspettata di protocolli inediti (come reti "Peer-to-Peer", traffico anonimo Tor, o connessioni di desktop remoto) rappresenta un forte indicatore di infezione o della presenza di un attaccante.
* **Metodologia di estrazione:** L'analisi si basa sulle capacità della *Deep Packet Inspection* (DPI) integrata in **ntopng**. Alla chiusura di ogni finestra oraria, lo strumento raccoglie e aggrega tutti i protocolli applicativi (L7) generati dall'host. Questo lista viene poi confrontata automaticamente con la *baseline* storica del dispositivo, ovvero l'elenco dei protocolli abituali imparati monitorando il traffico dei 7 giorni precedenti.
* **Modello matematico:** Applicando i principi della teoria degli insiemi, definiamo $P_{storico}$ come l'insieme di tutti i protocolli noti per l'host $h$, e definiamo $P_{batch}$ come l'insieme dei protocolli utilizzati dall'host nell'ultima ora di monitoraggio. L'insieme delle novità ( $N$ ) è dato dalla differenza tra questi due insiemi:

    $$N = P_{batch} \setminus P_{storico}$$

    Se questo nuovo insieme $N$ non è vuoto, significa che è comparso almeno un protocollo sconosciuto per la baseline dell'host. In questo caso, la metrica si attiva:
  
    $$N \neq \emptyset \implies M_{new} = 1$$

### 9. Asimmetria volumetrica in uscita ($M_{vol}$)

* **Obiettivo:** Rilevare il furto di dati o l'invio non autorizzato di file verso server esterni. Nella normale operatività aziendale, un computer scarica tipicamente molti più dati di quanti ne invia (pensiamo alla navigazione web, alla ricezione di email o al download di documenti). Se improvvisamente questa dinamica si inverte e l'host inizia a trasferire enormi quantità di dati verso internet, si stabilisce un forte sospetto che un attaccante o un malware stia copiando informazioni sensibili verso un server esterno di appoggio.
* **Metodologia di estrazione:** La raccolta è gestita da **ntopng**, che aggrega le statistiche di base del traffico di rete (come i log NetFlow) alla chiusura di ogni finestra oraria. Lo strumento filtra esclusivamente i flussi in uscita, ovvero le connessioni in cui l'host monitorato avvia la comunicazione verso un indirizzo IP esterno e somma in tempo reale il valore dei byte trasmessi.
* **Modello matematico:** Sia $V_{out}$ il volume totale in byte trasmessi verso l'esterno dall'host $h$ nell'ora corrente $t$. Per determinare se questo volume rappresenta una reale minaccia o solo un normale invio di file pesanti (classico backup), il sistema confronta il dato attuale con la mediana ($\tilde{V}$) e la dispersione assoluta ($MAD$) dei volumi storici in uscita, calcolate sui 7 giorni precedenti. Lo scostamento statistico standardizzato (Z-Score robusto) viene calcolato così:

    $$Z_{robusto} = \frac{|V_{out} - \tilde{V}|}{MAD}$$

    Se il picco di trasferimento genera un'asimmetria volumetrica notevole rispetto all'abitudine dell'host, il sistema certifica l'anomalia:

    $$Z_{robusto} > 3 \implies M_{vol} = 1$$
    
### 10. DNS Anomalies ($M_{dns}$)

* **Obiettivo:** Rilevare l'uso malevolo del protocollo DNS, spesso sfruttato per nascondere informazioni sensibili all'interno di normali richieste di rete (attraverso tecniche come DNS Tunneling o algoritmi DGA). Invece di chiedere alla rete di tradurre nomi a dominio leggibili e legittimi, gli attaccanti incapsulano frammenti di dati rubati o comandi di controllo all'interno di stringhe lunghissime e generate in modo pseudocasuale.
* **Metodologia di estrazione:** L'analisi del traffico è affidata a **ntopng**, che intercetta passivamente le interrogazioni DNS generate dagli host della rete. Per ogni nome a dominio, lo strumento calcola l'entropia di Shannon, un indicatore che valuta il livello di disordine o casualità dei caratteri che compongono la parola. Alla fine di ogni ora di monitoraggio, ntopng calcola un valore aggregato di entropia per l'host, permettendo di capire se le sue richieste stanno diventando troppo caotiche.
* **Modello matematico:** Sia $q$ la stringa del dominio interrogato e $p_i$ la frequenza con cui compare un determinato carattere al suo interno. L'entropia di Shannon per la singola richiesta si calcola con la formula:

    $$E(q) = - \sum_{i} p_i \log_2(p_i)$$

    Sia $E_{batch}$ il valore di entropia rappresentativo (la media o la mediana) registrato dall'host $h$ nell'ora corrente. Il sistema confronta questo valore con la baseline dell'host (ultimi 7 giorni), basato sulla mediana ($\tilde{E}$) e la dispersione assoluta ($MAD$), calcolando lo scostamento statistico:

    $$Z_{robusto} = \frac{|E_{batch} - \tilde{E}|}{MAD}$$

    Se il disordine dei domini interrogati risulta eccessivamente alto rispetto allo storico dell'host ($Z_{robusto} > 3$), si registra un abuso del protocollo e la metrica scatta:
  
    $$Z_{robusto} > 3 \implies M_{dns} = 1$$

### 11. Unidirectional flow ($M_{uni}$)

* **Obiettivo:** Rilevare anomalie strutturali nella comunicazione causate da traffico a senso unico. Il protocollo TCP è progettato per essere bidirezionale: anche in caso di invio massiccio di dati, il ricevente deve sempre trasmettere dei pacchetti ACK di conferma. La presenza di flussi in cui i dati viaggiano solo verso l'esterno senza ricevere risposte indica un'anomalia tipica di attacchi DOS (come il SYN Flood), scansioni di rete effettuate alla cieca o l'uso di indirizzi IP falsificati (IP Spoofing).
* **Metodologia di estrazione:** L'analisi del bilanciamento dei flussi è affidata a **ntopng**, che monitora passivamente lo stato delle sessioni di rete a livello di trasporto (L4). Al termine di ogni finestra oraria (1 ora), lo strumento calcola la percentuale di connessioni avviate dal dispositivo monitorato che non hanno registrato alcun pacchetto in ricezione. Per evitare falsi allarmi dovuti a momentanei malfunzionamenti di internet, ntopng confronta questo dato attuale con la tolleranza storica dell'host.
* **Modello matematico:** Definiamo $F_{tot}$ come l'insieme totale dei flussi TCP generati dall'host nell'ora corrente $t$, e $F_{uni} \subseteq F_{tot}$ come il sottoinsieme costituito dai soli flussi privi di pacchetti in ricezione. Il tasso orario di flussi unidirezionali si esprime come:

    $$u_t = \frac{|F_{uni}|}{|F_{tot}|}$$

    Il sistema valuta poi lo scostamento statistico standardizzato (Z-Score robusto) confrontando il tasso attuale ($u_t$) con la mediana ($\tilde{u}$) e la dispersione assoluta ($MAD$) registrate nei 7 giorni precedenti:

    $$Z_{robusto} = \frac{|u_t - \tilde{u}|}{MAD}$$

    Se l'analisi evidenzia uno particolare scostamento ($Z_{robusto} > 3$) e, allo stesso tempo, la percentuale attuale di flussi senza risposta supera la soglia abituale dell'host ($u_t > \tilde{u}$), l'anomalia viene certificata attivando la metrica:
  
    $$Z_{robusto} > 3 \land u_t > \tilde{u} \implies M_{uni} = 1$$

### 12. Connection failure rate ($M_{fail}$)

* **Obiettivo:** Rilevare attività di scansione silenziosa o tentativi disperati di contattare server malevoli monitorando le connessioni fallite. Nella normale operatività di un'azienda, la quasi tutte le comunicazioni avviate da un host legittimo va a buon fine. Al contrario, un malware che cerca dispositivi vulnerabili alla cieca o che tenta di rintracciare un server di comando e controllo di riserva utilizzando domini generati casualmente genererà una valanga di errori (come connessioni rifiutate o scadute per timeout). Un'impennata di questi fallimenti è dunque un segnale di ricerca malevola.
* **Metodologia di estrazione:** Il tracciamento delle sessioni è affidato a **ntopng**, che monitora passivamente l'esito di ogni singola comunicazione. Lo strumento registra se un flusso di rete viene stabilito correttamente o se viene interrotto in modo anomalo (ad esempio tramite pacchetti RST). Al termine della finestra oraria, ntopng aggrega tutti questi dati per calcolare il tasso percentuale di fallimento dell'host.
* **Modello matematico:** Definiamo $F_{tot}$ come l'insieme di tutti i flussi di rete originati dall'host nell'ora corrente $t$, e $F_{fail} \subseteq F_{tot}$ come il sottoinsieme dei flussi terminati con un esito anomalo. Il tasso di fallimento orario si esprime come:

    $$r_t = \frac{|F_{fail}|}{|F_{tot}|}$$

    Il sistema determina l'anomalia calcolando lo scostamento statistico standardizzato (Z-Score robusto), confrontando il tasso attuale ($r_t$) con la mediana ($\tilde{r}$) e la dispersione assoluta ($MAD$) storiche (calcolate sui 7 giorni precedenti):

    $$Z_{robusto} = \frac{|r_t - \tilde{r}|}{MAD}$$

    Se l'analisi rileva un incremento degli errori rispetto all'abituale tolleranza dell'host ($Z_{robusto} > 3$), l'attività malevola viene confermata:
  
    $$Z_{robusto} > 3 \implies M_{fail} = 1$$

### 13. Session duration / Reverse shell ($M_{dur}$)

* **Obiettivo:** Rilevare connessioni di rete che rimangono attive per un lasso di tempo innaturalmente lungo, segnale evidente di un canale di controllo remoto non autorizzato come una Reverse shell o un tunnel persistente. Il traffico generato da un normale utente (come la navigazione web) è per sua natura a raffiche: le connessioni si aprono per scaricare i dati e si chiudono quasi subito. Al contrario, un attaccante necessita di mantenere una sessione aperta per ore o giorni, per potersi inviare comandi interattivi al momento del bisogno.
* **Metodologia di estrazione:** Il tracciamento dei tempi è assegnato a **ntopng**, che misura costantemente la durata di ogni singola sessione di rete in secondi. Allo scadere del batch orario, lo strumento estrae il valore massimo di durata osservato tra tutti i flussi (attivi o chiusi) generati in quell'ora. Questo picco di durata temporale viene poi confrontato con la baseline delle durate massime registrate per quell'host specifico nei giorni precedenti.
* **Modello matematico:** Sia $T$ l'insieme delle durate (in secondi) di tutti i flussi originati dall'host nell'ora corrente, e sia $x_t = \max(T)$ il valore di durata massima. Il sistema calcola lo scostamento statistico standardizzato (Z-Score robusto) confrontando questo valore con la mediana ($\tilde{x}$) e la dispersione assoluta ($MAD$) calcolate sui 7 giorni precedenti:

    $$Z_{robusto} = \frac{|x_t - \tilde{x}|}{MAD}$$

    Affinché scatti l'allarme, devono verificarsi due condizioni: lo scostamento temporale deve essere insolito ($Z_{robusto} > 3$) e la durata osservata deve essere effettivamente maggiore dell'abitudine dell'host ($x_t > \tilde{x}$). Se entrambe sono vere, si certifica una persistenza anomala:

    $$Z_{robusto} > 3 \land x_t > \tilde{x} \implies M_{dur} = 1$$

### 14. ARP Storm ($M_{arp}$)

* **Obiettivo:** Individuare le fasi preparatorie di un attacco *ransomware* o l'espansione di un *worm* all'interno della rete locale. Prima di poter infettare altri dispositivi, questi malware di solito devono mappare l'ambiente circostante. Per farlo, inviano una "tempesta" di richieste ARP (**ARP Storm**) per scoprire gli indirizzi fisici (MAC address) di tutti i computer collegati alla stessa rete. Questo comportamento esplorativo, massiccio e molto rapido, è totalmente sconosciuto alla normale operatività di un computer aziendale.
* **Metodologia di estrazione:** Il monitoraggio di queste comunicazioni basilari è affidato a **ntopng**, che analizza il traffico al livello più basso della rete locale (L2). ntopng intercetta e somma tutte le singole interrogazioni ARP (messaggi del tipo: "Chi ha questo indirizzo IP?") generate dal computer monitorato allo scadere della finestra oraria. Questo volume totale viene poi messo a confronto con le abitudini storiche del dispositivo.
* **Modello matematico:** Sia $A_t$ il numero totale di richieste ARP inviate dal dispositivo $h$ nell'ora in corso $t$. Il sistema determina l'anomalia calcolando lo scostamento statistico standardizzato (Z-Score robusto), confrontando il volume attuale ($A_t$) con la mediana ($\tilde{A}$) e la dispersione assoluta ($MAD$) del traffico ARP storico del nodo (profilo a 7 giorni):

    $$Z_{robusto} = \frac{|A_t - \tilde{A}|}{MAD}$$

    Se il volume di queste richieste locali subisce un incremento notevole rispetto alla norma ($Z_{robusto} > 3$), il sistema certifica che è in corso una mappatura fisica della rete e fa scattare l'allarme:

    $$Z_{robusto} > 3 \implies M_{arp} = 1$$

### 15. RTT Latency / Hidden routing ($M_{rtt}$)

* **Obiettivo:** Individuare l'uso di instradamenti di rete anomali o nascosti, come connessioni verso server di comando e controllo remoti o l'utilizzo di reti anonime esempio Tor). Le normali comunicazioni aziendali (come quelle verso i classici servizi cloud) sono caratterizzate da tempi di risposta (RTT) molto bassi e stabili. Se un computer viene compromesso e inizia a inviare dati verso server malevoli situati dall'altra parte del mondo, o attraverso percorsi crittografati complessi, la latenza subirà un aumento ingiustificato.
* **Metodologia di estrazione:** La misurazione delle tempistiche è affidata a **ntopng**, che calcola passivamente la latenza di rete osservando lo scambio iniziale dei pacchetti (*3-way handshake* di TCP) senza rallentare il traffico. Alla chiusura di ogni finestra oraria, lo strumento estrae il valore mediano della latenza per tutte le connessioni generate verso l'esterno. Questo dato viene poi confrontato con la baseline dell'host.
* **Modello matematico:** Sia $L$ la latenza mediana (espressa in millisecondi) calcolata sui flussi in uscita dell'host nell'ora corrente. Il sistema calcola lo scostamento statistico standardizzato (Z-Score robusto) confrontando la latenza attuale ($L$) con la mediana ($M$) e la dispersione assoluta ($MAD$) storiche (registrate nei 7 giorni precedenti):

    $$Z_{robusto} = \frac{|L - M|}{MAD}$$

    Affinché la metrica si attivi, il deterioramento delle prestazioni deve essere direzionale ed eccezionale: la latenza attuale deve essere maggiore di quella storica ($L > M$) e lo scostamento deve superare la soglia di tolleranza ($Z_{robusto} > 3$). Verificate queste condizioni, si certifica il routing anomalo:

    $$Z_{robusto} > 3 \land L > M \implies M_{rtt} = 1$$

---

## 2. Architettura del sistema di scoring additivo

In questa sezione viene descritto il metodo con cui le diverse anomalie rilevate dalle metriche vengono aggregate per determinare il livello di salute complessivo di un host. L'obiettivo del sistema è superare la logica dei singoli allarmi isolati, fornendo invece un punteggio unico che rappresenti la gravità reale del comportamento dell'host. Attraverso l'assegnazione di pesi specifici a ogni violazione e un processo di normalizzazione matematica, il rischio viene visualizzato in una scala intuitiva da 0 a 100, permettendo agli analisti di identificare immediatamente le minacce che richiedono un intervento prioritario.

### 2.1 Frequenza di calcolo e logica di normalizzazione

Per garantire una risposta tempestiva senza sovraccaricare il sistema di monitoraggio, il calcolo dello **Score Globale** dell'host avviene seguendo due modalità distinte:
1. **In tempo reale (Event-driven):** Il punteggio viene ricalcolato istantaneamente ogni volta che **ntopng** rileva l'attivazione di una metrica deterministica (ad esempio, se viene contattato un sito pericoloso o viene usato un software non autorizzato).
2. **A intervalli orari (Time-driven):** Allo scadere di ogni ora, il sistema elabora tutti i dati statistici raccolti e aggiorna lo score in base ai comportamenti rilevati nell'ultima finestra temporale (1 ora).

Per evitare che il punteggio cresca in modo incontrollato e diventi illeggibile, il sistema adotta una **normalizzazione basata sulla finestra temporale**. In termini semplici, la penalità viene assegnata per la presenza di un comportamento anomalo nell'arco dell'ora, e non per quante volte quell'azione viene ripetuta.

Ad esempio, se un host effettua 1.000 connessioni verso una porta vietata all'interno della stessa ora, la metrica corrispondente scatterà una sola volta, applicando la penalità una sola volta. L'intensità dell'attacco non viene ignorata: essa è già stata valutata dai calcoli statistici (come lo Z-Score robusto) che hanno fatto scattare l'allarme. Questo meccanismo garantisce che il punteggio finale rimanga sempre all'interno della scala 0-100, rendendo facile per l'analista capire la gravità della situazione.

### 2.2 Assegnazione dei pesi e criteri di rischio
I pesi assegnati alle singole metriche non sono casuali, ma derivano da un'analisi del rischio basata su due fattori: l'**impatto** dell'anomalia e la **probabilità di falsi positivi**. Ogni anomalia rilevata aggiunge un punteggio predefinito:

* **Gravità critica (+50 punti):** Assegnati a comportamenti che indicano compromissione certa e falsi positivi pari allo zero. Una singola violazione compromette per metà l'affidabilità del nodo.
  * Destination reputation ($M_{rep}$)
  * Client fingerprinting ($M_{ja4}$)
  * SNI Evasion ($M_{sni}$)
* **Sospetto alto (+40 punti):** Anomalie strutturali gravi, ma che richiedono almeno un'altra anomalia secondaria per certificare la compromissione totale (superamento soglia 60).
  * TLS Certificate anomalies ($M_{cert}$)
  * Server role detection ($M_{srv}$)
* **Evasione e ricognizione (+30 punti):** Comportamenti tipici delle fasi intermedie di un attacco (es. movimenti laterali), che potrebbero però coincidere con interventi di amministrazione.
  * Non-standard Port/Protocol ($M_{proto}$)
  * Internal scanning / Fan-out ($M_{scan}$)
  * Connection failure rate ($M_{fail}$)
  * Session duration / Reverse shell ($M_{dur}$)
  * ARP Storm ($M_{arp}$)
  * RTT Latency / Hidden routing ($M_{rtt}$)
* **Anomalie di profilo e di volume (+20 punti):** Assegnati ad anomalie quantitative. Hanno un'alta probabilità di falsi positivi, pertanto il peso ridotto garantisce che l'host rimanga in zona "verde/sicura" se l'evento è unico.
  * Novel protocol detection ($M_{new}$)
  * Asimmetria Volumetrica ($M_{vol}$)
* **Segnali Deboli (+10 punti):** Anomalie che, prese singolarmente, non sono sufficienti per innescare allarme, ma fungono da moltiplicatori per confermare altre minacce.
  * DNS Anomalies ($M_{dns}$)
  * Unidirectional flow ($M_{uni}$)

Il calcolo finale somma i punti di tutte le metriche attive, limitando matematicamente il risultato a un massimo di 100 per mantenere lo score coerente e interpretabile:

$$S(h) = \min\left(100, \sum_{i=1}^{15} \text{Punti}_i \cdot M_i\right)$$

---

## 3. Dall'host all'intera rete

Il calcolo dell'equazione produce un valore intero compreso tra 0 e 100. Per capire se il comportamento di un nodo "va bene" oppure "va male", il sistema mappa il risultato $S(h)$ su tre fasce di rischio predefinite. 

Allo stesso tempo, per valutare la sicurezza dell'intera rete, il sistema applica una logica basata sul caso peggiore. Lo stato globale della rete è determinato dal punteggio massimo registrato tra tutti gli host attivi ( max $S(h)$ ), mappandosi direttamente sulle tre fasce:

* **Stato regolare / Rete sicura (Verde) $\rightarrow$ [0 - 29 punti]**
  * **Singolo host:** Svolge le sue normali attività. Anche in presenza di un isolato picco volumetrico (20 punti) o della presenza di un flusso unidirezionale, il punteggio cumulativo rimane sotto la soglia di allarme. 
  * **Intera rete:** Se nessun host supera i 29 punti, l'infrastruttura è considerata integra e non è richiesto alcun intervento.

* **Zona grigia / Rete in osservazione (Giallo) $\rightarrow$ [30 - 59 punti]**
  * **Singolo host:** Mostra variazioni anomale. Ad esempio, potrebbe aver iniziato a usare porte diverse dallo standard associato all'utilizzo di nuovi protocolli (totale 50 punti). Non vi è certezza matematica di compromissione, ma l'host scala le priorità nel sistema di monitoraggio (host sospetto).
  * **Intera rete:** La rete è tecnicamente intatta, ma la presenza di host in questa fascia richiede attenzione per prevenire deviazioni comportamentali o minacce silenziose.

* **Stato critico / Rete compromessa (Rosso) $\rightarrow$ [60 - 100 punti]**
  * **Singolo host:** Il superamento di quota 60 certifica la convergenza di anomalie gravi. L'host deve necessariamente aver contattato una destinazione malevola nota (50 punti) supportata da un'altra anomalia, oppure aver accumulato più comportamenti anomali.
  * **Intera rete:** Poiché in *Cybersecurity* una rete è forte quanto il suo anello più debole, un solo host in stato critico (max $S(h) \ge 60$) dichiara l'intero perimetro compromesso, innescando l'immediata neutralizzazione dell'attacco (*Incident Response*).
  
---

## 4. Analisi comparativa dell'architettura del sistema

La progettazione di questo modello operativo nasce da un'analisi critica delle più recenti evoluzioni nella letteratura scientifica in ambito *Cybersecurity*. La solidità del sistema non risiede solo nelle formule matematiche adottate, ma nella scelta di un'architettura che superi gli attuali limiti operativi dell'intelligenza artificiale, unita a un rigoroso dimensionamento dei parametri statistici e temporali.

### 4.1 L'uso della statistica robusta per superare il "rumore" di rete
L'applicazione di modelli statistici classici per la *Network Anomaly Detection* sconta storicamente il limite della sensibilità agli *outlier*: i normali (e legittimi) picchi di traffico alterano la media aritmetica e la deviazione standard, generando cecità falsi positivi.

Per risolvere questo problema, la letteratura più recente ha validato l'efficacia della statistica robusta applicata al traffico di rete. Romo-Chavero et al. [1] (2025) propongono un framework in cui la MAD (*Median Absolute Deviation*) viene impiegata per rilevare le anomalie del protocollo BGP, dimostrando che il calcolo delle deviazioni basato sulla mediana garantisce un'elevata resistenza ai naturali picchi di traffico. 

Il modello proposto in questa tesi condivide l'assunto teorico validato da Romo-Chavero et al., adottando la MAD e lo $Z_{robusto}$ come motore statistico per le metriche comportamentali. Tuttavia, se ne distacca per l'efficienza applicativa: mentre nella letteratura accademica la MAD viene spesso usata solo come fase di preparazione dati (*labeling*) per addestrare successivi e pesanti modelli di machine learning, il nostro sistema utilizza i superamenti della soglia dello $Z_{robusto}$ per incrementare direttamente il sistema di **scoring**. Questa scelta mantiene intatta la elasticità statistica, ma azzera i costi di addestramento computazionale.

### 4.2 Giustificazione dei parametri statistici e temporali
Una volta definita e validata l'architettura deterministica, è fondamentale dimensionare correttamente i parametri affinché il modello si adatti al traffico reale evitando di sommergere gli analisti di falsi allarmi (Alert Fatigue).
* **La soglia di anomalia ($Z_{robusto} > 3$):** L'impostazione della soglia di tolleranza $\theta = 3$ non è casuale, ma deriva direttamente dalla "regola empirica" della statistica descrittiva (nota come regola del 68-95-99.7). 

Basandoci sulla dispersione dei dati MAD, sappiamo che la normalità si distribuisce in tre fascie:
* Uno Z-Score pari a **1** copre circa il **68%** dei normali comportamenti dell'host.
* Uno Z-Score pari a **2** copre circa il **95%** delle attività regolari.
* Uno Z-Score pari a **3** ingloba il **99.7%** dei comportamenti ordinari dell'host.

Scegliere di attivare le metriche di allarme solo quando $Z_{robusto} > 3$ significa matematicamente che un evento ha meno dello **0.3%** di probabilità di essere un comportamento regolare casuale. Questa soglia è fondamentale in ambito *Cybersecurity* per abbattere drasticamente i falsi positivi e prevenire falsi allarmi (Alert Fatigue).
* **La finestra di osservazione (batch di 1 ora):** Le metriche statistiche richiedono l'accumulo di un set di dati sufficiente per calcolare indicatori validi. Il sistema utilizza una finestra di osservazione di **1 ora**, una scelta che rappresenta il miglior compromesso tecnico:
* **Contro delle analisi troppo brevi (es. 5 minuti):** Finestre troppo brevi sono sensibili a picchi istantanei legittimi, come il download di un file, che invaliderebbero la statistica generando allarmi inutili.
* **Contro delle analisi troppo lunghe (es. 24 ore):** Un'osservazione giornaliera creerebbe distribuzioni statisticamente perfette, ma risulterebbe totalmente inutile per la neutralizzazione degli attacchi (*Incident Response*). La finestra oraria bilancia perfettamente il rigore matematico e i tempi di reazione necessari per difendere la rete.
* **La profondità dello storico (baseline di 7 giorni):** Il calcolo della mediana $\tilde{x}$ e della $MAD$ avviene su una finestra storica di **7 giorni**. Questa scelta è dettata dalla necessità di assorbire la naturale **stagionalità settimanale** delle reti aziendali, naturalmente legata agli orari lavorativi e ai giorni di riposo. La profondità di 7 giorni assicura che il comportamento attuale venga confrontato con una baseline che ha già imparato i pattern dell'intera settimana, rendendo il modello consapevole dei cicli aziendali.

### 4.3 Vantaggi operativi del risk scoring deterministico rispetto all'AI

Sebbene l'intelligenza artificiale (AI) sia molto popolare nella ricerca accademica per rilevare le intrusioni di rete, la sua applicazione pratica nel mondo reale sconta diverse criticità. Gli stessi ricercatori che sviluppano questi modelli ammettono spesso la necessità di approcci meno pesanti e gestibili.

Il primo grande ostacolo riguarda i **costi computazionali** e il cosiddetto **Concept Drift**. Come evidenziato dallo studio di Talukder et al. [2] (2025), i modelli di *Machine Learning* richiedono un'enorme potenza di calcolo, rendendoli difficili da usare su reti ad alto traffico. Inoltre, l'AI impara esclusivamente dai dati passati: se gli attaccanti inventano una nuova tecnica per aggirare le difese, il modello diventa subito obsoleto (subisce un **Concept Drift**) e deve essere faticosamente riaddestrato con nuovi dati.

Il secondo problema riguarda le **nuove vulnerabilità e l'effetto "black box"**. Acharjya et al. [3] (2025) sottolineano come gli hacker utilizzino già tecniche mirate (*Adversarial Machine Learning*) per inquinare i dati di addestramento e ingannare l'AI. A questo si aggiunge un forte limite operativo delle reti neurali: la mancanza di **interpretabilità** (l'effetto *Black-Box*). Questo impedisce agli analisti di estrarre la catena logica che ha innescato un allarme, costringendoli a lunghe indagini manuali per validare l'effettiva presenza di una minaccia.

Per superare questi limiti, il nostro modello adotta una strategia di **Risk Scoring statico e deterministico (*White-Box*)**. Invece di affidarsi a previsioni basate sui dati storici, il sistema assegna punteggi di rischio precisi ogni volta che rileva una violazione delle regole di rete (come una scansione interna o l'uso di un protocollo anomalo). Questo approccio algoritmico garantisce tre vantaggi fondamentali:
1. **Immune all'inganno (*Adversarial ML*):** Basandosi su regole logiche fisse, il sistema non può essere manipolato o "avvelenato" dall'attaccante.
2. **Nessun riaddestramento (*Zero Training*):** Il modello non ha bisogno di imparare costantemente le nuove tattiche d'attacco, perché si concentra sul rilevare le violazioni dei principi di base della rete, che restano sempre invariati.
3. **Trasparenza immediata:** L'analista capisce in un istante perché è scattato l'allarme (es. "l'host ha 70 punti: 50 per un certificato falso + 20 per traffico anomalo"), velocizzando la risposta alla neutralizzazione della minaccia (*Incident Response*).

### 4.4 Rilevamento su traffico cifrato: efficienza vs. complessità

Oggi oltre il 90% del traffico web è protetto da protocolli crittografici (come TLS/HTTPS). Questo ha reso largamente inefficace la tradizionale *Deep Packet Inspection* (DPI), originariamente progettata per leggere il contenuto in chiaro dei pacchetti. Tuttavia, studi recenti come quello di Muttaqien et al. [4] (2025) dimostrano che è possibile identificare le minacce analizzando i metadati non cifrati scambiati durante la fase iniziale di *handshake*. Tra questi indicatori spiccano le caratteristiche dei certificati TLS e le impronte crittografiche del client.

Nel loro studio, Muttaqien et al. estraggono proprio le vecchie impronte JA3 e le classificano impiegando complesse architetture di *Deep Learning* (modelli ibridi Random Forest e LSTM). Pur garantendo un'elevata accuratezza, queste reti neurali risultano estremamente pesanti dal punto di vista computazionale: per addestrare il modello è stato necessario elaborare un dataset di ben 30 milioni di sessioni.

Il nostro modello operativo compie un doppio salto evolutivo rispetto a questo approccio. In primo luogo, aggiorna il set di estrazione adottando il più moderno e robusto standard **JA4** (metrica $M_{ja4}$), che supera i limiti strutturali e le vulnerabilità di collisione del suo predecessore. In secondo luogo, abbandona le pesanti architetture predittive in favore di una strategia deterministica. Invece di delegare l'analisi a una rete neurale, il sistema valida l'impronta JA4 e i certificati confrontandoli in tempo reale con fonti di firme malevole note (*Threat Intelligence*) ed eseguendo controlli sintattici. Questo approccio garantisce un blocco immediato e privo di falsi positivi per le minacce conosciute, risultando molto più leggero, rapido e facilmente implementabile rispetto alle architetture basate su *Deep Learning*.

### 4.5 Validazione funzionale e robustezza della rilevazione di evasione SNI

Quando navighiamo su internet, un'informazione chiamata SNI (*Server Name Indication*) viaggia in chiaro e rivela il nome del sito a cui ci stiamo collegando. Anche se questo rappresenta un piccolo compromesso per la privacy, uno studio recente (Shamsimukhametov et al., [5] 2022) ha dimostrato che leggere l'SNI è fondamentale per i sistemi aziendali che devono controllare e mettere in sicurezza la rete.

Proprio perché l'SNI è così utile ai sistemi di difesa, i virus e i programmi usati dagli hacker cercano di nasconderlo. A volte lo falsificano usando nomi innocui (es. "google.com") per aggirare i controlli, altre volte usano la tecnica più basilare di cancellarlo del tutto, provando a connettersi verso l'esterno usando solo l'indirizzo IP numerico del server.

È qui che entra in gioco la metrica **M_sni**. Nella navigazione normale di un dipendente, l'SNI è sempre presente perché è richiesto dal server per instaurare correttamente la connessione. Di conseguenza, se dal computer parte una connessione in cui l'SNI è mancante, il nostro sistema rileva subito un'evidente anomalia strutturale, tipica di un software malevolo, e fa scattare l'allarme. 

Infine, questo metodo di controllo rimane efficace anche contro i nuovi standard che mirano a nascondere e cifrare l'SNI (come la tecnologia ECH). Anche quando queste tecnologie nascondono i dati, la struttura del pacchetto di rete deve comunque rispettare delle regole rigide e fisse. Se il malware tenta di alterare la connessione omettendo delle parti fondamentali, il nostro modello rileva l'irregolarità strutturale e blocca la minaccia prima ancora di doverne leggere il contenuto.

### 4.6 Evoluzione del ransomware e necessità della metrica di ricognizione ($M_{arp}$)

Negli ultimi anni, il panorama delle minacce informatiche ha subito una trasformazione radicale. Come analizzato nel recente studio di Razaulla et al. [6] (2023) sull'evoluzione e la tassonomia dei ransomware, questi attacchi non si limitano più a infettare e bloccare un singolo host isolato. Le varianti moderne puntano a massimizzare i danni e i profitti paralizzando intere infrastrutture.

Per raggiungere questo scopo devastante, prima di avviare la vera e propria cifratura dei file, il ransomware attraversa una fase di preparazione silenziosa. In questo lasso di tempo, il software malevolo esegue una mappatura aggressiva della rete locale alla ricerca di altri dispositivi vulnerabili o di "file server" condivisi verso cui propagarsi (come il *Later movement*). 

A livello base della rete (L2/ Data link), questa esplorazione si traduce nell'invio di una tempesta di richieste ARP (ARP Storm): il computer infetto interroga freneticamente la rete per scoprire gli indirizzi fisici (MAC address) di tutti i dispositivi circostanti.

È proprio in questa fase critica che interviene la nostra metrica $M_{arp}$. Invece di agire in ritardo cercando firme note o file già cifrati, il nostro sistema valuta il volume di queste richieste di servizio L2. Poiché un **ARP Storm** rappresenta un comportamento totalmente innaturale per la normale operatività di un dipendente, il calcolo statistico del nostro sistema ($Z_{robusto}$) rileva immediatamente l'anomalia esplorativa. Questo approccio garantisce l'isolamento tempestivo del nodo compromesso, bloccando il malware nella sua fase preparatoria e prevenendo la compromissione dell'intera rete.

---

## 5. Riferimenti bibliografici

[1] M. A. Romo-Chavero, G. de los Ríos Alatorre, J. A. Cantoral-Ceballos, J. A. Pérez-Díaz, and C. Martinez-Cagnazzo, *"A Hybrid Model for BGP Anomaly Detection Using Median Absolute Deviation and Machine Learning"*, 2025. [DOI: 10.1109/OJCOMS.2025.3550010](https://doi.org/10.1109/OJCOMS.2025.3550010)

[2] A. Talukder and A. Rahman, *"Evaluating the Efficacy of Explainable Machine Learning Algorithms for the Detection and Classification of Network Intrusions"*, 2025. [DOI: 10.1109/COMPAS67506.2025.11381867](https://doi.org/10.1109/COMPAS67506.2025.11381867)

[3] K. Acharjya, M. Arora, M. Grover, and M. Eti, *"Application of Artificial Intelligence and Machine Learning Techniques for Network Intrusion Detection and Prevention"*, 2025. [DOI: 10.1109/NETCRYPT65877.2025.11102769](https://doi.org/10.1109/NETCRYPT65877.2025.11102769)

[4] H. Muttaqien, M. Niswar, Z. Zainuddin, and S. Syarif, *"Efficient Identification of Malicious Traffic in TLS Networks Using Machine Learning"*, 2025. [DOI: 10.1109/AIMS66189.2025.11229622](https://doi.org/10.1109/AIMS66189.2025.11229622)

[5] D. Shamsimukhametov, A. Kurapov, M. Liubogoshchev, and E. Khorov, *"Is Encrypted ClientHello a Challenge for Traffic Classification?"*, 2022. [DOI: 10.1109/ACCESS.2022.3191431](https://doi.org/10.1109/ACCESS.2022.3191431)

[6] S. Razaulla, C. Fachkha, C. Markarian, A. Gawanmeh, W. Mansoor, B. C. Fung, and C. Assi, *"The Age of Ransomware: A Survey on the Evolution, Taxonomy, and Research Directions"*, 2023. [DOI: 10.1109/ACCESS.2023.3268535](https://doi.org/10.1109/ACCESS.2023.3268535)

---
