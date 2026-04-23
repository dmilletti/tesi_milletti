# Implementazione delle metriche

Questo capitolo descrive l'implementazione pratica di un sottoinsieme selezionato delle metriche proposte nel modello generale. Abbiamo scelto di concentrarci su queste 10 metriche specifiche per trovare il giusto compromesso tra una visione completa delle anomalie di rete e l'efficienza computazionale.

La selezione è stata guidata da due criteri fondamentali:

1. **Efficienza computazionale su ClickHouse e nDPI:**  
Sono state privilegiate le metriche che riescono a sfruttare al massimo le capacità di aggregazione nativa del database colonnare di ClickHouse, evitando operazioni troppo costose. Ad esempio, per rilevare i domini generati artificialmente (DGA), si è scelto di implementare il *Connection failure rate* ($M_{fail}$) al posto del calcolo logaritmico dell'entropia di Shannon applicato alle query DNS ($M_{DNS}$). Questo permette di ottenere lo stesso risultato (scoprire la ricerca alla cieca del malware) con interrogazioni SQL dal costo quasi nullo.
2. **Copertura integrale della *Cyber Kill Chain*:**  
Nonostante la riduzione numerica, il sottoinsieme è stato accuratamente bilanciato per intercettare un attacco in ogni singola fase del suo ciclo:
   * **Command and Control (C2):** coperti intercettando il traffico verso host malevoli ($M_{rep}$) e infrastrutture crittografiche sospette ($M_{cert}$).
   * **Evasione e offuscamento:** smascherati analizzando il fingerprinting del software ($M_{ja4}$), l'aggiramento del parametro SNI ($M_{sni}$) e l'incapsulamento su porte non standard ($M_{proto}$).
   * **Ricognizione e lateral movement:** intercettati bloccando le scansioni interne ($M_{scan}$), le tempeste ARP ($M_{arp}$) e l'apertura di porte non autorizzate ($M_{srv}$).
   * **Esfiltrazione e DGA:** rilevati monitorando le anomalie volumetriche in uscita ($M_{vol}$) e gli errori di connessione ($M_{fail}$).

Di seguito viene descritto come ciascuna di queste metriche viene estratta dai flussi di rete e come viene analizzata.

---

### Metrica 1: Destination reputation ($M_{rep}$)

**1. Il modello matematico**  
La logica di questa metrica deterministica si basa sulla teoria degli insiemi:

$$d \in \mathcal{B} \lor q \in \mathcal{B} \implies M_{rep} = 1$$

Dove $d$ rappresenta l'indirizzo IP di destinazione della connessione, $q$ il dominio interrogato a livello applicativo e $\mathcal{B}$ l'insieme dinamico degli indicatori di compromissione (IoC), ovvero le *blacklist* di domini e IP noti per essere malevoli.

**2. Il motore di estrazione e rilevamento in tempo reale (nDPI)**  
L'estrazione dei parametri e l'appertenenza ai domini malevoli in tempo reale avvengono tramite **nDPI**, il motore di *Deep Packet Inspection* integrato in ntopng. Poiché il sistema deve analizzare il traffico in modo istantaneo, nDPI utilizza algoritmi avanzati di pattern matching:

* **Valutazione dell'indirizzo IP ($d \in \mathcal{B}$):**  
    Il sistema legge l'indirizzo IP di destinazione direttamente dall'intestazione del pacchetto (L3). Per verificare istantaneamente se questo IP è presente in una lista di indirizzi malevoli, nDPI utilizza strutture dati come **Patricia Trie** o **Radix Tree**. Questa struttura dati ad albero permette di cercare l'IP, garantendo tempi di ricerca in $O(k)$, dove $k$ è la lunghezza dell'indirizzo indipendente dalla dimensione totale della *blacklist*.

* **Valutazione del nome a dominio ($q \in \mathcal{B}$):**  
    Se la connessione è in chiaro (DNS sulla porta 53), nDPI isola il campo testo interrogato. Se la connessione è cifrata (HTTPS), nDPI intercetta il primo pacchetto inviato dal client (*TLS Client hello*) ed estrae l'estensione **SNI (Server Name Indication)**, ricavando il nome del server prima che la cifratura venga applicata al canale.
    Per confrontare in tempo reale queste stringhe con le *blacklist* di domini (algoritmi DGA, phishing, server C2), nDPI utilizza l'algoritmo di **Aho-corasick**. Si tratta di un algoritmo basato su un'automa a stati finiti che permette di cercare più stringhe simultaneamente all'interno del pacchetto, leggendo il payload di rete una sola volta. Questo garantisce che la "Deep Packet Inspection" (DPI) non crei colli di bottiglia o rallentamenti sulla rete.

**3. Implementazione operativa e dello storico (ClickHouse)**  
I risultati di questa ispezione in tempo reale vengono salvati all'interno del database colonnare **ClickHouse** e poi analizzati ed estratti facendo delle query.

---

### Metrica 2: Client fingerprinting ($M_{ja4}$)

**1. Il modello matematico**  
Questa metrica si concentra sull'identità del software che genera il traffico. Ogni applicazione (un browser, uno script Python o un malware) negozia le connessioni cifrate in modo unico.
La logica matematica esprime questa verifica di identità:

$$j \in \mathcal{J} \implies M_{ja4} = 1$$

In questa formula, $j$ rappresenta l'impronta digitale (**JA4**) calcolata per l'host monitorato, mentre $\mathcal{J}$ è l'insieme delle firme associate a software malevoli o non autorizzati. Se l'impronta del software appartiene all'elenco delle firme malevole, la metrica scatta.

**2. Il motore di estrazione e rilevamento in tempo reale (nDPI)**  
Non potendo leggere il contenuto del traffico (che è cifrato), nDPI analizza il modo in cui il client si presenta al server durante il **TLS Handshake**.

* **L'analisi del "Client hello":**  
  nDPI intercetta il pacchetto iniziale in cui il computer comunica al server quali versioni del protocollo supporta, quali algoritmi di cifratura e quali estensioni vuole utilizzare. Poiché l'ordine e la scelta di questi parametri sono specifici per ogni sviluppatore, nDPI li estrae per comporre l'impronta **JA4**.

* **L'algoritmo di normalizzazione e hashing:**  
  Per generare l'impronta $j$, nDPI non si limita a copiare i dati, ma applica una logica di **normalizzazione**. Gli algoritmi interni riordinano le liste di cifratura e le estensioni in ordine numerico: questo passaggio è fondamentale per evitare che un malware possa cambiare l'impronta semplicemente spostando l'ordine dei parametri. 
  Una volta normalizzati, i dati vengono passati attraverso una funzione di **hashing** (SHA-256 troncato). Per confrontare il fingerprinting (stringhe alfanumeriche) con il database $\mathcal{J}$ dei malware in tempo reale, nDPI utilizza nuovamente una **macchina a stati finiti** ottimizzata per il confronto di firme fisse, garantendo che l'identificazione avvenga in pochi microsecondi senza rallentare la navigazione dell'utente.

**3. Implementazione operativa e dello storico (ClickHouse)**  
Una volta calcolata l'impronta JA4, ntopng la invia a **ClickHouse**, dove viene salvata in una colonna dedicata e poi in seguito estratti ed analizzati con delle query.

---

### Metrica 3: TLS Certificate anomalies ($M_{cert}$)

**1. Il modello matematico**  
Un server sicuro deve presentare un il certificato valido e rilasciato da un'autorità riconosciuta.
La formula matematica valuta lo stato di questo certificato $c$:

$$Issuer(c) \notin \mathcal{T} \lor SelfSigned(c) \lor Invalid(c) \implies M_{cert} = 1$$

In breve: se l'ente che ha emesso il certificato non è nell'elenco di quelli fidati ($\mathcal{T}$), o se il server si è fatto il certificato da solo (*Self-signed*), o ancora se il certificato è scaduto o non ancora valido, la metrica segnala l'anomalia ($M_{cert} = 1$).

**2. Il motore di estrazione e rilevamento (nDPI)**  
Qui nDPI agisce durante la fase di negoziazione della connessione (Handshake TLS).

* **L'estrazione del certificato X.509:**  
    Durante lo scambio dei pacchetti iniziali, il server invia il proprio certificato in chiaro. nDPI intercetta questo passaggio ed esegue il parsing del certificato X.509. Senza dover decifrare i dati successivi, nDPI è in grado di leggere i campi fondamentali: chi ha emesso il certificato (*Issuer*), a chi è intestato (*Subject*) e le date di validità.
* **La verifica di attendibilità:**  
    Per capire se l'emittente è affidabile, ntopng carica in memoria una lista di *Certification Authority* (CA) globali. nDPI utilizza i suoi algoritmi di ricerca rapida per confrontare l'emittente del certificato appena visto con questa lista. Se non c'è corrispondenza, o se nDPI rileva che la firma del certificato appartiene al server stesso (auto-firmato), l'informazione viene immediatamente passata a ntopng per l'allerta.

**3. Implementazione operativa e dello storico (ClickHouse)**  
Tutti i dettagli tecnici del certificato vengono salvati da ntopng in ClickHous per permette di fare query molto utili per la sicurezza.

### Metrica 4: Evasione SNI nel traffico cifrato ($M_{sni}$)

**1. Il modello matematico**  
Nella normale navigazione web, i browser legittimi includono sempre in chiaro il nome del sito di destinazione all'inizio del *TLS Handshake*. I software malevoli, al contrario, tentano ad omettere questa informazione per contattare il loro server di comando (C2) direttamente tramite indirizzo IP.
La formula matematica è la seguente:

$$SNI(f) = \emptyset \implies M_{sni} = 1$$

Dove $f$ rappresenta un flusso di rete crittografato (TLS) in uscita verso un IP pubblico. La funzione $SNI(f)$ estrae la stringa del nome del server. Se questa operazione restituisce un insieme vuoto ($\emptyset$), il sistema certifica l'anomalia strutturale e fa scattare l'allarme.

**2. Il motore di estrazione e rilevamento in tempo reale (nDPI)**  
Il compito di nDPI è verificando che le regole strutturali del protocollo siano rispettate.
* **L'ispezione sintattica:** Durante il *TLS Handshake* (prima che i dati vengano crittografati), nDPI analizza l'estensione del parametro SNI (*Server Name Indication*). Il motore esegue un controllo sintattico a basso costo computazionale: verifica semplicemente se il campo `tls.sni` è popolato con un dominio valido.
* **Resistenza ai nuovi protocolli:** Questo approccio si rivela estremamente robusto anche contro i malware più evoluti. Anche qualora un attaccante cercasse di sfruttare i nuovi standard di cifratura che nascondono l'SNI (come la tecnologia ECH - *Encrypted Client Hello*), la struttura esterna del pacchetto di rete deve comunque rispettare regole rigide. Se nDPI intercetta una connessione in cui tale campo risulta del tutto assente, rileva immediatamente l'anomalia.

**3. Implementazione operativa e dello storico (ClickHouse)**  
A livello di database, questa metrica rappresenta una delle interrogazioni più leggere ed efficienti in assoluto per **ClickHouse**. La query SQL si limita a verificare se il valore del SNI è presente all'interno della colonna e segnalare l'anomalia nel caso sia assente.

---
