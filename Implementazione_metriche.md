# Guida all'Implementazione delle Metriche

## 1. Implementazione delle Metriche Deterministiche

### 1.1 Metrica: Reputazione Destinazione ($M_{rep}$)

**1. Obiettivo Operativo**  
Verificare in tempo reale se l'host monitorato genera traffico verso indirizzi IP o nomi a dominio compromessi (es. server *Command & Control*, domini di phishing, nodi Tor o *malware drop sites*). L'identificazione di un singolo evento di questo tipo è sufficiente per attivare la penalità massima di $M_{rep}$.

**2. Acquisizione del Dato (La Sonda Suricata)**  
Il fondamento tecnico di questa metrica poggia sul motore **Suricata** configurato come NIDS passivo (Network Intrusion Detection System). L'host o l'infrastruttura di rete dovrà essere monitorata da un sensore Suricata abilitato alla generazione dei log in formato `eve.json`. Questo formato produce un flusso continuo di metadati altamente strutturati relativi a ogni connessione, risoluzione DNS o sessione crittografata gestita dalla rete. 

Lo script di rilevamento agirà a valle della sonda, incaricandosi unicamente della lettura e del *parsing* (ovvero dell'analisi logica) di tale file. 

**3. Logica di Estrazione e Parsing**  
Il modulo di elaborazione (es. script Python) deve scorrere il log `eve.json` per la finestra oraria in esame e filtrare i record generati dall'host target (campo `"src_ip"`). La struttura dei dati generati da Suricata ci consente di estrarre tre elementi chiave, a seconda del tipo di evento di rete:

* **Destinazioni di Rete (Event-Type: `flow` o `netflow`):** Si cattura l'indirizzo IP pubblico verso cui la connessione è diretta tramite il campo `"dest_ip"`.
* **Domini Risolti (Event-Type: `dns`):** Suricata decodifica nativamente le query DNS. Per rintracciare i nomi a dominio (spesso utilizzati prima di stabilire la connessione effettiva), si interroga il campo `"dns" -> "rrname"`.
* **Domini nel Traffico Cifrato (Event-Type: `tls`):** Molto spesso il traffico verso server malevoli è crittografato. Il NIDS intercetta però il pacchetto *Client Hello* del protocollo TLS, dove il dominio di destinazione viaggia in chiaro. Pertanto, andrà estratto il campo `"tls" -> "sni"` (Server Name Indication).

Per ottimizzare le risorse di sistema, lo script dovrà memorizzare questi valori all'interno di una struttura dati che prevenga la duplicazione (ad esempio un oggetto di tipo `Set` in Python), limitandosi a creare una lista degli elementi *unici* contattati nel periodo.

**4. Architettura del Rilevamento (Threat Intelligence Locale)**  
Per stabilire la natura malevola o benigna dell'elenco generato, è necessario confrontarlo con gli *Indicatori di Compromissione* (IoC). Una richiesta API esterna per ogni singola risoluzione innescherebbe enormi latenze o un rapido blocco da parte del fornitore per il superamento delle quote (Rate Limiting).

Il design corretto (*Offline-First*) prevede un'infrastruttura di alimentazione asincrona. Un modulo indipendente si occuperà di scaricare periodicamente le *blacklist* aggiornate da *feed* di *Threat Intelligence* Open-Source (come OSINT.Bambenek, Abuse.ch, o MISP).
Queste liste devono essere caricate localmente in memoria, all'interno del motore di rilevamento (usando un Hash Set per look-up rapidi, o un database compatto come SQLite). L'elaborazione centrale effettuerà quindi un rapido controllo logico locale: si verificherà l'intersezione (look-up) tra l'insieme dei target contattati e la *blacklist* in memoria.

**5. Calcolo della Metrica (Output)**  
La metrica $M_{rep}$ si attiva secondo una rigida valutazione booleana:
* Se la funzione di look-up locale rileva una o più corrispondenze (MATCH $\ge$ 1), l'anomalia è confermata. Il sistema assegna la penalità: **$M_{rep} = 1$**.
* Se, al contrario, non emergono riscontri nei database di reputazione, la connessione si considera sicura: **$M_{rep} = 0$**.

### 1.2 Metrica: Fingerprinting Crittografico (JA4) - $M_{ja4}$

**1. Obiettivo Operativo**  
Identificare in modo deterministico applicazioni malevole, malware o strumenti di *penetration testing* (es. Metasploit, Cobalt Strike, script Python/Go malevoli) analizzando il modo in cui negoziano la connessione crittografata (TLS *Client Hello*), indipendentemente dall'IP di destinazione. Questa tecnica supera i limiti delle *blacklist* basate solo su IP/Domini, intercettando gli attaccanti anche quando cambiano dinamicamente l'infrastruttura (tecniche di *Fast-Flux*).

**2. Acquisizione del Dato (La Sonda Suricata)**  
Anche questa metrica si basa sul motore NIDS Suricata, il quale deve essere aggiornato a una versione che supporti nativamente il calcolo del fingerprinting JA4 (Suricata 7+ o versioni precedenti con apposito plugin abilitato).
Il NIDS osserverà il traffico TLS in transito e, analizzando i pacchetti di negoziazione inviati dal client (inviati in chiaro prima che il tunnel cifrato venga stabilito), genererà l'impronta JA4, iniettandola automaticamente all'interno del log strutturato `eve.json`.

**3. Logica di Estrazione e Parsing**  
Il modulo di elaborazione (script Python) intercetterà gli eventi generati dall'host monitorato e filtrerà esclusivamente i record relativi all'evento di tipo `tls`.
Il parser dovrà estrarre due stringhe fondamentali da ogni sessione analizzata:
* **Il fingerprint JA4 completo:** (in Suricata: campo `"tls" -> "ja4"`).
* **Il nome del dominio Server Name Indication (SNI):** (in Suricata: campo `"tls" -> "sni"`).

È essenziale memorizzare e analizzare la *coppia* (JA4, SNI). Un fingerprint JA4 isolato potrebbe infatti appartenere a una libreria legittima (es. `curl` o script Python standard); tuttavia, la stessa libreria usata per contattare un dominio sconosciuto o esterno al perimetro aziendale rappresenta un indicatore forte di anomalia. Per ottimizzare le performance, queste coppie verranno aggregate in un `Set` per eliminare i duplicati all'interno del batch orario.

**4. Architettura del Rilevamento (Threat Intelligence Locale)**  
Il sistema adotterà un approccio *Offline-First* per azzerare la latenza di rilevamento:
1.  **Sincronizzazione:** Un *worker* asincrono scaricherà periodicamente le liste di JA4 malevoli noti da database e feed di *Threat Intelligence* (come il database ufficiale del progetto JA4, FoxIO o feed commerciali).
2.  **Archiviazione:** Queste firme verranno caricate nel database locale del motore di rilevamento (in RAM o via SQLite).
3.  **Cross-Validation Logica:** Lo script confronterà l'insieme dei fingerprint estratti con il database locale. Se viene rilevato un JA4 "sospetto" o associato a tool generici (es. Python `requests`), il sistema effettuerà un controllo incrociato con il campo SNI associato: se il dominio non rientra in una *whitelist* aziendale predefinita (es. server API interni noti), l'allarme viene confermato.

**5. Calcolo della Metrica (Output)**  
Il rilevamento avviene secondo una rigida logica booleana:
* Se il look-up locale rileva una corrispondenza tra un JA4 generato dall'host e un JA4 malevolo noto (con eventuale fallimento della validazione SNI), la compromissione è confermata. Il sistema assegna la penalità massima: **$M_{ja4} = 1$**.
* Se il fingerprint appartiene a software noto e benigno (es. browser standard), o non è presente nelle *blacklist*, il valore è nullo: **$M_{ja4} = 0$**.

### 1.3 Metrica: Anomalie nei Certificati TLS ($M_{cert}$)

**1. Obiettivo Operativo**  
Identificare connessioni verso server che presentano certificati crittografici X.509 anomali, come certificati scaduti, non ancora validi o auto-firmati (*Self-Signed*). Poiché le infrastrutture d'attacco improvvisate, i server *Command & Control* o i malware tendono a non acquistare certificati legittimi da Autorità di Certificazione (CA) riconosciute, l'uso di un certificato anomalo è un forte indicatore di compromissione o di *Man-in-the-Middle*.

**2. Acquisizione del Dato (La Sonda Suricata)**  
Il sistema si affida nuovamente a Suricata. Durante la fase di *handshake* del protocollo TLS, il server invia il proprio certificato crittografico in chiaro al client. Suricata intercetta questo pacchetto, decodifica i campi del certificato X.509 e li registra in modo strutturato all'interno del file di log `eve.json`, rendendoli immediatamente disponibili per l'analisi senza necessità di decifrare il payload della connessione.

**3. Logica di Estrazione e Parsing**  
Il modulo di elaborazione (script Python) analizzerà la finestra oraria filtrando gli eventi generati dall'host monitorato con `event_type` pari a `tls`. 
Per ogni sessione TLS registrata, lo script dovrà estrarre quattro campi fondamentali situati all'interno dell'oggetto JSON del certificato:
* **Soggetto del certificato:** (in Suricata: campo `"tls" -> "subject"`). Indica a chi è stato rilasciato il certificato.
* **Emittente (Issuer):** (in Suricata: campo `"tls" -> "issuerdn"`). Indica l'Autorità che ha firmato e rilasciato il certificato.
* **Inizio Validità:** (in Suricata: campo `"tls" -> "notbefore"`). Il *timestamp* da cui il certificato è valido.
* **Fine Validità:** (in Suricata: campo `"tls" -> "notafter"`). Il *timestamp* di scadenza del certificato.

**4. Architettura del Rilevamento (Controlli Logici Locali)**  
A differenza delle metriche precedenti ($M_{rep}$ e $M_{ja4}$), per questa anomalia **non è necessario scaricare alcun database o blacklist esterna**. Il rilevamento avviene tramite puri controlli logici formali sui metadati estratti, eseguiti direttamente in RAM dallo script:
1. **Controllo Self-Signed:** Il sistema confronta le stringhe del Soggetto e dell'Emittente. Se coincidono perfettamente (`subject == issuerdn`), significa che il server ha firmato il certificato da solo, aggirando le Autorità ufficiali.
2. **Controllo Validità Temporale:** Il sistema converte i campi `notbefore` e `notafter` in *timestamp* UNIX e li confronta con l'orologio di sistema (il momento esatto in cui è avvenuta la connessione). Se la connessione avviene *prima* di `notbefore` o *dopo* `notafter`, il certificato è formalmente invalido.

**5. Calcolo della Metrica (Output)**  
L'esito dei controlli formali determina l'attivazione della penalità in modo booleano:
* Se si verifica **almeno una** delle condizioni di anomalia (il certificato è auto-firmato OPPURE risulta scaduto/non valido temporalmente), il canale di comunicazione è ritenuto inaffidabile. Il sistema assegna la penalità: **$M_{cert} = 1$**.
* Se il certificato è stato emesso da terzi e risulta in corso di validità, il traffico è considerato regolare: **$M_{cert} = 0$**.

## 2. Implementazione delle Metriche Statistiche e Comportamentali (Batch 1 Ora)

### 2.1 Metrica: Rilevamento Funzionalità Server ($M_{srv}$)

**1. Obiettivo Operativo**  
Rilevare l'inversione di ruolo dell'host monitorato all'interno della rete. Una *workstation* aziendale deve operare esclusivamente come "Client" (iniziando le connessioni). Se l'host inizia ad accettare connessioni in ingresso agendo da "Server", il sistema deve segnalare immediatamente il sospetto di una *backdoor* attiva, di un accesso remoto non autorizzato (es. RDP abusivo) o di un tentativo di movimento laterale da parte di un attaccante.

**2. Acquisizione del Dato (La Sonda Suricata)**  
Per questa metrica non analizzeremo i singoli pacchetti, ma sfrutteremo la capacità di Suricata di tracciare le connessioni complete, chiamate **flussi**. Il motore di rete tiene traccia del *3-way handshake* TCP e, quando una connessione termina (o scade per *timeout*), genera un log riassuntivo in `eve.json` con `event_type` impostato su `flow`. Questo log contiene tutte le direttrici del traffico, permettendoci di capire esattamente chi ha "chiamato" e chi ha "risposto".

**3. Logica di Estrazione e Parsing**  
Alla chiusura della finestra oraria (o tramite un'analisi continua in streaming), lo script Python filtrerà esclusivamente gli eventi di tipo `flow` limitati al protocollo TCP (che prevede il concetto di connessione stabilita).
Per ogni record di flusso, il parser dovrà estrarre tre informazioni cruciali:
* **Indirizzo IP Destinazione:** (in Suricata: campo `"dest_ip"`). Identifica il nodo che ha *ricevuto* e accettato la richiesta di connessione (il Responder/Server).
* **Indirizzo IP Sorgente:** (in Suricata: campo `"src_ip"`). Identifica chi ha *iniziato* la connessione (l'Originator/Client).
* **Stato del Flusso:** (in Suricata: campo `"flow" -> "state"`). Questo è vitale: un attaccante potrebbe fare uno *scan* di rete verso il nostro host. Se il nostro host rifiuta la connessione (porta chiusa), Suricata genererà comunque un log, ma non c'è stata inversione di ruolo. Per confermare l'anomalia, il campo `state` deve indicare che la connessione è andata a buon fine (valori come `established` o `closed`, che indicano una sessione aperta e poi chiusa regolarmente).

**4. Architettura del Rilevamento (Logica Zero-Trust)**  
A differenza delle successive metriche statistiche (che useranno storici di 7 giorni e Z-Score), questa metrica comportamentale adotta un approccio **Zero-Trust**. L'algoritmo non ha bisogno di imparare il comportamento passato, perché l'assunto architetturale è rigido: l'host non deve *mai* fare da server.
L'elaborazione si traduce in una singola condizione logica verificata su tutti i flussi estratti nel batch:
* Si cerca l'esistenza di almeno un log in cui l'IP dell'host monitorato compare nel campo `"dest_ip"` **E** il cui `"flow" -> "state"` indichi un avvenuto *handshake* TCP.

**5. Calcolo della Metrica (Output)**  
Essendo una regola comportamentale inderogabile, l'output rimane booleano e viene calcolato a fine batch:
* Se l'algoritmo trova **almeno un flusso** (MATCH $\ge$ 1) in cui l'host monitorato ha agito da server stabilendo la connessione, l'inversione di ruolo è confermata: **$M_{srv} = 1$**.
* Se in tutti i flussi analizzati l'host compare unicamente come `"src_ip"` (o se compare come `"dest_ip"` ma la connessione è stata rifiutata/bloccata), il comportamento è conforme: **$M_{srv} = 0$**.

### 2.2 Metrica: Protocollo su Porta Non Standard ($M_{proto}$)

**1. Obiettivo Operativo**  
Rilevare in modo esplicito i tentativi di evasione del firewall aziendale o l'occultamento del traffico (mascheramento). L'obiettivo è identificare se l'host monitorato sta trasmettendo dati utilizzando un protocollo applicativo di Livello 7 (es. SSH, RDP, SMB) su una porta logica di Livello 4 (es. porta 80 o 443) che non corrisponde allo standard assegnato dall'ente IANA.

**2. Acquisizione del Dato (La Sonda Suricata e la DPI)**  
Questa metrica si affida interamente ai *parser* applicativi di Suricata. Il motore del NIDS non si limita a leggere l'intestazione TCP/UDP (la porta), ma esegue una vera e propria *Deep Packet Inspection* (DPI) sui primissimi byte del *payload*. Quando Suricata riconosce inequivocabilmente la firma strutturale di un protocollo, valorizza automaticamente il campo `"app_proto"` all'interno del file di log `eve.json`, indipendentemente dalla porta su cui sta viaggiando.

**3. Logica di Estrazione e Parsing**  
Alla chiusura del *batch* orario, lo script di elaborazione analizzerà i log dell'host monitorato, filtrando i flussi di rete (eventi di tipo `flow`) in cui l'host ha il ruolo di *Originator* (`"src_ip"`).
Per ogni flusso utile, lo script dovrà estrarre due soli parametri numerici e testuali:
* **La porta logica di destinazione:** (in Suricata: campo `"dest_port"`).
* **Il protocollo applicativo reale:** (in Suricata: campo `"app_proto"`).

*Nota:* Saranno scartati a priori dall'analisi i record in cui il campo `"app_proto"` è assente, etichettato come `"failed"` o `"unknown"`. L'obiettivo della metrica non è sanzionare il traffico irriconoscibile (che potrebbe generare falsi positivi), ma sanzionare la discrepanza *certa* tra porta e protocollo noto.

**4. Architettura del Rilevamento (Mappatura IANA Locale)**  
Anche per questa metrica, la velocità di esecuzione è fondamentale, pertanto non vi sarà alcuna interrogazione a database esterni. L'architettura prevede l'inserimento, direttamente all'interno dello script Python o in un file di configurazione JSON locale, di un dizionario statico (Mappa Hash) contenente lo standard IANA.
Questo dizionario assocerà le porte maggiormente utilizzate per l'elusione ai rispettivi protocolli legittimi ammessi. Ad esempio:
`{ 443: ["tls", "http", "quic"], 80: ["http"], 53: ["dns"] }`
L'algoritmo centrale prenderà il valore estratto da `"dest_port"` e controllerà se il valore di `"app_proto"` rientra nella lista dei protocolli consentiti per quella specifica porta.

**5. Calcolo della Metrica (Output)**  
L'esito del controllo logico genera il valore booleano di fine batch:
* Se per l'host viene rilevato **almeno un flusso** in cui il protocollo applicativo differisce da quello atteso dalla mappa standard (es. `dest_port: 443` ma `app_proto: ssh`), l'occultamento è certificato. Il sistema attiva l'anomalia: **$M_{proto} = 1$**.
* Se tutto il traffico analizzato nell'ora rispetta la coerenza Porta/Protocollo, il valore rimane nullo: **$M_{proto} = 0$**.

### 2.3 Metrica: Scansione Interna o Fan-out ($M_{scan}$)

**1. Obiettivo Operativo**  
Rilevare un improvviso e anomalo allargamento del raggio d'azione dell'host all'interno della rete aziendale. Se una postazione infetta tenta di propagare un *malware* (Movimento Laterale) o cerca server vulnerabili (*Network Discovery*), inizierà a contattare a tappeto decine o centinaia di IP interni. L'obiettivo è misurare l'eccezionalità statistica di questo "Fan-out" (numero di destinazioni uniche) rispetto alle normali abitudini del dipendente.

**2. Acquisizione del Dato (La Sonda Suricata)**  
Il sistema sfrutta nuovamente i log di flusso di Suricata (`event_type: flow`). A differenza delle metriche precedenti, per questa misurazione non ci interessa affatto cosa contiene il pacchetto (nessuna *Deep Packet Inspection* L7), ma ci interessa esclusivamente la topologia dell'instradamento (Livello 3). Questo rende l'acquisizione del dato estremamente leggera e rapida.

**3. Logica di Estrazione e Aggregazione**  
Alla chiusura del batch orario, lo script di analisi prenderà in carico tutti i log di flusso generati. L'estrazione prevede un doppio filtro logico:
1.  **Filtro Origine:** Si isolano solo i flussi in cui l'host monitorato è l'origine della connessione (`"src_ip"`).
2.  **Filtro Destinazione Interna:** Tramite una funzione di maschera di rete, lo script scarta tutto il traffico diretto verso Internet e conserva **solo** il traffico diretto verso le *subnet* private aziendali (spazi di indirizzamento RFC 1918, es. `10.0.0.0/8`, `192.168.0.0/16`).

Dai log così filtrati, lo script estrarrà il campo `"dest_ip"`. Questi IP verranno inseriti in una struttura dati di tipo `Set`. Allo scoccare del 60° minuto dell'ora, si conterà la grandezza del `Set` (cardinalità), ottenendo il valore $x_t$: *il numero esatto di host interni unici contattati in quell'ora*.

**4. Architettura del Rilevamento (Serie Storiche con InfluxDB)**  
Trattandosi di un'anomalia statistica, il sistema necessita di memorizzare lo stato storico dell'host. L'architettura prevede l'adozione di **InfluxDB**, un *Time-Series Database* (TSDB) leader di settore, ottimizzato appositamente per la scrittura e l'interrogazione ultra-rapida di metriche temporali.
L'impiego di InfluxDB offre un vantaggio architetturale fondamentale: tramite le sue *Retention Policy* native, il database eliminerà automaticamente i dati più vecchi di 7 giorni, mantenendo la *baseline* sempre pulita e aggiornata senza richiedere script di manutenzione aggiuntivi.
Il flusso di elaborazione sarà il seguente:
1.  **Estrazione della Baseline:** Lo script Python interroga InfluxDB per recuperare l'array dei valori di "Fan-out" registrati per l'host nelle precedenti 168 ore (7 giorni).
2.  **Calcolo della Mediana ($\tilde{x}$):** Si calcola il valore centrale dell'array storico (operazione che può essere delegata nativamente al motore di query di InfluxDB per massimizzare le performance).
3.  **Calcolo della MAD (Median Absolute Deviation):** Si calcola la mediana delle deviazioni assolute di ciascun valore storico dalla Mediana $\tilde{x}$.

*Nota 1 (Gestione del Cold Start e Baseline Poisoning):* Un sistema statistico appena installato, o un nuovo host appena collegato alla rete, non possiede uno storico reale di 7 giorni. Affidarsi a un semplice periodo di apprendimento passivo (*Learning Mode*) espone la rete al rischio di *Baseline Poisoning*: se il nuovo host è già compromesso al momento dell'inserimento, il sistema apprenderà il comportamento malevolo come "normale".
Per mitigare questa vulnerabilità, l'architettura implementa il concetto di **Golden Profile (Profilo Aziendale Standard)**. Quando viene rilevato un nuovo indirizzo IP, lo script di inizializzazione inietta nel database InfluxDB una *baseline* pre-compilata e conservativa per i primi 7 giorni. Qualsiasi deviazione da questo profilo "pulito" genererà immediatamente un'anomalia. Man mano che trascorrono i giorni, i dati reali dell'host andranno a sostituire progressivamente il profilo standard, garantendo un passaggio sicuro da una sicurezza basata su policy a una basata sul comportamento reale dell'utente.

*Nota 2 (Prevenzione divisione per zero):* Se un host ha un comportamento estremamente rigido (es. contatta sempre e solo esattamente i soliti 3 server), la sua MAD storica sarà pari a $0$. Matematicamente questo causerebbe un errore nel calcolo dello Z-Score (divisione per zero). L'implementazione dovrà prevedere un "valore di clamp": se la $MAD = 0$, il sistema forzerà a codice $\max(MAD, 1)$ per garantire la stabilità matematica dell'algoritmo.

**5. Calcolo della Metrica (Output)**  
Avendo a disposizione il valore corrente ($x_t$), la Mediana ($\tilde{x}$) e la dispersione ($MAD$), lo script calcola lo scostamento statistico standardizzato:

$$Z_{robusto} = \frac{|x_t - \tilde{x}|}{MAD}$$

L'output della metrica si determina valutando il superamento della soglia:
* Se il "Fan-out" orario genera uno $Z_{robusto} > 3$ (comportamento con probabilità $\le 0.3\%$ di essere casuale), il picco di scansione è confermato: **$M_{scan} = 1$**.
* Se lo scostamento rientra nelle normali fluttuazioni storiche ($Z_{robusto} \le 3$), il comportamento volumetrico è tollerato: **$M_{scan} = 0$**.

### 2.4 Metrica: Esplorazione di Protocolli Inediti ($M_{new}$)

**1. Obiettivo Operativo**  
Rilevare l'impiego di un protocollo applicativo di Livello 7 mai utilizzato in precedenza dall'host. Poiché ogni postazione aziendale possiede una "firma comportamentale" limitata e ripetitiva (es. traffico HTTP/TLS, DNS, protocolli di posta o gestionali interni), la comparsa improvvisa di protocolli anomali (es. nodi *Peer-to-Peer* per esfiltrazione, *routing* Tor, o SSH/RDP su macchine non amministrative) è un indicatore primario dell'esecuzione di un *payload* malevolo.

**2. Acquisizione del Dato (La Sonda Suricata e DPI)**  
Analogamente alla Metrica 5 ($M_{proto}$), l'acquisizione si affida interamente alle capacità di *Deep Packet Inspection* (DPI) del NIDS Suricata. Indipendentemente dalla porta logica utilizzata, il motore ispeziona il payload dei pacchetti e classifica con certezza il protocollo applicativo, valorizzando il campo `"app_proto"` all'interno dei log di flusso (`event_type: flow`) nel file `eve.json`.

**3. Logica di Estrazione e Aggregazione**  
Allo scadere della finestra oraria (1 ora), lo script di analisi intercetta i log di flusso in cui l'host monitorato ha il ruolo di *Originator* (`"src_ip"`). 
Dal log viene estratto esclusivamente il valore testuale del campo `"app_proto"`. Vengono scartati a priori i record con valore assente, `"failed"` o `"unknown"` per prevenire rumore statistico.
Tutti i protocolli applicativi validi identificati nell'ora vengono inseriti in una struttura dati di tipo `Set`. Questo insieme, che chiameremo matematicamente $P_{batch}$, rappresenta la firma applicativa dell'host nella finestra corrente.

**4. Architettura del Rilevamento (Teoria degli Insiemi e InfluxDB)**  
L'architettura sfrutta il database temporale **InfluxDB** per definire il profilo comportamentale storico del nodo:
1. **Estrazione della Baseline:** Lo script interroga InfluxDB per estrarre l'elenco distinto di tutti i protocolli (valori di `"app_proto"`) associati a quell'host nelle precedenti 168 ore (7 giorni). L'impiego di InfluxDB permette di eseguire questa query di aggregazione (`DISTINCT`) direttamente lato database, azzerando il carico computazionale sullo script Python.
2. **Definizione dell'Insieme Storico:** I valori restituiti dal database formano l'insieme storico $P_{storico}$.
3. **Calcolo della Differenza Logica:** Il motore esegue una pura sottrazione tra insiemi matematici. Si calcola la differenza $P_{batch} \setminus P_{storico}$, ovvero si cercano elementi presenti nell'ora corrente ma totalmente assenti nei 7 giorni precedenti.

**5. Calcolo della Metrica (Output)**  
Superato il periodo di *Cold Start*, il rilevamento segue una ferrea logica insiemistica:
* Se la differenza tra gli insiemi **non è vuota** ($P_{batch} \setminus P_{storico} \neq \emptyset$), significa che è comparso almeno un protocollo totalmente inedito per la storicità del nodo. L'anomalia comportamentale è certificata e si impone la penalità: **$M_{new} = 1$**.
* Se l'insieme differenza è vuoto (ovvero i protocolli usati nell'ultima ora sono un sottoinsieme di quelli già noti storicamente), il comportamento è considerato consuetudinario: **$M_{new} = 0$**.

### 2.5 Metrica: Asimmetria Volumetrica in Uscita ($M_{vol}$)

**1. Obiettivo Operativo**  
Rilevare un trasferimento massivo di dati dalla postazione verso l'esterno. Nella normale operatività quotidiana, il traffico di un utente standard è fortemente asimmetrico verso il *download* (scaricamento di pagine web, video, documenti). Un'inversione improvvisa di questa tendenza, caratterizzata da un picco eccezionale di dati in *upload* verso Internet, è un forte indicatore di esfiltrazione di dati aziendali o dell'invio di archivi compressi verso un server "Drop point" controllato dagli attaccanti.

**2. Acquisizione del Dato (Contatori Volumetrici di Suricata)**  
Per questa metrica l'ispezione profonda (DPI) non è necessaria. Il NIDS Suricata tiene traccia di quanti byte vengono scambiati in ogni connessione. Al termine di ogni sessione, genera il consueto log `event_type: flow` in `eve.json`, inserendovi all'interno i contatori esatti dei byte trasmessi (dal Client al Server) e ricevuti.

**3. Logica di Estrazione e Aggregazione**  
Alla chiusura del batch orario (1 ora), lo script di analisi intercetterà tutti i log di flusso. La logica di filtraggio si struttura in due passaggi:
1.  **Filtro Direzionale Esterno:** Si mantengono solo i flussi in cui l'host è *Originator* (`"src_ip"`) e la destinazione (`"dest_ip"`) è un indirizzo IP pubblico (Internet), scartando tramite maschera di rete tutto il traffico intra-aziendale (RFC 1918). Questo evita che il normale invio di un grosso file a un server interno o a una stampante di rete generi falsi positivi.
2.  **Estrazione del Volume:** Per ogni flusso filtrato, lo script estrae il valore numerico del campo `"flow" -> "bytes_toserver"` (che in Suricata rappresenta i byte inviati dal sorgente alla destinazione). 

Lo script sommerà aritmeticamente tutti questi valori, ottenendo la variabile $V_{out}$: *il volume totale in byte trasmesso verso Internet nell'ora corrente*.

**4. Architettura del Rilevamento (Serie Storiche con InfluxDB)**  
Come per le altre metriche statistiche, l'architettura sfrutta **InfluxDB** per la gestione della *baseline* comportamentale:
1. **Salvataggio e Lettura:** Il valore orario $V_{out}$ viene scritto in InfluxDB. Subito dopo, lo script interroga il database per ottenere l'array dei volumi orari in uscita registrati dall'host negli ultimi 7 giorni (168 ore).
2. **Calcolo dei Parametri di Riferimento:** Sull'array storico vengono calcolate la Mediana ($\tilde{V}$) e la Dispersione Assoluta ($MAD$).
3. **Gestione (Cold Start e Clamp):** Come già definito per le metriche precedenti, per prevenire il *Baseline Poisoning* nei nuovi host si applica la logica del *Golden Profile*. In questo caso specifico, InfluxDB verrà inizializzato con una distribuzione volumetrica fittizia rappresentativa di un utente standard (ovvero flussi storici di *upload* di dimensioni molto contenute). A livello puramente algoritmico, viene inoltre forzato un "valore di clamp" sulla dispersione ($\max(MAD, 1)$) per prevenire errori critici di divisione per zero nel caso di host che non inviano mai dati verso Internet.

**5. Calcolo della Metrica (Output)**  
Lo script calcola lo Z-Score robusto per quantificare l'eccezionalità del picco volumetrico:

$$Z_{robusto} = \frac{|V_{out} - \tilde{V}|}{MAD}$$

Il verdetto finale viene stabilito dalla soglia statistica:
* Se il picco di trasferimento genera uno scostamento $Z_{robusto} > 3$ (comportamento anomalo con probabilità $\le 0.3\%$), l'esfiltrazione anomala è confermata: **$M_{vol} = 1$**.
* Se il volume di dati rientra nella naturale flessibilità del traffico dell'utente (es. l'invio di un allegato email leggermente più grande del solito, con $Z_{robusto} \le 3$), la metrica rimane passiva: **$M_{vol} = 0$**.

### 2.6 Metrica: Anomalie nel Protocollo di Risoluzione Nomi ($M_{dns}$)

**1. Obiettivo Operativo**  
Identificare la presenza di *malware* avanzati (es. *Ransomware* o *Botnet*) che utilizzano algoritmi DGA per generare dinamicamente i domini di Comando e Controllo, oppure rilevare tentativi di esfiltrazione dati tramite *DNS Tunneling*. Poiché la risoluzione dei nomi non viene quasi mai bloccata dai firewall aziendali, gli attaccanti incapsulano dati o comandi all'interno di query DNS composte da stringhe lunghissime e pseudo-casuali (es. `x9k2js8fq1...malicious.com`). L'obiettivo è misurare matematicamente questo "livello di disordine" testuale, che risulta impossibile da produrre durante la normale navigazione umana.

**2. Acquisizione del Dato (La Sonda Suricata)**  
Suricata è un eccellente analizzatore per il protocollo DNS. Configurato passivamente, cattura le richieste dirette ai *resolver* aziendali o pubblici. Il motore NIDS genera un log in formato `eve.json` con `event_type` pari a `dns`, decodificando nativamente i dettagli della richiesta in chiaro, senza richiedere ulteriori sforzi computazionali di ispezione profonda.

**3. Logica di Estrazione e Calcolo dell'Entropia**  
Durante il batch orario, lo script Python analizzerà i log filtrando quelli generati dall'host monitorato (`"src_ip"`) con tipologia `dns`. 
Per ogni record, viene estratto il nome a dominio interrogato tramite il campo `"dns" -> "rrname"`. Su questa stringa, lo script applica la funzione matematica dell'Entropia di Shannon, che calcola il grado di incertezza basandosi sulla frequenza ($p_i$) di ogni singolo carattere:

$$E(q) = - \sum_{i} p_i \log_2(p_i)$$

Al termine dell'ora, lo script aggregherà questi valori calcolando la media aritmetica dell'entropia di tutti i domini interrogati, ottenendo il valore $E_{batch}$ (l'entropia aggregata oraria dell'host).

*Nota (Estrazione Radice e Sottodomini):* Calcolare l'entropia sull'intero FQDN (Fully Qualified Domain Name, es. `www.azienda.com`) "inquina" la purezza del dato matematico, poiché i domini di primo livello (`.com`, `.it`, `.org`) sono ripetitivi e abbassano artificialmente il risultato. Per garantire precisione assoluta, l'implementazione Python impiegherà una libreria di *parsing* (es. `tldextract`) per eliminare il TLD e isolare solo la radice del dominio e gli eventuali sottodomini. L'Entropia di Shannon verrà calcolata **esclusivamente** sulla parte variabile della stringa.

**4. Architettura del Rilevamento (Serie Storiche con InfluxDB)**  
L'architettura per questa metrica statistica sfrutta l'ecosistema collaudato basato su InfluxDB:
1. **Memorizzazione Storica:** Il valore $E_{batch}$ viene scritto nel TSDB (InfluxDB), da cui viene parallelamente richiamato l'array storico delle entropie orarie degli ultimi 7 giorni.
2. **Parametri Robusti:** Vengono calcolate la Mediana ($\tilde{E}$) e la dispersione assoluta ($MAD$) sulla *baseline* storica.
3. **Gestione del Cold Start:** Come per le metriche volumetriche, si fa affidamento sull'architettura del *Golden Profile*. Per prevenire l'apprendimento di comportamenti DGA fin dall'inizio, InfluxDB viene pre-popolato per i nuovi host con valori di entropia bassi e stabili (tipicamente intorno a $2.5 - 3.5$, che rappresenta l'entropia della lingua inglese/italiana nei domini legittimi).

**5. Calcolo della Metrica (Output)**  
Il motore Python procede al calcolo dello scostamento statistico standardizzato:

$$Z_{robusto} = \frac{|E_{batch} - \tilde{E}|}{MAD}$$

La deviazione dalla normalità determina l'esito:
* Se il livello medio di disordine testuale genera uno $Z_{robusto} > 3$ (comportamento anomalo con probabilità $\le 0.3\%$), si certifica un abuso del protocollo di risoluzione nomi: **$M_{dns} = 1$**.
* Se l'entropia aggregata rientra nei parametri storici tollerati ($Z_{robusto} \le 3$), indicando domini leggibili e strutturalmente prevedibili, la metrica rimane dormiente: **$M_{dns} = 0$**.

### 2.7 Metrica: Rigidità Temporale e Automazione ($M_{time}$)

**1. Obiettivo Operativo**  
Rilevare la presenza di comunicazioni automatizzate tra la postazione e server esterni. I malware (come botnet o *Remote Access Trojan*) mantengono la connessione attiva con il server di Comando e Controllo (C2) inviando pacchetti a intervalli regolari (effetto *beaconing* o battito cardiaco). L'obiettivo è misurare la varianza temporale tra le connessioni: un crollo vertiginoso della varianza indica che a generare il traffico non è la caotica navigazione umana, ma un rigido algoritmo informatico.

**2. Acquisizione del Dato (Timestamp di Suricata)**  
L'analisi temporale sfrutta nuovamente i log di flusso di Suricata (`event_type: flow`). Per questa metrica, il dato cruciale non è la porta o il volume, ma la precisa marca temporale di inizio della connessione. Il NIDS registra questo dato nel campo `"timestamp"` di ogni flusso in formato ISO 8601 (o direttamente in UNIX Epoch se configurato), garantendo una precisione al microsecondo.

**3. Logica di Estrazione e Aggregazione**  
Al termine della finestra oraria, lo script Python analizzerà i flussi in cui l'host è *Originator* (`"src_ip"`) diretti verso Internet (`"dest_ip"` pubblico). L'elaborazione matematica procede per step:
1.  **Ordinamento Cronologico:** Si estraggono tutti i `"timestamp"` di inizio flusso e si ordinano dal più vecchio al più recente.
2.  **Calcolo dell'Inter-arrivo:** Lo script calcola il delta temporale ($\Delta t_i = t_{i} - t_{i-1}$) tra ogni connessione e la precedente.
3.  **Calcolo della Varianza:** Sull'array dei delta ($\Delta t_1, \Delta t_2, \dots, \Delta t_n$) viene calcolata la varianza statistica, ottenendo il valore aggregato orario $V_{batch}$.

*Nota (Formattazione Temporale):* Per garantire precisione ed evitare bug legati ai fusi orari (Timezone) o all'ora legale (DST), lo script Python dovrà convertire immediatamente tutti i timestamp testuali in formati interi (UNIX Timestamp in millisecondi) prima di eseguire qualsiasi sottrazione algebrica.

**4. Architettura del Rilevamento (Serie Storiche con InfluxDB)**  
Anche l'analisi temporale si appoggia all'infrastruttura InfluxDB per gestire la *baseline*:
1. **Storicità della Varianza:** Il valore $V_{batch}$ viene scritto nel TSDB, e lo script recupera l'array delle varianze orarie degli ultimi 7 giorni.
2. **Parametri Robusti:** Si calcolano la Mediana ($\tilde{V}$) e la dispersione assoluta ($MAD$) sulla *baseline* storica.
3. **Gestione del Golden Profile:** Per prevenire il *Baseline Poisoning*, il *Golden Profile* di un nuovo host viene inizializzato con varianze temporali pre-impostate volutamente **molto alte**. Questo simula il profilo irregolare di un operatore umano. Se il nuovo PC è già infetto e inizia a "battere" con regolarità algoritmica, la sua varianza reale risulterà drasticamente più bassa rispetto a quella del profilo assegnato, facendo scattare subito la trappola.

**5. Calcolo della Metrica (Output)**  
Lo script calcola lo scostamento statistico standardizzato:

$$Z_{robusto} = \frac{|V_{batch} - \tilde{V}|}{MAD}$$

A differenza delle altre metriche, in questo caso l'anomalia è unidirezionale: siamo preoccupati solo se il comportamento diventa **più rigido** (minore varianza), non se diventa più caotico.
Pertanto, la metrica si attiva solo se si verificano **due condizioni simultanee**:
* Se lo scostamento è eccezionale ($Z_{robusto} > 3$) **E** contestualmente la varianza attuale è sensibilmente inferiore alla varianza storica ($V_{batch} \ll \tilde{V}$), si certifica la presenza di un automatismo informatico: **$M_{time} = 1$**.
* Se lo scostamento rientra nella norma ($Z_{robusto} \le 3$) oppure la varianza è aumentata (traffico più irregolare e "umano"), l'allarme non si attiva: **$M_{time} = 0$**.
