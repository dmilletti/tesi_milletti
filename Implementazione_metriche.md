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
