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
