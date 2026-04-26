# Scelta delle metriche e architettura del sistema

Questo capitolo illustra la transizione dal modello teorico all'implementazione pratica del sistema di rilevamento all'interno di una di rete reale. L'obiettivo è definire un'architettura in grado di unire la velocità della *Deep Packet Inspection* di **ntopng** e del motore **nDPI** con l'efficienza di archiviazione del database colonnare **ClickHouse**, che si conclude in un motore di calcolo in grado di assegnare un punteggio di rischio a ogni host. Prima di descrivere l'architettura del sistema è necessario definire quali metriche sono state scelte per l'implementazione pratica.

## 1. Selezione delle metriche

Abbiamo scelto di concentrarci su 10 metriche specifiche per trovare il giusto compromesso tra una visione completa delle anomalie di rete e l'efficienza computazionale.

La selezione è stata guidata da due criteri fondamentali:

1. **Efficienza computazionale su ClickHouse e nDPI:**  
Sono state privilegiate le metriche che riescono a sfruttare al massimo le capacità di aggregazione nativa del database colonnare di ClickHouse, evitando operazioni troppo costose.
Ad esempio, per rilevare i domini generati artificialmente (DGA), si è scelto di implementare il *Connection failure rate* ($M_{fail}$) al posto del calcolo logaritmico dell'entropia di Shannon applicato alle query DNS ($M_{DNS}$). Questo permette di ottenere lo stesso risultato (scoprire la ricerca alla cieca del malware) con interrogazioni SQL dal costo quasi nullo.
2. **Copertura integrale della *Cyber Kill Chain*:**  
Il sottoinsieme è stato bilanciato per intercettare ogni fase di un attacco, dal primo contatto col server di controllo (C2) fino all'esfiltrazione finale dei dati.

Il sottoinsieme delle metriche selezionate per l'implementazione è il seguente:

1. **Destination reputation** ($M_{rep}$)
2. **Client fingerprinting** ($M_{ja4}$)
3. **TLS Certificate anomalies** ($M_{cert}$)
4. **SNI Evasion** ($M_{sni}$)
5. **Server role detection** ($M_{srv}$)
6. **Non-standard Port/Protocol** ($M_{proto}$)
7. **Internal scanning/Fan-out** ($M_{scan}$)
8. **Asimmetria volumetrica in uscita** ($M_{vol}$)
9. **Connection failure rate** ($M_{fail}$)
10. **ARP Storm** ($M_{arp}$)
  
## 2. Architettura software e integrazione con ntopng  

L'obiettivo del sistema è centralizzare tutta l'analisi all'interno di **ntopng**, trasformandolo nella vera e propria centrale operativa. In questo modo, ntopng non si limita a raccogliere i dati, ma analizza tutte le metriche (sia quelle native che quelle custum) per dare immediatamente il risultato finale.

### 2.1 Archiviazione su ClickHouse  
Il database **ClickHouse** rimane fondamentale. Serve per salvare la memoria storica del sistema, ntopng scrive lì ogni singola connessione e ogni allarme che è scattato. Questo è indispensabile per le metriche custum, perché ci permette di confrontare quello che succede adesso, con quello che è successo negli ultimi 7 giorni. 

La scelta di ClickHouse non è casuale, ma è dettata dalla sua architettura a **database colonnare**. A differenza dei database relazionali tradizionali (che salvano i dati riga per riga), ClickHouse memorizza i dati raggruppandoli per colonna. Questo porta a un'efficienza computazionale adatta per il nostro uso. 
Ad esempio, quando lo script deve calcolare la metrica dell'*asimmetria volumetrica*, non ha bisogno di leggere interi pacchetti di dati dal disco; il sistema andrà a estrarre e sommare solamente la colonna dei byte in uscita. Questo ci permette di analizzare la baseline di un host su una finestra di 7 giorni scansionando milioni di record in una frazione di secondo, senza creare alcun rallentamento sul sistema di monitoraggio.

### 2.2 Integrazione delle metriche in ntopng  
Tutte le 10 metriche si trovano all'interno di ntopng, ma vengono gestite in due modi diversi:

* **Metriche native (8):** sono i controlli che ntopng ha già di serie. Il sistema le usa così come sono, leggendo i risultati che nDPI fornisce in tempo reale.
* **Metriche custum (2):** Per l'**Asimmetria volumetrica** e il **Connection Failure Rate**, andremo a creare dei nuovi controlli all'interno di ntopng. Questi controlli useranno i dati storici salvati su ClickHouse per calcolare lo Z-Score e capire se il traffico attuale è normale oppure se è sospetto.

### 2.3 Ricalibrazione dei punteggi
Un aspetto critico dell'architettura riguarda la gestione e l'assegnazione dei pesi delle anomalie. ntopng utilizza un approccio di calcolo del rischio (*Risk-based scoring approach*) cumulativo e teoricamente illimitato, a ogni evento anomalo viene sommato un punteggio predefinito (es. +210 punti per *Malicious flow detection*), portando l'indicatore di un host compromesso a superare facilmente le migliaia di punti.

Il nostro modello matematico, al contrario, si basa su un indice di rischio diverso, con un limite massimo fissato a 100. Per risolvere questa incompatibilità senza alterare il codice sorgente di ntopng, il sistema delega il calcolo a un motore esterno che esegue una ricalibrazione automatica dei pesi.

Il nostro script interroga ClickHouse e non estrae il valore numerico del punteggio nativo, ma utilizza l'allarme generato da ntopng esclusivamente come interruttore logico. Se l'allarme esiste, la metrica corrispondente viene attivata ($M_i = 1$).
Una volta confermata la presenza dell'anomalia, il motore di calcolo assegna esattamente il peso di penalità definito nella nostra tabella teorica.

### 2.4 Valutazione della sicurezza degli host e della rete  
L'ultima fase del processo riguarda il calcolo dello *Score globale*. Ogni host viene infatti classificato in base al suo livello di rischio, permettendo di individuare immediatamente quali computer presentano comportamenti anomali e di identificare lo stato dell'intera rete.
