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

Prima di passare all'implementazione vera e propria delle metriche, andiamo a vedere alcuni scenari dove dimostriamo che le metriche scelte sono ideali per coprire la maggior parte dello specchio delle anomalie di rete.

### Scenario 1: Attacco ransomware e lateral movements

Immaginiamo che un dipendente riceva un'email di phishing e clicchi su un link malevolo, provocando involontariamente lo scaricamento di un malware sul proprio PC. Il malware non cifra subito i dati, ma prima cerca di capire dove si trova e se può infettare altri computer nella rete aziendale per massimizzare il danno.

Come le nostre metriche rilevano l'attacco:

1.  **Fase di Contatto (C&C):** Il malware prova a collegarsi al server dell'hacker per ricevere istruzioni. 
    * **$M_{rep}$ (Destination reputation):** Scatta subito se l'IP di destinazione è già noto nelle blacklist.
    * **$M_{cert}$ (TLS certificate anomalies):** Se l'hacker usa un server con un certificato auto-firmato per risparmiare, la metrica lo segnala immediatamente.
2.  **Fase di esplorazione (Reconnaissance):** Il malware inizia a scansionare la rete locale per trovare server con dati sensibili.
    * **$M_{arp}$ (ARP Storm):** Il PC infetto invia tante richieste ARP per mappare tutti i dispositivi fisici vicini. È un comportamento tipico dei ransomware che ntopng rileva immediatamente.
    * **$M_{scan}$ (Internal scanning):** Una volta individuati gli IP, il malware scansiona le porte. La nostra metrica rileva l'alto numero di connessioni verso host interni diversi (Fan out).
3.  **Fase di Preparazione:** Il malware apre una *Backdoor* per permettere all'hacker di entrare nel sistema.
    * **$M_{srv}$ (Server Role):** Il PC del dipendente, che è sempre stato un semplice client, inizia improvvisamente ad accettare connessioni dall'esterno. ntopng rileva l'inversione di ruolo e fa scattare l'allarme.

Quindi anche se il malware cercasse di mimetizzarsi, la combinazione di queste 5 metriche porterebbe lo **Score globale** a 100 in pochi minuti, permettendo all'amministratore di isolare il PC prima che inizi la cifratura dei file.

### Scenario 2: Esfiltrazione e tunneling

Immaginiamo un utente malintenzionato che ha già guadagnato l'accesso a un server interno. Il suo obiettivo è rubare l'intero database clienti, ma sa bene che un trasferimento di massa su porte non autorizzate farebbe scattare subito l'allarme. Per questo motivo, cerca di nascondere le proprie tracce mascherando il furto. Incapsula i dati in un tunnel cifrato (es. SSH) e lo fa passare sulla porta 443, sperando che il firewall lo scambi per normale traffico HTTPS verso un sito web innocuo.

Come le nostre metriche smascherano l'attacco:

1.  **Fase di evasione (Offuscamento del traffico):** L'attaccante cerca di aggirare i controlli perimetrali.
    * **$M_{sni}$ (SNI Evasion):** Per evitare di dover registrare un dominio falso (che potrebbe finire in *blacklist*), l'attaccante configura il suo strumento per contattare il server remoto direttamente tramite indirizzo IP. Il motore nDPI analizza l'handshake crittografico iniziale, nota che il campo testuale del dominio (SNI) è completamente assente e fa scattare l'allarme di evasione.
    * **$M_{proto}$ (Non-standard Port/Protocol):** Il firewall perimetrale vede traffico sulla porta 443 e lo lascia passare credendolo traffico web (HTTPS). Tuttavia, la *Deep Packet Inspection* di nDPI analizza il pacchetto e riconosce la firma di un protocollo remoto (es. SSH o RDP) nascosto al suo interno, segnalando immediatamente l'anomalia strutturale.
2.  **Fase di esfiltrazione :** L'attaccante avvia il trasferimento del database compresso verso l'esterno.
    * **$M_{vol}$ (Asimmetria volumetrica):** L'host monitorato ha uno storico settimanale (*baseline*) in cui scarica molti dati e ne carica pochissimi. Improvvisamente, il rapporto si inverte, inizia a inviare svariati gigabyte verso l'esterno in una sola ora. Lo script statistico interroga **ClickHouse**, calcola la deviazione standard ($Z_{robusto}$) e, rilevando uno scostamento eccezionale dalla mediana storica, attiva la metrica di esfiltrazione.

In questo scenario, non c'è nessun malware rumoroso. Nonostante ciò, il tentativo di nascondersi ha generato due anomalie specifiche. Il motore di scoring riceve l'allerta da nDPI (SNI Evasion) e da ClickHouse (Asimmetria volumetrica), portando l'host in zona di allerta.

### Scenario 3: Botnet e DGA (Domain generation algorithms)

Immaginiamo che un computer aziendale è stato silenziato e inglobato in una *Botnet*. Per ricevere i comandi dall'hacker senza farsi bloccare dalle liste nere dei firewall tradizionali, il malware utilizza un algoritmo DGA. Genera centinaia di domini casuali al minuto (es. `xkjdfgh.com`, `qweerty.net`) e tenta di contattarli tutti in sequenza, sapendo che l'hacker ne ha registrato e attivato solo uno. 

Come le nostre metriche scoprono l'attacco:

1.  **Fase di ricerca (Punto debole del DGA):** Il malware inizia a interrogare i server DNS e a tentare connessioni verso domini inventati.
    * **$M_{fail}$ (Connection failure rate):** Poiché quasi tutti i domini generati non esistono, il server DNS risponderà continuamente con errori `NXDOMAIN`, o i pacchetti andranno in Timeout/RST. La nostra metrica statistica interroga **ClickHouse** e nota che il tasso di fallimento delle connessioni di quell'host, storicamente fermo al 2%, è improvvisamente schizzato al 95%. L'elevato Z-Score fa scattare l'allarme. Questa metrica ci permette di rilevare il DGA a costo quasi nullo, senza dover calcolare pesanti indici di entropia testuale sulle singole stringhe DNS.
2.  **Fase di identificazione (Fingerprinting):** Nonostante i fallimenti, il malware tenta di usare il protocollo HTTPS per nascondere il contenuto delle sue richieste.
    * **$M_{ja4}$ (Client Fingerprinting):** Indipendentemente da quale dominio casuale il malware stia cercando di contattare, **nDPI** intercetta il *TLS Client Hello* e calcola il fingerprinting del software che sta generando il traffico. Questa impronta JA4 viene confrontata con il nostro database e risulta appartenere a una nota botnet. 

L'unione di un'anomalia puramente statistica (Connection failure rate) e di una firma (Client fingerprinting) certifica la compromissione. Lo *Score* dell'host raggiunge il livello critico e l'amministratore riceve la segnalazione.

---
  
## 2. Architettura software e integrazione con ntopng  

L'obiettivo del sistema è centralizzare tutta l'analisi all'interno di **ntopng**, trasformandolo nella vera e propria centrale operativa. In questo modo, ntopng non si limita a raccogliere i dati, ma analizza tutte le metriche (sia quelle native che quelle custum) per dare immediatamente il risultato finale.

### 2.1 Archiviazione su ClickHouse  
Il database **ClickHouse** rimane fondamentale. Serve per salvare la memoria storica del sistema, ntopng scrive lì ogni singola connessione e ogni allarme che è scattato. Questo è indispensabile per le metriche custum, perché ci permette di confrontare quello che succede adesso, con quello che è successo negli ultimi 7 giorni. 

La scelta di ClickHouse non è casuale, ma è dettata dalla sua architettura a **database colonnare**. A differenza dei database relazionali tradizionali (che salvano i dati riga per riga), ClickHouse memorizza i dati raggruppandoli per colonna. Questo porta a un'efficienza computazionale adatta per il nostro uso. 
Ad esempio, quando lo script deve calcolare la metrica dell'*asimmetria volumetrica*, non ha bisogno di leggere interi pacchetti di dati dal disco; il sistema andrà a estrarre e sommare solamente la colonna dei byte in uscita. Questo ci permette di analizzare la baseline di un host su una finestra di 7 giorni scansionando milioni di record in una frazione di secondo, senza creare alcun rallentamento sul sistema di monitoraggio.

### 2.2 Integrazione delle metriche in ntopng  
Tutte le 10 metriche si trovano all'interno di ntopng, ma vengono gestite in due modi diversi:

* **Metriche native (7):** sono i controlli che ntopng ha già di serie. Il sistema le usa così come sono, leggendo i risultati che nDPI fornisce in tempo reale.
* **Metriche custum (3):** Per l'**Asimmetria volumetrica**, **Connection failure rate** e **ARP Storm**, andremo a creare dei nuovi controlli all'interno di ntopng. Questi controlli useranno i dati storici salvati su ClickHouse per calcolare lo Z-Score e capire se il traffico attuale è normale oppure se è sospetto.

### 2.3 Ricalibrazione dei punteggi
Un aspetto critico dell'architettura riguarda la gestione e l'assegnazione dei pesi delle anomalie. ntopng utilizza un approccio di calcolo del rischio (*Risk-based scoring approach*) cumulativo e teoricamente illimitato, a ogni evento anomalo viene sommato un punteggio predefinito (es. +210 punti per *Malicious flow detection*), portando l'indicatore di un host compromesso a superare facilmente le migliaia di punti.

Il nostro modello matematico, al contrario, si basa su un indice di rischio diverso, con un limite massimo fissato a 100. Per risolvere questa incompatibilità senza alterare il codice sorgente di ntopng, il sistema delega il calcolo a un motore esterno che esegue una ricalibrazione automatica dei pesi.

Il nostro script interroga ClickHouse e non estrae il valore numerico del punteggio nativo, ma utilizza l'allarme generato da ntopng esclusivamente come interruttore logico. Se l'allarme esiste, la metrica corrispondente viene attivata ($M_i = 1$).
Una volta confermata la presenza dell'anomalia, il motore di calcolo assegna esattamente il peso di penalità definito nella nostra tabella teorica.

### 2.4 Valutazione della sicurezza degli host e della rete  
L'ultima fase del processo riguarda il calcolo dello *Score globale*. Ogni host viene infatti classificato in base al suo livello di rischio, permettendo di individuare immediatamente quali computer hanno comportamenti anomali e di identificare lo stato dell'intera rete.
