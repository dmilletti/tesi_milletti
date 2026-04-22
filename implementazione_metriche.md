# Implementazione delle metriche
Questo documento descrive come implementare un sottoinsieme delle metriche proposte, sono state selezionate in modo da coprire la maggior parte dello specchio delle anomalie di rete. 

### Metrica 1: Destination reputation ($M_{rep}$)

**1. Il modello matematico**
La logica di questa metrica deterministica si basa sulla teoria degli insiemi:
$$d \in \mathcal{B} \lor q \in \mathcal{B} \implies M_{rep} = 1$$
Dove $d$ rappresenta l'indirizzo IP di destinazione della connessione, $q$ il dominio interrogato a livello applicativo e $\mathcal{B}$ l'insieme dinamico degli indicatori di compromissione (IoC), ovvero le *blacklist* di domini e IP noti per essere malevoli.

**2. Il motore di estrazione e rilevamento in tempo reale (nDPI)**
L'estrazione dei parametri e l'appertenenza ai domini malevoli in tempo reale avvengono tramite **nDPI**, il motore di *Deep Packet Inspection* integrato in ntopng. Poiché il sistema deve analizzare il traffico in modo istantaneo (*wire-speed*), nDPI utilizza algoritmi avanzati di *pattern matching*:

* **Valutazione dell'indirizzo IP ($d \in \mathcal{B}$):**
    Il sistema legge l'indirizzo IP di destinazione direttamente dall'intestazione del pacchetto (L3). Per verificare istantaneamente se questo IP è presente in una lista di indirizzi malevoli, nDPI utilizza strutture dati come **Patricia Trie** o **Radix Tree**. Questa struttura dati ad albero permette di cercare l'IP, garantendo tempi di ricerca in $O(k)$, dove $k$ è la lunghezza dell'indirizzo indipendente dalla dimensione totale della *blacklist*.

* **Valutazione del nome a dominio ($q \in \mathcal{B}$):**
    Se la connessione è in chiaro (DNS sulla porta 53), nDPI isola il campo testo interrogato. Se la connessione è cifrata (HTTPS), nDPI intercetta il primo pacchetto inviato dal client (*TLS Client hello*) ed estrae l'estensione **SNI (Server Name Indication)**, ricavando il nome del server prima che la cifratura venga applicata al canale.
    Per confrontare in tempo reale queste stringhe con le *blacklist* di domini (algoritmi DGA, phishing, server C2), nDPI utilizza l'algoritmo di **Aho-corasick**. Si tratta di un algoritmo basato su un'automa a stati finiti che permette di cercare più stringhe simultaneamente all'interno del pacchetto, leggendo il payload di rete una sola volta. Questo garantisce che la "Deep Packet Inspection" (DPI) non crei colli di bottiglia o rallentamenti sulla rete.

**3. Implementazione operativa e dello storico (ClickHouse)**
I risultati di questa ispezione in tempo reale vengono salvati all'interno del database colonnare **ClickHouse** e poi analizzati ed estratti facendo delle query.
