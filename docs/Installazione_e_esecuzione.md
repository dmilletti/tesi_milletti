# Guida all'installazione e all'esecuzione degli script

Questo documento descrive tutti i passaggi per replicare l'ambiente di sviluppo e mandare in esecuzione i script delle metriche presentati nei capitoli precedenti. La guida e i comandi sono generalmente validi per qualunque ambiente linux.

L'architettura, illustrata nel capitolo "Implementazione_metriche.md" prevede tre componenti:
1. **ntopng**: la sonda passiva che cattura il traffico di rete e generara gli allarmi nativi.
2. **clickhouse**: il database colonnare che archivia i flussi e gli allarmi prodotti da ntopng.
3. **venv**: ambiente virtuale python contente la libreria `clickhouse-connect` ed esegue i script python che calcolano le metriche di rischio.

## 1. Installazione di ntopng
Per installare la sonda è necessario seguire le istruzioni presenti sul sito ufficiale di ntop, valide per qualunque sistema operativo: https://www.ntop.org/support/documentation/software-installation/

## 2. Installazione di ClickHouse
Allo stesso modo, per l'installazione del database dedicato all'archiviazione dello storico, è necessario seguire le istruzioni presenti nella documentazione ufficiale di ntopng: https://www.ntop.org/guides/ntopng/flow_dump/clickhouse/installation.html

## 3. Setup ambiente python
Tutti i script delle metriche sono scritti in Python3 e dipendono da l'unica libreria chiamata **clickhouse-connect** (v 0.15.1) e per evitare conflitti con pacchetti di sistema l'ambiente viene isolato nell'ambiente virtuale di `venv`.

### 3.1 Installazione di venv e della libreria clickhouse-connect
1. Assicurarsi che l'interprete Python 3 e il gestore di pacchetti `pip` siano installare e aggiornati. Su distribuzioni basate su Debian/Ubuntu, installare il supporto per gli ambienti virtuali digitando nel terminale:

```bash
sudo apt update
sudo apt install python3-pip python3-venv -y
```

2. Dopo essersi posizionati nella directory principale del progetto, eseguire il seguente comando per inizializzare l'ambiente virtuale:

```bash
python3 -m venv venv
```

3. Attivare l'ambiente virtuale:

```bash
source venv/bin/activate
```

4. Con l'ambiente virtuale attivo, procedere con l'installazione della libreria:

```bash
pip install --upgrade pip
pip install clickhouse-connect
```

5.  Per disattivare l'ambiente virtuale, basta eseguire:

```bash
deactivate
```

## 4. Modifica dei parametri di configurazione

All'interno del file di configurazione `config.ini` sono presenti le costanti necessarie alla connessione con il database ClickHouse:

```ini
[clickhouse]
host     = localhost
port     = 8123
database = ntopng
user     = default
password = 0022

```

È necessario adattare questi valori alle specifiche del proprio ambiente per garantire la corretta instaurazione della sessione e prevenire errori di connessione durante l'esecuzione delle metriche. Di norma, l'unico parametro che richiede una variazione è la password di autenticazione.

### 4.1 Configurazione per IP pubblici o file PCAP

Qualora si desidera analizzare file PCAP o reti con indirizzi IP pubblici, è fondamentale aggiornare la configurazione di **ntopng** e del file `config.ini`:

1. **Configurazione di ntopng**: Questa operazione è necessaria per evitare che alcuni host non generino correttamente gli allarmi. Per farlo bisogna accedere al file di configurazione tramite il percorso `/etc/ntopng/ntopng.conf` e specificare le subnet da considerare nell'analisi e modificare la seguente riga:
```bash
-m=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
```

2. **Configurazione di `config.ini`**: Aggiornare parallelamente le reti locali all'interno del file `config.ini` per garantire la correttezza dei risultati restituiti dalle query.

## 5. Abilitazione metriche di ntopng
All'interno del sistema di scoring viene utilizzato il segnale *"Server Port Detected"* fornito direttamente da ntopng. Di default questa metrica è disabilitata; pertanto, per far sì che il rilevamento di nuove porte server funzioni correttamente, è necessario abilitare l'opzione dalla dashboard (UI) di ntopng.

Nello specifico, occorre navigare nel menu `Settings` $\rightarrow$ `Policies` $\rightarrow$ `Behavioural Checks`, inserire *"Server Port Detected"* nella barra di ricerca e attivare il relativo flag.

Inoltre, dato che questo segnale richiede un periodo di apprendimento algoritmico per mappare le abitudini della rete, è possibile personalizzarne la durata dal menu: `Settings` $\rightarrow$ `Behavioural Analysis`, scorrendo la pagina fino alla voce *"Server Port Learning Period"*. Si consiglia di mantenere il valore predefinito proposto dal sistema.

## 6. Esecuzione dello scoring finale e delle metriche singole
Con ntopng in esecuzione, con l'esportazione attiva sul database di ClikHouse e l'ambiente virtuale `venv` abilitato, è possibile testare i **singoli script** Python lanciando da terminale il relativo comando:

```bash
python nome_script.py
```

Questo comando avvia l'analisi basata sulla finestra temporale di default (1 ora). Se si desidera personalizzare l'arco temporale di osservazione, la metriche supportano un argomento da riga di comando:

```bash
python nome_script.py --finestra-minuti <numero_minuti>
```
 
**NOTA IMPORTANTE**:  
La metrica *m_vol* e *m_fail* non supportano finestre temporali dinamiche da CLI, questo perché lavorano su bucket orari di un'ora. 

### 6.1 Esecuzione dello scoring finale
Per eseguire il calcolo dello scoring finale, dopo aver soddisfatto i requisiti preliminari descritti nel paragrafo 5, è sufficiente avviare lo script dedicato digitando nel terminale il seguente comando:

```bash
python scoring.py
```

### 6.2 Esecuzione degli script di "test"
Per eseguire gli script di validazione delle metriche statistiche ($M_{vol}​$ e $M_{fail}$​), oltre ai requisiti descritti nel paragrafo 5, è necessario configurare un utente dedicato con privilegi di scrittura sul database ClickHouse. Questo isolamento garantisce che i test end-to-end possano generare e distruggere le tabelle temporanee senza interferire con i flussi di produzione.

Dopo aver effettuato l'accesso alla CLI tramite clickhouse-client, è possibile creare l'utente ed assegnargli i permessi necessari eseguendo i seguenti comandi:

```sql
CREATE USER IF NOT EXISTS tester 
IDENTIFIED WITH plaintext_password BY 'test_password' 
HOST LOCAL 
SETTINGS readonly = 0;

GRANT ALL ON ntopng.* TO tester;
```

Una volta completata la configurazione del database, i singoli script di test automatizzati possono essere lanciati direttamente dal terminale posizionandosi nella cartella del progetto ed eseguendo il comando:

```bash
python nome_script.py
```

