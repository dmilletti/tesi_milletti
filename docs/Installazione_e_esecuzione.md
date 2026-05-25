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

## 4. Modifica dei parametri di configurazione di clickhouse
All'interno di ogni singolo script, sono presenti le costanti di configurazione per la connessione al database di ClickHouse:

```bash
# Parametri di connessione a ClickHouse
CLICKHOUSE_HOST     = "localhost"
CLICKHOUSE_PORT     = 8123
CLICKHOUSE_DATABASE = "ntopng"
CLICKHOUSE_USER     = "default"
CLICKHOUSE_PASSWORD = "0022"
```

È necessario modificare tali valori e adattarli alle specifiche del proprio ambiente per garantire la corretta instaurazione della sessione e prevenire errori di connessione durante l'esecuzione delle metriche. Di norma, l'unico parametro che richiede una variazione è la password di autenticazione.

## 5. Esecuzione degli script delle metriche
Con ntopng in esecuzione, con l'esportazione attiva sul database di ClikHouse e l'ambiente virtuale `venv` abilitato, è possibile l'esecuzione dei singoli script Python lanciando da terminale il relativo comando:

```bash
python nome_script.py
```
