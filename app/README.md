# Applicazione locale HK6

Client Python 3.10+ per video, impostazioni e registrazioni della HK6/BK7252. Il servizio usa la libreria standard e converte il protocollo UDP proprietario in una Web UI locale. La password viene richiesta con `getpass`, senza argomenti CLI o salvataggio su disco.

```sh
python3 app/main.py --camera 192.168.1.54
```

IP d'esempio: usare quello della propria camera. Stessa LAN del computer, app vendor chiusa. Aprire **http://127.0.0.1:8765/**. `Ctrl+C` chiude la sessione.

| Scheda | Funzioni e limiti |
| --- | --- |
| Video | MJPEG, snapshot, dimensioni JPEG osservate, profili VGA/QVGA, audio live on/off |
| Immagine | Orientamento, infrarossi e indicatore solo quando esposti dai parametri letti |
| Wi-Fi | Rete configurata, scansione e cambio rete con riepilogo della disconnessione prevista |
| Registrazioni | Stato microSD, modalità spenta/continua/evento, sensibilità e durata, ricerca per data/ora, player, pausa, audio, export AVI |
| Dispositivo | Parametri dichiarati, sincronizzazione orologio e riavvio con conferma |

## Stato verificato

Primo JPEG e browser funzionanti dal 19 ottobre 2026. Il vecchio firmware trasmetteva 640×352; EXP2E/F hanno corretto l'encoder a **640×480 / 320×240**. Le etichette dei profili indicano la richiesta; la UI mostra separatamente le dimensioni ricevute.

Il microfono trasmette ADPCM, decodificato in PCM mono 8 kHz. L'ascolto richiede un clic, mantiene una coda breve e si disabilita dopo disconnessione o abbandono del player. Qualità percepita e sincronismo A/V non sono certificati.

Letture parametri, Wi-Fi e scansione sono state verificate. Cambio rete e alcune scritture immagine restano sperimentali: dopo un comando si cerca una rilettura, mentre un timeout rimane un esito non verificato. Nessuna modifica Wi-Fi viene ripetuta automaticamente dopo la riconnessione.

MicroSD FAT32 da 2 GB riconosciuta; playback di filmati continui, export AVI, pausa/ripresa e ricezione audio verificati. **Prima del playback impostare registrazione Spenta.** Il servizio riduce temporaneamente il live a QVGA, attende un JPEG effettivo e ripristina il profilo allo stop. Memoria contigua insufficiente può richiedere un riavvio.

I file evento vengono scritti, ma il firmware stock li esclude dall'elenco per un'incompatibilità nel formato dei nomi. Cancellazione selettiva, seek e download originale non sono implementati. L'AVI esportato ricostruisce i frame ricevuti, senza audio e con temporizzazione stimata, massimo 32 MiB o 1800 frame. [Diagnosi microSD](analysis/microsd.md).

## Endpoint e riconnessione

- `/`: Web UI.
- `/stream.mjpg`: live MJPEG.
- `/snapshot.jpg`: frame recente, oppure 503.
- `/status`: stato, contatori, età del frame e ultimo errore.
- `/api/state`, POST `/api/action`: stato e azioni con token di sessione e controllo Origin.

Il servizio ascolta solo sul loopback e non consente l'accesso da smartphone. Dopo errori ricrea la sessione UDP con attesa crescente, fino a 15 secondi. Un cambio IP DHCP richiede di aggiornare l'indirizzo; non effettua una scansione della rete. Una sessione camera alimenta i client HTTP e i client lenti saltano frame.

```sh
python3 app/main.py --camera 192.168.1.54 --snapshot /tmp/hk6-first.jpg
PYTHONPATH=app python3 -m unittest discover -s app/tests -v
```

## Server HTTP sulla camera

HTTP1 è un'estensione firmware distinta: serve una pagina minima e video direttamente sull'IP della camera, senza computer. Non include tutte le impostazioni di questa applicazione. [Risultati](../docs/collaudo-http1.md) e [implementazione](../firmware/stock-http/README.md).

[Protocollo e fonti](PROTOCOL.md) · [Orologio e player](analysis/web-extensions.md) · [Studio HTTP](analysis/firmware-http-feasibility.md)

I riferimenti a `analysis/` alla radice e ai report grezzi descrivono artefatti privati di laboratorio, esclusi dal repository. I risultati pubblici sono riassunti nella documentazione.
