# Da una mini camera Wi-Fi al video nel browser

*Diario di reverse engineering della HK6 con chip Beken BK7252 — ottobre 2026*

Una piccola camera Wi-Fi, un’app Android obbligatoria e una domanda: possiamo usarla in locale, controllando meglio cosa fa e senza dipendere dal software del produttore?

Il progetto è partito da qui. Attraverso analisi dell’app, collegamenti seriali, modifiche al firmware e una Web UI, siamo arrivati a un primo risultato concreto: il video servito direttamente dalla camera a un browser. Il percorso, però, è stato più interessante del solo risultato finale.

## 1. Prima di scrivere: capire cosa avevamo davanti

La scheda era una **HK6**, basata sul **Beken BK7252UQN48**, con microfono e slot microSD. Il software di riferimento era HDWifiCamPro. Non bastava riconoscere il chip: camere dall’aspetto quasi identico possono montare sensori, memorie e firmware differenti.

Abbiamo cominciato dall’analisi dell’app Android e di un aggiornamento firmware richiamato dal suo codice. Sono emersi comandi JSON per video, Wi-Fi e impostazioni, trasportati da una pila proprietaria PPPP/CS2. Quei comandi non erano normali API HTTP: conoscere il loro nome non era sufficiente per parlare con la camera.

Abbiamo anche preparato una build sperimentale, LocalCam, partendo dall’SDK e dai riferimenti OpenCam. Compilava, ma le differenze rispetto alla scheda reale rendevano prematuro installarla. La scelta successiva è stata lavorare sul firmware originale, conservando i driver già funzionanti.

## 2. La seriale: dal sospetto alla misura

Il primo salto di qualità è arrivato con un adattatore USB-seriale e l’identificazione delle piazzole UART. A 115200 baud la camera ha iniziato a raccontare il proprio avvio: **RT-Thread 3.1.0**, inizializzazione delle periferiche e sensore **HI704**. Una lettura del registro identificativo ha poi confermato il sensore.

Dalla console abbiamo ricostruito le partizioni e acquisito un backup completo dell’area flash da **2 MiB**. È stato necessario distinguere gli indirizzi logici da quelli fisici: alcune zone inseriscono due byte CRC ogni 32 byte di dati. Ignorare questo dettaglio avrebbe reso sbagliati indirizzi e immagini di ripristino.

Prima degli aggiornamenti abbiamo verificato anche l’accesso al bootloader e un ciclo di cancellazione, scrittura e ripristino di un settore. Una prova circoscritta, utile per ridurre l’incertezza: il ripristino completo dell’applicazione via UART resta una verifica distinta.

## 3. Rendere locale il firmware originale

La prima patch, EXP1, modificava appena sette byte e interveniva su alcuni percorsi di connessione esterna. L’aggiornamento è passato attraverso il meccanismo HTTP OTA già presente nella camera, usando un server locale. Dopo il riavvio abbiamo riletto dalla flash i punti modificati e verificato il video nell’app vendor, anche su una rete senza Internet.

Una cattura di rete ha però mostrato tentativi residui verso servizi esterni. Era una lezione importante: togliere una chiamata o una stringa dal firmware non dimostra che tutti i percorsi di rete siano stati eliminati.

Le revisioni successive hanno introdotto un filtro di uscita orientato alla LAN, con eccezioni controllate per la sincronizzazione dell’ora. Abbiamo corretto anche un problema con i pacchetti NTP suddivisi in più buffer e uniformato l’orologio a **Europe/Rome**, comprese le regole dell’ora legale applicate alla sincronizzazione.

Ogni passaggio aveva hash, confronto delle modifiche, prove sul codice ARM e controlli del pacchetto OTA. L’obiettivo era mantenere piccole e verificabili le modifiche al firmware funzionante.

## 4. Il primo video senza HDWifiCamPro

A quel punto abbiamo aperto il fronte applicativo, nella cartella `app/`: un servizio Python sul Mac avrebbe parlato il protocollo della camera e reso il video accessibile al browser.

È stato necessario gestire handshake, frammentazione UDP, riordino, duplicati e conferme dei pacchetti. Anche il JPEG aveva una particolarità: cinque byte aggiunti dall’SDK dopo l’immagine, da riconoscere e rimuovere.

Il primo fotogramma reale misurava **640×352 pixel**. Il video funzionava, ma non corrispondeva alla risoluzione VGA indicata nei log. Abbiamo quindi evitato di fidarci delle etichette: contavano le dimensioni del JPEG ricevuto.

Le successive patch EXP2E ed EXP2F hanno portato i due profili a **640×480** e **320×240**. Nel servizio abbiamo inoltre aggiunto la riconnessione automatica: dopo uno spegnimento della camera, un vecchio contatore di frame non doveva più far sembrare attivo uno stream fermo.

## 5. Dal visualizzatore alla Web UI

La pagina sul Mac è diventata un piccolo pannello di controllo: video live, snapshot, profili con risoluzione esplicita e stato della connessione. Abbiamo aggiunto lettura dei parametri, controlli immagine disponibili, scansione delle reti e configurazione Wi-Fi.

Il criterio è rimasto lo stesso: una risposta positiva al comando non basta sempre a dimostrare che l’impostazione sia stata applicata. Dove possibile, il servizio rilegge il valore; un timeout rimane un esito incerto, soprattutto quando un cambio rete può interrompere la connessione.

Il microfono ha aggiunto un altro percorso: audio ADPCM dalla camera, decodifica in PCM e ascolto dal browser con un toggle. Sono arrivati anche sincronizzazione dell’orologio e riavvio del dispositivo.

Questa Web UI completa dipende ancora dal servizio locale sul Mac. Ha permesso di esplorare e utilizzare la camera senza dover riscrivere subito tutta l’applicazione nel firmware.

## 6. La microSD: registrare era solo metà del problema

Con una microSD FAT32 da 2 GB abbiamo provato registrazione continua, eventi di movimento e consultazione dell’archivio. La Web UI ha acquisito stato e spazio della scheda, impostazioni degli eventi, ricerca dei filmati, player ed esportazione AVI.

Qui sono emersi due problemi concreti. Il player poteva fallire perché non trovava circa 40 KiB contigui: abbassare temporaneamente il live a QVGA ha consentito la riproduzione in alcune prove, mentre la registrazione concorrente restava un fattore critico.

Gli eventi, invece, venivano davvero salvati, ma non comparivano nell’elenco. La seriale ha svelato il motivo: il registratore produceva nomi con trattini che il filtro dell’archivio escludeva; anche il player si aspettava un formato diverso. Allungare le clip non risolveva il problema.

Abbiamo verificato playback, pausa, ripresa e ricezione dell’audio registrato. L’export AVI ricostruisce il video ricevuto, senza audio: non è il download del file originale. Cancellazione selettiva, download originale e correzione dell’archivio eventi restano da implementare.

## 7. Togliere il Mac dal percorso video

La domanda successiva era naturale: possiamo aprire l’IP della camera dallo smartphone e vedere il video?

Prima di intervenire abbiamo studiato memoria, acquisizione JPEG e API di rete del firmware. Abbiamo valutato anche WebSocket e altri trasporti. Non è emersa una capacità H.264 utilizzabile e verificata sul sensore montato; **MJPEG su HTTP** era il primo percorso concreto verso il browser.

L’estensione HTTP1 riusa i JPEG prodotti dal firmware e aggiunge pagina, snapshot e stream. Il buffer video viene allocato nell’heap principale durante la sessione; acquisizione e invio sono separati, così un client lento non deve bloccare il produttore.

Dopo le prove sul computer e sul codice ARM, abbiamo confezionato e installato l’OTA. Il collaudo reale ha restituito **363 fotogrammi validi a 640×480 in due minuti**, circa **3 fps**. Sono riuscite anche sei riconnessioni e il recupero dopo una richiesta HTTP incompleta.

## 8. Dove siamo arrivati

Oggi esistono due modalità d’uso: la **Web UI sul Mac**, più ricca di impostazioni e funzioni di archivio, e il **server HTTP sulla camera**, che consente il video diretto senza tenere acceso il computer.

HTTP1 è una prima versione: un solo spettatore, video senza audio e riconnessione manuale. Restano da collaudare Chrome Android, funzionamento prolungato e convivenza con le registrazioni su microSD. Il server è pensato per la rete locale e non dispone ancora di autenticazione applicativa o TLS.

Il risultato più utile del progetto è aver reso osservabile un dispositivo inizialmente opaco. Log seriali, catture di rete e misure dei fotogrammi hanno spesso corretto le nostre ipotesi: la risoluzione dichiarata, gli eventi “scomparsi”, i comandi accettati senza immagini. Sono state proprio queste verifiche a trasformare una serie di esperimenti in un sistema utilizzabile e documentato.

---

*Nota editoriale: questo articolo riassume lo stato del progetto al 23 ottobre 2026. Procedure, sorgenti e risultati dettagliati sono conservati nella documentazione tecnica del progetto.*
