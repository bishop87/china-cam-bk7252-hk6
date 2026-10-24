# Streaming HTTP nel firmware HK6: studio di fattibilità

Data: 23 ottobre 2026. Analisi statica e verifica host; nessuna modifica al firmware, OTA, riavvio o modifica della configurazione della camera.

## Esito

**Fattibile come architettura; fattibilità dell'integrazione in EXP2F ancora condizionata a RAM e aggancio del produttore JPEG.** Non è una funzione attivabile con un comando noto. Serve codice firmware aggiuntivo. La strada consigliata è estendere EXP2F, conservando sensore, configurazione Wi-Fi, registratore SD e restrizioni di rete già collaudati.

Obiettivo iniziale: smartphone nella stessa LAN, apertura di `http://IP_CAMERA/`, pagina minima con `<img src="/stream.mjpg">`, un solo spettatore, solo video. Il Mac non partecipa al percorso dei dati. Il router deve consentire comunicazioni tra client; isolamento Wi-Fi o rete ospiti possono impedirle. IP ottenuto via DHCP: una prenotazione sul router evita cambiamenti.

## Evidenze e loro limiti

| Evidenza locale | Implicazione | Limite |
| --- | --- | --- |
| EXP2F produce JPEG VGA 640×480 e QVGA 320×240; `tools/build_exp2f_candidate.py` verifica configurazione encoder e dispatcher | Nessuna ricodifica video necessaria | Frequenza e dimensione massima dei JPEG HTTP da misurare |
| `firmware/localcam/localcam.c` contiene server HTTP, snapshot e MJPEG | Esiste un riferimento riusabile per framing e parsing | È il firmware alternativo, non codice installato in EXP2F |
| `upstream/sdk/beken378/old_app/video_work/video_buffer.c` usa un unico `g_vbuf`, callback e semaforo | Disponibile un modello di acquisizione JPEG | Non prova ABI o indirizzi equivalenti nello stock; non è un'API multi-consumatore |
| `firmware/stock-exp2/egress.c` ammette TCP verso la stessa subnet | Risposte HTTP LAN compatibili con la logica del filtro | Va verificato sul nuovo binario; non autorizza altre subnet/VPN |
| Player stock: errore reale `vidBuf malloc failed` per 40.960 byte contigui, documentato in `web-extensions.md` | Memoria e frammentazione sono rischi concreti | Non è una misura dell'heap libero attuale |
| Patch EXP2B aggiunge codice senza `.data`/`.bss`, EXP2F eredita le patch | Esiste una procedura di estensione del binario | Un server necessita stato, stack e socket: molto più complesso della patch orologio |

Il payload EXP2F registrato nel manifest è 827.255 byte, SHA-256 `981d33db1b1af8b94bdcfc98e369214b312a2f4d00b82aacdcbc0a962f50ea5d`. Il packager EXP2 verifica payload+96 <= 0x110000 e contenitore <= 0xcc000. Il margine aritmetico sul primo limite è 286.761 byte: indica spazio potenziale per codice, **non RAM disponibile né garanzia di caricabilità del nuovo binario**. Layout effettivo, metadati, compressione e recupero andranno riconfermati per ogni candidato.

## Browser e formato

HTTP MJPEG trasporta JPEG successivi con `multipart/x-mixed-replace; boundary=...`; ciascuna parte indica `Content-Type: image/jpeg` e la lunghezza. La pagina HTML incorpora il flusso come immagine, senza player proprietario o JavaScript obbligatorio. La documentazione primaria [Chromium](https://issues.chromium.org/issues/40337476) distingue immagini multipart da risorse principali: non assumere che la navigazione diretta a `/stream.mjpg` funzioni come la pagina con `<img>`. Il [registro HTML del MIME](https://html.spec.whatwg.org/multipage/iana.html#multipart/x-mixed-replace) descrive il formato. Compatibilità da collaudare sul Chrome Android effettivo.

La pagina deve essere servita dalla camera stessa via HTTP: nessun sito HTTPS esterno necessario. MJPEG non porta audio; audio sincronizzato, WebRTC, HLS e transcodifica restano fuori dal primo obiettivo. Non sono necessari per vedere i JPEG già disponibili.

## Alternative

1. **Estensione stock EXP2F — preferita.** Riusare rete e acquisizione native; aggiungere listener HTTP e consegna JPEG. Conserva il lavoro hardware verificato, ma richiede reverse engineering degli ingressi RTOS/socket e proprietà dei buffer.
2. **LocalCam completo — alternativa più invasiva.** Server già scritto, sorgenti SDK disponibili e build storica completata; restano integrazione della board, layout, inizializzazione sensore e regressioni. Il prototipo non conserva automaticamente registrazione, comandi e gestione Wi-Fi dello stock.
3. **PPPP sul browser — non sufficiente.** Una normale pagina non dispone del socket UDP arbitrario richiesto dal protocollo. Un ponte esterno risolve ma contraddice l'obiettivo di eliminare il Mac e altri servizi locali.

## Disegno proposto per EXP2F

- Avvio del listener dopo inizializzazione della rete, senza cambiare credenziali o modalità Wi-Fi. Porta 80 solo dopo averne verificato la disponibilità.
- Tre route: `/` (pagina), `/snapshot.jpg` (diagnostica), `/stream.mjpg` (video). Eventuale stato minimale senza dati sensibili.
- Un worker HTTP, parser e header limitati, scritture parziali gestite, timeout di invio/ricezione e scadenza totale della richiesta. Limite esplicito a un video client; un secondo client deve ricevere rifiuto finito, non restare appeso.
- Prelievo del frame completo a un punto verificato del produttore stock. Non inviare TCP da interrupt/callback di acquisizione. Non chiamare alla cieca `video_buffer_open` mentre lo stock gestisce il sensore.
- Prima opzione: un buffer JPEG posseduto dal server, con protocollo di consegna che impedisca sovrascritture mentre viene inviato. Se occupato, scartare i nuovi frame. Nessuna coda crescente. Riutilizzo diretto dei buffer vendor solo dopo averne provato vita e sincronizzazione.
- Client lento/disconnesso: rilascio tempestivo di socket e buffer, nessun blocco della registrazione o del watchdog. Avvio video senza sessione HDWifiCamPro da verificare: non basta intercettare i JPEG quando una sessione vendor è già attiva.
- Primo collaudo con registrazione esplicitamente spenta e senza PPPP concorrente. La convivenza con registrazione su movimento è un secondo criterio separato, non una promessa iniziale.

## Budget preliminare

LocalCam alloca 48 KiB per un JPEG e uno stack da 4 KiB: almeno 52 KiB nominali, oltre a stato RTOS, TCP/pbuf, Wi-Fi, buffer encoder e allocazioni già presenti. È un riferimento di costo, non una configurazione approvata per lo stock. Due buffer da 48 KiB richiederebbero già 96 KiB solo per JPEG: evitarli come scelta predefinita.

Misurare heap libero, minimo storico, massimo blocco contiguo e stack disponibile: prima del video, durante VGA/QVGA, durante evento SD e dopo ripetute connessioni. Non dedurre la RAM dal solo BSS del firmware alternativo. Un frame che supera il limite va scartato intero e contato; non troncato né interpretato come JPEG valido.

Esempi di banda, **non misure della camera**: JPEG medio 20 KiB a 5 fps ≈ 0,82 Mbit/s; 40 KiB a 10 fps ≈ 3,28 Mbit/s, più overhead. Primo target QVGA a 3–5 fps per validare l'integrazione, poi VGA 640×480 a 5 fps; frequenza finale subordinata alle misure. Il prototipo LocalCam limita gli invii a circa 10/s ma non prova questa prestazione sulla board.

## Criticità del prototipo esistente

Il test host passa ma non rende LocalCam pronto da installare. Il server è sequenziale: durante uno stream non serve altri client. Il buffer da 48 KiB non è dimensionato da una distribuzione misurata dei JPEG. Non ha autenticazione HTTP. Lo SDK restituisce anche zero in alcuni fallimenti di `video_buffer_open`; quindi il solo esito zero non garantisce inizializzazione riuscita. `prepare_build.py` limita l'attesa acquisizione a 2000 ms, ma non risolve tutte le questioni di proprietà buffer e concorrenza stock.

Per l'uso LAN, decidere una protezione applicativa prima della distribuzione: senza login chi raggiunge l'IP può vedere la camera. HTTP Basic non cifra password o video; TLS richiede una valutazione RAM separata. Nessuna apertura porte router o accesso Internet prevista nello studio.

## Passi e criteri prima dell'implementazione hardware

1. Mappare nello stock: startup adatto, create/start thread, alloc/free, socket/bind/listen/accept/send/close/timeout, produttore JPEG e avvio/arresto senza PPPP. Verificare ABI e interworking ARM/Thumb; i simboli SDK sono indizi, non indirizzi utilizzabili automaticamente.
2. Definire allocazione dello stato persistente: non introdurre BSS in appendice senza inizializzazione e spazio RAM riservato. Verificare hook con hash, disassemblato ed emulazione delle chiamate modellabili.
3. Misurare memoria e JPEG sul dispositivo. Se manca margine, ridurre profilo/fps o rendere HTTP esclusivo rispetto ad archivio/PPPP. Se anche la modalità esclusiva non ha margine, riconsiderare LocalCam.
4. Solo dopo questi riscontri preparare candidato e recupero verificabile. Progressione: risposta HTTP statica, snapshot, stream QVGA, VGA, infine registrazione concorrente.
5. Collaudo: Chrome Android con Mac spento; 30 minuti di stream; 100 connessioni/disconnessioni senza crescita memoria; Wi-Fi perso/ritrovato, client lento, secondo client, assenza frame, frame massimo, watchdog e riavvio. Verificare separatamente che eventi SD restino riproducibili e rete LAN/NTP mantenga le restrizioni precedenti.

**Criterio di via libera:** JPEG completi senza app vendor, memoria stabile e recupero della camera dopo disconnessione. Fallimento del criterio RAM o blocco acquisizione impediscono di dichiarare la funzione pronta, anche con una singola immagine HTTP riuscita.

## Verifica svolta in questa sessione

Riletti sorgenti LocalCam, acquisizione SDK, preparazione build, filtro rete, build EXP2B/F e documentazione dei test SD. Rieseguito il test esistente:

```
cc -std=c99 -Wall -Wextra -Werror -Itests tests/test_http.c -o /tmp/hk6-feasibility-http-test
/tmp/hk6-feasibility-http-test
```

Esito: `HTTP host checks passed: fragmented reads, partial writes, routes, JPEG trailer, stream, errors, limits.` Sono frame e socket simulati: nessuna prova hardware HTTP, misura heap attuale o implementazione stock effettuata. Restano aperti gli indirizzi/ABI degli agganci, la proprietà dei frame e il budget RAM effettivo; non vengono presentati come già risolti.

## Aggiornamento: agganci e misure del 23 ottobre

Completata la prima mappatura statica con emulazione e misure seriali (rapporto di laboratorio locale; vedere la cronologia pubblica). Heap 256 KiB, disponibili 107.476–122.036 byte nei campioni; massimo blocco contiguo non misurato. Lettore JPEG individuato ed emulato in sei casi. Il campionamento video LAN non è riuscito: nessun dato nuovo sotto streaming. Nessun firmware modificato.

Seconda verifica: memtrace distingue TCM e heap principale; blocchi liberi mostrati di 43 e 98 KiB rispettivamente. Verificate in emulazione ABI TCP e sequenza startup (21 casi totali con il lettore JPEG). Vedere aggiornamento nel rapporto collegato. La scelta dell’allocatore è vincolante: buffer JPEG sul principale, stack TCM. Misure sotto streaming ancora mancanti per timeout LAN.

Terza verifica: alternative a multipart, stato RTOS e diagnosi UDP (rapporto di laboratorio locale; vedere la cronologia pubblica). TCP nativo raggiungibile, UDP video ancora senza handshake; WebSocket/JPEG è una seconda strada plausibile senza ricodifica.

## Esito implementazione HTTP1 — 23 ottobre 2026

Server installato e verificato sulla camera: pagina, snapshot e MJPEG 640×480 a circa 3 fps. Le limitazioni LAN dei precedenti tentativi PPPP non hanno impedito il video HTTP diretto. Rapporto: `analysis/http-candidate/hardware.md`; evidenze: `app/evidence/native-http1-*.json`. Le sezioni precedenti documentano le fasi dello studio.
