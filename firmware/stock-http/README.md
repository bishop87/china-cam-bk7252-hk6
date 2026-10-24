# HTTP video per EXP2F — prima implementazione

23 ottobre 2026. **HTTP1 installato e verificato sulla camera.**
Questa estensione riusa il produttore JPEG stock, senza sessione PPPP obbligatoria
nel percorso inattivo normale. Video diretto verificato a 640×480, circa 3 fps; dettagli nel rapporto hardware.

## Comportamento implementato

- Server TCP porta 80 e pagina minima `/` con video incorporato.
- `/snapshot.jpg`: un JPEG puro; `/stream.mjpg`: multipart JPEG, massimo cinque
  richieste frame/s. Nessuna ricodifica, audio, configurazione remota o WebSocket
  in questa prima versione. Trasporto separato da acquisizione e ABI stock.
- Un client servito alla volta; backlog 1. Ulteriori client possono aspettare:
  non è un server concorrente né promette una risposta immediata al secondo.
- Slot da 40.928 byte allocato **nel pool principale** soltanto durante una
  richiesta video. Validazione SOI, EOI, lunghezza e trailer stock di 5 byte.
  JPEG massimo consegnabile 40.923 byte. Nessuna coda crescente.
- Il produttore copia soltanto su richiesta e con slot libero. Durante invio,
  scarta la consegna HTTP dei nuovi frame senza attendere il client.
- Timeout socket 1 s, deadline richiesta/invio 3 s controllata tra le operazioni,
  attesa frame 2,5 s. Una chiamata bloccante già iniziata può oltrepassare la
  deadline fino al timeout socket. Zero frame iniziali → HTTP 503; assenza frame
  successiva chiude il multipart. Rilascio del buffer anche dopo invio fallito.
- Stato piccolo persistente nel parametro del thread `hk6http`; nessun BSS
  aggiunto e nessun indirizzo RAM libero presunto. Stack dedicato da 4096 byte,
  priorità 21; gli stack vengono allocati dallo stock in TCM.

La pagina offre Riconnetti. Non c'è riconnessione automatica dopo fine stream.
HTTP è LAN senza autenticazione applicativa o TLS, come previsto per il primo
collaudo; chi raggiunge l'IP può leggere il video. Il filtro di uscita EXP2F resta
identico. Non esporre questa versione come servizio pubblico.

## Struttura

- `http.c` / `http.h`: slot e stati EMPTY/COPYING/READY/SENDING, richieste HTTP,
  snapshot e multipart. Dipendenze di piattaforma dichiarate nell'header.
- `stock.c`: ABI stock fissate a EXP2F, pool principale esplicito, socket,
  thread, clock e wrapper lettura. Nessun fallback allocazione sulla TCM per
  il JPEG. Rete/registrazione/sensore stock non sono reinizializzati dal server.
- `entry.S`: deviazione del ramo inattivo quando HTTP richiede un frame.

Il thread è creato e inizializzato prima della creazione di p2pvideo; viene
avviato dopo l'inizializzazione stock. Il produttore non può quindi trovare un
parametro in costruzione lungo questa sequenza normale. Lo stato/thread non
vengono cancellati dopo pubblicazione. Alla disconnessione il worker disabilita
le richieste, attende il completamento di COPYING, poi libera solo il buffer.
Una mancata allocazione iniziale lascia eseguire lo startup stock. Un fallimento
di avvio del thread HTTP lascia il piccolo stato registrato inattivo fino al
riavvio; non viene liberato mentre potrebbe essere trovato dal produttore.

## Candidato offline

```
.venv/bin/python tools/build_http_candidate.py
.venv/bin/python tools/verify_http_candidate.py
cc -std=c99 -Wall -Wextra -Werror -fsanitize=address,undefined \
  tests/test_stock_http.c firmware/stock-http/http.c -o /tmp/test_stock_http
/tmp/test_stock_http
```

Output: `analysis/http-candidate/candidate-logical.bin`, ELF, manifest con hash
sorgenti e patch, rapporto di validazione. **Il binario è un payload logico da
analisi, non un'immagine flash fisica o un pacchetto OTA.** Il pacchetto OTA separato è in `dist/hk6-stock-http1`; installatore `tools/ota_http.py`. Non cambiare nome al file per tentare un aggiornamento da SD.

Build ARM968E-S Thumb GCC 5.4 con `-Wall -Wextra -Werror`, nessun simbolo esterno
irrisolto, `.data`/`.bss` vuote. Codice e costanti aggiunti: **3033 byte**, più un
byte di allineamento. Payload: **830289 byte**, SHA-256:

`59065131195ae6823e28858c0de3b61a6aa12d9f12768f8123d820f06922c4f7`

Tre sole aree stock modificate:

| Indirizzo logico | Funzione |
| --- | --- |
| 0x16da0, 4 byte | Wrapper startup: stato HTTP prima dei produttori, worker dopo |
| 0x1a628, 4 byte | Lettura stock invariata + offerta non bloccante del JPEG |
| 0x1a72e, 6 byte | Acquisizione su richiesta HTTP quando il ramo stock era inattivo |

Il generatore verifica SHA del payload EXP2F e byte originali dei tre siti.
Il validatore verifica che tutti gli altri byte stock restino identici.
Il pacchetto RBL identifica la versione `2M.1220-LAN-HTTP1`; il payload conserva il banner stock.

## Verifiche concluse

- **13 gruppi host**, AddressSanitizer e UndefinedBehaviorSanitizer: header
  frammentati, invii parziali, pagina/snapshot/multipart, scarto durante invio,
  frame assenti, malloc fallito, errore send negativo diverso da -1, timeout,
  wrap del clock, route esatta, timeout socket non configurabile, header lungo,
  trailer invalido, limite massimo JPEG e frame troppo grande.
- **13 casi sul codice ARM compilato**: due rami del gate, quattro casi cattura,
  quattro percorsi startup, pagina/snapshot/503 reali del parser compilato con
  I/O modellato. Verificati stack e registri preservati per gate/cattura.
- Regressione encoder/dispatcher **VGA 640×480 e QVGA 320×240** passata.
- Regressione filtro rete sul candidato: **25 casi limite, 13 pacchetti reali
  riprodotti, 5 confronti completi IPv4**, più casi DNS/NTP. Rapporto in
  `analysis/http-candidate/network-check/emulation-validation.json`.
- Due build consecutive producono lo stesso SHA del payload.

Le prove host e Unicorn non riproducono scheduling, DMA, timing radio o
frammentazione heap reali. Non sono prove di streaming dalla camera.

## Checklist originaria del collaudo hardware

1. Confermare il percorso normale di boot e l'immagine effettivamente installata;
   il ramo alternativo a 0x16d9a non avvia questo server.
2. Preparare un backup della versione corrente e il ritorno a EXP2F. La lettura
   bootloader e scrittura/ripristino di un settore sono documentate; il ripristino
   completo dell'applicazione non risulta collaudato nel rapporto di recupero.
3. Versionare e confezionare il candidato con verifica separata di layout/RBL;
   non riusare automaticamente un uploader vincolato a un altro SHA.
4. Prima prova controllata via seriale: boot, risposta pagina, snapshot, poi
   stream. Misurare heap e stack durante avvio/chiusura ripetuti, client lento,
   disconnessione, esaurimento memoria e assenza frame.
5. Verificare video senza app vendor/Mac, successivamente convivenza con eventi
   SD. Il gate playback stock rimane prioritario: HTTP può rispondere 503 durante
   playback nativo. Non disabilitare implicitamente registrazioni dell'utente.

La prima fase era solo offline. Il successivo aggiornamento OTA e le prove reali sono documentati nel [rapporto hardware pubblico](../../docs/collaudo-http1.md). La convivenza con registrazione SD e playback resta da verificare.
