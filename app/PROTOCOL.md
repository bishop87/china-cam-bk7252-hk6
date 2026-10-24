# Evidenze e formato candidato

## Fonti

- `../ANALISI.md`: APK HDWifiCamPro 8.3, JNI PPPP/CS2 e comandi JSON.
- `../analysis/hdwificampro/commands.json` e smali di CommonUtil: `stream`,
  cmd 111, campi user/pwd/devmac. Non definiscono il trasporto nativo.
- [hyc/a9serv](https://github.com/hyc/a9serv), commit
  `10d686d1aa30749afd8b4dfe2875fb65313244ed`, consultato il 19 ottobre 2026:
  `pppp.c` per formato wire e `cipher.c` per tabella/algoritmo di offuscamento.
- [datenstau/A9_PPPP](https://github.com/datenstau/A9_PPPP), riferimento storico
  citato da a9serv e dall'analisi del progetto; compatibilità dichiarata su altre board.

Implementazione Python locale del formato osservato nei riferimenti. La tabella
wire in `protocol.py` proviene da `cipher.c`; non è una chiave segreta utente.
Il checkout a9serv consultato non contiene un file LICENSE: prima di distribuire
il prodotto occorre chiarire i termini delle parti derivate. Nessun sorgente C
upstream è stato aggiunto al progetto.

## Wire format da validare su HK6

Datagrammi UDP, discovery unicast sulla porta 32108. Offuscamento byte per byte
con tabella da 256 byte, chiave `69 97 cc 19` e feedback sul byte cifrato precedente,
inizializzato a zero a ogni datagramma. Non è TLS né cifratura moderna.
Probe in chiaro `f1 30 00 00`, cifrato `2c ba 5f 5d`.

Header: magic `f1`, tipo a un byte, lunghezza body uint16 big endian.
Handshake candidato: LAN_SEARCH 30 → PUNCH 41 → eco PUNCH → P2P_RDY 42.
L'endpoint camera è fissato al mittente del PUNCH, soltanto sull'IP richiesto.

DRW d0: body `d1`, canale, indice uint16 big endian, payload. ACK d1:
`d1`, canale, numero indici uint16 big endian (1), indice uint16 big endian.
ALIVE e0 riceve ALIVE_ACK e1; CLOSE f0 termina la sessione.

Comando stream: canale 0, indice 0, magic `06 0a a0 80`, lunghezza JSON uint32
little endian, JSON compatto. Richiesta `pro=stream, cmd=111, video=1` con
user/pwd e devmac `0000` come nel client di riferimento. `video=1` non certifica
una specifica risoluzione, che va misurata dal JPEG.

La successiva analisi del gestore firmware `0x17f0c`, riproducibile con
`tools/analyze_stream_profiles.py`, associa `video=1` al modo sensore 1
(VGA 640×480) e `video=2` al modo 0 (QVGA 320×240). Evidenze in
`analysis/original/reverse/stream-profiles.json` e `hi704-modes.json`.
Sono risoluzioni richieste: nella prova reale del 20 ottobre, dopo l'ACK al
comando `video=1`, quattro misure consecutive restano 640×352. L'ACK non
dimostra l'applicazione della risoluzione e l'origine della differenza nel
percorso acquisizione/encoder non è ancora determinata.

Frame: payload con magic `55 aa 15 a8 03 00`, header 32 byte; dimensione frame
uint32 little endian a offset 16 del payload. Il JPEG comincia dopo l'header.
Frammenti successivi sullo stesso canale, indici consecutivi modulo 65536.
Lunghezza esatta e marcatori SOI/EOI richiesti prima della pubblicazione.
Nessun assunto che i datagrammi siano ricevuti interi in una cattura snaplen 512.

## Cosa dimostrano le prove

Il rapporto `capture-evidence.json` viene prodotto da `inspect_capture.py` senza
stampare payload, credenziali o UID. Le tre decodifiche candidate `f1 f9` nella
prima cattura corroborano l'offuscamento, ma non dimostrano supporto al comando
111, header video, JPEG, handshake o password sulla camera reale. Le catture non
mostrano DRW video. I test con camera simulata verificano il comportamento locale
rispetto al formato candidato, non costituiscono una verifica indipendente del
protocollo proprietario. Nessuna prova hardware effettuata in questo lavoro.

## Verifica hardware del 19 ottobre 2026

Camera sulla stessa Wi-Fi del computer; identificativi della singola unità omessi.
Handshake 30/41/42 riuscito. Comando stream/111 e credenziali predefinite
accettati; DRW video sul canale 1, header come sopra. Primo tentativo senza
rimozione trailer: timeout nonostante ricezione di migliaia di DRW validi.

Il frame dichiarato include cinque byte dopo EOI: `00` e lunghezza JPEG uint32
little endian. Esempio misurato: frame 15556 byte, EOI a offset 15549,
trailer `00 bf 3c 00 00` (15551 byte di JPEG). Il parser ora rimuove il trailer
solo se lunghezza e posizione EOI coincidono; mantiene supporto al JPEG puro.
Snapshot ricevuto tramite CLI dopo la correzione: 15635 byte, 640×352,
decodificato e ispezionato visivamente. MJPEG visualizzato nel browser integrato.
Questo supera lo stato preliminare di mancata verifica hardware riportato sopra;
le conclusioni sulle vecchie catture restano valide. Nessuna modifica firmware
o comando seriale è stato necessario. Report quantitativo in `evidence/`.


## Canale di controllo — 20 ottobre 2026

Risposte DRW sul canale 0, indici consecutivi a partire da 0, header
`06 0a a0 80`, lunghezza JSON uint32 LE, JSON con `cmd` e `result` (0 nelle
letture riuscite). La risposta non include sempre `pro`: si mantiene una sola
operazione pendente e si ricrea la sessione dopo un timeout per evitare ambiguità.
Frammentazione, riordino e duplicati sono gestiti con limiti di memoria.

Verificati: 101 espone `tz,time,icut,batValue,batStatus,sysver,mcuver,
isShow4KMenu,isShowIcutAuto,rotmir,signal,lamp`; 112 espone `conmode,ssid`;
113 espone `count,ssid[i],signal[i],encryption[i]`. I dati pubblicati dalla API
sono una selezione esplicita; password e campi non previsti vengono esclusi.

Il comando 102 per `rotmir`, `icut` e `lamp` è ricostruito da CameraControl
in CommonUtil.smali e dai call site MJCameraLiveActivity.smali. `rotmir`:
0 normale, 1 mirror, 2 flip, 3 entrambi. `icut` 0/1/2 sono associati a
close/open/auto da popup_icut.xml e dai call site; auto è disponibile solo
quando isShowIcutAuto=1. Scritture non collaudate dall'agente sulla camera.

`set_wifi`/114 segue SHIX_SetWifi: wifissid/wifipwd in UTF-8 JSON,
encwifissid/encwifipwd con Java URLEncoder UTF-8 (spazio '+', tilde '%7E'),
encryption copiato dalla scansione. Nessuna password persistita dal bridge.
Cambio rete non effettuato durante il collaudo; una risposta positiva conferma
l'accettazione del comando, non il successivo collegamento alla nuova rete.

L'ACK PPPP d1 conferma il trasporto, non l'applicazione. Durante le prove,
comandi singoli inviati nello streaming hanno talvolta mancato anche l'ACK.
Una seconda copia identica dopo 20 ms e i retry limitati hanno permesso lettura
101/112/113 confermata nella stessa sessione. Non è una prova causale definitiva
sul difetto firmware; non si dichiarano risolte tutte le perdite di rete.

## Audio — 21 ottobre 2026

Il JNI Android `CPPPPChannel::StartAudio`/`StopAudio` usa `stream/111` con
`audio=1`/`audio=0`. Il firmware stock `0x17f70` aggiorna il flag audio senza
cambiare il profilo video. Il mittente `0x1ab80` legge il microfono, comprime con
`0x12b78` e invia sul canale PPPP 2: magic `55 aa 15 a8`, header 32 byte,
lunghezza payload LE a offset 16. Il byte codec a offset 4 non viene inizializzato
esplicitamente da questa routine; il valore effettivo resta da misurare.

Il codec stock è ADPCM con tabella IMA, nibble alto per primo, predittore e indice
azzerati a ogni blocco; incremento `(step * magnitude) // 4 + step // 8`.
Non usare un decoder IMA generico con header WAV o ordine nibble invertito.
La pagina assume mono 8000 Hz, come AudioPlayer Android e il default del driver
microfono SDK. Supportati codec 0/11 ADPCM, 12 G.711 A-law e 13 PCM16 LE, seguendo
il decoder JNI; valori diversi vengono segnalati, senza riproduzione.
`tools/check_audio_decoder.py` verifica byte per byte il decoder Python contro
le funzioni ARM64 dell'APK eseguite in Unicorn. Rapporto in
`evidence/audio-decoder-20261021.json` (quattro casi ADPCM, tutti i 256 codici A-law).

API: azione `audio` con booleano `enabled`; `/audio.pcm?after=N` restituisce PCM16
LE e `X-Audio-Sequence`. Il buffer conserva al massimo un secondo in RAM, senza
file. Il browser usa Web Audio dopo il clic, con coda limitata. Spegnimento,
disconnessione e chiusura pagina interrompono l'ascolto; in assenza di richieste
PCM per 8 secondi il servizio invia audio=0. L'ACK conferma solo il comando:
`audio.receiving` indica invece l'arrivo di dati decodificabili. Nessun riavvio
automatico dell'audio dopo la riconnessione. Video e audio non sono sincronizzati.

Collaudo hardware non completato il 21 ottobre: 192.168.1.54 ha restituito
`No route to host`. Header codec, frequenza effettiva, qualità udibile e stop del
flusso sulla camera rimangono da verificare. La UI non presenta l'ACK come prova
di ricezione. I test offline passano (26 test più confronto decoder ARM64).


### Successiva verifica hardware nella stessa giornata

Camera nuovamente raggiungibile. Il byte codec osservato è **0xaa (170)**,
coerente con il campo non inizializzato dal mittente stock. Aggiunto questo
valore al riconoscimento ADPCM HK6, senza accettare indiscriminatamente altri
codec. Ricevuti 76 blocchi / 48.640 campioni in 6,05 secondi, coerenti con
8 kHz: RMS 626,24 e picco 3007, quindi dati non silenziosi e non saturati.
Video contemporaneo 640×480, nessuna riconnessione nella sessione. Dal browser
verificato il toggle on → «In ascolto · mono 8 kHz» → off → «Audio spento».
Audio lasciato spento. Rapporto `evidence/audio-live-20261021.json`.
Non è stata salvata alcuna registrazione; la qualità percepita resta da valutare
all'ascolto. L'off ha ricevuto ACK e ha fermato riproduzione/buffer locali;
la cessazione dei datagrammi sulla rete non è stata misurata separatamente.


## MicroSD: protocollo verificato sul dispositivo (21–22 ottobre 2026)

Comandi JSON: get_sd/109, set_sd/110 (recMode 0/1), get_alarm/107,
set_alarm/108 (pirenable, pirvideo, pirsensitive, pirvideotime, pirDelayTime).
Scritture seguite da rilettura; nessuna formattazione implicita.
get_record_day/205 accetta year intero e restituisce month[0..11] come bitmap
(giorno 1 = bit 0). get_record_hour/401 richiede ymd `2026_10_21` e restituisce
record_hour (ora 0 = bit 0). get_record_min/402 richiede ymdh `2026_10_21_18`
e restituisce record_num e record_name[i]. Date compatte senza separatori
non funzionano su questa camera.
play_record_file/207: type 1 e filename per avvio, type 0 per stop.
I JPEG del playback arrivano sul canale DRW 3 e non devono alimentare il live.
Export locale RIFF AVI/MJPG ricostruito, video soltanto; nessun download originale.
Per evidenze statiche e limiti della cancellazione vedere `analysis/microsd.md`.


## Estensioni orologio e player (22 ottobre 2026)

`set_datetime`: richiesta cmd126, risposta cmd128; time UTC int e tz secondi
ovest. Non correlare la risposta con il solo cmd della richiesta.
La patch Europe/Rome del progetto ignora tz in ingresso e converte time.
`dev_control/102` con reboot:1 riavvia (presenza del campo, non valore booleano).
`play_record_file/207` senza type: suspend 1/0 per pausa, audio 1/0 per audio.
Il canale 3 miscela frame video codec3 e ADPCM codec11: mantenerlo separato
sia dal live sia dal canale2 del microfono. Nessun seek esposto.
Analisi riproducibile: `tools/analyze_web_extensions.py`; rapporto completo
in `analysis/web-extensions.md`.

## Stato successivo: EXP2F e HTTP1

Le misure 640×352 sopra sono storiche. EXP2E/F correggono le dimensioni encoder: VGA 640×480 e QVGA 320×240. HTTP1 riusa il produttore JPEG e offre video diretto; vedere [collaudo pubblico](../docs/collaudo-http1.md). Il protocollo PPPP resta quello usato dal servizio locale. Le catture e i report grezzi citati sono artefatti locali esclusi dal repository.
