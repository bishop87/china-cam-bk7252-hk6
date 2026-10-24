# HK6 / BK7252UQN48: analisi preliminare

Aggiornamento del 16 ottobre: disassemblaggio, confronto SDK, build sperimentale e procedure riproducibili sono nel [readme.md](readme.md). Questa analisi iniziale non costituisce una conferma di compatibilità per il flashing.

Data: 15 ottobre 2026. Obiettivo: firmware controllabile, con video esclusivamente locale e senza app proprietaria obbligatoria.

## Hardware e strumenti disponibili

- Foto dell'utente: SoC BK7252UQN48, PCB `HK6_V0.1D230606`.
- Visibili: micro-USB, microSD, connettore sensore, microfono, antenna PCB; piazzole TDI/TDO/TCK/TMS/CEN/VIO/GND/5V.
- Sensore ottico, capacità flash, pin UART e tensione VIO non ancora identificati con certezza.
- Disponibili: adattatore FT232RL e multimetro. Verificare il livello effettivo del TX dell'adattatore, non soltanto la posizione del jumper.
- Le etichette TDI/TDO/TCK/TMS non identificano una UART. Nessun cablaggio TX/RX è stato dedotto dalle sole foto.

## Materiali e metodo

Analisi statica del pacchetto fornito dall'utente `HDWifiCamPro_8.3_apkcube.apks`; estrazione ZIP, decodifica con Apktool 2.11.1 in smali/XML, ispezione delle stringhe della libreria nativa. L'app non è stata installata o eseguita. Non sono stati inviati pacchetti alla camera, eseguiti aggiornamenti o modificati dispositivi.

Il pacchetto contiene `base.apk` e split di architettura, lingua e densità. Il manifest identifica `com.shix.qhipc`; apktool.yml riporta versione 8.3, codice 83. Questo identifica il campione analizzato: la firma non è stata confrontata con un APK ufficiale di Google Play.

Hash e dimensioni degli input: `analysis/hdwificampro/input-hashes.json`.
Output decodificato: `analysis/hdwificampro/decoded/`.
Stringhe native: `analysis/hdwificampro/native-strings.txt`.
Comandi JSON estratti: `analysis/hdwificampro/commands.json` (inventario parziale, non specifica completa del protocollo).

## Manuale

PDF dell'utente: `manuale originale (copia privata)`, sei pagine. Testo estratto e pagine 2, 3 e 5 verificate visivamente; rendering conservati in `analysis/manual/`.

- Pagine 2-3: collegamento diretto al punto di accesso della camera e visualizzazione del video; prefissi esemplificativi DGO, DBG, HTM, TUT.
- Pagina 4: configurazione della connessione al router.
- Pagina 5: password predefinita dichiarata `6666`; lo screenshot esemplificativo riporta una versione `7252_CY_IPC_210728` e `1433` sulla riga seguente.
- Queste informazioni descrivono la famiglia di prodotti del manuale: non sono una lettura del firmware o delle credenziali della camera dell'utente.
- La voce "1080P" nell'interfaccia non dimostra la risoluzione effettiva del sensore.
- Il reset descritto nel manuale cancella la configurazione; non è necessario effettuarlo per questa analisi.

## Protocollo nell'app

La libreria `lib/arm64-v8a/libobject_jni.so` esporta funzioni JNI quali `StartPPPP`, `StartPPPPLivestream`, `PPPPInitial`, e funzioni `cs2p2p_PPPP_*`. Le stringhe comprendono prefissi DGOA, DGOC e altre varianti. È evidenza diretta che il campione incorpora una pila PPPP/CS2; non identifica da sola la variante usata dalla camera.

Il codice `smali_classes4/com/shix/shixipc/utils/CommonUtil.smali` costruisce messaggi JSON. Esempi verificati:

| pro | cmd decimale | Metodo / utilità |
| --- | ---: | --- |
| get_parms | 101 | getCameraParms: interrogazione parametri |
| get_attribute | 103 | SHIX_GetAtt: interrogazione attributi |
| stream | 111 | CutStream: selezione video |
| get_wifi | 112 | getWifiParms |
| scan_wifi | 113 | scanWifi |
| set_wifi | 114 | SHIX_SetWifi: modifica configurazione |
| check_ota | 406 | SHIX_CheckOTA: richiesta OTA |

I campi comprendono `user`, `pwd` e, per alcuni messaggi, `devmac`. Esiste anche `get_user` con cmd 103: il numero da solo non basta a descrivere un comando. I messaggi sono trasportati dalla libreria nativa; non sono endpoint HTTP da chiamare direttamente.

### Progetti pertinenti

1. [datenstau/A9_PPPP](https://github.com/datenstau/A9_PPPP): implementazione JavaScript specifica per HDWifiCamPro, provata dall'autore su prefissi DGOA/DGOC, PCB HB3 e firmware A9_IPC_20220506. Ricostruisce MJPEG e offre un server HTTP. Le operazioni `stream` 111, `get_parms` 101 e `set_wifi` 114 coincidono con quelle osservate nel campione Android.
2. [hyc/a9serv](https://github.com/hyc/a9serv): implementazione C derivata da A9_PPPP, concentrata sulla conversione del video in HTTP/MJPEG.
3. [Issue HDWifiCamPro in a9-v720](https://github.com/intx82/a9-v720/issues/6): riferimento storico per questa app e board HB6. La chiusura dell'issue non è prova che il client V720 supporti la camera dell'utente.

Conclusione: A9_PPPP/a9serv sono riferimenti più pertinenti di V720 per il primo test locale. Compatibilità effettiva da verificare: il campione Android è più recente del firmware su cui A9_PPPP è stato provato, e l'app gestisce più famiglie di dispositivi.

Il bridge richiede un computer acceso e conserva il firmware originale. Può servire come prova iniziale del video e del sensore, ma non realizza da solo l'obiettivo del firmware sostitutivo.

## Pista OTA

`CommonUtil.SHIX_CheckOTA` (riga 504 del file smali) costruisce `check_ota`, cmd 406, con campi opzionali `md5_path`, `bin_path` e il campo `otaType`.

`activity/OtaShowActivity$3.smali` contiene un gestore che passa:

```text
http://shixapp.oss-cn-hongkong.aliyuncs.com/hqbka9/bka9.rbl
```

come `bin_path`, con `otaType = 1`, e consegna il JSON a `NativeCaller.TransferMessage`.

È un indizio concreto per studiare formato e procedura degli aggiornamenti. Non prova che tale schermata sia raggiungibile nella normale UI, che il comando sia implementato dalla HK6, o che il firmware accetti file arbitrari/non firmati. Il file è stato successivamente scaricato e analizzato, come documentato nell'aggiornamento in fondo. Nessun comando OTA è stato inviato alla camera.

### File binari inclusi nell'app

| Asset | Dimensione | Risultato statico |
| --- | ---: | --- |
| app42045.bin | 1.495.040 byte | Archivio tar; contiene `app/bin/target`, ELF con e_machine=8 (MIPS), e `jxh62-t31.bin`: non è un'applicazione ARM per BK7252 |
| flash3.bin | 8.388.608 byte | Stringhe U-Boot 2013.07; destinazione hardware non stabilita |
| flash10.bin | 8.388.608 byte | Stringhe U-Boot 2013.07; destinazione hardware non stabilita |
| 4111230.bin | 444.524 byte | Formato/destinazione non identificati; intestazione testuale wifi-camera-sys- |
| test.bin | 12.572 byte | Testo UTF-8, non un'immagine firmware identificata |

Nessuno di questi asset è stato validato come firmware per la HK6. La loro presenza conferma che non è corretto attribuire automaticamente tutte le funzionalità dell'app a questa camera.

## Rete e privacy: limiti dei risultati

Nel codice e nelle stringhe native sono presenti riferimenti ad Aliyun OSS, cypush.com e cyczcam.com. `analysis/hdwificampro/app-endpoints.txt` conserva gli URL letterali estratti dalle classi applicative, ma non comprende necessariamente quelli composti a runtime o presenti nelle librerie native.

Il manifest richiede accesso a rete, microfono, fotocamera, posizione, stato telefonico e identificatori pubblicitari, fra gli altri permessi. Le richieste nel manifest non dimostrano che tutti siano concessi o utilizzati. Analogamente, gli URL non provano traffico effettivo o invio di video: per attribuire dati e destinazioni servono catture di rete, distinguendo app e camera.

## Percorso verso il firmware locale

[Beken7252 OpenCam](https://github.com/daniel-dona/beken7252-opencam) rimane il riferimento principale: l'autore dichiara acquisizione e HTTP multipart su alcuni sensori; non abbiamo una build verificata per HK6/BK7252UQN48. Il [piano 1.0](https://github.com/daniel-dona/beken7252-opencam/issues/21) menziona altri PCB QFN48.

[OpenBeken](https://github.com/openshwprojects/OpenBK7231T_App/releases) è utile per strumenti e porting della piattaforma, ma le note delle release dichiarano assente il driver camera BK7252. [Apache02/bk7252-cam](https://github.com/Apache02/bk7252-cam) è un riferimento per la piattaforma sviluppata senza SDK; il README non dichiara ancora una camera completa funzionante.

Ordine proposto:

1. Rilevare prefisso SSID/UID, indirizzo IP locale e versione firmware effettivi, senza reset o aggiornamenti.
2. Eventuale prova di sola lettura del video con A9_PPPP/a9serv su rete senza uscita Internet: nessuna configurazione, reset o OTA automatica.
3. Verificare livelli elettrici e identificare UART con misure/continuità. Alimentare dalla porta prevista; lasciare scollegato VCC del FTDI. Primo ascolto con GND comune e TX camera verso RX FTDI.
4. Salvare e verificare la flash originale, dimensione e partizioni incluse. La possibilità di recupero non deriva dal solo possesso di un dump: va confermato il percorso di riscrittura.
5. Identificare sensore e mappatura GPIO, quindi adattare OpenCam: singolo JPEG, streaming HTTP/MJPEG, stabilità, verifica del traffico.
6. Studiare l'OTA solo dopo aver identificato immagine, partizioni e recupero; conservare inizialmente il bootloader funzionante.

Non sono state eseguite prove hardware o di rete; i risultati attuali sono documentali e statici.

## Aggiornamento: firmware OTA acquisito e decifrato

Su richiesta dell'utente, il 15 ottobre 2026 è stato scaricato l'esatto URL `hqbka9/bka9.rbl` presente nell'app. Risposta HTTP 200, 537.376 byte, Last-Modified 17 dicembre 2021. La data è un dato del server e non prova che sia la versione più recente disponibile per la camera. Gli header sono salvati in `analysis/ota/bka9-http-headers.txt`.

Il file ha un'intestazione RT-Thread RBL di 96 byte:

| Campo | Valore verificato |
| --- | --- |
| Partizione destinazione | app |
| Versione dichiarata | A9_IPC_20211217 |
| Timestamp intestazione UTC | 2021-12-16T12:54:08Z |
| Algoritmo | 0x102: AES-256-CBC + gzip |
| Dimensione payload impacchettato | 537.280 byte |
| Dimensione applicazione estratta | 794.612 byte |
| SHA-256 RBL | 5941fc2c44253c3186e6ff5f6494a9df3371f803c18af6063d39153b6e9fbeff |
| SHA-256 applicazione | a7bda080533d98ef8a4ddbd3e332193bd3058b2b9fbdef94c4184c7d20c52790 |

La decifratura riesce con chiave ASCII `0123456789ABCDEF0123456789ABCDEF` e IV ASCII `0123456789ABCDEF`, parametri di esempio pubblicati in [rtthread_tools](https://github.com/0xE9DEADBEEF/rtthread_tools). Il [reader del progetto](https://github.com/0xE9DEADBEEF/rtthread_tools/blob/main/rtthread_tools/ota_firmware.py) e il [packager RT-OTA](https://github.com/GlideLeo/rt_ota_package_cmd/blob/master/Package.py) documentano il formato. È stata scritta una piccola utility locale, senza installare o eseguire i progetti esterni.

Verifiche passate: dimensioni, CRC32 dell'intestazione, CRC32 del payload, integrità gzip e FNV1a dell'immagine estratta. Il MD5 coincide inoltre con quello dichiarato dal server. Questi controlli dimostrano la coerenza del campione, non l'autenticità del produttore: il trasferimento usava l'URL HTTP dell'app.

Artefatti:

- `analysis/ota/bka9.rbl`: file OTA originale.
- `analysis/ota/bka9-app.bin`: applicazione decifrata e decompressa.
- `analysis/ota/bka9-metadata.json`: metadati e checksum.
- `analysis/ota/bka9-app-strings.txt`: stringhe con offset esadecimali nel file estratto.
- `analysis/ota/unpack_bka9.py`: estrazione riproducibile e controlli; dipendenza Python cryptography.

L'immagine estratta inizia con istruzioni compatibili con una tabella vettori ARM. Contiene riferimenti `beken_camera`, `7252_CY_IPC_20210923`, RT-Thread, motore JPEG, UART1/2 e funzioni OTA. Stringhe relative ai sensori includono GC0308, GC0309, GC0328 e OV76xx. Sono indizi per individuare codice e tabelle di inizializzazione, non identificazioni del sensore montato sulla HK6.

Sono presenti anche `/sd/rtthread.rbl`, `http_ota`, `sd_ota_fw_download`, `check_ota`, `bin_path` e descrittori di partizione. La loro presenza non prova che tutte queste funzioni siano accessibili nel prodotto dell'utente.

Conclusione operativa: si può iniziare il reverse del firmware senza estrarre nulla dalla board. Il campione è del 2021 e la compatibilità con HK6/BK7252UQN48 non è stabilita. È un pacchetto applicativo, non un backup completo dell'esemplare: non conserva necessariamente bootloader, configurazione e calibrazione della camera. Il dump fisico resta utile in seguito per confronto e recupero prima di modificare la flash.
