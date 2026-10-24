# MicroSD HK6: fattibilità e progetto di integrazione

Analisi iniziale del 21 ottobre 2026, aggiornata il 22 ottobre dopo inserimento
di microSD FAT32 vuota da 2 GB e implementazione della web UI. Nessuna
formattazione o cancellazione eseguita. Stato del collaudo in `../README.md`.

## Risultato

La camera contiene già un registratore autonomo e un archivio consultabile via
PPPP. La strada iniziale è riutilizzarli nel servizio locale: il Mac serve per
configurazione e consultazione, non dovrebbe servire per registrare su microSD.
Quest'ultimo comportamento va confermato con una prova a servizio locale spento.
La cancellazione selettiva e il download dei file originali sono i punti meno
certi: l'APK supporta più famiglie di camere e i suoi comandi non sono tutti
implementati dalla HK6.

## Evidenze e limiti

Fonti: firmware stock `analysis/original/app-logical.bin`, SHA256
`8f2e8d40497634a801fffb4c28c54d1d19400c08a0286ba1e6b365997163d900`;
APK estratto in `analysis/hdwificampro/decoded/`, in particolare `CommonUtil`,
`SDCardModel`, `AlarmModel`, `VideoRecordModel` e `SettingSDCardActivity`.
`tools/analyze_sd_support.py` riproduce gli estratti annotati in
`analysis/original/reverse/sd-support.asm`.
Le conclusioni sono statiche sullo stock: verificare anche il firmware sperimentale
attualmente caricato prima di attribuirgli lo stesso comportamento.

| Funzione | Comando / evidenza | Stato |
|---|---|---|
| Stato scheda e spazio | `get_sd`, 109, handler `0x18704`; `sdstatu`, `total`, `free`, `recMode`, `isShowCapacity` | Implementato nello stock; prova reale da fare |
| Registrazione continua | `set_sd`, 110, `recMode`; handler `0x18ec0` e registratore | Valori 0/1 usati dall'APK BK; 1 riabilita registrazione alla fine del playback |
| Configurazione eventi | `get_alarm` 107 / `set_alarm` 108; `0x18840` / `0x189ac` | Campi rilevamento e registrazione presenti |
| Calendario | `get_record_day` 205 con `year`, `get_record_hour` 401 con `ymd` | Dispatcher e handler presenti |
| Elenco filmati per ora | `get_record_min` 402 con `ymdh`; risposta `record_num`, `record_name[i]` | Handler `0x197bc`; formato esatto dei nomi da misurare |
| Riproduzione | `play_record_file` 207; `filename`, `type`, `offset`, `suspend`, `audio` | Handler `0x19958`, thread `0x1ae20`; trasporto da collaudare |
| Formattazione | `set_sd` 110, `format=1`; `dfs_mkfs("elm","sd0")` | Implementata, distruttiva; non necessaria per la prima integrazione |
| Cancellazione singola | APK: `del_record_file` 207 | Non trovata nel dispatcher stock esaminato; supporto non dimostrato |
| Download originale | APK: `file_download` 150 / `stop_download` 151 oppure `down_file` 507 | Non trovati nel dispatcher stock esaminato; supporto non dimostrato |
| Pianificazione per orario | APK: `get_record_param` / `set_record_param` | Non dimostrata su HK6; non esporre come funzione nativa verificata |

Attenzione: il numero 207 non identifica da solo un'operazione. Il firmware
sceglie il gestore anche da `pro`: non usare un comando di riproduzione per
tentare una cancellazione. Non derivare percorsi o nomi da input arbitrario:
per playback e future cancellazioni usare soltanto gli elementi dell'elenco.

`get_sd` divide le quantità in byte per 2^20: visualizzarle in MiB/GiB, non
assumere settori o byte. `sdstatu` vale 1 nel ramo in cui il controllo filesystem
riesce, 0 nell'altro ramo. Capacità massima, FAT32/exFAT, velocità sostenibile,
recupero dopo interruzione alimentazione e affidabilità dell'espulsione non sono
ancora verificati. Il nome `elm` identifica il filesystem usato dalla routine
di formattazione, non prova la compatibilità con ogni scheda preformattata.

## Movimento: cosa fa davvero il firmware

I parametri si chiamano `pirenable`, `pirsensitive`, `pirvideo`, `pirvideotime`,
`pirDelayTime`, `pirPush`, `AalarmInterval`, `pirCloudUpCount`.
Questi nomi non provano la presenza di un sensore PIR fisico.

Nel ciclo di acquisizione (`0x1a620`) il firmware riceve un frame e usa il valore
restituito dalla funzione `0x2837c`. Nel ramo `0x1a740` confronta la differenza
assoluta rispetto al frame precedente con una soglia derivata da
`(9 - pirsensitive) * 128` (con troncamenti del codice originale). Il valore è
usato anche come dimensione del frame nel percorso di registrazione: l'evidenza
indica un rilevamento basato sulla variazione della dimensione del JPEG, non un
riconoscimento di persone o oggetti. È una deduzione dal flusso del programma,
da confermare sperimentalmente. Esistono anche flag/eventi alternativi.

Conseguenze previste: luce, esposizione e rumore possono generare eventi;
movimenti piccoli possono sfuggire. Occorrono prove con scena ferma, passaggio
di una persona, variazioni di luce e diversi livelli di sensibilità. Non
inventare una scala o durata valida prima di controllare i valori accettati.
`pirvideo` abilita il percorso di registrazione su evento; `pirPush` è distinto
e non è necessario abilitarlo per progettare la registrazione locale.

Proporre tre modalità nell'app: Spenta, Continua, Su evento. Sono profili
composti da più impostazioni, non necessariamente tre valori di `recMode`.
In particolare `recMode=0` non prova che anche la registrazione su evento sia
spenta: va verificata la combinazione con `pirvideo` e riletta dopo il salvataggio.
Non esporre opzioni cloud come prerequisito della modalità locale.

## Archivio, formato e concorrenza

Il registratore scrive `/sd/record/temp.avi`, usa il codec dichiarato `JPEG`,
parametri audio 8000 Hz / 16 bit e rinomina il file alla chiusura. È una forte
indicazione di contenitore AVI con video MJPEG; audio effettivo, indice e file
finale devono essere ispezionati su una registrazione reale. Non assumere MP4
né applicare automaticamente il formato `.av` di altre famiglie dell'APK.

Il servizio dovrebbe inizialmente tradurre la riproduzione PPPP in MJPEG e PCM
come per il live. Per un file esportabile e riproducibile in `<video>` occorrerà
verificare il recupero dell'originale e probabilmente una conversione locale
in un contenitore/codec supportato dal browser. Un'esportazione ricostruita dal
playback va distinta dal download dell'originale: può richiedere tempo reale.

Il gestore playback azzera il flag di registrazione; `type=0` può ripristinarlo
se il `recMode` persistente è 1. La web UI deve quindi indicare l'interruzione
prevista prima del playback e verificare il ripristino dopo Stop, errore o
chiusura della pagina. Non promettere live, registrazione e archivio simultanei.
Audio live e audio registrato vanno separati: il toggle attuale controlla il
solo ascolto live e non dimostra che il registratore includa/escluda l'audio.

Esiste gestione spazio: sotto una soglia di circa 50 MiB viene richiamata
`0x17038`, che scorre le directory dell'archivio. È candidata alla pulizia dei
vecchi filmati, ma ordine di eliminazione e policy di sovrascrittura non sono
ancora verificati. Non presentare una garanzia di conservazione dei filmati.

## Interfaccia proposta

Una scheda **Registrazioni** con:

- Stato microSD, capacità/libero, stato registrazione e modalità attiva.
- Configurazione continua/su evento, sensibilità e durata solo dopo validazione.
- Calendario e filtro per ora; lista filmati con nome, data e durata quando nota.
- Player con play/stop, pausa e spostamento temporale se confermati dal firmware.
- Esporta sul Mac, indicando se originale o ricostruzione dal playback.
- Elimina con riepilogo dei soli file selezionati e rilettura dell'archivio:
  attivabile soltanto quando esiste un comando verificato. Mai ripetere una
  cancellazione automaticamente dopo timeout o riconnessione.

Eventuale estensione firmware: API limitate per elenco metadati, download e
cancellazione, con percorsi confinati all'archivio, esclusione del file aperto
in registrazione, gestione degli indici e risultati espliciti. La formattazione
completa deve restare un'operazione distinta dalla cancellazione dei filmati.

## Sequenza di lavoro e collaudo

1. Inserire una microSD di prova, a camera spenta, annotando capacità e filesystem.
   Leggere 109 e 107; gestire anche scheda assente, vuota e non riconosciuta.
2. Registrare pochi minuti in continuo, fermare e rileggere. Verificare calendario,
   file chiuso correttamente, audio e data/ora. Provare con il Mac scollegato.
3. Provare gli eventi e determinare range sensibilità/durata e loro effetto reale.
4. Integrare calendario e player, misurando l'interferenza con la registrazione e
   il ripristino dopo chiusura del browser o errore di rete.
5. Verificare export e, separatamente, cancellazione su un filmato di prova.
   Se mancano i comandi, valutare l'estensione firmware con le prove precedenti.
6. Solo in seguito: policy di spazio pieno, sovrascrittura e tenuta nel tempo.

Alternativa senza modifica firmware: rilevamento movimento nel servizio sul Mac
con soglie, zone e pre/post evento, salvando sul disco del Mac. Richiede il Mac
sempre acceso; non consente da solo di scrivere file nella microSD della camera,
perché non è stato identificato un comando di upload verso il suo archivio.


## Diagnosi seriale del 22 ottobre 2026

Il registratore ha creato file evento reali: `2026-10-22-07-28-14-1.avi`,
`2026-10-22-07-29-53-1.avi`, `2026-10-22-07-30-26-1.avi`,
`2026-10-22-07-33-38-1.avi`. Il log di lettura directory li vede, ma
`recordList.count = 0`. Il filtro in `0x1b3bc–0x1b3c0` esclude esplicitamente
nomi con trattino al quinto carattere. Non è quindi dimostrato un problema
con la durata corta: l'assenza dal protocollo non prova l'assenza sulla scheda.
Anche il player costruisce il percorso estraendo anno/mese/giorno/ora dalle
posizioni del nome compatto (`0x1aea6–0x1aef4`): rimuovere solo il filtro non basta.
Serve una modifica firmware coerente di elenco e risoluzione del percorso,
oppure uniformare i nomi del registratore evento e gestire quelli già esistenti.

Per i filmati continui, la seriale mostra `vidBuf malloc failed` nel player:
l'allocazione in `0x1af16–0x1af1e` richiede 40.960 byte contigui.
Un passaggio manuale del live a QVGA ha consentito 37 frame e un export AVI da
279.952 byte, poi il live è stato riportato a VGA. L'app automatizza il passaggio
attendendo un JPEG 320×240 effettivo prima del comando play, e ripristina il
profilo precedente allo stop. Il file registrato mantiene la sua risoluzione.
Nessuna modifica o flash firmware è stata eseguita per queste prove.
