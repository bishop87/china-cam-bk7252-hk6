# Estensioni web UI — 22 ottobre 2026

## Ambito

Orologio Europe/Rome, riavvio, pausa/ripresa e audio delle registrazioni.
Nessuna modifica firmware, formattazione, cambio password o reset.
La UI continua ad ascoltare soltanto sul loopback e usa token e controllo Origin.

## Evidenza riproducibile

`tools/analyze_web_extensions.py` produce
`analysis/original/reverse/web-extensions.asm` dal firmware stock con hash fissato.
Per la versione del progetto considerare anche `firmware/stock-exp2b/entry.S`
e `clock.c`, ereditati da EXP2F (vedere `analysis/exp2f-candidate/README.md`).

- **Orologio:** `set_datetime`, richiesta cmd **126**, risposta cmd **128**.
  La prova isolata ha confermato questa asimmetria; il servizio correla
  esplicitamente la risposta 128 alla sola richiesta orologio 126.
  `time` è epoch UTC intero, `tz` secondi a ovest di UTC. Entrambi obbligatori:
  l'handler stock dereferenzia `tz` senza controllare che esista.
  L'handler stock converte `time - tz`; la patch EXP2B converte invece `time`
  in Europe/Rome, ignorando `tz`. Il server calcola i valori, non accetta
  timestamp arbitrari dal browser. Range limitato al time_t firmware a 32 bit.
  `get_parms/101.time` rappresenta l'ora locale RTC codificata come epoch:
  visualizzarla in UTC evita una seconda applicazione del fuso.
  L'ora legale viene ricalcolata alle sincronizzazioni, non garantita offline
  all'istante della transizione stagionale.
- **Riavvio:** `dev_control/102`, campo `reboot:1`. La sola presenza del campo
  attiva il riavvio: non inviare `reboot:0` come disattivazione. Non include
  `reset` o `sleep`. Dialogo esplicito nella UI; nessuna ripetizione automatica
  dopo riconnessione. La risposta positiva non certifica il ritorno online.
- **Pausa:** `play_record_file/207`, `suspend:1/0`, senza `type`. Il ciclo
  firmware legge il flag e attende 200 tick. La pausa esclude il timeout per
  assenza frame, ma resta la scadenza del player abbandonato dopo 8 secondi.
- **Audio:** stesso comando, `audio:1/0`, dopo avvio del player: `type:1`
  azzera il flag audio. Pacchetti ADPCM codec 11 e video codec 3 condividono
  il canale 3. Decoder e buffer separati dal microfono live; PCM mono 8 kHz,
  buffer breve in RAM, stop/disconnessione disabilitano l'audio. Browser senza
  permessi microfono. L'export AVI resta solo video. Sincronismo A/V non garantito.
- **Seek:** il comando memorizza `offset`, ma il ciclo playback esaminato non
  lo usa. Non è esposta una barra di avanzamento priva di effetto verificato.

## Memoria e registrazione

I log mostrano `vidBuf malloc failed` quando il player non trova 40.960 byte
contigui. QVGA riduce la pressione di memoria, ma non basta se il registratore
su evento crea contemporaneamente `temp.avi`. Prima del playback si richiede
modalità **Spenta**, riletta dalla camera. Nessuna modifica implicita della
modalità di registrazione dell'utente. Il live passa temporaneamente a QVGA
solo dopo aver salvato il profilo precedente; allo stop viene ripristinato.

## Prove

Suite: `PYTHONPATH=app python3 -m unittest discover -s app/tests -q`.
42 test, incluse validazione orologio, comandi esclusi, demultiplexing di video
frammentato e ADPCM, lease del player in pausa, profili temporanei.
Rapporti hardware in `app/evidence/extensions-*-20261022.json`.
Le risposte positive dei comandi senza frame o PCM non valgono come prova
positiva di riproduzione: i rapporti conservano i contatori effettivi.


### Esito hardware e UI

- Sincronizzazione: risposta 128 positiva alla richiesta 126; rilettura RTC con
  differenza **0 secondi** rispetto all'ora locale attesa. Pulsante web provato:
  messaggio «Ora riletta e verificata» (screenshot in evidence).
- Riavvio: la seriale ha mostrato risposta 102 positiva, sequenza di boot e
  inizializzazione SD. La sessione si è chiusa prima che il bridge ricevesse
  la conferma: l'API ha correttamente riportato esito non verificato. Il video
  è poi tornato disponibile. Il dialogo web è stato verificato e annullato
  senza eseguire un secondo riavvio non necessario.
- Playback dopo riavvio, registrazione spenta: 18 frame prima della pausa,
  22 dopo smaltimento dei pacchetti già inviati; contatore fermo a 22 durante
  5 secondi di pausa, poi 35 dopo ripresa. Audio: **72.960 byte PCM** ricevuti,
  cioè 36.480 campioni mono a 8 kHz. Qualità percepita e sincronismo A/V
  richiedono ascolto; non sono dedotti dalla sola ricezione.
- Un primo ciclo con eventi attivi, e il successivo prima del riavvio,
  accettavano i comandi ma non fornivano frame: non sono conteggiati come
  successi. La necessità di memoria contigua può richiedere riavvio anche
  dopo aver fermato il registratore.
- L'export sottrae gli intervalli di pausa dalla temporizzazione stimata;
  continua a non includere audio né garantire i timestamp originali.

Seek, gestione utenti, formattazione e correzione firmware dell'archivio eventi
non fanno parte di questa implementazione. Restano attività separate.
