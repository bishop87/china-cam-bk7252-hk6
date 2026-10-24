# HTTP1: risultati hardware

Collaudo del 23 ottobre 2026 su HK6_V0.1D230606, BK7252UQN48, HI704. Firmware `2M.1220-LAN-HTTP1`, derivato da EXP2F.

| Prova | Risultato |
| --- | --- |
| Installazione OTA locale | Download, riavvio, header e regioni modificate riletti e verificati |
| Pagina e snapshot | Risposta nativa sulla porta 80; JPEG 640×480 |
| Primo stream, 30 secondi | 92 JPEG completamente decodificati, circa 3,06 fps |
| Stream di due minuti | 363 JPEG distinti in 120,11 s, circa 3,02 fps; 13251–13571 byte/frame |
| Riconnessioni | Sei stream interrotti, ognuno seguito da snapshot valido |
| Richiesta incompleta | Server di nuovo accessibile dopo chiusura della richiesta |
| Stack HTTP | 4096 byte, massimo osservato 47% |
| Heap durante video | 79772–80928 byte disponibili nel pool principale |
| Heap a sessioni chiuse | 117128–121928 byte disponibili |

Il test usava un client Python diretto alla porta 80 della camera, senza bridge sulla porta 8765 e senza app vendor. I report pubblicati in [evidence](evidence/) contengono soltanto metadati; nessuna immagine, credenziale o identificativo hardware. Gli IP sono stati sostituiti con indirizzi d'esempio.

RBL verificato in laboratorio: SHA-256 `dbeb8d8d848f3504d33b444e9a651d53948f661d0e9395e8b70ed86ba558ddd9`, 562272 byte. Payload: SHA-256 `59065131195ae6823e28858c0de3b61a6aa12d9f12768f8123d820f06922c4f7`, 830289 byte. Questi hash identificano il campione collaudato, non un file distribuito nel repository.

La rilettura ha verificato header, siti modificati e regione aggiunta; non è una rilettura completa della flash. Registrazione continua e su evento erano disattivate, come verificato prima dell'OTA. La ripresa dell'heap è compatibile con il rilascio del buffer, ma non dimostra assenza assoluta di leak.

## Limiti

Un solo spettatore, video senza audio, riconnessione manuale. Limite richiesto di cinque frame/s, risultato misurato circa tre. Chrome Android, registrazione SD contemporanea, playback concorrente e funzionamento prolungato restano da collaudare. HTTP è privo di autenticazione/TLS, per uso in LAN fidata.

Il rollback EXP2F è stato preparato e verificato su file, non eseguito dopo il collaudo HTTP1. Il recupero UART completo dell'applicazione non è stato provato; è stato verificato il ripristino di un settore.
