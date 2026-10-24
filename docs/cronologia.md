# Cronologia del progetto

Ottobre 2026. I risultati si riferiscono alla nostra HK6 e non a tutta la famiglia BK7252.

| Fase | Lavoro e risultato |
| --- | --- |
| 15–16 ottobre | Analisi HDWifiCamPro e contenitore OTA RBL; primo prototipo LocalCam da SDK compilato, ma non installato sulla HK6 |
| 16–17 ottobre | Identificazione UART, RT-Thread e sensore HI704; mappa partizioni e backup di 2 MiB; verifica bootloader e scrittura/ripristino di un settore |
| EXP1 | Prima patch di sette byte; OTA riuscito e video nell'app vendor anche senza Internet. Le catture mostrano tentativi esterni residui |
| EXP2 / EXP2A | Filtro di uscita LAN con eccezioni DNS/NTP controllate; correzione delle richieste NTP suddivise in più buffer |
| EXP2B | Conversione Europe/Rome per app e NTP, verificata anche sui cambi stagionali. Conversione applicata alle sincronizzazioni |
| EXP2C / EXP2D | Attribuzione UART, poi collocazione della firma nel banner di avvio; nessuna nuova funzione video |
| 19 ottobre | Primo ricevitore Python PPPP: JPEG reale 640×352 e MJPEG nel browser |
| 20 ottobre, EXP2E / EXP2F | Correzione encoder a VGA 640×480 e QVGA 320×240; integrazione profili e impostazioni nella Web UI |
| 21 ottobre | Microfono live: ADPCM, decodifica PCM e toggle web |
| 21–22 ottobre | MicroSD FAT32 2 GB, registrazione, ricerca, playback ed export AVI; diagnosi memoria e nomi incompatibili dei file evento |
| 22 ottobre | Orologio, riavvio, pausa/ripresa e audio dei filmati nella Web UI |
| 23 ottobre, HTTP1 | Server sulla camera: pagina, snapshot e MJPEG. Installazione verificata, 640×480 a circa 3 fps, test di due minuti e sei riconnessioni |
| 24 ottobre | Preparazione del repository pubblico: foto della board, documentazione corrente, separazione degli input privati e test eseguibili senza dump |

Lettura narrativa: [dalla camera al browser](dalla-camera-al-browser.md). Risultati dell'ultima versione: [collaudo HTTP1](collaudo-http1.md).
