# Preparazione del repository pubblico — 24 ottobre 2026

Repository: https://github.com/bishop87/china-cam-bk7252-hk6

## Revisione eseguita

- README aggiornato a HTTP1, distinta la Web UI locale dal server video sulla camera.
- Integrate quattro foto della board e istruzioni UART; rimosse dalle copie pubbliche le sezioni EXIF GPS e gli altri metadati, preservando orientamento e dati JPEG.
- Aggiornata la guida applicativa e aggiunte cronologia, istruzioni di sviluppo, attribuzioni e regole per contribuire.
- Esclusi da Git backup, estrazioni APK, log, catture, registrazioni, configurazioni Wi-Fi, SDK, toolchain, output di build e pacchetti firmware con parti proprietarie. Gli originali rimangono nel laboratorio locale.
- Rimossi MAC e identificativo dell'adattatore dai default degli strumenti diagnostici: ora sono argomenti espliciti.
- Pubblicati soltanto tre report HTTP1 di metadati revisionati; IP della camera sostituito con un indirizzo riservato alla documentazione.
- Preparato un modello CI su Python 3.10/3.12, test C con sanitizzatori e controllo dei file indicizzati. La creazione del workflow attivo è stata rifiutata da GitHub perché il token salvato non dispone dello scope `workflow`; il modello è pubblicato in `docs/github-actions-checks.yml`.

## Verifica prima del primo commit

La suite è stata eseguita sia nel laboratorio completo sia in una copia esportata dall'indice Git, priva di tutti gli input esclusi.

| Verifica | Esito locale |
| --- | --- |
| Applicazione | 42 test passati, anche nella copia pubblica |
| Strumenti con input di laboratorio | 54 test passati |
| Strumenti nella copia pubblica | 54 test raccolti, 35 passati e 19 saltati per input privati assenti |
| Nucleo HTTP stock | 13 gruppi passati, AddressSanitizer e UndefinedBehaviorSanitizer |
| Prototipo LocalCam HTTP | Test host passati |
| Foto | Solo orientamento EXIF; dati JPEG confrontati con le copie originali ripulite |
| Contenuto pubblico | Controllo di percorsi vietati, file binari inattesi, pattern di segreti, metadati foto e link locali |
| Configurazione privata | Password Wi-Fi locale assente dall'indice |

Sono prove host su macOS; GitHub Actions non è ancora attivo. Non sono state effettuate nuove scritture o prove sulla camera durante la preparazione del repository.

La licenza generale dei contributi originali resta da scegliere; provenienze e limiti di riutilizzo sono descritti in [THIRD_PARTY.md](../THIRD_PARTY.md). Non viene attribuita implicitamente una licenza ai componenti vendor.
