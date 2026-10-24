# Sviluppo e riproducibilità

## Applicazione

Python 3.10+, sola libreria standard. Il comando di avvio e i test sono nel [README](../readme.md). Non servono APK, firmware o SDK per eseguire la Web UI e i suoi test con camera simulata.

## Test host degli strumenti

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r tools/requirements.txt
PYTHONPATH=app .venv/bin/python -m unittest discover -s app/tests -v
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
python3 tools/check_publication.py
```

Le dipendenze di analisi sono Capstone, Unicorn, pyelftools e cryptography; SCons serve per il prototipo da SDK. Pillow, in `tools/requirements-validation.txt`, serve soltanto per decodificare completamente i JPEG nel collaudo HTTP reale.

I test che leggono dump, catture o pacchetti OTA non pubblicati hanno `skipUnless` sul relativo input: in un clone pulito risultano **saltati**, mentre parser, controlli HTTP e test sintetici continuano a girare. Non è una validazione di una build firmware assente. I test con artefatti si riattivano soltanto quando gli input sono presenti.

Per il trasporto firmware:

```sh
cc -std=c99 -Wall -Wextra -Werror -fsanitize=address,undefined \
  tests/test_stock_http.c firmware/stock-http/http.c -o /tmp/hk6-stock-http-test
/tmp/hk6-stock-http-test
cc -std=c99 -Wall -Wextra -Werror -Itests tests/test_http.c -o /tmp/hk6-localcam-test
/tmp/hk6-localcam-test
```

Il modello [GitHub Actions](github-actions-checks.yml) configura questi controlli host su Linux, Python 3.10 e 3.12. Per attivarlo copiarlo in `.github/workflows/checks.yml` e pubblicarlo con credenziali abilitate a modificare i workflow. Il token disponibile durante la prima pubblicazione non disponeva di tale permesso: la CI non è ancora attiva. Il modello non aggiorna dispositivi e non contiene credenziali.

## Input di laboratorio esclusi

| Percorso locale | Contenuto / necessità |
| --- | --- |
| `analysis/backups/` | Backup della singola camera, checkpoint e configurazione potenzialmente privata |
| `analysis/original/` | Estrazioni del firmware esatto: necessarie per analisi e prima patch |
| `analysis/hdwificampro/` | APK decodificato e librerie per confronto decoder/protocollo |
| `analysis/network/`, `analysis/uart/` | Catture e log grezzi; possono contenere credenziali e identificativi |
| `upstream/` | Checkout SDK e riferimenti, con licenze proprie |
| `tools/gcc-arm-none-eabi-5_4-2016q3/` | Toolchain ARM GCC 5.4 per le build storiche |
| `build/`, `dist/` | Output generati, manifest e firmware con componenti vendor |
| `firmware/local-config.json` | Configurazione Wi-Fi privata del prototipo LocalCam |
| `app/evidence/` | Evidenze originali e screenshot, non pubblicati automaticamente |

I percorsi citati nei rapporti storici descrivono file locali, non download mancanti dal repository. Le sintesi pubbliche sono in `docs/`; non ricreare fixture false con nomi o hash attesi per aggirare le verifiche.

## Catena firmware originale → HTTP1

Gli script operano su payload fissati per SHA-256. La catena documentata è EXP1 → EXP2 → EXP2A → EXP2B → EXP2C → EXP2D → EXP2E → EXP2F → HTTP1. Le revisioni C/D riguardano l'attribuzione nel log; E/F le dimensioni encoder. Il codice nuovo di filtro, orologio e server è in `firmware/stock-*`.

Per riprodurre servono la stessa immagine originale, estrazioni coerenti e artefatti intermedi generati dagli script `build_*`, `verify_*`, `package_*`. Il repository pubblico da solo **non può produrre il firmware stock modificato**, perché non distribuisce il payload proprietario di partenza. Non esiste un comando di flashing generico per camere simili.

`tools/build_http_candidate.py` produce il payload logico da EXP2F; `tools/verify_http_candidate.py` verifica i percorsi ARM; `tools/package_http_candidate.py` confeziona RBL e rollback. Le cartelle di analisi generate devono esistere prima di avviare la catena. L'ABI è quella della nostra immagine: indirizzi diversi richiedono nuovo studio.

Il prototipo alternativo LocalCam si prepara con l'SDK fissato in `tools/prepare_build.py` e `tools/build.sh`. È compilato, ma non collaudato sulla HK6; il suo layout e le ipotesi hardware non vanno confusi con il firmware HTTP1 installato.

## Diagnostica hardware

Backup e comandi seriali richiedono la porta reale, per esempio `/dev/cu.usbserial-XXXX`. `tools/probe_http_memory.py` richiede ora `--port`; la cattura macOS `tools/capture_hk6_network.py` richiede `--camera-mac`. Quest'ultima è specifica del laboratorio HK6-LAB su `bridge100`, con indirizzi e guardie firewall espliciti: non è una cattura universale.

```sh
python3 tools/probe_http_memory.py --port /dev/cu.usbserial-XXXX --output /tmp/hk6-memory.json
python3 tools/check_native_http.py --camera 192.168.1.54 --seconds 120 --output /tmp/hk6-http.json
```

Sostituire l'IP di esempio. L'ultimo comando richiede Pillow e occupa lo stream sequenziale durante la prova. Log e dati acquisiti restano privati; pubblicare soltanto sintesi revisionate.
