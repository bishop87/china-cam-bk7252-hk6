# Provenienza, attribuzioni e distribuzione

Questo repository raccoglie codice e documentazione del progetto HK6 di Bishop87. Non è associato a Beken, al produttore della camera o a HDWifiCamPro.

## Materiale non distribuito

APK e risorse HDWifiCamPro, librerie native, manuale vendor, dump originali, backup, firmware modificati contenenti codice vendor, SDK e toolchain rimangono input locali. Il repository non attribuisce diritti su questi materiali. Le patch richiedono immagini esatte ottenute e conservate separatamente.

## Riferimenti del protocollo

- [hyc/a9serv](https://github.com/hyc/a9serv), commit consultato `10d686d1aa30749afd8b4dfe2875fb65313244ed`: formato wire, algoritmo e tabella di offuscamento usati come riferimento per `app/protocol.py`.
- [datenstau/A9_PPPP](https://github.com/datenstau/A9_PPPP): riferimento storico per camere HDWifiCamPro.

La tabella wire è una costante di protocollo, non una credenziale dell'utente. Il checkout a9serv consultato non conteneva un file LICENSE: **questa pubblicazione non presenta quelle parti come MIT, Apache o liberamente rilicenziabili**. Prima di riutilizzare o ridistribuire componenti derivati occorre chiarire i termini con i rispettivi titolari.

## SDK e prototipo LocalCam

- [Beken7252 OpenCam](https://github.com/daniel-dona/beken7252-opencam).
- [daniel-dona/bdk_rtt](https://github.com/daniel-dona/bdk_rtt), SDK fissato al commit `266d54fd8965a093d345c1a1cdb6ca26da6a6488` in `tools/prepare_build.py`.
- [hid_download_py](https://github.com/OpenBekenIOT/hid_download_py), riferimento per la comunicazione bootloader.

I checkout esterni non sono inclusi. Conservare e rispettare le licenze dei componenti effettivamente utilizzati, comprese le parti RT-Thread e le librerie radio precompilate. Una build da SDK non è automaticamente un firmware interamente open source.

## Foto e documentazione

Le quattro fotografie in `docs/images/` sono quelle della board usate nel progetto, fornite da Bishop87 e pubblicate su sua richiesta. Non provengono da un datasheet o da una board di terzi. L'articolo e le guide sono documentazione del progetto.

## Licenza del progetto

Non è ancora stata scelta una licenza generale di riutilizzo per i contributi originali. In assenza di una concessione esplicita restano riservati i relativi diritti. La visibilità pubblica su GitHub non sostituisce una licenza. Questo file documenta le provenienze e non concede diritti sui componenti esterni.
