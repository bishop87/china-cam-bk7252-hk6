"""Package EXP2 for review after bounded validation. Never install it."""
import json,struct,zlib
from pathlib import Path
from build_stock_patch import ROOT,sha,write_bundle,BOOT_SHA256
from rbl import HEADER,pack,unpack
from verify_stock_patch import verify_boot_decryption,verify_boot_custom_check

def main():
    source=ROOT/'analysis/exp2-candidate'
    payload=(source/'candidate-logical.bin').read_bytes()
    manifest=json.loads((source/'manifest.json').read_text())
    checks=json.loads((source/'emulation-validation.json').read_text())
    assert checks['passed'] and checks['candidate_sha256']==sha(payload)==manifest['candidate_sha256']
    boot=(ROOT/'analysis/original/bootloader-logical.bin').read_bytes()
    assert sha(boot)==BOOT_SHA256
    version='2M.1220-LAN-EXP2A'
    package=pack(payload,version,1792281600)
    old=HEADER.unpack((ROOT/'analysis/original/app-logical.bin').read_bytes()[0xfffa0:0x100000])
    fields=list(HEADER.unpack_from(package));fields[5]=old[5];fields[-1]=0
    header=HEADER.pack(*fields);header=header[:92]+struct.pack('<I',zlib.crc32(header[:92]))
    package=header+package[96:]
    assert unpack(package)[0]==payload
    assert len(package)<=0xcc000 and len(payload)+96<=0x110000
    boot_checks={'crypto':verify_boot_decryption(boot,package,payload),'custom_check':verify_boot_custom_check(boot,payload)}
    manifest.update(version=version,status='offline_validated_experimental_hardware_untested',ready_to_flash=False,ota_produced=True,payload_sha256=sha(payload),rbl_sha256=sha(package),rbl_bytes=len(package),ntp='europe.pool.ntp.org; exact UDP DNS to configured resolvers, standard NTP request to matching unexpired cache IP',readiness_note='Review package only. EXP1 installer is not compatible with this candidate. Hardware behavior, complete egress coverage and full-image rollback remain untested.')
    manifest['limitations'] = [x.replace('Appending executable code requires bootloader bounds and image-layout validation before OTA packaging', 'Appended code fits the declared app partition; execution from the appended area remains hardware-untested') for x in manifest['limitations']]
    readme='''# HK6 EXP2A — candidato sperimentale

**Pacchetto verificato offline, non ancora collaudato sulla camera.**
Questa revisione corregge il rifiuto delle richieste NTP in pbuf concatenati.
La camera conserva EXP2; questa revisione non è ancora installata.
Non usare gli installer EXP1/EXP2 senza aggiornare i controlli,
né scrivere questi file a offset fisici.

Deriva da EXP1 e aggiunge un controllo all'uscita IPv4 lwIP: LAN determinata
tramite IP/netmask dell'interfaccia, DHCP iniziale e broadcast UDP consentiti;
destinazioni esterne e DNS TCP/UDP porta 53 respinti, salvo eccezione NTP.
NTP originale riabilitato verso europe.pool.ntp.org: consentita solo la domanda
DNS A esatta ai resolver configurati e una richiesta standard da 48 byte UDP/123
verso l’IP nella cache DNS valida di quel nome. Nessun IP pubblico fissato.
Multicast e IP_HDRINCL sono respinti in questa versione sperimentale.
Non è un firmware open source, non aggiunge RTSP/MJPEG.

Il codice e le costanti aggiunti occupano 729 byte dopo il payload originale; una chiamata
Thumb sostituisce quattro byte del prologo della funzione IPv4 originale.
Validazioni: 25 casi di confine; replay di 13 pacchetti UDP reali (11 respinti,
2 DHCP ammessi); 128 casi dell’eccezione NTP e delle catene pbuf, quattro slot della cache verificati
con il resolver originale e richiesta prodotta dalla routine NTP originale; 5 confronti con l'uscita IPv4 originale fino al callback del
driver, incluso ritorno di errore. Contenitore e AES del bootloader verificati.
Queste prove non simulano radio, scheduling, intero sistema operativo o
l'installazione completa. La copertura di uscite alternative/raw e IPv6 non è
stata dimostrata. Il salto NetworkDetect di EXP1 rimane; i dati anomali osservati
non sono stati riparati, ma le destinazioni corrispondenti vengono respinte.

.bin è il payload logico; .rbl è il contenitore OTA per app. Bootloader e
configurazioni non sono inclusi. Mantenere l'isolamento esterno durante le prove.
Il recupero UART è provato su un settore; il ripristino completo rimane da provare.

Rigenerazione, dalla radice del progetto:

```sh
.venv/bin/python tools/build_exp2_candidate.py
.venv/bin/python tools/verify_exp2_candidate.py
.venv/bin/python tools/package_exp2_candidate.py
```
'''
    files={'hk6-stock-lan-exp2a.bin':payload,'hk6-stock-lan-exp2a.rbl':package,'manifest.json':(json.dumps(manifest,indent=2)+'\n').encode(),'emulation-validation.json':(source/'emulation-validation.json').read_bytes(),'bootloader-validation.json':(json.dumps(boot_checks,indent=2)+'\n').encode(),'README.md':readme.encode()}
    archive=write_bundle(ROOT/'dist/hk6-stock-lan-exp2a',files)
    print(f'{archive}: {len(payload)} raw bytes, {len(package)} RBL bytes; offline checks passed; NOT installed.')

if __name__=='__main__':main()
