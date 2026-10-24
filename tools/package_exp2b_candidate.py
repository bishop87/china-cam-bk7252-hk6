"""Package clock-only EXP2B after code and bootloader validation, no installation."""
import json,struct,zlib
from build_stock_patch import ROOT,sha,write_bundle,BOOT_SHA256
from rbl import HEADER,pack,unpack
from verify_stock_patch import verify_boot_decryption,verify_boot_custom_check

def main():
 d=ROOT/'analysis/exp2b-candidate';payload=(d/'candidate-logical.bin').read_bytes()
 m=json.loads((d/'manifest.json').read_text());v=json.loads((d/'validation.json').read_text())
 assert v['passed'] and v['payload_sha256']==m['payload_sha256']==sha(payload)
 boot=(ROOT/'analysis/original/bootloader-logical.bin').read_bytes();assert sha(boot)==BOOT_SHA256
 package=pack(payload,m['version'],1792281600)
 old=HEADER.unpack((ROOT/'analysis/original/app-logical.bin').read_bytes()[0xfffa0:0x100000]);fields=list(HEADER.unpack_from(package));fields[5]=old[5];fields[-1]=0
 header=HEADER.pack(*fields);package=header[:92]+struct.pack('<I',zlib.crc32(header[:92]))+package[96:]
 assert unpack(package)[0]==payload and len(package)<=0xcc000 and len(payload)+96<=0x110000
 b={'crypto':verify_boot_decryption(boot,package,payload),'custom_check':verify_boot_custom_check(boot,payload)}
 m.update(status='offline_validated_not_installed',ready_to_flash=False,rbl_sha256=sha(package),rbl_bytes=len(package))
 readme='''# EXP2B — Europe/Rome

Revisione offline, non installata. Parte dal payload EXP2A fissato per hash;
il codice del filtro DNS/NTP e tutti i vincoli sul pool restano byte-identici.

Corregge il fuso in due percorsi: sincronizzazione NTP e comando set_datetime
dell’app. Usa la data UTC per scegliere UTC+1/UTC+2 secondo le regole moderne
EU di Europe/Rome (1996–limite time_t 32 bit). Ignora il tz dell’app, che usa
getRawOffset senza ora legale. Non aggiunge traffico di rete.

La conversione avviene quando l’orologio viene impostato. NON implementa ancora
un timer per spostare l’ora al cambio stagionale senza una nuova sincronizzazione.
Questa limitazione va risolta/verificata prima di promettere DST offline continuo.

Validazione: migliaia di confronti con ZoneInfo, transizioni marzo/ottobre,
anni bisestili, ABI dei due hook e intera regressione della rete EXP2A.
RBL e decifratura col bootloader originale verificati. Non collaudato su hardware;
il ripristino UART completo resta non provato. Non usare installer EXP2A.

Fonti: https://data.iana.org/time-zones/tzdb/europe ; codice app locale e
analysis/network/hk6-lab/capture-20261018-202036/uart-readable.txt (contiene
anche dati privati, non distribuirlo). Rapporto: analysis/exp2b-candidate/README.md.

Rigenerazione:

```sh
.venv/bin/python tools/build_exp2b_candidate.py
.venv/bin/python tools/verify_exp2b_candidate.py
.venv/bin/python tools/package_exp2b_candidate.py
```
'''
 files={'hk6-stock-lan-exp2b.bin':payload,'hk6-stock-lan-exp2b.rbl':package,'manifest.json':(json.dumps(m,indent=2)+'\n').encode(),'validation.json':(d/'validation.json').read_bytes(),'network-validation.json':(d/'network-check/emulation-validation.json').read_bytes(),'bootloader-validation.json':(json.dumps(b,indent=2)+'\n').encode(),'README.md':readme.encode()}
 print(write_bundle(ROOT/'dist/hk6-stock-lan-exp2b',files))
if __name__=='__main__':main()
