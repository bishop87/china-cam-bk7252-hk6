"""Package clock-only EXP2C after code and bootloader validation, no installation."""
import json,struct,zlib
from build_stock_patch import ROOT,sha,write_bundle,BOOT_SHA256
from rbl import HEADER,pack,unpack
from verify_stock_patch import verify_boot_decryption,verify_boot_custom_check

def main():
 d=ROOT/'analysis/exp2c-candidate';payload=(d/'candidate-logical.bin').read_bytes()
 m=json.loads((d/'manifest.json').read_text());v=json.loads((d/'validation.json').read_text())
 assert v['passed'] and v['payload_sha256']==m['payload_sha256']==sha(payload)
 boot=(ROOT/'analysis/original/bootloader-logical.bin').read_bytes();assert sha(boot)==BOOT_SHA256
 package=pack(payload,m['version'],1792281600)
 old=HEADER.unpack((ROOT/'analysis/original/app-logical.bin').read_bytes()[0xfffa0:0x100000]);fields=list(HEADER.unpack_from(package));fields[5]=old[5];fields[-1]=0
 header=HEADER.pack(*fields);package=header[:92]+struct.pack('<I',zlib.crc32(header[:92]))+package[96:]
 assert unpack(package)[0]==payload and len(package)<=0xcc000 and len(payload)+96<=0x110000
 b={'crypto':verify_boot_decryption(boot,package,payload),'custom_check':verify_boot_custom_check(boot,payload)}
 m.update(status='offline_validated_not_installed',ready_to_flash=False,rbl_sha256=sha(package),rbl_bytes=len(package))
 readme="""# EXP2C — firma UART

Aggiunge patched by Bishop87 dopo HI704 init finish. Solo il puntatore al
testo e una stringa aggiunta cambiano rispetto a EXP2B; codice eseguibile,
risoluzione, filtro LAN/NTP e Europe/Rome restano invariati.

Pacchetto sperimentale. Consultare hardware-validation.json quando presente
per l’esito dell’installazione. Ripristino UART completo non collaudato.

Rigenerazione: tools/build_exp2c_candidate.py e tools/package_exp2c_candidate.py
con .venv/bin/python. Non usare gli installer delle revisioni precedenti.
"""
 files={'hk6-stock-lan-exp2c.bin':payload,'hk6-stock-lan-exp2c.rbl':package,'manifest.json':(json.dumps(m,indent=2)+'\n').encode(),'validation.json':(d/'validation.json').read_bytes(),'bootloader-validation.json':(json.dumps(b,indent=2)+'\n').encode(),'README.md':readme.encode()}
 print(write_bundle(ROOT/'dist/hk6-stock-lan-exp2c',files))
if __name__=='__main__':main()
