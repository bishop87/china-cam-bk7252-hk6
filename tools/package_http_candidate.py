"""Package HTTP1 and retain byte-exact EXP2F OTA rollback; never install."""
import json,struct,zlib
from build_stock_patch import ROOT,sha,write_bundle,BOOT_SHA256
from rbl import HEADER,pack,unpack
from verify_stock_patch import verify_boot_decryption,verify_boot_custom_check
VERSION='2M.1220-LAN-HTTP1'

def main():
 d=ROOT/'analysis/http-candidate';payload=(d/'candidate-logical.bin').read_bytes()
 m=json.loads((d/'manifest.json').read_text());v=json.loads((d/'validation.json').read_text())
 n=json.loads((d/'network-check/emulation-validation.json').read_text())
 assert v['passed'] and n['passed'] and v['payload_sha256']==m['payload_sha256']==n['candidate_sha256']==sha(payload)
 for name,digest in m['source_files'].items():assert sha((ROOT/name).read_bytes())==digest
 boot=(ROOT/'analysis/original/bootloader-logical.bin').read_bytes();assert sha(boot)==BOOT_SHA256
 previous=(ROOT/'dist/hk6-stock-lan-exp2f/hk6-stock-lan-exp2f.rbl').read_bytes()
 previous_payload,previous_meta=unpack(previous)
 assert sha(previous)=='c65fe022b5e267525507685d50c837d6f95c8f952cf44361993e9fc5c7071c39'
 assert sha(previous_payload)==m['source_sha256']
 package=pack(payload,VERSION,1792713600)
 fields=list(HEADER.unpack_from(package));fields[5]=HEADER.unpack_from(previous)[5];fields[-1]=0
 header=HEADER.pack(*fields);package=header[:92]+struct.pack('<I',zlib.crc32(header[:92]))+package[96:]
 assert unpack(package)[0]==payload and len(package)<=0xcc000 and len(payload)+96<=0x110000
 b={'crypto':verify_boot_decryption(boot,package,payload),'custom_check':verify_boot_custom_check(boot,payload)}
 m.update(version=VERSION,status='packaged_for_controlled_hardware_trial',hardware_tested=False,rbl_sha256=sha(package),rbl_bytes=len(package),rollback_rbl_sha256=sha(previous),rollback_payload_sha256=sha(previous_payload),ota_produced=True)
 files={'hk6-stock-http1.bin':payload,'hk6-stock-http1.rbl':package,
 'rollback-exp2f.rbl':previous,'manifest.json':(json.dumps(m,indent=2)+'\n').encode(),
 'validation.json':(d/'validation.json').read_bytes(),'bootloader-validation.json':(json.dumps(b,indent=2)+'\n').encode(),
 'README.md':b'# HTTP1 controlled trial\n\nUse only tools/ota_http.py with live UART preflight. No hardware test yet. rollback-exp2f.rbl is the pinned prior release. This is not a physical flash image.\n'}
 print(write_bundle(ROOT/'dist/hk6-stock-http1',files))
 print(json.dumps({'version':VERSION,'rbl_sha256':sha(package),'rbl_bytes':len(package),'payload_sha256':sha(payload)}))
if __name__=='__main__':main()
