"""Build an offline HTTP candidate pinned to EXP2F. Never package OTA or flash."""
import hashlib,json,subprocess
from elftools.elf.elffile import ELFFile
from build_stock_patch import ROOT
from build_exp2_candidate import branch_link
OUT=ROOT/'analysis/http-candidate'
SOURCE=ROOT/'dist/hk6-stock-lan-exp2f/hk6-stock-lan-exp2f.bin'
SHA='981d33db1b1af8b94bdcfc98e369214b312a2f4d00b82aacdcbc0a962f50ea5d'
def main():
 raw=SOURCE.read_bytes();assert hashlib.sha256(raw).hexdigest()==SHA
 OUT.mkdir(exist_ok=True);addr=65536+((len(raw)+3)&~3)
 tool=str(ROOT/'tools/gcc-arm-none-eabi-5_4-2016q3/bin/arm-none-eabi-')
 src=ROOT/'firmware/stock-http'
 cmd=[tool+'gcc','-mcpu=arm968e-s','-mthumb','-Os','-std=c99','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fno-stack-protector','-nostdlib',str(src/'http.c'),str(src/'stock.c'),str(src/'entry.S'),'-Wl,--build-id=none','-Wl,-e,hk6_boot','-Wl,-Ttext='+hex(addr),'-lgcc','-o',str(OUT/'http.elf')]
 subprocess.run(cmd,check=True)
 with (OUT/'http.elf').open('rb') as f:
  e=ELFFile(f);symbols={s.name:s['st_value'] for s in e.get_section_by_name('.symtab').iter_symbols() if s.name.startswith('hk6_')}
  assert not any(s['sh_size'] for s in e.iter_sections() if s.name in ('.data','.bss'))
  assert not any(s['st_shndx']=='SHN_UNDEF' and s.name for s in e.get_section_by_name('.symtab').iter_symbols())
 subprocess.run([tool+'objcopy','-O','binary','--only-section=.text','--only-section=.rodata',str(OUT/'http.elf'),str(OUT/'http.bin')],check=True)
 candidate=bytearray(raw)+b'\xff'*(addr-65536-len(raw))+(OUT/'http.bin').read_bytes();patches=[]
 for site,before,name in [(0x16da0,branch_link(0x16da0,0x1aca8),'hk6_boot'),(0x1a628,branch_link(0x1a628,0x2837c),'hk6_read'),(0x1a72e,bytes.fromhex('6648')+branch_link(0x1a730,0x5c2e8),'hk6_idle_gate')]:
  off=site-65536
  assert raw[off:off+len(before)]==before,(hex(site),raw[off:off+len(before)].hex(),before.hex())
  after=branch_link(site,symbols[name]&~1)+bytes.fromhex('c046')*(len(before)==6)
  candidate[off:off+len(before)]=after
  patches.append(dict(address=hex(site),before=before.hex(),after=after.hex(),symbol=name))
 assert len(candidate)+96<=0x110000
 (OUT/'candidate-logical.bin').write_bytes(candidate)
 report=dict(status='offline_candidate_not_for_installation',source_sha256=SHA,payload_sha256=hashlib.sha256(candidate).hexdigest(),payload_bytes=len(candidate),appended_address=hex(addr),appended_bytes=len(candidate)-(addr-65536),symbols=symbols,patches=patches,ota_produced=False,hardware_writes=False,source_files={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (src/'http.h',src/'http.c',src/'stock.c',src/'entry.S')},limitations=['No hardware HTTP test','Normal boot branch only','Single sequential client; queued clients wait','LAN HTTP without authentication/TLS','Native playback can prevent acquisition; HTTP returns 503 on missing frames','Shared-state lifetime and real scheduler require hardware validation'])
 (OUT/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
