"""Append clock conversion to pinned EXP2A; preserve network filter byte-for-byte."""
from pathlib import Path
import hashlib,json,struct,subprocess
from elftools.elf.elffile import ELFFile
from build_stock_patch import ROOT,sha
from build_exp2_candidate import branch_link
OUT=ROOT/'analysis/exp2b-candidate'
def main():
 raw=(ROOT/'dist/hk6-stock-lan-exp2a/hk6-stock-lan-exp2a.bin').read_bytes()
 assert sha(raw)=='629543c6287118b0d3bcf130f67c4d13968f75b234fbb5c67c19b0a948a47620'
 OUT.mkdir(exist_ok=True);addr=0x10000+((len(raw)+3)&~3)
 tool=str(ROOT/'tools/gcc-arm-none-eabi-5_4-2016q3/bin/arm-none-eabi-')
 subprocess.run([tool+'gcc','-mcpu=arm968e-s','-mthumb','-Os','-ffreestanding','-fno-builtin','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fno-stack-protector','-nostdlib',str(ROOT/'firmware/stock-exp2b/entry.S'),str(ROOT/'firmware/stock-exp2b/clock.c'),'-Wl,--build-id=none','-Wl,-e,hk6_app_clock','-Wl,-Ttext='+hex(addr),'-lgcc','-o',str(OUT/'clock.elf')],check=True)
 subprocess.run([tool+'objcopy','-O','binary','--only-section=.text','--only-section=.rodata',str(OUT/'clock.elf'),str(OUT/'clock.bin')],check=True)
 with (OUT/'clock.elf').open('rb') as f:
  elf=ELFFile(f);symbols={s.name:s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name in ['hk6_app_clock','hk6_rome']}
  assert not any(s['sh_size'] for s in elf.iter_sections() if s.name in ('.data','.bss'))
 candidate=bytearray(raw)+b'\xff'*(addr-0x10000-len(raw))+(OUT/'clock.bin').read_bytes()
 patches=[]
 def patch(address,before,after):
  off=address-0x10000
  assert raw[off:off+len(before)]==before and len(before)==len(after)
  candidate[off:off+len(after)]=after;patches.append({'address':hex(address),'before':before.hex(),'after':after.hex()})
 patch(0x19b50,bytes.fromhex('436903a89b1a0393'),branch_link(0x19b50,symbols['hk6_app_clock']&~1)+b'\xc0\x46'*2)
 patch(0x584da,bytes.fromhex('e123db01c018'),branch_link(0x584da,symbols['hk6_rome']&~1)+b'\xc0\x46')
 old=b'The system time is updated. Timezone is %d.\n\0';new=b'Time updated. Timezone: Europe/Rome.\n\0'
 patch(0xca46e,old,new.ljust(len(old),b'\0'))
 assert candidate[0xc9a44:len(raw)]==raw[0xc9a44:]
 report={'version':'2M.1220-LAN-EXP2B','status':'offline_candidate_not_installed','payload_sha256':sha(candidate),'previous_sha256':sha(raw),'appended_address':hex(addr),'appended_bytes':len(candidate)-(addr-0x10000),'payload_bytes':len(candidate),'symbols':symbols,'patches':patches,'timezone':'Europe/Rome modern EU rules, 1996 through signed-32-bit epoch limit','scope':'Offset chosen at NTP/app clock update; continuous offline DST transition not implemented; network guard unchanged'}
 (OUT/'candidate-logical.bin').write_bytes(candidate);(OUT/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
