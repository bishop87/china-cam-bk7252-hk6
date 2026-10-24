"""Export stock HK6 microSD evidence; no camera connection or filesystem writes on SD."""
from pathlib import Path
import hashlib
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
ROOT=Path(__file__).resolve().parents[1]
source=ROOT/'analysis/original/app-logical.bin'
b=source.read_bytes()
assert hashlib.sha256(b).hexdigest()=='8f2e8d40497634a801fffb4c28c54d1d19400c08a0286ba1e6b365997163d900'
windows=[('get_sd',0x18704,0x18816),('get_alarm',0x18840,0x189ac),
 ('set_alarm',0x189ac,0x18b0c),('set_sd',0x18ec0,0x18f98),
 ('get_record_day',0x19598,0x196b8),('get_record_hour',0x196b8,0x197bc),
 ('get_record_min',0x197bc,0x19958),('play_record_file',0x19958,0x19aaa),
 ('dispatcher',0x19f28,0x1a110),('space_management',0x1a3b4,0x1a3d8),
 ('record_motion',0x1a600,0x1a87c),('record_container',0x1a8ee,0x1a97e)]
m=Cs(CS_ARCH_ARM,CS_MODE_THUMB);m.skipdata=True
lines=['Stock SHA256 '+hashlib.sha256(b).hexdigest()]
for name,start,end in windows:
 lines.append('\n# '+name)
 for i in m.disasm(b[start-65536:end-65536],start):
  extra=''
  if i.mnemonic=='ldr' and '[pc, #' in i.op_str:
   a=((i.address+4)&~3)+int(i.op_str.split('#')[1].split(']')[0],0)-65536
   if 0<=a<len(b)-4:
    v=struct.unpack_from('<I',b,a)[0];extra=' ; '+hex(v)
    if 65536<=v<65536+len(b):
     raw=b[v-65536:v-65536+100].split(b'\0')[0]
     if raw and all(32<=c<127 for c in raw):extra+=' '+repr(raw.decode())
  lines.append(f'{i.address:08x} {i.mnemonic:8} {i.op_str}{extra}')
out=ROOT/'analysis/original/reverse/sd-support.asm';out.write_text('\n'.join(lines)+'\n');print(out)
