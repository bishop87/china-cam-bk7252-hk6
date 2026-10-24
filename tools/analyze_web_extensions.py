"""Read-only stock HK6 evidence for clock, reboot and playback controls."""
from pathlib import Path
import hashlib
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
root=Path(__file__).resolve().parents[1]
data=(root/'analysis/original/app-logical.bin').read_bytes()
assert hashlib.sha256(data).hexdigest()=='8f2e8d40497634a801fffb4c28c54d1d19400c08a0286ba1e6b365997163d900'
engine=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
lines=[]
for name,start,end in [('device',0x17fb4,0x180fa),('clock',0x19af4,0x19bcc),('playback_control',0x19958,0x19a80),('playback_loop',0x1af88,0x1b130),('event_filter',0x1b3bc,0x1b3c2)]:
 lines.append('\n# '+name)
 for ins in engine.disasm(data[start-65536:end-65536],start):
  extra=''
  if ins.mnemonic=='ldr' and '[pc, #' in ins.op_str:
   address=((ins.address+4)&~3)+int(ins.op_str.split('#')[1].split(']')[0],0)-65536
   value=struct.unpack_from('<I',data,address)[0];extra=' ; '+hex(value)
   if 65536<=value<65536+len(data):
    raw=data[value-65536:value-65536+100].split(b'\0')[0]
    if raw and all(32<=c<127 for c in raw):extra+=' '+repr(raw.decode())
  lines.append(f'{ins.address:08x} {ins.mnemonic:8} {ins.op_str}{extra}')
path=root/'analysis/original/reverse/web-extensions.asm'
path.write_text('\n'.join(lines)+'\n');print(path)
