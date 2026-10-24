"""Read-only EXP2F HTTP feasibility mapping; outputs evidence, never firmware."""
from pathlib import Path
import hashlib, json, re, struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'analysis/http-feasibility'
TARGETS = ['rt_thread_find','rt_object_find','lwip_socket','lwip_bind','lwip_listen','lwip_accept','lwip_send',
           'lwip_close','lwip_setsockopt','lwip_recv','rt_thread_create',
           'rt_thread_startup','rt_malloc','rt_free','video_buffer_open',
           'video_buffer_read_frame','video_buffer_recv_video_data']
WINDOWS = [('thread_find',0x5d378,0x5d3cc),('thread_init',0x5d010,0x5d08c),('app_startup',0x16c70,0x16db4),('heap_init',0x55540,0x5557e),
 ('main_allocator',0x5c974,0x5c9c4),('socket_bind',0x682d8,0x6833a),
 ('socket_timeouts',0x68d32,0x68d7a),('memtrace_blocks',0x5c45e,0x5c4e4),('video_callback',0x28190,0x282b8),('video_open',0x282b8,0x2835c),
 ('video_read',0x2837c,0x283e4),('producer_entry',0x1a570,0x1a600),
 ('producer_read_call',0x1a600,0x1a680),('producer_idle_gate',0x1a712,0x1a740),
 ('thread_startup_calls',0x1ad02,0x1ad4e),('thread_create',0x5d0f8,0x5d144),
 ('thread_startup',0x5d2e0,0x5d344),('malloc_wrapper',0x55524,0x55534),
 ('free_wrapper',0x55534,0x5553c),('tcp_send',0x68824,0x6889c),
 ('memory_command',0x64930,0x6498a)]

def main():
 b=(ROOT/'dist/hk6-stock-lan-exp2f/hk6-stock-lan-exp2f.bin').read_bytes()
 sha=hashlib.sha256(b).hexdigest()
 assert sha=='981d33db1b1af8b94bdcfc98e369214b312a2f4d00b82aacdcbc0a962f50ea5d'
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB); rows=[]
 elf_path=ROOT/'build/sdk/rtthread.elf'
 with elf_path.open('rb') as f:
  e=ELFFile(f)
  for s in e.get_section_by_name('.symtab').iter_symbols():
   if s.name not in TARGETS or not isinstance(s['st_shndx'],int): continue
   sec=e.get_section(s['st_shndx']); a=s['st_value']&~1; off=a-sec['sh_addr']
   d=sec.data()[off:off+s['st_size']]; mask=bytearray(b'\1'*len(d))
   for i in md.disasm(d,a):
    if i.mnemonic in ('bl','blx'):mask[i.address-a:i.address-a+i.size]=b'\0'*i.size
    if i.mnemonic=='ldr' and '[pc, #' in i.op_str:
     v=((i.address+4)&~3)+int(i.op_str.split('#')[1].split(']')[0],0)-a
     if 0<=v<=len(d)-4:mask[v:v+4]=b'\0'*4
   # Tiny wrappers cannot identify a function reliably.
   hits=[]
   if sum(mask)>=32:
    pattern=b''.join(re.escape(bytes([v])) if mask[k] else b'.' for k,v in enumerate(d))
    hits=[hex(m.start()+65536) for m in re.finditer(pattern,b,re.S) if m.start()%2==0]
   rows.append(dict(symbol=s.name,sdk_bytes=len(d),fixed_bytes=sum(mask),
                    candidates=hits,status='unique structural candidate' if len(hits)==1 else 'unresolved'))
 OUT.mkdir(exist_ok=True)
 report=dict(source_sha256=sha,sdk_elf_sha256=hashlib.sha256(elf_path.read_bytes()).hexdigest(),
  method='Mask BL/BLX and PC-relative literal values, preserve other bytes; >=32 fixed bytes; even alignment. Unique match is evidence, not ABI/runtime validation.',
  matches=rows,manual_candidates={'video_read':'0x2837c','video_state_pointer':'0x404870',
   'video_callback':'0x28190','p2pvideo_thread':'0x1a570','frame_read_call':'0x1a628',
   'frame_buffer_limit':40928,'frame_prefix_bytes':32,'thread_startup':'0x5d2e0',
   'malloc_wrapper':'0x55524','free_wrapper':'0x55534','tcp_send':'0x68824'},
  runtime_calls_executed=False,firmware_modified=False)
 (OUT/'mapping.json').write_text(json.dumps(report,indent=2)+'\n')
 lines=['; EXP2F SHA256 '+sha,'; Static evidence; addresses are not a validated callable API.']
 md.skipdata=True
 for name,start,end in WINDOWS:
  lines.append('\n; '+name)
  for i in md.disasm(b[start-65536:end-65536],start):
   extra=''
   if i.mnemonic=='ldr' and '[pc, #' in i.op_str:
    off=((i.address+4)&~3)+int(i.op_str.split('#')[1].split(']')[0],0)-65536
    if 0<=off<=len(b)-4:extra=' ; literal '+hex(struct.unpack_from('<I',b,off)[0])
   lines.append(f'{i.address:08x} {i.bytes.hex():10s} {i.mnemonic:8s} {i.op_str}{extra}')
 (OUT/'windows.asm').write_text('\n'.join(lines)+'\n')
 print(json.dumps({'unique_candidates':sum(len(r['candidates'])==1 for r in rows),'out':str(OUT)}))
if __name__=='__main__':main()
