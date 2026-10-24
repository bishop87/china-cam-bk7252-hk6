"""Build a bounded research prototype; no OTA package or hardware writes."""
from pathlib import Path
import hashlib,json,struct,subprocess
from elftools.elf.elffile import ELFFile
from build_stock_patch import apply_patch, ROOT, BASE
OUT=ROOT/'analysis/exp2-candidate'
HOOK=0x72222

def branch_link(src,dst):
    delta=dst-(src+4)
    if delta%2 or not -(1<<22)<=delta<(1<<22):raise ValueError('Thumb BL out of range')
    return struct.pack('<HH',0xf000|((delta>>12)&0x7ff),0xf800|((delta>>1)&0x7ff))

def main():
    OUT.mkdir(exist_ok=True)
    raw=(ROOT/'analysis/original/app-payload.bin').read_bytes()
    patched,_=apply_patch(raw)
    append=(len(raw)+3)&~3
    addr=BASE+append
    tool=ROOT/'tools/gcc-arm-none-eabi-5_4-2016q3/bin/arm-none-eabi-'
    cmd=[str(tool)+'gcc','-mcpu=arm968e-s','-mthumb','-Os','-ffreestanding','-fno-builtin','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fno-stack-protector','-nostdlib',str(ROOT/'firmware/stock-exp2/entry.S'),str(ROOT/'firmware/stock-exp2/egress.c'),'-Wl,--build-id=none','-Wl,-e,hk6_guard_entry','-Wl,-Ttext='+hex(addr),'-o',str(OUT/'guard.elf')]
    subprocess.run(cmd,check=True)
    subprocess.run([str(tool)+'objcopy','-O','binary','--only-section=.text','--only-section=.rodata',str(OUT/'guard.elf'),str(OUT/'guard.bin')],check=True)
    with (OUT/'guard.elf').open('rb') as f:
        elf=ELFFile(f)
        symbols={s.name:s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name in ['hk6_guard_entry','hk6_packet_allowed','hk6_ntp_name']}
        assert symbols['hk6_guard_entry']==addr|1
        assert not any(s['sh_size'] for s in elf.iter_sections() if s.name in ('.data','.bss'))
    guard=(OUT/'guard.bin').read_bytes()
    offset=HOOK-BASE
    assert patched[offset:offset+4]==bytes.fromhex('8bb00593')
    candidate=bytearray(patched)+b'\xff'*(append-len(patched))+guard
    candidate[offset:offset+4]=branch_link(HOOK,addr)
    # Restore original NTP routine, and redirect only its fixed hostname pointer.
    assert raw[0x583b0-BASE:0x583b4-BASE]==bytes.fromhex('f0b53d4d')
    candidate[0x583b0-BASE:0x583b4-BASE]=raw[0x583b0-BASE:0x583b4-BASE]
    assert struct.unpack_from('<I',raw,0x584b0-BASE)[0]==0xca3df
    struct.pack_into('<I',candidate,0x584b0-BASE,symbols['hk6_ntp_name'])
    (OUT/'candidate-logical.bin').write_bytes(candidate)
    report={'status':'research_prototype_not_installable','hardware_writes':False,'ota_produced':False,'hook':hex(HOOK),'resume':'0x72226','appended_address':hex(addr),'symbols':symbols,'guard_bytes':len(guard),'original_payload_bytes':len(raw),'candidate_bytes':len(candidate),'candidate_sha256':hashlib.sha256(candidate).hexdigest(),'ntp_hostname':'europe.pool.ntp.org','ntp_hostname_pointer_address':'0x584b0','original_hook_bytes':'8bb00593','hook_bytes':candidate[offset:offset+4].hex(),'limitations':['IPv4 output routine only; raw link-layer and alternate stack paths not audited','Only exact pool DNS query to configured resolvers allowed; NTP to corresponding live cache address only','Multicast and IP_HDRINCL output denied; LAN compatibility requires hardware test','EXP1 NetworkDetect skip retained; anomalous server structures not repaired','Appending executable code requires bootloader bounds and image-layout validation before OTA packaging']}
    (OUT/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
