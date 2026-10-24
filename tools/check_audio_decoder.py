"""Compare our decoder with the actual APK ARM64 decoder in an offline emulator."""
import hashlib
import json
from pathlib import Path
import random
import sys
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_LR
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
from audio_stream import adpcm_pcm, alaw_pcm
path=ROOT/'analysis/hdwificampro/native/lib/arm64-v8a/libobject_jni.so'
with path.open('rb') as f:
    elf=ELFFile(f)
    symbols={s.name:s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols()}
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(0,0x100000)
    for seg in elf.iter_segments():
        if seg['p_type']=='PT_LOAD':uc.mem_write(seg['p_vaddr'],seg.data())
uc.mem_map(0x100000,0x100000)
rng=random.Random(21)
cases=[bytes(range(256)),b'\x77'*320,b'\xff'*320,bytes(rng.randrange(256) for _ in range(320))]
for data in cases:
    uc.mem_write(0x110000,bytes(32));uc.mem_write(0x120000,data)
    for reg,val in ((UC_ARM64_REG_X0,0x110000),(UC_ARM64_REG_X1,0x120000),
                    (UC_ARM64_REG_X2,len(data)),(UC_ARM64_REG_X3,0x130000),
                    (UC_ARM64_REG_X4,0),(UC_ARM64_REG_LR,0x190000)):
        uc.reg_write(reg,val)
    uc.emu_start(symbols['_ZN6CAdpcm11ADPCMDecodeEPciS0_i'],0x190000,count=100000)
    assert bytes(uc.mem_read(0x130000,len(data)*4))==adpcm_pcm(data)
data=bytes(range(256));uc.mem_write(0x120000,data);uc.mem_write(0x140000,(512).to_bytes(4,'little'))
for reg,val in ((UC_ARM64_REG_X0,0x120000),(UC_ARM64_REG_X1,256),(UC_ARM64_REG_X2,0x130000),(UC_ARM64_REG_X3,0x140000),(UC_ARM64_REG_LR,0x190000)):
    uc.reg_write(reg,val)
uc.emu_start(symbols['ADecode'],0x190000,count=100000)
assert bytes(uc.mem_read(0x130000,512))==alaw_pcm(data)
report=dict(apk_library_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),adpcm_cases=len(cases),alaw_codes=256,result='byte-identical PCM to emulated Android decoders',limits='Offline verification; live microphone, header codec value and sample rate still require hardware validation.')
out=ROOT/'app/evidence/audio-decoder-20261021.json';out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
