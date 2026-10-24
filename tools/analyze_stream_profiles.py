"""Trace the stock stream handler offline; all I/O and JSON parsing are mocked."""
import hashlib
import json
import struct
from pathlib import Path
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_PC, UC_ARM_REG_LR
from verify_stock_patch import machine, call

ROOT = Path(__file__).resolve().parents[1]

def main():
    data = (ROOT/'analysis/original/app-logical.bin').read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == '8f2e8d40497634a801fffb4c28c54d1d19400c08a0286ba1e6b365997163d900'
    cases = []
    for video in (0, 1, 2, 3):
        uc = machine(data, 0x10000)
        uc.mem_write(0x440114, struct.pack('<I', video))
        calls = []
        def hook(u, address, size, unused):
            result = 0
            if address == 0x574b8:
                result = 0x440000
            elif address == 0x574d2:
                key = bytes(u.mem_read(u.reg_read(UC_ARM_REG_R1), 16)).split(b'\0')[0]
                result = 0x440100 if key == b'video' else 0
            elif address == 0x532e0:
                calls.append([u.reg_read(UC_ARM_REG_R0),u.reg_read(UC_ARM_REG_R1)])
            elif address not in (0x17950, 0x5d274, 0x57404, 0x5c2e8):
                return
            u.reg_write(UC_ARM_REG_R0,result)
            u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
        uc.hook_add(UC_HOOK_CODE,hook)
        call(uc,0x17f0d,[],count=10000)
        cases.append(dict(video=video,resolution_calls=calls))
    assert [c['resolution_calls'] for c in cases] == [[],[[1,1]],[[0,1]],[]]
    report = dict(source_sha256=digest, handler='0x17f0c', wrapper='0x532e0',
                  resolution_dispatch='0x5270c', cases=cases,
                  mapping={'1':{'sensor_mode':1,'requested_dimensions':[640,480]},
                           '2':{'sensor_mode':0,'requested_dimensions':[320,240]}},
                  limits='Real stream handler, mocked JSON/authentication/I/O. Sensor modes established separately in hi704-modes.json. Actual JPEG size must be measured.')
    out=ROOT/'analysis/original/reverse/stream-profiles.json'
    out.write_text(json.dumps(report,indent=2)+'\n')
    print(out)

if __name__=='__main__':main()
