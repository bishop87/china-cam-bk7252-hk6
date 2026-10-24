"""Restore full VGA encoder height on pinned EXP2D; offline only."""
import json
import struct
from build_stock_patch import ROOT, sha
from verify_stock_patch import machine, call
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_LR, UC_ARM_REG_PC

OUT = ROOT/'analysis/exp2e-candidate'
SOURCE_SHA = '7e6e71eeb8463159d8638b25d6f18ef9f4beb290d657dbefe91b08a3ff0161c4'

def validate(data):
    cases = []
    for mode, expected in ((0, (40,22)), (1, (80,60))):
        u = machine(data, 0x10000)
        call(u, 0x51731, [mode], count=100)
        actual = struct.unpack('<HH',bytes(u.mem_read(0x40d2e0,4)))
        assert actual == expected
        # Execute the stream resolution dispatcher, intercepting hardware calls.
        u = machine(data, 0x10000)
        u.mem_write(0x4007e0,struct.pack('<I',1))
        u.mem_write(0x404bd8,struct.pack('<I',0x96))
        controls = []; sensor = []; fps = []
        def hook(uc, address, size, unused):
            if address == 0x1e6dc:
                value = struct.unpack('<I',bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R2),4)))[0]
                controls.append([uc.reg_read(UC_ARM_REG_R1),value])
            elif address == 0x522b4: sensor.append(uc.reg_read(UC_ARM_REG_R0))
            elif address == 0x5261c: fps.append(uc.reg_read(UC_ARM_REG_R0))
            elif address != 0x2525c: return
            uc.reg_write(UC_ARM_REG_R0,0)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        u.hook_add(UC_HOOK_CODE,hook)
        call(u,0x5270d,[mode,1],count=1000)
        assert controls == [[0xebc0007,expected[0]],[0xebc000d,expected[1]]]
        assert sensor == [mode] and fps == [1]
        cases.append(dict(mode=mode,dimensions=[n*8 for n in expected],driver_controls=controls,sensor_modes=sensor,fps_modes=fps))
    return cases

def main():
    raw=(ROOT/'dist/hk6-stock-lan-exp2d/hk6-stock-lan-exp2d.bin').read_bytes()
    assert sha(raw)==SOURCE_SHA
    assert raw[0x41750:0x41752]==bytes.fromhex('243b') # subs r3, #36
    data=bytearray(raw);data[0x41750]=0x14 # subs r3, #20: 80-20=60 blocks
    data=bytes(data)
    assert [i for i in range(len(raw)) if raw[i]!=data[i]]==[0x41750]
    cases=validate(data)
    OUT.mkdir(exist_ok=True)
    (OUT/'candidate-logical.bin').write_bytes(data)
    manifest=dict(version='2M.1220-LAN-EXP2E',status='offline_candidate',payload_sha256=sha(data),previous_sha256=sha(raw),payload_bytes=len(data),patches=[dict(address='0x51750',before='243b',after='143b')],scope='VGA encoder height only: 352 to 480. QVGA remains 320x176; sensor tables, buffers, bitrate, LAN/NTP, timezone and banner unchanged.')
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (OUT/'validation.json').write_text(json.dumps(dict(passed=True,payload_sha256=sha(data),exact_single_byte_diff=True,cases=cases,scope='Real Thumb setup and dispatcher; hardware calls mocked. Live JPEG and stability not yet verified.'),indent=2)+'\n')
    print(json.dumps(manifest,indent=2))
if __name__=='__main__':main()
