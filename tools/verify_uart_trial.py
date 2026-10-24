"""Emulate original HK6 command parser; model flash hardware and UART only.

Checks packet dispatch, erase/program addresses, page data, replies and the
real CheckCRC/protection control flow before the physical trial.
"""
import json
from pathlib import Path
import struct
import zlib

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_LR, UC_ARM_REG_PC
from verify_stock_patch import machine, call
from uart_write_trial import ROOT, TARGET, SIZE, ERASED, PATTERN, ERASE, WRITE, CRC, read_cmd, sha


def main():
    boot = (ROOT/'analysis/original/bootloader-logical.bin').read_bytes()
    assert sha(boot) == '5bc9d1458fdbebba682947b0d11f231a74729522f7741cfab62d6a1cf445fac6'
    uc = machine(boot, 0)
    uc.mem_write(0x400060, bytes(0x100))
    uc.mem_write(0x400098, struct.pack('<III', 0x1b08, 0xc84015, 0x200000))
    # Flash table row is an emulation example, NOT a JEDEC identification.
    flash = bytearray(ERASED)
    state = dict(sr=0x7c, replies=[], writes=[], erases=[], protection=[])
    def ret(value=0):
        uc.reg_write(UC_ARM_REG_R0, value)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    def hook(u, address, size, unused):
        r0, r1, r2 = (u.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
        if address == 0x103c:
            assert TARGET <= r1 and r1+r2 <= TARGET+SIZE
            assert state['sr'] == 0, 'Programming while protected'
            data = bytes(u.mem_read(r0, r2))
            state['writes'].append([hex(r1), r2])
            for i, byte in enumerate(data): flash[r1-TARGET+i] &= byte
            ret()
        elif address == 0xec4:
            assert r0 == TARGET and state['sr'] == 0
            state['erases'].append(hex(r0))
            flash[:] = ERASED
            ret()
        elif address == 0xf34:
            assert TARGET <= r1 and r1+r2 <= TARGET+SIZE
            u.mem_write(r0, bytes(flash[r1-TARGET:r1-TARGET+r2]))
            ret()
        elif address == 0xfa4:
            ret(state['sr'])
        elif address == 0x10d4:
            state['protection'].append(r1)
            state['sr'] = r1
            ret()
        elif address == 0xde0:
            state['replies'].append(bytes(u.mem_read(r0, r1)))
            ret()
    uc.hook_add(UC_HOOK_CODE, hook)
    def packet(data):
        uc.mem_write(0x404000, data)
        state['replies'].clear()
        call(uc, 0xac9, [0x404000, len(data)])
        return b''.join(state['replies'])
    # LINK sets the flag that causes the first erase to unprotect flash.
    assert packet(bytes.fromhex('01e0fc0100')) == bytes.fromhex('040e0501e0fc0100')
    assert packet(ERASE) == bytes.fromhex('040eff01e0fcf407000f0020')+struct.pack('<I', TARGET)
    assert packet(WRITE) == bytes.fromhex('040eff01e0fcf406000700')+struct.pack('<I', TARGET)
    assert bytes(flash) == PATTERN
    assert len(state['writes']) == 16 and all(n == 256 for _, n in state['writes'])
    reply = packet(read_cmd(TARGET))
    assert reply == bytes.fromhex('040eff01e0fcf406100900')+struct.pack('<I', TARGET)+PATTERN
    packet(ERASE)
    assert bytes(flash) == ERASED
    reply = packet(CRC)
    assert reply == bytes.fromhex('040e0801e0fc10')+struct.pack('<I', zlib.crc32(ERASED)^0xffffffff)
    assert state['sr'] == 0x7c
    result = dict(passed=True, boot_sha256=sha(boot), erase_addresses=state['erases'],
                  program_calls=state['writes'], protection_values=state['protection'],
                  crc_matches=True, model='Original parser, dispatcher, CRC and protection routine; flash I/O and UART modeled',
                  flash_table_row='0x1B08 example only; actual device ID not identified')
    out = ROOT/'analysis/uart/write-trial'
    out.mkdir(parents=True, exist_ok=True)
    (out/'emulation.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
