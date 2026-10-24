"""Bounded static disassembly of the installed HK6 upload/recovery paths."""
import hashlib
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_OP_MEM

ROOT = Path(__file__).resolve().parents[1]


def dump(source, base, windows, destination):
    data = source.read_bytes()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    lines = [f'; Source: {source.relative_to(ROOT)}',
             f'; SHA256: {hashlib.sha256(data).hexdigest()}',
             '; Bounded code windows; literal pools omitted, no full CFG claim.']
    for start, end, label in windows:
        lines.append(f'\n; {label}')
        for ins in md.disasm(data[start-base:end-base], start):
            line = f'{ins.address:08x}: {ins.mnemonic:8} {ins.op_str}'
            if (ins.mnemonic == 'ldr' and len(ins.operands) > 1
                    and ins.operands[1].type == CS_OP_MEM
                    and ins.reg_name(ins.operands[1].mem.base) == 'pc'):
                address = ((ins.address+4) & ~3)+ins.operands[1].mem.disp
                value = struct.unpack_from('<I', data, address-base)[0]
                line += f' ; literal {value:#x}'
                if base <= value < base+len(data):
                    raw = data[value-base:value-base+200].split(b'\0')[0]
                    if raw and all(c in (9, 10, 13) or 32 <= c < 127 for c in raw):
                        line += ' '+repr(raw.decode())
            lines.append(line)
    destination.write_text('\n'.join(lines)+'\n')


def main():
    original = ROOT/'analysis/original'
    out = original/'reverse'
    dump(original/'app-logical.bin', 0x10000, [
        (0x59d28, 0x5a088, 'HTTP download: validate lengths, read/erase/write/readback'),
        (0x5a108, 0x5a160, 'OTA verification, cleanup and reset'),
        (0x5a178, 0x5a1b0, 'http_ota command: explicit URL or compiled default'),
    ], out/'http-ota-upload.asm')
    dump(original/'bootloader-logical.bin', 0, [
        (0xa00, 0xa9c, 'Startup and idle timeout loop (loop counts, not milliseconds)'),
        (0xb96, 0xbe2, 'Read4K: reject addresses below 0x2000'),
        (0xbe2, 0xc4e, 'Erase: reject low addresses, automatic unprotect, sector opcode 0x20'),
        (0xca8, 0xd32, 'Write4K: program 256-byte chunks, acknowledge at completion'),
        (0x103c, 0x10ca, 'Flash programming helper and physical capacity check'),
        (0x1664, 0x168e, 'Table-defined protected/unprotected status values'),
        (0xdc0, 0xdda, 'Select UART baud initializer'),
        (0xde0, 0xdfa, 'Select response UART'),
        (0x1740, 0x17a8, 'UART1 initialization'),
        (0x17e4, 0x184a, 'UART2 initialization'),
        (0x18c4, 0x1932, 'Standard commands dispatcher and LINK response'),
        (0x1932, 0x1978, 'CheckCRC: CRC computation and explicit protection before response'),
        (0x19ca, 0x19e6, 'Reboot command'),
        (0x1a14, 0x1a2a, 'Both UARTs initialized with 225 << 9 = 115200'),
    ], out/'uart-recovery-boot.asm')
    print('Wrote HTTP upload and UART recovery disassembly windows.')


if __name__ == '__main__':
    main()
