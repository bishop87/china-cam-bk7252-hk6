"""Verify the experimental patch with the real ARM/Thumb instructions in Unicorn.

Emulates bounded routines, not the hardware, radio, full OS or full OTA upgrade.
"""
import gzip
import json
from pathlib import Path
import struct
import zlib

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                              UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                              UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
                              UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                              UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
                              UC_ARM_REG_CPSR)
from build_stock_patch import ROOT, BOOT_SHA256, SOURCE_SHA256, apply_patch, sha, write_bundle
from rbl import HEADER, IV, KEY, fnv1a, unpack

STOP = 0x300000
STACK = 0x470000
ARG_REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
SAVED_REGS = [UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
              UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11]


def require(value, message):
    if not value:
        raise ValueError(message)


def machine(data, base):
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(base, (len(data)+4095) & ~4095)
    uc.mem_write(base, data)
    uc.mem_map(0x400000, 0x80000)
    uc.mem_map(STOP, 0x1000)
    if base == 0:
        src, dst, count = struct.unpack_from('<III', data, 0x6d44)
        require((src, dst, count) == (0xd3f0, 0x400060, 0x6c), 'Boot RAM copy map changed')
        uc.mem_write(dst, data[src:src+count])
    return uc


def prepare(uc, args=()):
    uc.reg_write(UC_ARM_REG_CPSR, 0x13)
    for reg, value in zip(ARG_REGS, args):
        uc.reg_write(reg, value)
    if len(args) > 4:
        uc.mem_write(STACK, struct.pack('<'+'I'*(len(args)-4), *args[4:]))
    uc.reg_write(UC_ARM_REG_SP, STACK)
    uc.reg_write(UC_ARM_REG_LR, STOP)


def call(uc, entry, args=(), count=10_000_000):
    prepare(uc, args)
    uc.emu_start(entry, STOP, count=count)
    require(uc.reg_read(UC_ARM_REG_PC) == STOP, f'Routine {entry:#x} did not return')
    require(uc.reg_read(UC_ARM_REG_SP) == STACK, f'Stack not restored at {entry:#x}')
    return uc.reg_read(UC_ARM_REG_R0)


def verify_instructions(patched):
    checks = {}
    uc = machine(patched, 0x10000)
    for n, reg in enumerate(SAVED_REGS):
        uc.reg_write(reg, 0x12340000+n)
    require(call(uc, 0x583b1) == 0, 'Patched NTP did not return failure')
    require(all(uc.reg_read(reg) == 0x12340000+n for n, reg in enumerate(SAVED_REGS)),
            'NTP clobbered a callee-saved register')
    checks['ntp_returns_zero_preserves_stack_and_saved_registers'] = True

    visited = []
    def init_hook(u, address, size, unused):
        if address == 0x172dc:
            visited.append('shared_initialization')
            # Model a returning initialization; its internals are NOT emulated here.
            u.reg_write(UC_ARM_REG_R0, 0)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        if address == 0x7a764:
            raise ValueError('Patched thread still reaches NetworkDetect')
    hook = uc.hook_add(UC_HOOK_CODE, init_hook)
    call(uc, 0x17489, count=100)
    uc.hook_del(hook)
    require(visited == ['shared_initialization'], 'Initialization not preserved exactly once')
    require(all(uc.reg_read(reg) == 0x12340000+n for n, reg in enumerate(SAVED_REGS)),
            'Patched thread clobbered a callee-saved register')
    checks['thread_initializes_then_returns_without_network_detect'] = True

    def did_hook(u, address, size, unused):
        if address == 0x5796c:
            u.reg_write(UC_ARM_REG_R0, 0x440300)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
    hook = uc.hook_add(UC_HOOK_CODE, did_hook)
    prepare(uc)
    uc.reg_write(UC_ARM_REG_R5, 0x440400)
    uc.emu_start(0x1a363, 0x7a66c, count=100)
    uc.hook_del(hook)
    require(uc.reg_read(UC_ARM_REG_PC) == 0x7a66c, 'Listen caller did not reach expected callee')
    require([uc.reg_read(r) for r in ARG_REGS] == [0x440300, 300, 0, 0], 'Listen arguments wrong')
    require(struct.unpack('<I', uc.mem_read(STACK, 4))[0] == 0x440400, 'License argument changed')
    checks['listen_arguments_preserved_except_mode_zero'] = True

    # Execute both zero and one paths: original mode must reach the send path,
    # experimental mode must skip it. Stops before any socket or send routine.
    for mode in (0, 1):
        prepare(uc)
        uc.mem_write(STACK+0x38, struct.pack('<I', mode))
        uc.mem_write(STACK+0x48, struct.pack('<I', 0x417d00))
        uc.mem_write(0x407d68, struct.pack('<I', 0x441000))
        uc.reg_write(UC_ARM_REG_R4, 0)
        uc.reg_write(UC_ARM_REG_R5, 0x407d68)
        uc.reg_write(UC_ARM_REG_R7, 0)
        end = 0x78e04 if mode == 0 else 0x7a94c
        uc.emu_start(0x78df7, end, count=100)
        require(uc.reg_read(UC_ARM_REG_PC) == end, f'Hello guard mode {mode} wrong')
        prepare(uc)
        end = 0x78e78 if mode == 0 else 0x78e28
        uc.emu_start(0x78e23, end, count=10)
        require(uc.reg_read(UC_ARM_REG_PC) == end, f'Login guard mode {mode} wrong')
    checks['server_send_guards_zero_skips_one_enters'] = True
    return checks


def verify_boot_decryption(boot, package, expected):
    uc = machine(boot, 0)
    call(uc, 0x9f59, [0x440000, 0x440100])
    require(bytes(uc.mem_read(0x440000, 16)) == IV, 'Actual IV getter differs')
    require(bytes(uc.mem_read(0x440100, 32)) == KEY, 'Actual key getter differs')
    call(uc, 0xb245, [0x440200, 0x440100, 256])
    # Use the real bootloader CBC routine in the same 4096-byte chunks as its OTA path.
    plain = bytearray()
    for start in range(96, len(package), 4096):
        chunk = package[start:start+4096]
        uc.mem_write(0x441000, chunk)
        call(uc, 0xaa79, [0x440200, 0, len(chunk), 0x440000, 0x441000, 0x442000])
        plain.extend(uc.mem_read(0x442000, len(chunk)))
    padding = plain[-1]
    require(1 <= padding <= 16 and plain[-padding:] == bytes([padding])*padding, 'PKCS7 mismatch')
    decoded = gzip.decompress(bytes(plain[:-padding]))
    require(decoded == expected, 'Real bootloader AES + host gzip did not recover exact payload')
    fields = HEADER.unpack_from(package)
    require(fields[6] == zlib.crc32(package[96:]), 'Encrypted payload CRC mismatch')
    require(fields[7] == fnv1a(decoded), 'Decoded FNV mismatch')
    require(fields[-1] == zlib.crc32(package[:92]), 'Header CRC mismatch')
    return dict(actual_bootloader_key_getter=True, actual_bootloader_aes_schedule_and_cbc=True,
                all_ciphertext_bytes_decrypted=len(package)-96, host_gzip_recovers_exact_payload=True,
                note='Gzip and container hash checks run on host; full updater, flash and radio not emulated.')


def verify_boot_custom_check(boot, patched):
    results = {}
    # CRC-interleaved and incorrectly linked inputs are negative controls.
    crc = 0xffff
    for byte in patched[:32]:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x8005 if crc & 0x8000 else 0)) & 0xffff
    physical = patched[:32] + crc.to_bytes(2, 'big') + patched[34:1024]
    wrong_link = patched[:32] + struct.pack('<I', 0x400000) + patched[36:1024]
    for name, data, expected in [('logical_payload', patched[:1024], 0),
                                  ('physical_crc_input', physical, 0xffffffff),
                                  ('wrong_link_address', wrong_link, 0xffffffff)]:
        uc = machine(boot, 0)
        uc.mem_write(0x440000, b'\0'*4+b'download\0')
        uc.mem_write(0x441000, data)
        uc.mem_write(0x440500, b'app\0')
        part = bytearray(64)
        struct.pack_into('<II', part, 0x34, 0x10000, 0x110000)
        uc.mem_write(0x440600, bytes(part))
        uc.mem_write(0x400060, b'\0')  # First verification call, no prior success.
        def model(u, address, size, unused):
            if address in (0x9f34, 0x7e78, 0x70ec):
                # Model metadata/partition lookup and logging, not flash I/O.
                value = {0x9f34: 0x440500, 0x7e78: 0x440600, 0x70ec: 0}[address]
                u.reg_write(UC_ARM_REG_R0, value)
                u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        uc.hook_add(UC_HOOK_CODE, model)
        value = call(uc, 0x9bc1, [0x440000, 0, 0x441000, len(data)])
        require(value == expected, f'Boot custom verification unexpectedly returned {value:#x} for {name}')
        results[name] = 'accepted' if value == 0 else 'rejected'
    results['limit'] = 'Metadata/partition lookup and logging modeled; not full OTA acceptance.'
    return results


def main():
    directory = ROOT/'dist/hk6-stock-lan-exp1'
    boot = (ROOT/'analysis/original/bootloader-logical.bin').read_bytes()
    original = (ROOT/'analysis/original/app-payload.bin').read_bytes()
    require(sha(boot) == BOOT_SHA256 and sha(original) == SOURCE_SHA256, 'Original hashes changed')
    patched = (directory/'hk6-stock-lan-exp1.bin').read_bytes()
    package = (directory/'hk6-stock-lan-exp1.rbl').read_bytes()
    require(apply_patch(original)[0] == patched, 'Generated patch differs from specification')
    require(unpack(package)[0] == patched, 'Container does not contain expected patched payload')
    report = dict(status='passed_bounded_emulation', ready_to_flash=False,
                  payload_sha256=sha(patched), rbl_sha256=sha(package),
                  instruction_checks=verify_instructions(patched),
                  bootloader_crypto=verify_boot_decryption(boot, package, patched),
                  bootloader_custom_check=verify_boot_custom_check(boot, patched),
                  limits=['No full-device emulation', 'PPCS initialization stubbed for thread control-flow test',
                          'No proof of LAN video or absence of all cloud traffic',
                          'No physical flash or recovery test'])
    encoded = json.dumps(report, indent=2)+'\n'
    manifest = json.loads((directory/'manifest.json').read_text())
    require(manifest['payload_sha256'] == sha(patched) and manifest['rbl_sha256'] == sha(package),
            'Manifest does not match generated firmware')
    manifest['bounded_emulation'] = 'passed; see emulation-validation.json'
    files = {name: (directory/name).read_bytes() for name in
             ['hk6-stock-lan-exp1.bin', 'hk6-stock-lan-exp1.rbl', 'readme.md']}
    files['manifest.json'] = (json.dumps(manifest, indent=2)+'\n').encode()
    files['emulation-validation.json'] = encoded.encode()
    write_bundle(directory, files)
    (ROOT/'analysis/original/reverse/stock-patch-validation.json').write_text(encoded)
    print(encoded)


if __name__ == '__main__':
    main()
