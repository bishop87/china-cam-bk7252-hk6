"""Record bounded static evidence for HK6 LAN-only research; never patch firmware."""
import hashlib
import json
from pathlib import Path
import re
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'analysis/original/reverse'
EXPECTED = {
    'app': '8f2e8d40497634a801fffb4c28c54d1d19400c08a0286ba1e6b365997163d900',
    'bootloader': '5bc9d1458fdbebba682947b0d11f231a74729522f7741cfab62d6a1cf445fac6',
}
images = {name: (ROOT / f'analysis/original/{name}-logical.bin').read_bytes()
          for name in EXPECTED}
for name, data in images.items():
    if hashlib.sha256(data).hexdigest() != EXPECTED[name]:
        raise ValueError(f'Unexpected {name} revision')

# Bounded code windows, excluding known literal/data pools. Not a complete CFG.
windows = [
    ('app', 'Listen caller', 0x1a362, 0x1a38e, 'thumb'),
    ('app', 'Listen wrapper and argument forwarding', 0x7a66c, 0x7a74a, 'thumb'),
    ('app', 'Listen core parameter capture', 0x78a18, 0x78a44, 'thumb'),
    ('app', 'Listen core server-send guards', 0x78dd0, 0x78e90, 'thumb'),
    ('app', 'Listen core guarded send paths', 0x790b8, 0x79134, 'thumb'),
    ('app', 'Hello-like packet builder', 0x7a94c, 0x7a97a, 'thumb'),
    ('app', 'Login-like packet builder prefix', 0x7b1dc, 0x7b21a, 'thumb'),
    ('app', 'NTP socket DNS request and return', 0x583b0, 0x584a8, 'thumb'),
    ('app', 'NTP timezone wrapper', 0x584d0, 0x584e2, 'thumb'),
    ('app', 'NTP RTC wrapper', 0x584e4, 0x5851c, 'thumb'),
    ('app', 'Preserved initialization and skipped detection', 0x17488, 0x174c6, 'thumb'),
    ('app', 'PPCS initialized addresses and workers', 0x79896, 0x79904, 'thumb'),
    ('bootloader', 'OTA policy and dispatch', 0x91b6, 0x921c, 'thumb'),
    ('bootloader', 'Custom image verification', 0x9bc0, 0x9cae, 'thumb'),
    ('bootloader', 'Algorithm getter', 0x9f10, 0x9f30, 'arm'),
    ('bootloader', 'Partition-name getter', 0x9f34, 0x9f50, 'arm'),
    ('bootloader', 'CRC16 helper', 0x6d80, 0x6db4, 'thumb'),
    ('bootloader', 'Initialized RAM copy', 0x6d0c, 0x6d34, 'arm'),
    ('bootloader', 'Actual OTA key IV getter', 0x9f58, 0x9f72, 'thumb'),
    ('bootloader', 'Accepted algorithm selection', 0xa554, 0xa66c, 'arm'),
    ('bootloader', 'AES 256 setup in OTA path', 0x89cc, 0x8a00, 'arm'),
    ('bootloader', 'CBC decryption and padding removal', 0x8a58, 0x8ab4, 'arm'),
]
lines = []
for name, label, start, end, isa in windows:
    base = 0x10000 if name == 'app' else 0
    data = images[name]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if isa == 'thumb' else CS_MODE_ARM)
    instructions = list(md.disasm(data[start-base:end-base], start))
    if sum(i.size for i in instructions) != end-start:
        raise ValueError(f'Incomplete disassembly: {label}')
    lines.append(f'\n; {name}: {label}; {isa}; logical {start:#x}\n')
    for ins in instructions:
        annotation = ''
        match = re.search(r'\[pc, #(0x[0-9a-f]+|\d+)\]', ins.op_str)
        if ins.mnemonic.startswith('ldr') and match:
            pc = ((ins.address+4)&~3) if isa == 'thumb' else ins.address+8
            pos = pc+int(match[1], 0)-base
            if 0 <= pos <= len(data)-4:
                annotation = f' ; literal {struct.unpack_from("<I", data, pos)[0]:#x}'
        if ins.mnemonic == 'adr' and isa == 'thumb':
            delta = int(ins.op_str.split('#')[-1], 0)
            ptr = ((ins.address+4)&~3)+delta
            text = data[ptr-base:ptr-base+160].split(b'\0')[0]
            if text and all(c in (9,10,13,27) or 32 <= c <127 for c in text):
                annotation += f' ; {ptr:#x} {text!r}'
        lines.append(f'{ins.address:08x} {ins.bytes.hex():10s} {ins.mnemonic:8s} {ins.op_str}{annotation}\n')
(OUT/'local-only-candidate.asm').write_text(''.join(lines))

candidate_offset = 0xa36c
original = images['app'][candidate_offset:candidate_offset+2]
if original != bytes.fromhex('0123'):
    raise ValueError('Unexpected Listen argument instruction')
for blob, expected in [(original, 'r3, #1'), (bytes.fromhex('0023'), 'r3, #0')]:
    ins = list(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(blob, 0x1a36c))
    if len(ins) != 1 or ins[0].mnemonic != 'movs' or ins[0].op_str != expected:
        raise ValueError('Candidate opcode did not decode as expected')
report = {
    'status': 'static_candidate_only_no_firmware_written',
    'ready_to_flash': False,
    'input_sha256': EXPECTED,
    'listen_candidate': {
        'logical_address': '0x1a36c', 'app_file_offset': hex(candidate_offset),
        'before_hex': original.hex(), 'proposed_hex': '0023',
        'effect': 'Set fourth Listen argument to zero rather than one.',
        'argument_flow': ['0x1a36c: r3=1', '0x7a684: sb=r3',
                          '0x7a71a..0x7a71c: stack argument from sb',
                          '0x78a30..0x78a36: sixth core argument to local stack+0x38'],
        'confirmed_zero_guards': [
            '0x78df6..0x78dfc skips call 0x790e4 -> 0x7a94c',
            '0x78e22..0x78e26 skips calls 0x78e74 -> 0x7b07c and 0x7912e -> 0x7b1dc'],
        'limits': ['Mode has additional comparisons with value 2 and is passed onward.',
                   'Hello/login naming is inferred by structural comparison, not exported symbols.',
                   'Does not disable NetworkDetect, NTP or prove all external traffic is suppressed.',
                   'Initialization and LAN runtime behavior still need validation.'],
    },
    'bootloader': {
        'custom_verify_entry': '0x9bc0',
        'evidence': [
            'Hook checks partition name download, early offset (<1024), and once-only state.',
            'Rejects first 32 data bytes followed by matching big-endian CRC16 (physical CRC image).',
            'For target app, checks little-endian word at payload+0x20 against app partition bounds.',
            'CRC helper 0x6d80 uses init 0xffff and polynomial 0x8005.',
            'OTA dispatch 0x91b6..0x91e2 rejects zero low nibble in algorithm value.',
        ],
        'original_app_word_0x20': hex(struct.unpack_from('<I', images['app'], 32)[0]),
        'limits': 'These bounded checks are not a full audit of OTA acceptance or recovery.',
    },
    'comparison_source': {
        'repository': 'https://github.com/xen0bit/libPPCS_API',
        'commit': '0734ada97f708472ad19729b622a767732a16cad',
        'files': ['PPCS_Listen.c', 'cs2p2p_PPPP_Listen_Do.c'],
        'limit': 'Decompiler output for a different binary/architecture; structural reference only.',
    },
}
(OUT/'local-only-candidate.json').write_text(json.dumps(report, indent=2)+'\n')
print('Recorded Listen candidate and bootloader checks. No firmware produced or modified.')
