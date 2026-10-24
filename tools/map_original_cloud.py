"""Document network-related evidence in the exact original HK6 image; no patches."""
import hashlib
import json
from pathlib import Path
import re
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'analysis/original/reverse'
raw = (ROOT/'analysis/original/app-logical.bin').read_bytes()
EXPECTED = '8f2e8d40497634a801fffb4c28c54d1d19400c08a0286ba1e6b365997163d900'
assert hashlib.sha256(raw).hexdigest() == EXPECTED, 'Unexpected firmware revision'
BASE = 0x10000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

# Addresses inferred from original thread-creation literal pools and messages.
# Windows intentionally exclude observed trailing literal pools, where known.
windows = [
    ('PPCS initialization path (inferred)', 0x172dc, 0x17456),
    ('p2pinit thread entry', 0x17488, 0x174c6),
    ('p2plisten thread entry', 0x1a2ac, 0x1a38e),
    ('P2P thread creation path (inferred)', 0x1aca8, 0x1ad4e),
    ('ntp_sync Finsh command', 0x58520, 0x58544),
    ('PPCS wrapper candidates', 0x7a754, 0x7a794),
]
disassembly, calls = [], []
for label, start, end in windows:
    disassembly.append(f'\n; {label}, logical address {start:#x}, app file offset {start-BASE:#x}\n')
    for instruction in md.disasm(raw[start-BASE:end-BASE], start):
        suffix = ''
        match = re.search(r'\[pc, #(0x[0-9a-f]+|\d+)\]', instruction.op_str)
        if instruction.mnemonic == 'ldr' and match:
            pos = ((instruction.address+4)&~3)+int(match[1],0)-BASE
            if 0 <= pos < len(raw)-4:
                value = struct.unpack_from('<I',raw,pos)[0]
                suffix = f' ; literal {value:#x}'
                if BASE <= value < BASE+len(raw):
                    string = raw[value-BASE:value-BASE+128].split(b'\0')[0]
                    if string and all(32<=c<127 for c in string):
                        suffix += ' '+repr(string.decode('ascii'))
        if instruction.mnemonic in ('bl','blx'):
            calls.append(dict(window=label, address=hex(instruction.address), target=instruction.op_str))
        disassembly.append(f'{instruction.address:08x}  {instruction.bytes.hex():10s} '
                           f'{instruction.mnemonic:8s} {instruction.op_str}{suffix}\n')
(OUT/'cloud-windows.asm').write_text(''.join(disassembly))

keys = ['HK6_IPC','Jul  4 2023','ntp1.aliyun.com','discovery_listen_thread_func',
        'localUdp_listen_thread_func','PPCS_API Version','P2P_SERVERSTRING',
        'PPCS_NetworkDetect','p2pVideoSendBuf','p2pinit','p2plisten','p2pvideo','p2paudio']
strings = []
for match in re.finditer(rb'[\x20-\x7e]{5,}',raw):
    value = match.group().decode('ascii')
    if any(key in value for key in keys):
        strings.append(dict(value=value,file_offset=hex(match.start()),logical_address=hex(BASE+match.start())))
threads = []
for name, entry_slot, name_slot in [('p2pinit',0xad50,0xad54),('p2plisten',0xad5c,0xad60),
                                     ('p2pvideo',0xad68,0xad6c),('p2paudio',0xad74,0xad78)]:
    entry = struct.unpack_from('<I',raw,entry_slot)[0]
    name_ptr = struct.unpack_from('<I',raw,name_slot)[0]
    assert raw[name_ptr-BASE:name_ptr-BASE+len(name)+1] == name.encode()+b'\0'
    threads.append(dict(name=name,entry_logical=hex(entry&~1),isa='thumb' if entry&1 else 'arm',
                        entry_file_offset=hex((entry&~1)-BASE),
                        entry_literal_file_offset=hex(entry_slot),name_literal_file_offset=hex(name_slot)))
sdk = json.loads((OUT/'sdk-comparison.json').read_text())
network_matches = [x for x in sdk['exact_function_matches']
                   if any(k in x['symbol'] for k in ('ip4_output','udp_sendto_if'))]
report = dict(app_partition_sha256=EXPECTED, strings=strings, threads=threads,
              network_sdk_byte_matches=network_matches, calls_in_windows=calls,
              findings=[
                  'p2pinit first calls the shared initialization path at 0x172dc, then a '
                  'network-detection wrapper at 0x7a764. Skipping the whole thread also skips initialization.',
                  'PPCS initialization wrapper at 0x7a75c calls 0x79680; network-detection wrapper '
                  'at 0x7a764 calls 0x76cd4. Labels inferred from surrounding messages and arguments.',
                  'Local discovery strings and P2P video paths coexist; user reports video on an isolated phone hotspot. Packet capture and full offline client conditions are unverified.',
                  'Disabling NetworkDetect alone does not prove suppression of login, heartbeat or relay traffic.',
                  'ntp1.aliyun.com is embedded in this actual firmware, unlike the older reference OTA.',
              ],
              caveats=['Logical addresses are not physical flash offsets.',
                       'This is a map for investigation, not a patch recipe or complete control-flow graph.',
                       'No source-level confirmation of a LAN-only PPCS option was found in this pass.',
                       'User reports LAN video without hotspot WAN; packet capture is deferred, not a prerequisite for static analysis. No binary modified.'])
(OUT/'cloud-map.json').write_text(json.dumps(report,indent=2)+'\n')
print(f'{len(threads)} thread entries, {len(network_matches)} SDK network matches, {len(strings)} relevant strings.')
