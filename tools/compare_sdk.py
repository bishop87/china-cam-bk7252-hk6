"""Compare vendor raw image with the ELF linked from the pinned SDK + LocalCam."""
import hashlib
import argparse
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--input', type=Path, default=ROOT / 'analysis/ota/bka9-app.bin')
parser.add_argument('--output', type=Path, default=ROOT / 'analysis/reverse')
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
vendor = args.input.read_bytes()
path = ROOT / 'build/sdk/rtthread.elf'
with path.open('rb') as handle:
    elf = ELFFile(handle)
    sections = [dict(name=s.name, address=hex(s['sh_addr']), size=s['sh_size']) for s in elf.iter_sections()
                if s['sh_flags'] & 2]
    matches = []
    for symbol in elf.get_section_by_name('.symtab').iter_symbols():
        if symbol['st_info']['type'] != 'STT_FUNC' or symbol['st_size'] < 32:
            continue
        idx = symbol['st_shndx']
        if not isinstance(idx, int): continue
        section = elf.get_section(idx)
        offset = (symbol['st_value'] & ~1) - section['sh_addr']
        data = section.data()[offset:offset+symbol['st_size']]
        if len(data) != symbol['st_size']: continue
        pos = vendor.find(data)
        if pos >= 0:
            matches.append(dict(symbol=symbol.name, bytes=len(data), sdk_address=hex(symbol['st_value'] & ~1),
                                vendor_address=hex(0x10000+pos), vendor_file_offset=hex(pos),
                                isa='thumb' if symbol['st_value'] & 1 else 'arm'))
    report = dict(sdk_commit='266d54fd8965a093d345c1a1cdb6ca26da6a6488',
                  elf_machine=elf['e_machine'], elf_entry=hex(elf['e_entry']),
                  vendor_sha256=hashlib.sha256(vendor).hexdigest(),
                  sdk_sections=sections, exact_function_matches=sorted(matches, key=lambda x:-x['bytes']),
                  caveat='Exact byte sequences are code reuse evidence, not sensor/board compatibility or runtime testing.')
(args.output / 'sdk-comparison.json').write_text(json.dumps(report, indent=2)+'\n')
seen = set()
lines = ['; Vendor code byte-identical to SDK ELF function symbols.\n',
         '; Labels are inferred from exact matches; literal pools can appear as instructions.\n']
for x in sorted(matches, key=lambda x:int(x['vendor_file_offset'], 16)):
    key = (x['vendor_address'], x['bytes'])
    if key in seen: continue
    seen.add(key)
    offset = int(x['vendor_file_offset'], 16)
    lines.append(f"\n; SDK label {x['symbol']}, {x['isa']}, {x['bytes']} matching bytes\n")
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if x['isa'] == 'thumb' else CS_MODE_ARM)
    for ins in md.disasm(vendor[offset:offset+x['bytes']], 0x10000+offset):
        lines.append(f'{ins.address:08x}  {ins.bytes.hex():10s} {ins.mnemonic:8s} {ins.op_str}\n')
(args.output / 'vendor-sdk-matched.asm').write_text(''.join(lines))
print(f"{len(matches)} exact function byte sequences (at least 32 bytes), ARM ELF entry {report['elf_entry']}")
for x in report['exact_function_matches'][:12]: print(x)
