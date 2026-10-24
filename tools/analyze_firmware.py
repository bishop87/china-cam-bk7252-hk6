"""Static, reproducible analysis of the decoded vendor image; no execution."""
import hashlib
import argparse
import json
import re
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "analysis/reverse"
BASE = 0x10000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'analysis/ota/bka9-app.bin')
    parser.add_argument('--output', type=Path, default=OUT)
    args = parser.parse_args()
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    raw = args.input.read_bytes()

    def cstr(ptr):
        off = ptr - BASE
        if not 0 <= off < len(raw):
            return None
        value = raw[off:off + 256].split(b"\0", 1)[0]
        if not value or any(x < 32 or x > 126 for x in value):
            return None
        return value.decode("ascii")

    commands = []
    for off in range(0, len(raw) - 12, 4):
        name, desc, fun = struct.unpack_from("<III", raw, off)
        label = cstr(name)
        if (label and re.fullmatch(r'__cmd_[A-Za-z][A-Za-z0-9_]*', label) and cstr(desc)
                and BASE <= (fun & ~1) < BASE + len(raw) and (fun & 1 or fun % 4 == 0)):
            commands.append(dict(name=label, description=cstr(desc), table_file_offset=hex(off),
                                 address=hex(fun & ~1), isa="thumb" if fun & 1 else "arm"))
    partitions = []
    for match in re.finditer(b"01PE", raw):
        off = match.start()
        if off + 64 > len(raw):
            continue
        _, name, flash, pos, size, reserved = struct.unpack_from("<I24s24sIII", raw, off)
        partitions.append(dict(name=name.split(b"\0")[0].decode("ascii"),
                               flash=flash.split(b"\0")[0].decode("ascii"),
                               offset=hex(pos), length=hex(size), table_file_offset=hex(off)))

    # Exact subsequences of literal register/value pairs, not approximate string matches.
    matches = []
    for path in sorted((ROOT / "upstream/sdk/beken378/func/camera_intf/sensors").glob("*.h")):
        source = re.sub(r"/\*.*?\*/|//[^\n]*", "", path.read_text(errors="replace"), flags=re.S)
        for table in re.finditer(r"(\w+)\s*\[\s*\]\s*\[\s*2\s*\]\s*=\s*\{(.*?)\n\s*\};", source, re.S):
            pairs = re.findall(r"\{\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\}", table[2])
            values = [int(v, 0) for pair in pairs for v in pair]
            if any(v > 255 for v in values):
                continue  # This pass only compares 8-bit register tables.
            data = bytes(values)
            best = (0, 0, 0)
            for i in range(0, len(data) - 31, 2):
                pos = raw.find(data[i:i + 32])
                if pos < 0:
                    continue
                n = 32
                while i + n < len(data) and pos + n < len(raw) and data[i+n] == raw[pos+n]:
                    n += 1
                if n > best[0]:
                    best = (n, i, pos)
            if best[0]:
                matches.append(dict(source=str(path.relative_to(ROOT)), table=table[1], table_bytes=len(data),
                                    exact_matching_bytes=best[0], table_byte_offset=best[1],
                                    firmware_file_offset=hex(best[2]), firmware_address=hex(best[2]+BASE)))

    report = dict(input_sha256=hashlib.sha256(raw).hexdigest(), logical_base=hex(BASE),
                  basis="ARM reset vectors and SDK link.lds; file offsets do not include flash CRC interleaving",
                  thumb_entry=hex(struct.unpack_from('<I', raw, 0x1d8)[0]),
                  finsh_commands=commands, fal_partitions=partitions, sensor_table_matches=matches)
    (output / "vendor-analysis.json").write_text(json.dumps(report, indent=2) + "\n")
    chunks = ["; Bounded disassembly windows: not a complete function/control-flow reconstruction.\n"]
    windows = [("vectors (0x10020..0x1003c are pointer data, omitted)", BASE, "arm", 0x20),
               ("reset (0x101d8 is a Thumb function pointer, omitted)", BASE+0x40, "arm", 0x198)]
    windows += [(x['name'], int(x['address'], 16), x['isa'], 160) for x in commands
                if any(y in x['name'] for y in ('camera', 'video', 'sccb', 'ota'))]
    for name, addr, isa, length in windows:
        chunks.append(f"\n; {name} {isa}, file offset 0x{addr-BASE:x}\n")
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if isa == 'thumb' else CS_MODE_ARM)
        for ins in md.disasm(raw[addr-BASE:addr-BASE+length], addr):
            chunks.append(f"{ins.address:08x}  {ins.bytes.hex():10s} {ins.mnemonic:8s} {ins.op_str}\n")
            if isa == 'thumb' and (ins.mnemonic == 'bx' and ins.op_str == 'lr' or
                                   ins.mnemonic == 'pop' and 'pc' in ins.op_str):
                break
    (output / "vendor-windows.asm").write_text(''.join(chunks))
    print(json.dumps(dict(commands=len(commands), partitions=partitions, sensor_matches=matches), indent=2))


if __name__ == '__main__':
    main()
