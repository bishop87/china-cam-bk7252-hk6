#!/usr/bin/env python3
"""Count candidate PPPP headers in Ethernet PCAP; never print payloads or UIDs."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
from protocol import crypt


def inspect(path):
    counts = Counter()
    with path.open('rb') as source:
        header = source.read(24)
        magic = header[:4]
        if magic in (bytes.fromhex('d4c3b2a1'), bytes.fromhex('4d3cb2a1')):
            endian = '<'
        elif magic in (bytes.fromhex('a1b2c3d4'), bytes.fromhex('a1b23c4d')):
            endian = '>'
        else:
            raise ValueError('Expected classic PCAP')
        if len(header) != 24 or struct.unpack_from(endian + 'I', header, 20)[0] != 1:
            raise ValueError('Expected Ethernet link type')
        while record := source.read(16):
            if len(record) != 16:
                raise ValueError('Truncated record')
            _, _, length, original = struct.unpack(endian + 'IIII', record)
            if length > 1024 * 1024:
                raise ValueError('Record too large')
            data = source.read(length)
            if len(data) != length:
                raise ValueError('Truncated record data')
            counts['packets'] += 1
            counts['truncated'] += length < original
            if len(data) < 34 or data[12:14] != b'\x08\x00' or data[23] != 17:
                continue
            offset = 14 + (data[14] & 15) * 4
            if offset < 34 or len(data) < offset + 8:
                continue
            counts['udp'] += 1
            sport, dport, size, _ = struct.unpack_from('>HHHH', data, offset)
            if {sport, dport} & {53, 67, 68, 123}:
                continue
            counts['other_udp'] += 1
            payload = data[offset + 8:offset + size]
            decoded = crypt(payload, decrypt=True)
            if len(decoded) >= 4 and decoded[0] == 0xf1:
                counts[f'candidate_pppp_0x{decoded[1]:02x}'] += 1
    return dict(file=str(path), counts=dict(counts))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap', type=Path, nargs='+')
    args = parser.parse_args()
    print(json.dumps([inspect(path) for path in args.pcap], indent=2))
