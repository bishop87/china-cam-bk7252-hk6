"""Pack/verify the observed RT-Thread RBL 0x102 format, entirely offline.

This is container compatibility, NOT proof that a bootloader accepts the image.
The AES key and IV are the vendor constants verified against bka9.rbl and the
backed-up HK6 bootloader; they differ from the pinned SDK's source defaults.
"""
import argparse
import gzip
import hashlib
import json
import struct
import zlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HEADER = struct.Struct('<4sII16s24s24sIIIII')
KEY = b'0123456789ABCDEF0123456789ABCDEF'
IV = b'0123456789ABCDEF'
MAX_RAW = 16 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fnv1a(data):
    h = 0x811c9dc5
    for byte in data:
        h = ((h ^ byte) * 16777619) & 0xffffffff
    return h


def unpack(package):
    require(len(package) >= HEADER.size, 'Truncated header')
    magic, algo, stamp, part, version, serial, crc, fnv, raw_size, size, header_crc = HEADER.unpack_from(package)
    require(magic == b'RBL\0' and algo == 0x102, 'Unsupported RBL format')
    require(zlib.crc32(package[:92]) == header_crc, 'Header CRC mismatch')
    require(len(package) == 96 + size and size > 0 and size % 16 == 0, 'Invalid payload size')
    require(0 < raw_size <= MAX_RAW, 'Invalid expanded size')
    require(zlib.crc32(package[96:]) == crc, 'Payload CRC mismatch')
    decryptor = Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor()
    padded = decryptor.update(package[96:]) + decryptor.finalize()
    pad = padded[-1]
    require(1 <= pad <= 16 and padded[-pad:] == bytes([pad]) * pad, 'Invalid PKCS7 padding')
    z = zlib.decompressobj(31)
    raw = z.decompress(padded[:-pad], raw_size + 1)
    require(z.eof and not z.unused_data and len(raw) == raw_size, 'Invalid gzip stream or size')
    require(fnv1a(raw) == fnv, 'Raw FNV1a mismatch')
    text = lambda b: b.split(b'\0', 1)[0].decode('ascii')
    return raw, dict(partition=text(part), version=text(version), timestamp=stamp, serial=text(serial),
                     raw_bytes=len(raw), rbl_bytes=len(package),
                     raw_sha256=hashlib.sha256(raw).hexdigest(), rbl_sha256=hashlib.sha256(package).hexdigest(),
                     checks='header CRC32, payload CRC32, PKCS7, gzip integrity, sizes, FNV1a')


def pack(raw, version, timestamp):
    require(0 < len(raw) <= MAX_RAW, 'Invalid input size')
    version = version.encode('ascii')
    require(0 < len(version) < 24, 'Version must be 1..23 ASCII bytes')
    compressed = gzip.compress(raw, compresslevel=9, mtime=timestamp)
    pad = 16 - len(compressed) % 16
    encryptor = Cipher(algorithms.AES(KEY), modes.CBC(IV)).encryptor()
    payload = encryptor.update(compressed + bytes([pad]) * pad) + encryptor.finalize()
    header = HEADER.pack(b'RBL\0', 0x102, timestamp, b'app', version, b'00010203040506070809',
                         zlib.crc32(payload), fnv1a(raw), len(raw), len(payload), 0)
    header = header[:92] + struct.pack('<I', zlib.crc32(header[:92]))
    package = header + payload
    require(unpack(package)[0] == raw, 'Packing round-trip failed')
    return package


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='cmd', required=True)
    for cmd in ('pack', 'unpack', 'inspect'):
        p = sub.add_parser(cmd)
        p.add_argument('input', type=Path)
        if cmd != 'inspect': p.add_argument('output', type=Path)
        if cmd == 'pack':
            p.add_argument('--version', default='LocalCam-0.1-EXPERIMENT')
            p.add_argument('--timestamp', type=int, default=1792108800)
    args = parser.parse_args()
    data = args.input.read_bytes()
    if args.cmd == 'pack':
        data = pack(data, args.version, args.timestamp)
        args.output.write_bytes(data)
    raw, meta = unpack(data)
    if args.cmd == 'unpack': args.output.write_bytes(raw)
    print(json.dumps(meta, indent=2))


if __name__ == '__main__':
    main()
