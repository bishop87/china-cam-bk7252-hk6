"""Validate the original HK6 dump and extract partitions without changing it."""
import argparse
import datetime
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import zlib

from uart_backup import BLOCK, SIZE, parse_dump, stored_chunks

EXPECTED = 'b92beaf5a9500bccb4044905ab926fa82f25b88343443930f9459e6c253a4eed'
PARTS = [('bootloader', 0, 0xf000, True), ('app', 0x10000, 0x110000, True),
         ('download', 0x132000, 0xcc000, False), ('EasyFlash', 0x1fe000, 0x1000, False),
         ('param2', 0x1ff000, 0x1000, False)]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_installed_header(region, offset, partition):
    header = region[offset:offset+96]
    magic, algo, stamp, part, version, _, crc, expected_fnv, raw_size, padded_size, header_crc = \
        struct.unpack('<4sII16s24s24sIIIII', header)
    if magic != b'RBL\0' or part.split(b'\0')[0] != partition.encode() or algo != 0:
        raise ValueError('Unexpected installed image header')
    if not 0 < raw_size <= padded_size <= offset:
        raise ValueError('Invalid installed payload lengths')
    fnv = 0x811c9dc5
    for byte in region[:raw_size]:
        fnv = ((fnv ^ byte)*0x1000193) & 0xffffffff
    return dict(logical_file_offset=hex(offset), algorithm=algo,
                version=version.split(b'\0')[0].decode('ascii'),
                timestamp_utc=datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).isoformat(),
                raw_bytes=raw_size, padded_bytes=padded_size,
                header_crc32_valid=zlib.crc32(header[:92]) == header_crc,
                payload_crc32_valid=zlib.crc32(region[:padded_size]) == crc,
                payload_fnv1a_valid=fnv == expected_fnv,
                payload_sha256=sha(region[:raw_size]),
                note='Installed plaintext header, not evidence that plaintext OTA updates are accepted.')


def decode_crc_region(raw):
    if len(raw) % 34:
        raise ValueError('CRC region length must be a multiple of 34')
    table = []
    for value in range(256):
        crc = value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x8005 if crc & 0x8000 else crc << 1) & 0xffff
        table.append(crc)
    stats = Counter(valid=0, erased=0, invalid=0)
    errors, decoded = [], bytearray()
    for offset in range(0, len(raw), 34):
        block = raw[offset:offset+34]
        decoded.extend(block[:32])
        if block == b'\xff'*34:
            stats['erased'] += 1  # Erased blocks are not CRC-validated.
            continue
        crc = 0xffff
        for value in block[:32]:
            crc = ((crc << 8) & 0xffff) ^ table[(crc >> 8) ^ value]
        if crc == int.from_bytes(block[32:], 'big'):
            stats['valid'] += 1
        else:
            stats['invalid'] += 1
            if len(errors) < 16:
                errors.append(hex(offset))
    return bytes(decoded), dict(stats, first_invalid_relative_offsets=errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', type=Path, default=Path('analysis/backups/hk6-original'))
    parser.add_argument('--output', type=Path, default=Path('analysis/original'))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = args.backup/'flash-2MiB.bin'
    raw = source.read_bytes()
    if len(raw) != SIZE or sha(raw) != EXPECTED:
        raise ValueError('Input does not match the completed original HK6 backup')
    manifest = json.loads((args.backup/'manifest.json').read_text())
    checksum = (args.backup/'SHA256SUMS').read_text().split()[0]
    if manifest['sha256'] != EXPECTED or manifest['bytes'] != SIZE or checksum != EXPECTED:
        raise ValueError('Manifest/checksum inconsistent')
    db = sqlite3.connect((args.backup/'checkpoint.sqlite3').resolve().as_uri()+'?mode=ro', uri=True)
    try:
        integrity = db.execute('PRAGMA integrity_check').fetchone()[0]
        rows = stored_chunks(db)
    finally:
        db.close()
    if integrity != 'ok' or b''.join(row[1] for row in rows) != raw:
        raise ValueError('Checkpoint differs from full dump')

    # Independently verify the recorded UART reads against the exported binary.
    transcript = (args.backup/'serial-transcript.bin').read_bytes()
    headers = list(re.finditer(rb'(?m)^flash_dump 0x([0-9a-fA-F]{8}) (\d+)\r?\n', transcript))
    matching, malformed, differing = Counter(), 0, []
    for index, header in enumerate(headers):
        address, count = int(header[1], 16), int(header[2])
        end = headers[index+1].start() if index+1 < len(headers) else len(transcript)
        if count != BLOCK or address % BLOCK or not 0 <= address < SIZE:
            malformed += 1
            continue
        try:
            data = parse_dump(transcript[header.start():end], address)
        except ValueError:
            malformed += 1
            continue
        if data != raw[address:address+BLOCK]:
            differing.append(hex(address))
        else:
            matching[address] += 1
    insufficient = [hex(a) for a in range(0, SIZE, BLOCK) if matching[a] < 2]
    partitions = []
    for name, offset, size, crc in PARTS:
        physical = offset//32*34 if crc else offset
        physical_size = size//32*34 if crc else size
        region = raw[physical:physical+physical_size]
        decoded, validation = decode_crc_region(region) if crc else (region, None)
        filename = name + ('-logical.bin' if crc else '-physical.bin')
        (args.output/filename).write_bytes(decoded)
        installed = None
        if crc:
            installed = verify_installed_header(decoded, 0xefa0 if name == 'bootloader' else 0xfffa0, name)
            (args.output/(name+'-payload.bin')).write_bytes(decoded[:installed['raw_bytes']])
        partitions.append(dict(name=name, address_space='logical' if crc else 'physical',
                               offset=hex(offset), length=hex(size), physical_offset=hex(physical),
                               physical_length=hex(physical_size), physical_sha256=sha(region),
                               extracted_file=filename, extracted_sha256=sha(decoded),
                               crc_validation=validation, installed_header=installed))
    # Cross-check the actual app's FAL table against the UART observations.
    app = (args.output/'app-logical.bin').read_bytes()
    embedded_parts = []
    for match in re.finditer(b'01PE', app):
        pos = match.start()
        if pos+64 > len(app): continue
        _, name, dev, offset, length, _ = struct.unpack_from('<I24s24sIII', app, pos)
        embedded_parts.append((name.split(b'\0')[0].decode('ascii'),
                               dev.split(b'\0')[0].decode('ascii'), offset, length))
    expected_parts = [(name, 'beken_onchip_crc' if crc else 'beken_onchip', offset, size)
                      for name, offset, size, crc in PARTS]
    if embedded_parts != expected_parts:
        raise ValueError('Embedded FAL table differs from UART observations')
    report = dict(source=str(source), bytes=len(raw), sha256=EXPECTED, checksum_manifest_match=True,
                  sqlite_integrity=integrity, checkpoint_blocks=len(rows), checkpoint_equals_binary=True,
                  transcript=dict(bytes=len(transcript), sha256=sha(transcript),
                                  parsed_headers=len(headers), malformed_responses=malformed,
                                  matching_responses=sum(matching.values()),
                                  minimum_matching_reads_per_block=min(matching[a] for a in range(0,SIZE,BLOCK)),
                                  differing_response_addresses=differing,
                                  blocks_with_fewer_than_two_matches=insufficient),
                  partitions=partitions, embedded_fal_matches_uart=True, restore_tested=False,
                  caveats=['Two reads per block are not an atomic snapshot of a running camera.',
                           'CRC is checked only in CRC-bearing partitions, excluding erased 0xFF blocks.',
                           'The flash configuration covers 2 MiB; physical chip capacity is not independently read.',
                           'EasyFlash and param2 may contain credentials, identifiers and calibration; keep local.'])
    (args.output/'backup-validation.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('caveats',)},indent=2))
    if insufficient or differing or any(p['crc_validation'] and p['crc_validation']['invalid'] for p in partitions):
        raise SystemExit('Validation failed; see backup-validation.json')
    for part in partitions:
        header = part['installed_header']
        if header and not all(header[k] for k in ('header_crc32_valid', 'payload_crc32_valid', 'payload_fnv1a_valid')):
            raise SystemExit('Installed header integrity check failed')


if __name__ == '__main__': main()
