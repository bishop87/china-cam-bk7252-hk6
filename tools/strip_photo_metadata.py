"""Remove JPEG EXIF/XMP/IPTC/comments losslessly; retain only EXIF orientation.

Image scan data is copied byte-for-byte. Originals should be kept separately.
"""
import argparse
from pathlib import Path
import struct


def orientation(payload):
    if not payload.startswith(b'Exif\0\0'):
        return None
    tiff = payload[6:]
    if tiff[:2] not in (b'II', b'MM'):
        raise ValueError('Invalid EXIF byte order')
    endian = '<' if tiff[:2] == b'II' else '>'
    if struct.unpack_from(endian+'H', tiff, 2)[0] != 42:
        raise ValueError('Invalid TIFF header')
    off = struct.unpack_from(endian+'I', tiff, 4)[0]
    count = struct.unpack_from(endian+'H', tiff, off)[0]
    for i in range(count):
        entry = off + 2 + 12*i
        tag, kind, n = struct.unpack_from(endian+'HHI', tiff, entry)
        if tag == 274:
            if kind != 3 or n != 1:
                raise ValueError('Unsupported orientation field')
            value = struct.unpack_from(endian+'H', tiff, entry+8)[0]
            if not 1 <= value <= 8:
                raise ValueError('Invalid orientation')
            return value
    return None


def clean(data):
    if data[:2] != b'\xff\xd8':
        raise ValueError('Expected JPEG')
    pos, retained, value = 2, [], 1
    while pos < len(data):
        start = pos
        if data[pos] != 255:
            raise ValueError('Expected JPEG marker')
        while data[pos] == 255:
            pos += 1
        marker = data[pos]
        pos += 1
        if marker in (0xda, 0xd9):
            retained.append(data[start:])
            break
        size = struct.unpack_from('>H', data, pos)[0]
        if size < 2 or pos+size > len(data):
            raise ValueError('Truncated JPEG segment')
        payload = data[pos+2:pos+size]
        if marker == 0xe1:
            found = orientation(payload)
            if found is not None:
                value = found
        if marker not in (0xe1, 0xed, 0xfe):
            retained.append(data[start:pos+size])
        pos += size
    else:
        raise ValueError('JPEG has no scan')
    # A single TIFF IFD containing only orientation. No GPS/thumbnail pointers.
    # Explicit layout: TIFF header, count, tag/type/count/value, next-IFD zero.
    exif = b'Exif\0\0II' + struct.pack('<HIH', 42, 8, 1) + struct.pack('<HHIHHI', 274, 3, 1, value, 0, 0)
    return b'\xff\xd8\xff\xe1' + struct.pack('>H', len(exif)+2) + exif + b''.join(retained)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('photos', nargs='+', type=Path)
    args = parser.parse_args()
    for photo in args.photos:
        photo.write_bytes(clean(photo.read_bytes()))
        print(photo)
