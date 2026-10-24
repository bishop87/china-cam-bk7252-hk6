import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import rbl


class RblTests(unittest.TestCase):
    @unittest.skipUnless((Path(__file__).resolve().parents[1] / 'analysis/ota/bka9.rbl').is_file(), "Private laboratory fixture not distributed; see docs/sviluppo.md")
    def test_vendor_fixture(self):
        raw, meta = rbl.unpack((ROOT / 'analysis/ota/bka9.rbl').read_bytes())
        self.assertEqual(meta['raw_sha256'], 'a7bda080533d98ef8a4ddbd3e332193bd3058b2b9fbdef94c4184c7d20c52790')
        self.assertEqual(len(raw), 794612)

    def test_roundtrip_various_lengths(self):
        for size in (1, 15, 16, 17, 4096, 100001):
            raw = bytes(i % 251 for i in range(size))
            package = rbl.pack(raw, 'test', 1792108800)
            self.assertEqual(rbl.unpack(package)[0], raw)
            self.assertEqual(package, rbl.pack(raw, 'test', 1792108800))

    def test_corruption_rejected(self):
        package = rbl.pack(b'test' * 100, 'test', 1792108800)
        for offset in (0, 20, 92, 100, len(package)-1):
            damaged = bytearray(package)
            damaged[offset] ^= 1
            with self.assertRaises(ValueError): rbl.unpack(bytes(damaged))

    def test_truncation_rejected(self):
        package = rbl.pack(b'test', 'test', 1792108800)
        for length in (0, 4, 95, len(package)-1):
            with self.assertRaises(ValueError): rbl.unpack(package[:length])


if __name__ == '__main__': unittest.main()
