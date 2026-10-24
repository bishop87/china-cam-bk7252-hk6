import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from build_stock_patch import apply_patch, build_package
from rbl import unpack


@unittest.skipUnless((ROOT/'analysis/original/app-payload.bin').exists(), 'Original dump required')
class StockPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (ROOT/'analysis/original/app-payload.bin').read_bytes()
        cls.header = (ROOT/'analysis/original/app-logical.bin').read_bytes()[0xfffa0:0x100000]
        cls.patched, _ = apply_patch(cls.raw)
        cls.package, _ = build_package(cls.patched, cls.header)

    def test_different_revision_and_second_application_rejected(self):
        damaged = bytearray(self.raw)
        damaged[0x200] ^= 1
        for data in (bytes(damaged), self.patched, self.raw[:-1]):
            with self.assertRaises(ValueError):
                apply_patch(data)

    def test_corrupted_or_truncated_container_rejected(self):
        for offset in (10, 92, 100, len(self.package)-1):
            damaged = bytearray(self.package)
            damaged[offset] ^= 1
            with self.assertRaises(ValueError):
                unpack(bytes(damaged))
        with self.assertRaises(ValueError):
            unpack(self.package[:-16])

    def test_wrong_target_header_rejected(self):
        wrong = bytearray(self.header)
        wrong[12:28] = b'bootloader'.ljust(16, b'\0')
        with self.assertRaises(ValueError):
            build_package(self.patched, bytes(wrong))


if __name__ == '__main__':
    unittest.main()
