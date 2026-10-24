from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from analyze_backup import decode_crc_region, verify_installed_header


class BackupAnalysisTests(unittest.TestCase):
    @unittest.skipUnless((Path(__file__).resolve().parents[1] / 'analysis/uart/originale-01/flash-start-256bytes.bin').is_file(), "Private laboratory fixture not distributed; see docs/sviluppo.md")
    def test_captured_crc_and_corruption(self):
        sample = (ROOT/'analysis/uart/originale-01/flash-start-256bytes.bin').read_bytes()[:238]
        decoded, check = decode_crc_region(sample)
        self.assertEqual(len(decoded), 7*32)
        self.assertEqual(check['valid'], 7)
        self.assertEqual(check['invalid'], 0)
        damaged = bytearray(sample)
        damaged[0] ^= 1
        _, check = decode_crc_region(damaged)
        self.assertEqual(check['invalid'], 1)
        self.assertEqual(check['valid'], 6)

    def test_erased_is_not_reported_as_verified(self):
        decoded, check = decode_crc_region(b'\xff'*68)
        self.assertEqual(decoded, b'\xff'*64)
        self.assertEqual(check['erased'], 2)
        self.assertEqual(check['valid'], 0)
        with self.assertRaises(ValueError): decode_crc_region(b'\xff'*35)

    @unittest.skipUnless((Path(__file__).resolve().parents[1] / 'analysis/original/app-logical.bin').is_file(), "Private laboratory fixture not distributed; see docs/sviluppo.md")
    def test_actual_installed_header_and_changed_payload(self):
        app = (ROOT/'analysis/original/app-logical.bin').read_bytes()
        report = verify_installed_header(app, 0xfffa0, 'app')
        for key in ('header_crc32_valid', 'payload_crc32_valid', 'payload_fnv1a_valid'):
            self.assertTrue(report[key])
        damaged = bytearray(app)
        damaged[0] ^= 1
        report = verify_installed_header(damaged, 0xfffa0, 'app')
        self.assertTrue(report['header_crc32_valid'])
        self.assertFalse(report['payload_crc32_valid'])
        self.assertFalse(report['payload_fnv1a_valid'])


if __name__ == '__main__': unittest.main()
