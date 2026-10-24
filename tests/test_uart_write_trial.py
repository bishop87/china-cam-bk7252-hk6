import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
from uart_write_trial import (TARGET, SIZE, ERASED, PATTERN, Trial, packet, run_trial)


class FakeTrial:
    def __init__(self, fail_write=False, occupied=False):
        self.target = b'\x00'*SIZE if occupied else ERASED
        self.fail_write, self.erases, self.protected = fail_write, 0, False

    def sector(self, address):
        return self.target if address == TARGET else ERASED

    def link(self):
        pass

    def erase(self):
        self.erases += 1
        self.target = ERASED

    def write(self):
        self.target = PATTERN
        if self.fail_write:
            raise TimeoutError('Lost write acknowledgement after device wrote')

    def protect_and_crc(self, data):
        self.protected = True


class TrialTests(unittest.TestCase):
    def execute(self, fake):
        report = {}
        with tempfile.TemporaryDirectory() as directory:
            run_trial(fake, b'\xff'*0x200000, Path(directory), report, lambda: None)
        return report

    def test_success_restores_and_protects(self):
        fake = FakeTrial()
        report = self.execute(fake)
        self.assertTrue(report['pattern_verified_twice'])
        self.assertTrue(report['original_restored_twice'])
        self.assertTrue(report['guards_unchanged'])
        self.assertEqual(fake.erases, 2)
        self.assertTrue(fake.protected)
        self.assertEqual(fake.target, ERASED)

    def test_lost_ack_still_restores(self):
        fake = FakeTrial(fail_write=True)
        with self.assertRaises(TimeoutError):
            self.execute(fake)
        self.assertEqual(fake.target, ERASED)
        self.assertTrue(fake.protected)
        self.assertEqual(fake.erases, 2)

    def test_occupied_target_aborts_before_erase(self):
        fake = FakeTrial(occupied=True)
        with self.assertRaises(ValueError):
            self.execute(fake)
        self.assertEqual(fake.erases, 0)
        self.assertFalse(fake.protected)

    def test_reject_other_sector_and_arbitrary_data(self):
        trial = Trial(None, io.StringIO())
        for address in (0, 0x11000, TARGET-4096, TARGET+4096, 0x1fe000):
            with self.assertRaises(ValueError):
                trial.send(packet(15, b'\x20'+struct.pack('<I', address)))
        with self.assertRaises(ValueError):
            trial.send(packet(7, struct.pack('<I', TARGET)+ERASED))


if __name__ == '__main__':
    unittest.main()
