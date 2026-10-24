"""Protocol framing checks; no serial device or hardware access."""
import io
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from uart_boot_probe import ACK, VERSION, Probe, extract_frame, read_command


class BootProbeTests(unittest.TestCase):
    def test_fragmented_ack_after_noise(self):
        buffer = bytearray(b'boot log\r\n' + ACK[:1])
        self.assertIsNone(extract_frame(buffer))
        buffer.extend(ACK[1:5])
        self.assertIsNone(extract_frame(buffer))
        buffer.extend(ACK[5:])
        self.assertEqual(extract_frame(buffer), ACK)
        self.assertEqual(buffer, b'')

    def test_sector_frame_leaves_next_ack(self):
        frame = bytes.fromhex('040eff01e0fcf40610090000100100') + bytes(4096)
        buffer = bytearray(frame + ACK)
        self.assertEqual(extract_frame(buffer), frame)
        self.assertEqual(extract_frame(buffer), ACK)

    def test_protected_and_unapproved_addresses_rejected(self):
        for address in (0, 0x1000, 0x1fff, 0x1fe000, 0x200000):
            with self.assertRaises(ValueError):
                read_command(address)
        self.assertEqual(read_command(0x11000).hex(), '01e0fcfff405000900100100')

    def test_stale_ack_not_reported_as_version(self):
        probe = Probe(None, io.StringIO())
        sent = []
        version = bytes.fromhex('040e0501e0fc1141')
        replies = iter((ACK, version))
        probe.send = sent.append
        probe.receive = lambda seconds: next(replies)
        self.assertEqual(probe.request(VERSION), version)
        self.assertEqual(sent, [VERSION])

    def test_write_command_rejected_before_serial_access(self):
        probe = Probe(None, io.StringIO())
        with self.assertRaises(ValueError):
            probe.send(bytes.fromhex('01e0fcfff405000f2000100100'))


if __name__ == '__main__':
    unittest.main()
