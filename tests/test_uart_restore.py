from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
from uart_restore_original import validate_packet, restore_sectors, DOWNLOAD, START, END
from uart_write_trial import packet, SIZE


class RestoreTests(unittest.TestCase):
    def test_only_exact_original_bytes_in_app_download(self):
        original = b'\xa5'*0x200000
        for address in (START, DOWNLOAD, END-SIZE):
            validate_packet(packet(7, struct.pack('<I', address)+original[address:address+SIZE]), original)
            validate_packet(packet(15, b'\x20'+struct.pack('<I', address)), original)
        for address in (0, 0x2000, START-1, START-4096, END, 0x1ff000):
            for cmd in (packet(15, b'\x20'+struct.pack('<I', address)),
                        packet(7, struct.pack('<I', address)+b'\xa5'*SIZE)):
                with self.assertRaises(ValueError): validate_packet(cmd, original)
        with self.assertRaises(ValueError):
            validate_packet(packet(7, struct.pack('<I', START)+b'\xff'*SIZE), original)
        with self.assertRaises(ValueError):
            validate_packet(packet(15, b'\xd8'+struct.pack('<I', START)), original)

    def test_download_first_then_app_configs_untouched(self):
        original = b'\xa5'*0x200000
        class Device:
            def __init__(self):
                self.memory = bytearray(original)
                self.memory[START] = self.memory[DOWNLOAD] = 0
                self.changes = []
            def sector(self, address): return bytes(self.memory[address:address+SIZE])
            def replace(self, address, data):
                self.changes.append(address)
                self.memory[address:address+SIZE] = data
        device = Device()
        checked = []
        restore_sectors(device, original, lambda done,total,changes: checked.append(done))
        self.assertEqual(device.changes, [DOWNLOAD, START])
        self.assertEqual(device.memory, original)
        self.assertEqual(len(checked), (END-START)//SIZE)

    def test_failure_stops_before_touching_app(self):
        class Device:
            def sector(self, address): return b'\x00'*SIZE
            def replace(self, address, data):
                self.address = address
                raise TimeoutError('lost session')
        device = Device()
        with self.assertRaises(TimeoutError):
            restore_sectors(device, b'\xff'*0x200000, lambda *args: None)
        self.assertEqual(device.address, DOWNLOAD)


if __name__ == '__main__': unittest.main()
