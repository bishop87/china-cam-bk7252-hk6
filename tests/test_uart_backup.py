import hashlib
import io
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import uart_backup as backup


def response(data, address=0):
    lines = [f'flash_dump 0x{address:08X} {len(data)}\r\n'.encode()]
    for i in range(0, len(data), 16):
        lines.append(f'{i:08X}: '.encode() +
                     b''.join(f'{b:02X} '.encode() for b in data[i:i+16]) + b' ................\r\n')
    return b''.join(lines) + b'msh />'


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.data = bytes(range(256))
        self.db = sqlite3.connect(':memory:')
        self.db.execute('CREATE TABLE chunks (address INTEGER PRIMARY KEY, data BLOB, sha256 TEXT)')

    def tearDown(self):
        self.db.close()

    @unittest.skipUnless((Path(__file__).resolve().parents[1] / 'analysis/uart/originale-01/flash-start-256bytes-response.txt').is_file() and (Path(__file__).resolve().parents[1] / 'analysis/uart/originale-01/flash-start-64bytes.bin').is_file(), "Private laboratory fixture not distributed; see docs/sviluppo.md")
    def test_actual_camera_sample(self):
        raw = (ROOT / 'analysis/uart/originale-01/flash-start-256bytes-response.txt').read_bytes()
        data = backup.parse_dump(raw, 0)
        self.assertEqual(data[:64], (ROOT / 'analysis/uart/originale-01/flash-start-64bytes.bin').read_bytes())
        self.assertEqual(len(data), 256)

    def test_fragmented_serial_response_with_background_logs(self):
        left, right = socket.socketpair()
        console = backup.Console.__new__(backup.Console)
        console.fd, console.log = left.fileno(), io.BytesIO()
        packet = response(self.data, 256).replace(b'00000080:', b'\x1b[31m[E/NTP] timeout\x1b[0m\r\n00000080:')
        received = []
        def serve():
            command = b''
            while not command.endswith(b'\r'):
                command += right.recv(64)
            received.append(command)
            for i in range(0, len(packet), 7):
                right.sendall(packet[i:i+7])
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            self.assertEqual(console.read_block(256), self.data)
        finally:
            thread.join(timeout=3)
            left.close(); right.close()
        self.assertEqual(received, [b'flash_dump 256 256\r'])

    def test_lost_enter_is_resynchronized_before_fresh_read(self):
        left, right = socket.socketpair()
        right.settimeout(3)
        console = backup.Console.__new__(backup.Console)
        console.fd, console.log = left.fileno(), io.BytesIO()
        console.timeout = 0.1
        console.character_delay = console.command_pause = 0
        received, failures = [], []
        def receive_line():
            value = b''
            while not value.endswith(b'\r'):
                value += right.recv(1)
            received.append(value)
            return value
        def serve():
            try:
                first = receive_line()
                # Actual failure observed: echo only, no CRLF, dump or prompt.
                right.sendall(first[:-1])
                receive_line()  # Recovery CR completes the pending read.
                right.sendall(response(b'X'*256))  # Must NOT be returned as fresh data.
                receive_line()
                right.sendall(response(self.data))
            except Exception as error:
                failures.append(error)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with patch.object(backup, 'status'):
                self.assertEqual(console.read_block(0), self.data)
        finally:
            thread.join(timeout=4)
            left.close(); right.close()
        self.assertFalse(failures)
        self.assertEqual(received, [b'flash_dump 0 256\r', b'\r', b'flash_dump 0 256\r'])

    def test_retries_are_bounded_and_do_not_accept_wrong_response(self):
        console = backup.Console.__new__(backup.Console)
        with patch.object(console, 'exchange', return_value=response(self.data, 256)) as exchange:
            with patch.object(console, 'synchronize') as synchronize, patch.object(backup, 'status'):
                with self.assertRaises(RuntimeError): console.read_block(0)
        self.assertEqual(exchange.call_count, 3)
        self.assertEqual(synchronize.call_count, 2)

    def test_status_lines_include_carriage_return_on_raw_terminal(self):
        class RawTerminal(io.StringIO):
            def isatty(self): return True
        output = RawTerminal()
        backup.status('first\nsecond', output)
        self.assertEqual(output.getvalue(), '\rfirst\r\nsecond\r\n')

    def test_limited_capture_retains_resumable_checkpoint(self):
        with patch.object(backup, 'SIZE', 768):
            backup.acquire(self.db, lambda _: self.data, lambda _: None, max_blocks=1)
            self.assertEqual(len(backup.stored_chunks(self.db)), 1)
            backup.acquire(self.db, lambda _: self.data, lambda _: None, max_blocks=1)
            self.assertEqual(len(backup.stored_chunks(self.db)), 2)

    def test_rejects_incomplete_duplicate_wrong_address_and_corrupt_rows(self):
        raw = response(self.data)
        variants = [
            raw.replace(b'00000020:', b'00000030:'),
            raw.replace(b'flash_dump 0x00000000', b'flash_dump 0x00000100'),
            raw.replace(b'00 01 02', b'00 XX 02'),
            raw[:raw.index(b'000000F0:')] + b'msh />',
            raw + b'\n000000F0: ' + b'00 '*16 + b'\n',
        ]
        for broken in variants:
            with self.subTest(broken=broken[:50]):
                with self.assertRaises(ValueError): backup.parse_dump(broken, 0)

    def test_refuses_non_read_commands(self):
        console = backup.Console.__new__(backup.Console)
        with self.assertRaises(ValueError): console.exchange(b'flash_erase 0\r')

    def test_mismatch_never_committed_and_resume_exports_exact_bytes(self):
        calls = []
        def mismatch(address):
            calls.append(address)
            if address == 256 and calls.count(256) == 2:
                return b'X'*256
            return self.data
        with patch.object(backup, 'SIZE', 512):
            with self.assertRaises(ValueError): backup.acquire(self.db, mismatch, lambda _: None)
            self.assertEqual(len(backup.stored_chunks(self.db)), 1)
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError): backup.export(self.db, Path(directory))
                backup.acquire(self.db, lambda _: self.data, lambda _: None)
                image, digest = backup.export(self.db, Path(directory))
                self.assertEqual(image.read_bytes(), self.data*2)
                self.assertEqual(digest, hashlib.sha256(self.data*2).hexdigest())

    def test_resume_rejects_changed_target_and_corrupt_checkpoint(self):
        self.db.execute('INSERT INTO chunks VALUES (?, ?, ?)',
                        (0, self.data, hashlib.sha256(self.data).hexdigest()))
        with self.assertRaises(ValueError):
            backup.acquire(self.db, lambda _: b'X'*256, lambda _: None)
        self.db.execute('UPDATE chunks SET sha256 = ?', ('incorrect',))
        with self.assertRaises(ValueError): backup.stored_chunks(self.db)


if __name__ == '__main__':
    unittest.main()
