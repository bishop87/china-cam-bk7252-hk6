import io
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
from ota_exp1 import (ROOT, PATCHES, logical_read, header_info, make_handler,
                      ENDPOINT, ORIGINAL_HEADER_ADDR, UPDATED_HEADER_ADDR)


class OTATests(unittest.TestCase):
    @unittest.skipUnless((Path(__file__).resolve().parents[1] / 'analysis/backups/hk6-original/flash-2MiB.bin').is_file(), "Private laboratory fixture not distributed; see docs/sviluppo.md")
    def test_physical_crc_mapping_and_factory_header(self):
        original = (ROOT/'analysis/backups/hk6-original/flash-2MiB.bin').read_bytes()
        class Console:
            def read_block(self, address): return original[address:address+256]
        c = Console()
        for patch in PATCHES:
            self.assertEqual(logical_read(c, patch['address'], len(bytes.fromhex(patch['before']))).hex(), patch['before'])
        header = logical_read(c, ORIGINAL_HEADER_ADDR, 96)
        self.assertEqual(header_info(header)['version'], '2M.1220')
        with self.assertRaises(ValueError): logical_read(c, UPDATED_HEADER_ADDR, 96)
        with self.assertRaises(ValueError): header_info(header[:-1]+bytes([header[-1]^1]))

    @unittest.skipUnless((Path(__file__).resolve().parents[1] / 'analysis/uart/ota-exp1/20261017-225427/installed-header.bin').is_file() and (Path(__file__).resolve().parents[1] / 'dist/hk6-stock-lan-exp1/hk6-stock-lan-exp1.rbl').is_file(), "Private laboratory fixture not distributed; see docs/sviluppo.md")
    def test_installed_exp1_header_retains_ota_algorithm(self):
        installed = (ROOT/'analysis/uart/ota-exp1/20261017-225427/installed-header.bin').read_bytes()
        package = (ROOT/'dist/hk6-stock-lan-exp1/hk6-stock-lan-exp1.rbl').read_bytes()
        self.assertEqual(installed, package[:96])
        self.assertEqual(header_info(installed)['algorithm'], 0x102)

    def test_server_only_pinned_path_and_camera_or_host(self):
        for path, client, expected in [(ENDPOINT,'192.168.1.54',200),
                                       ('/../analysis/backups/flash.bin','192.168.1.54',404),
                                       ('/', '192.168.1.54',404),
                                       (ENDPOINT,'192.168.1.77',404)]:
            event, records, status = threading.Event(), [], []
            cls = make_handler(b'fixture', '192.168.1.53', '192.168.1.54', records, event)
            handler = object.__new__(cls)
            handler.path, handler.client_address = path, (client, 1234)
            handler.command, handler.wfile = 'GET', io.BytesIO()
            handler.connection = type('Conn', (), {'settimeout': lambda *args: None})()
            handler.send_response = status.append
            handler.send_error = status.append
            handler.send_header = lambda *args: None
            handler.end_headers = lambda: None
            handler.handle_file(True)
            self.assertEqual(status, [expected])
            self.assertEqual(handler.wfile.getvalue(), b'fixture' if expected == 200 else b'')
            self.assertEqual(event.is_set(), expected == 200)


if __name__ == '__main__': unittest.main()
