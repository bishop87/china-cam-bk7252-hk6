import json
import socket
import struct
import threading
import unittest
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from camera import Camera
from main import Latest, handler_for
from protocol import Frames, VIDEO_MAGIC, ack, crypt, packet, stream_command, unpack

JPEG = b'\xff\xd8' + b'test-frame' * 12 + b'\xff\xd9'


def start(data, size):
    header = bytearray(32)
    header[:6] = VIDEO_MAGIC
    struct.pack_into('<I', header, 16, size)
    return bytes(header) + data


class ProtocolTests(unittest.TestCase):
    def test_known_probe(self):
        self.assertEqual(packet(0x30), bytes.fromhex('2cba5f5d'))
        data = bytes(range(256)) * 8
        self.assertEqual(crypt(crypt(data), decrypt=True), data)

    def test_lengths_and_commands(self):
        for invalid in (b'', b'123', packet(0xd0, b'123')[:-1]):
            with self.assertRaises(ValueError):
                unpack(invalid)
        kind, body = unpack(stream_command('admin', 'secret'))
        self.assertEqual(kind, 0xd0)
        self.assertEqual(struct.unpack_from('<I', body, 8)[0], len(body) - 12)
        self.assertEqual(json.loads(body[12:])['cmd'], 111)
        self.assertEqual(unpack(ack(1, 65535)), (0xd1, bytes.fromhex('d1010001ffff')))

    def test_reordering_duplicate_and_wrap(self):
        f = Frames()
        self.assertIsNone(f.feed(1, 65535, start(JPEG[:20], len(JPEG))))
        self.assertIsNone(f.feed(1, 1, JPEG[60:]))
        self.assertIsNone(f.feed(1, 1, JPEG[60:]))
        self.assertEqual(f.feed(1, 0, JPEG[20:60]), JPEG)
        self.assertIsNone(f.feed(1, 65535, start(JPEG, len(JPEG))))

    def test_missing_fragment_and_channel_isolation(self):
        f = Frames()
        f.feed(1, 10, start(JPEG[:20], len(JPEG)))
        self.assertIsNone(f.feed(2, 11, JPEG[20:]))
        self.assertIsNone(f.feed(1, 12, JPEG[20:]))
        self.assertEqual(f.feed(1, 20, start(JPEG, len(JPEG))), JPEG)

    def test_invalid_frame(self):
        for size, data in ((2**32 - 1, JPEG), (4, b'abcd'), (4, JPEG)):
            self.assertIsNone(Frames().feed(1, 1, start(data, size)))

    def test_hk6_sdk_trailer(self):
        raw = JPEG + b"\0" + struct.pack("<I", len(JPEG))
        self.assertEqual(Frames().feed(1, 0, start(raw, len(raw))), JPEG)
        bad = JPEG + b"\0" + struct.pack("<I", len(JPEG) + 1)
        self.assertIsNone(Frames().feed(1, 0, start(bad, len(bad))))

    def test_udp_session(self):
        fake = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fake.bind(('127.0.0.1', 0))
        fake.settimeout(3)
        errors = []
        def vendor():
            try:
                data, peer = fake.recvfrom(4096)
                self.assertEqual(unpack(data), (0x30, b''))
                fake.sendto(packet(0x41, b'camera-uid'), peer)
                self.assertEqual(unpack(fake.recvfrom(4096)[0]), (0x41, b'camera-uid'))
                fake.sendto(packet(0x42), peer)
                command = unpack(fake.recvfrom(4096)[0])[1]
                self.assertEqual(json.loads(command[12:])['pro'], 'stream')
                fake.sendto(packet(0xe0), peer)
                while True:
                    kind, body = unpack(fake.recvfrom(4096)[0])
                    if kind == 0xe1:
                        break
                    self.assertEqual(kind, 0xd0)
                    self.assertEqual(json.loads(body[12:])['pro'], 'stream')
                body = bytes.fromhex('d1010000') + start(JPEG, len(JPEG))
                fake.sendto(packet(0xd0, body), peer)
                self.assertEqual(unpack(fake.recvfrom(4096)[0])[0], 0xd1)
                self.assertEqual(unpack(fake.recvfrom(4096)[0])[0], 0xf0)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=vendor)
        thread.start()
        camera = Camera('127.0.0.1', 'admin', 'test', timeout=2, port=fake.getsockname()[1])
        try:
            camera.connect()
            self.assertEqual(next(camera.video(threading.Event())), JPEG)
        finally:
            camera.close()
            thread.join(4)
            fake.close()
        self.assertFalse(thread.is_alive())
        if errors:
            raise errors[0]

    def test_timeout(self):
        camera = Camera('127.0.0.1', 'admin', 'test', timeout=0.1)
        try:
            with self.assertRaises(TimeoutError):
                camera.connect()
        finally:
            camera.close()

    def test_http(self):
        latest = Latest()
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(latest))
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        url = f'http://127.0.0.1:{server.server_port}'
        try:
            with self.assertRaises(HTTPError) as error:
                urlopen(url + '/snapshot.jpg')
            self.assertEqual(error.exception.code, 503)
            error.exception.close()
            latest.publish(JPEG)
            with urlopen(url + '/snapshot.jpg') as response:
                self.assertEqual(response.read(), JPEG)
            with urlopen(url + '/status') as response:
                self.assertEqual(json.load(response)['frames'], 1)
            with urlopen(url + '/stream.mjpg') as response:
                self.assertEqual(response.readline(), b'--frame\r\n')
                self.assertEqual(response.readline(), b'Content-Type: image/jpeg\r\n')
                self.assertEqual(response.readline(), f'Content-Length: {len(JPEG)}\r\n'.encode())
                self.assertEqual(response.readline(), b'\r\n')
                self.assertEqual(response.read(len(JPEG)), JPEG)
            with self.assertRaises(HTTPError) as error:
                urlopen(Request(url + '/status', headers={'Host': 'example.org'}))
            self.assertEqual(error.exception.code, 403)
            error.exception.close()
        finally:
            with latest.condition:
                latest.stopped = True
                latest.condition.notify_all()
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == '__main__':
    unittest.main()
