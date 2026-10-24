import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import urlopen
from main import Latest, handler_for, receive_forever

JPEG = b'\xff\xd8test\xff\xd9'


class ReconnectTests(unittest.TestCase):
    def test_session_failure_then_recovery(self):
        latest, stop = Latest(), threading.Event()
        recovered = threading.Event()
        release = threading.Event()
        sessions = []

        class FakeCamera:
            def __init__(self):
                self.number = len(sessions)
                self.closed = False
                sessions.append(self)
            def connect(self, cancel):
                if self.number == 1:
                    raise TimeoutError('Camera still off')
            def video(self, cancel):
                if self.number == 0:
                    yield JPEG
                    raise TimeoutError('Camera switched off')
                yield JPEG
                recovered.set()
                release.wait(2)
            def close(self):
                self.closed = True

        worker = threading.Thread(target=receive_forever,
                                  args=(FakeCamera, latest, stop, .001, .002))
        worker.start()
        try:
            self.assertTrue(recovered.wait(2))
            with latest.condition:
                self.assertEqual(latest.state, 'streaming')
                self.assertIsNone(latest.error)
                self.assertEqual(latest.count, 2)
                self.assertEqual(latest.reconnects, 2)
            self.assertTrue(all(s.closed for s in sessions[:2]))
        finally:
            stop.set()
            release.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertTrue(all(s.closed for s in sessions))

    def test_existing_http_stream_survives_outage(self):
        latest = Latest()
        latest.publish(JPEG)
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(latest))
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        def read_frame(response):
            self.assertEqual(response.readline(), b'--frame\r\n')
            response.readline()
            size = int(response.readline().split(b':')[1])
            response.readline()
            body = response.read(size)
            response.readline()
            return body
        try:
            with urlopen(f'http://127.0.0.1:{server.server_port}/stream.mjpg', timeout=3) as response:
                self.assertEqual(read_frame(response), JPEG)
                with latest.condition:
                    latest.frame = None
                    latest.error = 'offline'
                    latest.state = 'reconnecting'
                    latest.condition.notify_all()
                timer = threading.Timer(.15, latest.publish, args=(JPEG+b'new',))
                timer.start()
                self.assertEqual(read_frame(response), JPEG+b'new')
                timer.join()
        finally:
            with latest.condition:
                latest.stopped = True
                latest.condition.notify_all()
            server.shutdown()
            server.server_close()
            worker.join()
