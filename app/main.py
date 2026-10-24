#!/usr/bin/env python3
"""Receive a JPEG on disk or expose MJPEG on loopback, using only stdlib."""
import argparse
import getpass
import ipaddress
import json
import secrets
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from camera import Camera
from controls import Controls, BusyError, VIDEO_PROFILES
from protocol import jpeg_size


class Latest:
    def __init__(self):
        self.condition = threading.Condition()
        self.frame = None
        self.count = 0
        self.updated = None
        self.error = None
        self.state = "connecting"
        self.reconnects = 0
        self.stopped = False
        self.dimensions = None

    def publish(self, frame):
        with self.condition:
            self.error = None
            self.state = "streaming"
            self.dimensions = jpeg_size(frame)
            self.frame = frame
            self.count += 1
            self.updated = time.monotonic()
            self.condition.notify_all()


def receive_forever(factory, latest, stop, retry_delay=2, max_delay=15, controls=None):
    """Create a fresh UDP session and assembler after every disconnect."""
    delay = retry_delay
    try:
        while not stop.is_set():
            camera = None
            try:
                camera = factory()
                camera.connect(stop)
                if controls and not stop.is_set():
                    controls.connected()
                for frame in camera.video(stop):
                    latest.publish(frame)
                    delay = retry_delay
                if not stop.is_set():
                    raise ConnectionError("Flusso terminato")
            except (OSError, ValueError) as exc:
                if not stop.is_set():
                    with latest.condition:
                        latest.error = str(exc)
                        latest.state = "reconnecting"
                        latest.frame = None
                        latest.reconnects += 1
                        latest.condition.notify_all()
                    print(f"Camera non disponibile: {exc}. Nuovo tentativo tra {delay:g}s.", flush=True)
            finally:
                try:
                    if camera is not None:
                        camera.close()
                finally:
                    if controls:
                        controls.disconnected()
            if stop.wait(delay):
                break
            delay = min(max_delay, delay * 2)
    finally:
        with latest.condition:
            latest.stopped = True
            latest.state = "stopped"
            latest.condition.notify_all()


def handler_for(latest, controls=None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Loopback binding plus strict Host prevents browser DNS rebinding.
            if self.headers.get('Host') not in {
                f'127.0.0.1:{self.server.server_port}',
                f'localhost:{self.server.server_port}',
            }:
                self.send_error(403)
                return
            self.connection.settimeout(5)
            with latest.condition:
                frame, error = latest.frame, latest.error
                age = None if latest.updated is None else time.monotonic() - latest.updated
                status = dict(frames=latest.count, age_seconds=age, error=error,
                              state=latest.state, reconnects=latest.reconnects, dimensions=latest.dimensions)
            if controls:
                with controls.lock:
                    status['requested_dimensions'] = VIDEO_PROFILES[controls.video_mode]['dimensions']
                status['audio'] = controls.audio.snapshot()
                status['playback'] = controls.storage.playback_status()
            assets = {'/': ('index.html', 'text/html; charset=utf-8'),
                      '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                      '/audio.js': ('audio.js', 'text/javascript; charset=utf-8'),
                      '/storage.js': ('storage.js', 'text/javascript; charset=utf-8'),
                      '/record-audio.js': ('record-audio.js', 'text/javascript; charset=utf-8'),
                      '/device.js': ('device.js', 'text/javascript; charset=utf-8'),
                      '/style.css': ('style.css', 'text/css; charset=utf-8')}
            if self.path in assets:
                name, mime = assets[self.path]
                self.respond(200, mime, (Path(__file__).parent / 'web' / name).read_bytes())
            elif self.path == '/api/state' and controls:
                self.respond(200, 'application/json', json.dumps(controls.snapshot()).encode())
            elif self.path == '/status':
                self.respond(200, 'application/json', json.dumps(status).encode())
            elif urlsplit(self.path).path in ('/audio.pcm','/recording.pcm') and controls:
                try:
                    after = int(parse_qs(urlsplit(self.path).query).get('after', ['0'])[0])
                    if after < 0:
                        raise ValueError()
                except ValueError:
                    self.send_error(400)
                    return
                source=controls.storage.audio if urlsplit(self.path).path=='/recording.pcm' else controls.audio
                sequence, pcm = source.read(after)
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(len(pcm)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Audio-Sequence', str(sequence))
                self.send_header('X-Audio-Rate', '8000')
                self.end_headers()
                try:
                    self.wfile.write(pcm)
                except OSError:
                    pass
            elif self.path == '/recording/status' and controls:
                self.respond(200,'application/json',json.dumps(controls.storage.playback_status(heartbeat=True)).encode())
            elif self.path == '/recording.avi' and controls:
                try:
                    data=controls.storage.avi()
                    self.respond(200,'video/x-msvideo',data)
                except ValueError as exc:
                    self.respond(409,'text/plain; charset=utf-8',str(exc).encode())
            elif self.path == '/recording.mjpg' and controls:
                storage=controls.storage
                self.send_response(200)
                self.send_header('Content-Type','multipart/x-mixed-replace; boundary=frame')
                self.send_header('Cache-Control','no-store');self.end_headers()
                sequence=0
                try:
                    while True:
                        with storage.condition:
                            storage.condition.wait_for(lambda: not storage.playing or (storage.frame is not None and storage.count!=sequence),timeout=1)
                            if not storage.playing:break
                            if not storage.frame or sequence==storage.count:continue
                            sequence,data=storage.count,storage.frame
                        self.wfile.write(b'--frame\r\nContent-Type: image/jpeg\r\nContent-Length: '+str(len(data)).encode()+b'\r\n\r\n'+data+b'\r\n')
                except OSError:pass
            elif self.path == '/snapshot.jpg':
                if frame and not error and age < 10:
                    self.respond(200, 'image/jpeg', frame)
                else:
                    self.respond(503, 'text/plain', b'Video non disponibile\n')
            elif self.path == '/stream.mjpg':
                self.send_response(200)
                self.send_header('Content-Type', 'multipart/x-mixed-replace; boundary=frame')
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                sequence = 0
                try:
                    while True:
                        with latest.condition:
                            ready = latest.condition.wait_for(
                                lambda: (latest.frame is not None and latest.count != sequence)
                                or latest.stopped, timeout=1)
                            if latest.stopped:
                                break
                            if not ready:
                                continue
                            sequence, data = latest.count, latest.frame
                        self.wfile.write(b'--frame\r\nContent-Type: image/jpeg\r\nContent-Length: '
                                         + str(len(data)).encode() + b'\r\n\r\n' + data + b'\r\n')
                    self.wfile.write(b'--frame--\r\n')
                except (OSError, TimeoutError):
                    pass
            else:
                self.send_error(404)

        def do_POST(self):
            host = self.headers.get('Host')
            allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
            if (not controls or host not in allowed
                    or self.headers.get('Origin') != f'http://{host}'
                    or not secrets.compare_digest(self.headers.get('X-Control-Token', ''), controls.token)):
                self.send_error(403)
                return
            if self.path != '/api/action':
                self.send_error(404)
                return
            self.connection.settimeout(5)
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 1 <= size <= 4096 or self.headers.get('Content-Type') != 'application/json':
                    raise ValueError('Richiesta JSON non valida o troppo grande')
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError('Richiesta incompleta')
                body = json.loads(raw)
                if not isinstance(body, dict) or set(body) != {'action', 'data'} or not isinstance(body['action'], str) or not isinstance(body['data'], dict):
                    raise ValueError('Richiesta non valida')
                result = controls.request(body['action'], body['data'])
                self.respond(200, 'application/json', json.dumps(result).encode())
            except BusyError as exc:
                self.respond(409, 'application/json', json.dumps({'error': str(exc)}).encode())
            except (ValueError, UnicodeError) as exc:
                # Never echo request bodies or JSON decoder excerpts (may contain passwords).
                message = str(exc) if not isinstance(exc, (json.JSONDecodeError, UnicodeError)) else 'JSON non valido'
                self.respond(400, 'application/json', json.dumps({'error': message}).encode())
            except OSError:
                self.close_connection = True

        def respond(self, code, mime, body):
            self.send_response(code)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass
    return Handler


def local_ipv4(value):
    address = ipaddress.IPv4Address(value)
    if not any(address in ipaddress.IPv4Network(net) for net in
               ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
        raise argparse.ArgumentTypeError('Specificare un IPv4 privato della camera')
    return str(address)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--camera', required=True, type=local_ipv4)
    parser.add_argument('--user', default='admin')
    parser.add_argument('--port', type=int, default=8765, help='Porta HTTP locale')
    parser.add_argument('--timeout', type=float, default=10)
    parser.add_argument('--snapshot', type=Path, help='Salva un JPEG ed esce; non avvia HTTP')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 0 < args.timeout <= 120:
        parser.error('Porta 1–65535; timeout maggiore di 0 e al massimo 120 secondi')
    password = getpass.getpass('Password camera (Invio = 6666): ') or '6666'
    stop, latest = threading.Event(), Latest()
    camera = None
    server = None
    controls = Controls(args.camera)
    def factory():
        with controls.lock:
            controls.restart = False
            return Camera(controls.host, args.user, password, args.timeout, controls=controls)

    worker = None
    try:
        if args.snapshot:
            camera = factory()
            camera.connect()
            frame = next(camera.video(stop))
            # Exclusive creation avoids replacing an existing recording.
            with args.snapshot.open('xb') as output:
                output.write(frame)
            print(f'JPEG ricevuto: {args.snapshot} ({len(frame)} byte)')
        else:
            server = ThreadingHTTPServer(('127.0.0.1', args.port), handler_for(latest, controls))
            server.daemon_threads = True
            worker = threading.Thread(target=receive_forever, args=(factory, latest, stop), kwargs={"controls": controls}, daemon=True)
            worker.start()
            print(f'Pagina: http://127.0.0.1:{args.port}/', flush=True)
            print(f'MJPEG: http://127.0.0.1:{args.port}/stream.mjpg', flush=True)
            print(f'Stato: http://127.0.0.1:{args.port}/status — Ctrl+C per terminare', flush=True)
            server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Errore: {exc}\n')
    finally:
        stop.set()
        if server:
            server.server_close()
        if worker:
            worker.join(timeout=args.timeout + 1)
        elif camera is not None:
            camera.close()


if __name__ == '__main__':
    main()
