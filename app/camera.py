"""Single local UDP session. No cloud lookup, configuration, reset or OTA."""
import socket
import struct
import time
from protocol import Frames, Responses, ack, command, packet, unpack, jpeg_size
from audio_stream import AudioFrames


class Camera:
    def __init__(self, host, user, password, timeout=10, port=32108, controls=None):
        self.host, self.port = host, port
        self.user, self.password = user, password
        self.timeout = timeout
        self.controls = controls
        self.sequence = 0
        self.outgoing = {}
        self.responses = Responses()
        self.peer = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind(("0.0.0.0", 0))
            self.sock.settimeout(0.5)
        except OSError:
            self.sock.close()
            raise
        self.frames = Frames()
        self.audio_frames = AudioFrames()
        self.playback_audio_frames = AudioFrames(playback=True)
        self.received = 0
        self.invalid = 0

    def receive(self):
        data, peer = self.sock.recvfrom(65535)
        if peer[0] != self.host or (self.peer and peer != self.peer):
            return None
        try:
            kind, body = unpack(data)
        except ValueError:
            self.invalid += 1
            return None
        self.received += 1
        return kind, body, peer

    def connect(self, stop=None):
        deadline = time.monotonic() + self.timeout
        next_send = 0
        punch = None
        while time.monotonic() < deadline:
            if stop is not None and stop.is_set():
                return
            if time.monotonic() >= next_send:
                self.sock.sendto(punch or packet(0x30), self.peer or (self.host, self.port))
                next_send = time.monotonic() + 1
            try:
                message = self.receive()
            except socket.timeout:
                continue
            if not message:
                continue
            kind, body, peer = message
            if kind == 0x41:
                self.peer = peer
                punch = packet(kind, body)
                self.sock.sendto(punch, peer)
            elif kind == 0x42 and self.peer:
                video = self.controls.video_mode if self.controls else 1
                self.send_command("stream", 111, {"video": video})
                return
        raise TimeoutError("Handshake PPPP non completato: verificare IP, rete e variante del protocollo")

    def send_command(self, pro, cmd, fields=None):
        index = self.sequence
        self.sequence = (index + 1) % 65536
        data = command(self.user, self.password, pro, cmd, fields, index)
        self.sock.sendto(data, self.peer)
        # Space the command from the high-rate ACK stream on this firmware.
        time.sleep(.02)
        self.sock.sendto(data, self.peer)
        self.outgoing[index] = [data, time.monotonic(), 0]
        return index

    def service_commands(self):
        now = time.monotonic()
        for index, entry in list(self.outgoing.items()):
            if now - entry[1] >= .8:
                if entry[2] >= 5:
                    del self.outgoing[index]
                else:
                    self.sock.sendto(entry[0], self.peer)
                    entry[1] = now
                    entry[2] += 1
        if self.controls:
            self.controls.tick(self)

    def video(self, stop):
        # Deadline follows complete frames, not keepalives: wrong credentials
        # or unsupported video cannot hold the session open indefinitely.
        deadline = time.monotonic() + self.timeout
        while not stop.is_set():
            self.service_commands()
            if time.monotonic() > deadline and not (self.controls and self.controls.storage.paused):
                raise TimeoutError("Video interrotto o assente: nessun JPEG completo entro il timeout")
            try:
                message = self.receive()
            except socket.timeout:
                continue
            if not message:
                continue
            kind, body, _ = message
            if kind == 0xd1 and len(body) >= 4 and body[:2] == b"\xd1\x00":
                count = int.from_bytes(body[2:4], "big")
                if len(body) == 4 + count * 2:
                    for offset in range(4, len(body), 2):
                        index = int.from_bytes(body[offset:offset+2], "big")
                        if not self.controls or not self.controls.retry_read(index):
                            self.outgoing.pop(index, None)
                        if self.controls:
                            self.controls.acknowledged(index)
            elif kind == 0xe0:
                self.sock.sendto(packet(0xe1), self.peer)
            elif kind == 0xf0:
                raise ConnectionError("La camera ha chiuso la sessione")
            elif kind == 0xd0 and len(body) >= 4 and body[0] == 0xd1:
                channel, index = body[1], struct.unpack_from(">H", body, 2)[0]
                self.sock.sendto(ack(channel, index), self.peer)
                if channel == 0:
                    for reply in self.responses.feed(index, body[4:]):
                        if self.controls:
                            with self.controls.lock:
                                job = self.controls.active
                                if job and job.get('response_cmd',job['cmd']) == reply.get('cmd'):
                                    self.outgoing.pop(job['index'], None)
                                if job and job.get('response_cmd',job['cmd'])!=reply.get('cmd'):
                                    print(f"Risposta camera inattesa: cmd={reply.get('cmd')}, atteso={job['cmd']}",flush=True)
                                self.controls.reply(reply)
                                if reply.get('cmd')==207:deadline=time.monotonic()+self.timeout
                    continue
                if channel == 2:
                    for pcm in self.audio_frames.feed(index, body[4:]):
                        if self.controls:
                            self.controls.audio.publish(pcm)
                    if self.controls and self.audio_frames.unsupported is not None:
                        with self.controls.audio.condition:
                            self.controls.audio.error = 'Codec audio non supportato: ' + str(self.audio_frames.unsupported)
                    continue
                if channel==3 and self.controls:
                    for pcm in self.playback_audio_frames.feed(index,body[4:]):
                        self.controls.storage.audio.publish(pcm)
                frame = self.frames.feed(channel, index, body[4:])
                if frame and channel == 3:
                    if self.controls:self.controls.storage.publish(frame)
                    deadline = time.monotonic() + self.timeout
                    continue
                if frame:
                    if self.controls:self.controls.live_dimensions = jpeg_size(frame)
                    deadline = time.monotonic() + self.timeout
                    yield frame

    def close(self):
        try:
            if self.peer:
                if self.controls and self.controls.storage.playing:
                    # Best effort on shutdown; only a JSON reply would confirm stop.
                    self.send_command('play_record_file', 207, {'type': 0})
                for _ in range(3):
                    self.sock.sendto(packet(0xf0), self.peer)
        except OSError:
            pass
        finally:
            self.sock.close()
