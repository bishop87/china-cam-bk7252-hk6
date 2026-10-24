"""Bounded channel-2 audio assembly and transient PCM delivery (no recording)."""
import struct
import threading
import time
from collections import deque

MAGIC = bytes.fromhex('55aa15a8')
RATE = 8000


def alaw_pcm(data):
    samples = []
    for code in data:
        value = code ^ 0x55
        segment = (value >> 4) & 7
        sample = ((value & 15) << 4) + 8
        if segment:
            sample += 256
            sample <<= segment - 1
        samples.append(sample if value & 128 else -sample)
    return struct.pack('<' + 'h' * len(samples), *samples)


# IMA step table; HK6 uses high nibble first and resets predictor per frame.
STEPS = (7,8,9,10,11,12,13,14,16,17,19,21,23,25,28,31,34,37,41,45,50,55,60,66,73,80,88,97,107,118,130,143,157,173,190,209,230,253,279,307,337,371,408,449,494,544,598,658,724,796,876,963,1060,1166,1282,1411,1552,1707,1878,2066,2272,2499,2749,3024,3327,3660,4026,4428,4871,5358,5894,6484,7132,7845,8630,9493,10442,11487,12635,13899,15289,16818,18500,20350,22385,24623,27086,29794,32767)
INDEX = (-1,-1,-1,-1,2,4,6,8)


def adpcm_pcm(data):
    predictor = index = 0
    samples = []
    for byte in data:
        for nibble in (byte >> 4, byte & 15):
            step = STEPS[index]
            delta = (step * (nibble & 7)) // 4 + step // 8
            predictor = max(-32768, min(32767, predictor + (-delta if nibble & 8 else delta)))
            samples.append(predictor)
            index = max(0, min(88, index + INDEX[nibble & 7]))
    return struct.pack('<' + 'h' * len(samples), *samples)


class AudioFrames:
    """Native client uses 32-byte headers, payload length at offset 16, channel 2."""
    def __init__(self, playback=False):
        self.playback = playback
        self.next = None if playback else 0
        self.pending = {}
        self.buffer = bytearray()
        self.updated = time.monotonic()
        self.unsupported = None

    def feed(self, index, payload):
        if self.next is None:self.next=index
        distance = (index - self.next) % 65536
        if distance >= 32768:
            return []
        now = time.monotonic()
        if distance > 64 or (distance and now - self.updated > .5):
            self.pending.clear()
            self.buffer.clear()
            self.next = index
        self.pending.setdefault(index, payload)
        output = []
        while self.next in self.pending:
            self.buffer.extend(self.pending.pop(self.next))
            self.next = (self.next + 1) % 65536
            self.updated = now
            if len(self.buffer) > (2*1024*1024+32 if self.playback else 8192):
                self.buffer.clear()
            while len(self.buffer) >= 32:
                if self.buffer[:4] != MAGIC:
                    pos = self.buffer.find(MAGIC, 1)
                    if pos < 0:
                        self.buffer[:] = self.buffer[-3:]
                        break
                    del self.buffer[:pos]
                    continue
                size = int.from_bytes(self.buffer[16:20], 'little')
                if not 1 <= size <= (2*1024*1024 if self.playback else 2048):
                    del self.buffer[:4]
                    continue
                if len(self.buffer) < 32 + size:
                    break
                codec = self.buffer[4]
                data = bytes(self.buffer[32:32+size])
                del self.buffer[:32+size]
                if self.playback and codec==3:continue
                # Stock HK6 leaves byte 4 uninitialized; 0xaa observed live.
                if codec in (0, 11, 0xaa):
                    output.append(adpcm_pcm(data))
                elif codec == 12:
                    output.append(alaw_pcm(data))
                elif codec == 13 and size % 2 == 0:
                    output.append(data)
                else:
                    self.unsupported = codec
        return output


class AudioBuffer:
    def __init__(self):
        self.condition = threading.Condition()
        self.enabled = False
        self.chunks = deque()
        self.sequence = 0
        self.updated = None
        self.lease = 0
        self.error = None

    def enable(self, value):
        with self.condition:
            self.enabled = value
            self.chunks.clear()
            self.updated = None
            self.error = None
            self.lease = time.monotonic()
            self.condition.notify_all()

    def publish(self, pcm):
        with self.condition:
            if not self.enabled:
                return
            now = time.monotonic()
            self.sequence += 1
            self.updated = now
            self.chunks.append((self.sequence, now, pcm))
            while self.chunks and (now-self.chunks[0][1] > 1 or len(self.chunks) > 64):
                self.chunks.popleft()
            self.condition.notify_all()

    def read(self, after):
        with self.condition:
            self.lease = time.monotonic()
            self.condition.wait_for(lambda: not self.enabled or self.sequence > after, timeout=1)
            now = time.monotonic()
            data = b''.join(pcm for seq, stamp, pcm in self.chunks
                            if seq > after and now-stamp <= 1) if self.enabled else b''
            return self.sequence, data

    def snapshot(self):
        with self.condition:
            age = None if self.updated is None else time.monotonic()-self.updated
            return dict(enabled=self.enabled, chunks=self.sequence, age_seconds=age,
                        receiving=self.enabled and age is not None and age < 2,
                        sample_rate=RATE, error=self.error)
