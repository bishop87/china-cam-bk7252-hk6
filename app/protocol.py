"""Experimental PPPP wire format; see PROTOCOL.md for evidence and sources."""
import json
import struct

TABLE = bytes.fromhex("7C9CE84A13DEDCB22F2123E4307B3D8CBC0B270C3CF79AE7087196009785EFC11FC4DBA1C2EBD901FABA3B05B81587832872D18B5AD6DA9358FEAACC6E1BF0A388AB43C00DB545384F502266207F075B14981D9BA72AB9A8CBF1FC4947063EB10E043A945EEE541134DD4DF9ECC7C9E3781A6F706BA4BDA95DD5F8E5BB26AF4237D8E1020AAE5F1CC573094E6924906D12B319AD748A2940F52DBEA559E0F479D24BCE8982488425C6912BA2FB8FE9A6B09E3F65F603312EAC0F952C5CED39B7336C567EB4A0FD7A815351868D9F77FF6A80DFE2BF10D775645776F355CDD0C818E6364162CF99F2324C67606192CAD3EA637D16B68ED46835C3529D46441E17")
KEY = bytes.fromhex("6997cc19")
VIDEO_MAGIC = bytes.fromhex("55aa15a80300")
MAX_FRAME = 2 * 1024 * 1024


def crypt(data, *, decrypt=False):
    previous = 0
    result = bytearray()
    for value in data:
        transformed = value ^ TABLE[(KEY[previous & 3] + previous) & 255]
        result.append(transformed)
        previous = value if decrypt else transformed
    return bytes(result)


def packet(kind, body=b""):
    return crypt(struct.pack(">BBH", 0xf1, kind, len(body)) + body)


def unpack(data):
    plain = crypt(data, decrypt=True)
    if len(plain) < 4 or plain[0] != 0xf1:
        raise ValueError("Invalid PPPP header")
    if int.from_bytes(plain[2:4], "big") != len(plain) - 4:
        raise ValueError("Truncated or inconsistent PPPP length")
    return plain[1], plain[4:]


def command(user, password, pro, cmd, fields=None, index=0):
    value = dict(pro=pro, cmd=cmd, user=user, pwd=password, devmac="0000")
    value.update(fields or {})
    data = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    if len(data) > 8192:
        raise ValueError("Command too large")
    body = struct.pack(">BBH", 0xd1, 0, index)
    body += bytes.fromhex("060aa080") + struct.pack("<I", len(data)) + data
    return packet(0xd0, body)


def stream_command(user, password, index=0, video=1):
    return command(user, password, "stream", 111, {"video": video}, index)


def ack(channel, index):
    return packet(0xd1, struct.pack(">BBHH", 0xd1, channel, 1, index))


class Frames:
    """Bounded per-channel assembly. Gaps are never concatenated into a JPEG.

    Reorders fragments after a start header; pre-header fragments are discarded.
    A new start supersedes an incomplete frame. Duplicate starts are ignored.
    """
    def __init__(self):
        self.channels = {}

    def feed(self, channel, index, payload):
        state = self.channels.get(channel)
        if payload.startswith(VIDEO_MAGIC):
            if len(payload) < 32:
                return None
            size = struct.unpack_from("<I", payload, 16)[0]
            if not 4 <= size <= MAX_FRAME:
                self.channels.pop(channel, None)
                return None
            if state and state[0] == index:
                return None
            # Reject delayed starts from older frames (16-bit sequence space).
            if state and (index - state[0]) % 65536 >= 32768:
                return None
            state = [index, size, {}, False]
            self.channels[channel] = state
            payload = payload[32:]
        if state is None or state[3]:
            return None
        offset = (index - state[0]) % 65536
        if offset >= 4096 or len(payload) > state[1]:
            return None
        state[2].setdefault(offset, payload)
        if sum(map(len, state[2].values())) > state[1]:
            state[3] = True
            return None
        if set(state[2]) != set(range(len(state[2]))):
            return None
        if sum(map(len, state[2].values())) != state[1]:
            return None
        data = b"".join(state[2][i] for i in range(len(state[2])))
        state[3] = True
        # HK6 stock includes SDK trailer: zero byte + JPEG length uint32 LE.
        # Validate both the declared length and EOI before stripping it.
        if (len(data) >= 9 and data[-5] == 0
                and int.from_bytes(data[-4:], "little") == len(data) - 5
                and data[-7:-5] == b"\xff\xd9"):
            data = data[:-5]
        if data.startswith(b"\xff\xd8") and data.endswith(b"\xff\xd9"):
            return data
        return None


class Responses:
    """Ordered, bounded channel-0 byte stream of length-prefixed JSON replies."""
    def __init__(self):
        self.next = 0
        self.pending = {}
        self.buffer = bytearray()

    def feed(self, index, payload):
        distance = (index - self.next) % 65536
        if distance >= 32768:
            return []
        if distance > 255:
            raise ValueError('Control channel sequence gap too large')
        self.pending.setdefault(index, payload)
        replies = []
        while self.next in self.pending:
            self.buffer.extend(self.pending.pop(self.next))
            self.next = (self.next + 1) % 65536
            if len(self.buffer) > 65536:
                raise ValueError('Control response too large')
            while len(self.buffer) >= 8:
                if self.buffer[:4] != bytes.fromhex('060aa080'):
                    raise ValueError('Unknown control response header')
                size = int.from_bytes(self.buffer[4:8], 'little')
                if not 1 <= size <= 65528:
                    raise ValueError('Invalid control response length')
                if len(self.buffer) < size + 8:
                    break
                data = bytes(self.buffer[8:8+size]).rstrip(b'\0')
                del self.buffer[:8+size]
                value = json.loads(data)
                if not isinstance(value, dict):
                    raise ValueError('Expected JSON object')
                replies.append(value)
        return replies


def jpeg_size(data):
    """Read SOF dimensions without decoding or external dependencies."""
    offset = 2
    while offset + 4 <= len(data):
        if data[offset] != 255:
            return None
        kind = data[offset + 1]
        offset += 2
        if kind in (0xd8, 0xd9) or 0xd0 <= kind <= 0xd7:
            continue
        size = int.from_bytes(data[offset:offset+2], 'big')
        if size < 2 or offset + size > len(data):
            return None
        if kind in (0xc0, 0xc1, 0xc2) and size >= 7:
            height, width = struct.unpack_from('>HH', data, offset + 3)
            return [width, height]
        if kind == 0xda:
            return None
        offset += size
    return None
