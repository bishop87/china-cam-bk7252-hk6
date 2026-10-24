import struct
import threading
import unittest
from audio_stream import AudioFrames, AudioBuffer, alaw_pcm, adpcm_pcm, MAGIC
from controls import Controls
from main import Latest, handler_for
from http.server import ThreadingHTTPServer
from urllib.request import urlopen


def wire(data, codec=12):
    header=bytearray(32);header[:4]=MAGIC;header[4]=codec
    struct.pack_into('<I',header,16,len(data))
    return bytes(header)+data


class AudioTests(unittest.TestCase):
    def test_adpcm_nibble_order_reset_and_clipping(self):
        self.assertEqual(struct.unpack('<4h',adpcm_pcm(bytes([0x17,0xf0]))),(1,13,-17,-13))
        self.assertEqual(AudioFrames().feed(0,wire(b'\x17',0)),[adpcm_pcm(b'\x17')])
        self.assertEqual(AudioFrames().feed(0,wire(b'\x17',0xaa)),[adpcm_pcm(b'\x17')])
        samples=struct.unpack('<640h',adpcm_pcm(b'\x77'*320))
        self.assertEqual(samples[-1],32767)

    def test_alaw_vectors(self):
        self.assertEqual(struct.unpack('<6h',alaw_pcm(bytes([0xd5,0x55,0x80,0,0xaa,0x2a]))),
                         (8,-8,5504,-5504,32256,-32256))

    def test_split_reordered_duplicate_and_multiple_frames(self):
        p=AudioFrames();data=wire(b'\xd5'*160)
        self.assertEqual(p.feed(1,data[20:]),[])
        self.assertEqual(p.feed(0,data[:20]),[alaw_pcm(b'\xd5'*160)])
        self.assertEqual(p.feed(1,data[20:]),[])
        self.assertEqual(p.feed(2,data+wire(b'\x01\x00',13)),[alaw_pcm(b'\xd5'*160),b'\x01\x00'])

    def test_gap_recovery_unknown_codec_and_bounds(self):
        p=AudioFrames();p.feed(0,wire(b'x'*160)[:50]);p.updated-=1
        self.assertEqual(p.feed(2,wire(b'\xd5')), [b'\x08\x00'])
        self.assertEqual(p.feed(3,wire(b'x',99)),[])
        self.assertEqual(p.unsupported,99)
        p.feed(4,b'x'*9000)
        self.assertLessEqual(len(p.buffer),8192)

    def test_stop_discards_buffer_disconnect_disables(self):
        c=Controls('192.168.1.54');a=c.audio
        a.publish(b'a');self.assertEqual(a.sequence,0)
        a.enable(True);a.publish(b'\x08\x00')
        self.assertEqual(a.read(0)[1],b'\x08\x00')
        c.disconnected();self.assertFalse(a.enabled)
        self.assertEqual(a.read(0)[1],b'')
        self.assertEqual(c.prepare('audio',{'enabled':True}),('stream',111,{'audio':1}))
        with self.assertRaises(ValueError):c.prepare('audio',{'enabled':1})

    def test_lease_expiry_stops_camera_and_clears_pcm(self):
        c=Controls('192.168.1.54');c.audio.enable(True);c.audio.publish(b'aa');c.audio.lease-=9
        class Camera:
            def send_command(self,*args):self.sent=args
        camera=Camera();c.tick(camera)
        self.assertEqual(camera.sent,('stream',111,{'audio':0}))
        self.assertFalse(c.audio.enabled);self.assertFalse(c.audio.chunks)

    def test_http_pcm_delivery_and_stop(self):
        c=Controls('192.168.1.54');c.audio.enable(True);c.audio.publish(b'\x08\x00')
        server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(Latest(),c))
        worker=threading.Thread(target=server.serve_forever);worker.start()
        base=f'http://127.0.0.1:{server.server_port}'
        try:
            with urlopen(base+'/audio.pcm?after=0') as response:
                self.assertEqual(response.headers['X-Audio-Rate'],'8000')
                self.assertEqual(response.headers['X-Audio-Sequence'],'1')
                self.assertEqual(response.read(),b'\x08\x00')
            c.audio.enable(False)
            with urlopen(base+'/audio.pcm?after=0') as response:self.assertEqual(response.read(),b'')
        finally:
            server.shutdown();server.server_close();worker.join()

    def test_audio_ack_is_not_reception(self):
        c=Controls('192.168.1.54');c.active=dict(index=4,action='audio',fields={'audio':1},done=threading.Event())
        job=c.active;c.acknowledged(4)
        self.assertEqual(job['result']['state'],'sent')
        self.assertTrue(c.audio.enabled);self.assertFalse(c.audio.snapshot()['receiving'])

if __name__=='__main__':unittest.main()
