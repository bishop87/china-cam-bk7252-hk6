import struct
import time
import unittest
from unittest.mock import patch
from controls import Controls
from storage import Storage
from audio_stream import AudioFrames

class ExtensionsTests(unittest.TestCase):
    def test_clock_uses_seconds_west_and_server_time(self):
        c=Controls('192.168.1.54')
        with patch('controls.time.time',return_value=1792656000):
            pro,cmd,f=c.prepare('clock_sync',{})
        self.assertEqual((pro,cmd),('set_datetime',126))
        self.assertEqual(f,{'time':1792656000,'tz':-7200})
        with self.assertRaises(ValueError):c.prepare('clock_sync',{'time':0})
        self.assertEqual(c.prepare('reboot',{}),('dev_control',102,{'reboot':1}))
        c.storage.start('x.avi')
        with self.assertRaises(ValueError):c.prepare('reboot',{})

    def test_playback_controls_require_active_player(self):
        s=Storage()
        with self.assertRaises(ValueError):s.prepare('record_pause',{'enabled':True})
        s.start('x.avi')
        self.assertEqual(s.prepare('record_pause',{'enabled':True})[2],{'suspend':1})
        self.assertEqual(s.prepare('record_audio',{'enabled':True})[2],{'audio':1})
        s.reply('record_pause',{}, {'suspend':1});self.assertTrue(s.paused)
        s.reply('record_audio',{}, {'audio':1});self.assertTrue(s.audio.enabled)
        s.stop('stop');self.assertFalse(s.audio.enabled);self.assertFalse(s.paused)

    def test_mixed_playback_audio_skips_fragmented_video(self):
        def frame(codec,payload):
            h=bytearray(32);h[:4]=bytes.fromhex('55aa15a8');h[4]=codec
            struct.pack_into('<I',h,16,len(payload));return bytes(h)+payload
        stream=frame(3,b'x'*12000)+frame(11,b'\x12'*320)
        decoder=AudioFrames(playback=True);samples=[]
        for n,start in enumerate(range(0,len(stream),1000)):
            samples.extend(decoder.feed((50000+n)%65536,stream[start:start+1000]))
        self.assertEqual(sum(map(len,samples)),1280)
        self.assertIsNone(decoder.unsupported)

    def test_pause_does_not_trigger_idle_stop_but_lease_does(self):
        c=Controls('192.168.1.54');c.storage.start('x.avi');c.storage.started-=30;c.storage.paused=True
        class Cam:
            def send_command(self,*args):return 0
        c.tick(Cam());self.assertIsNone(c.active)
        c.storage.lease-=9;c.tick(Cam());self.assertEqual(c.active['action'],'record_stop')

    def test_clock_reply_id_is_distinct_from_request(self):
        import threading
        c=Controls('192.168.1.54')
        c.active=dict(action='clock_sync',cmd=126,response_cmd=128,fields={},done=threading.Event())
        c.reply({'cmd':126,'result':0});self.assertIsNotNone(c.active)
        c.reply({'cmd':128,'result':0});self.assertIsNone(c.active)

    def test_recording_must_be_off_before_play(self):
        s=Storage();s.sd={'sdstatu':1,'recMode':0};s.files=['x.avi']
        for alarm in ({},{'pirvideo':1}):
            s.alarm=alarm
            with self.assertRaises(ValueError):s.prepare('record_play',{'filename':'x.avi'})
        s.alarm={'pirvideo':0};self.assertEqual(s.prepare('record_play',{'filename':'x.avi'})[2]['type'],1)
