import struct
import threading
import unittest
from storage import Storage
from controls import Controls
from avi import export_avi

JPEG=b'\xff\xd8\xff\xc0'+struct.pack('>HBHH',7,8,480,640)+b'\xff\xd9'

class StorageTests(unittest.TestCase):
    def test_dates_converted_to_firmware_format(self):
        s=Storage()
        self.assertEqual(s.prepare('record_hours',{'ymd':'20261021'}),('get_record_hour',401,{'ymd':'2026_10_21'}))
        self.assertEqual(s.prepare('record_files',{'ymdh':'2026102118'})[2],{'ymdh':'2026_10_21_18'})
        for value in ('20260230','../../sd','20260101_'):
            with self.assertRaises(ValueError):s.prepare('record_hours',{'ymd':value})

    def test_no_card_or_arbitrary_files_or_destructive_commands(self):
        s=Storage()
        with self.assertRaises(ValueError):s.prepare('record_continuous',{'enabled':True})
        s.sd={'sdstatu':1,'recMode':0};s.alarm={'pirvideo':0}
        s.reply('record_files',{'record_num':3,'record_name[0]':'20261021182840.avi','record_name[1]':'../x','record_name[2]':'/sd/x'},{})
        self.assertEqual(s.files,['20261021182840.avi'])
        with self.assertRaises(ValueError):s.prepare('record_play',{'filename':'other.avi'})
        with self.assertRaises(ValueError):s.prepare('record_delete',{'filename':s.files[0]})
        self.assertEqual(s.prepare('record_play',{'filename':s.files[0]})[2]['type'],1)

    def test_modes_are_independent_and_no_implicit_format(self):
        s=Storage();s.sd={'sdstatu':1,'recMode':0};s.alarm={'pirvideo':0}
        self.assertEqual(s.prepare('record_continuous',{'enabled':False})[2],{'recMode':0})
        self.assertEqual(s.prepare('record_motion',{'enabled':True})[2],{'pirenable':1,'pirvideo':1})
        with self.assertRaises(ValueError):s.prepare('record_motion',{'enabled':1})

    def test_playback_isolation_stop_and_export(self):
        s=Storage();s.start('test.avi');s.publish(JPEG)
        self.assertEqual(s.playback_status()['frames'],1)
        s.stop('done');s.publish(JPEG);self.assertEqual(len(s.frames),1)
        result=s.avi();self.assertEqual(result[:4],b'RIFF');self.assertEqual(result[8:12],b'AVI ')
        self.assertEqual(struct.unpack_from('<I',result,4)[0],len(result)-8)
        self.assertIn(b'MJPG',result);self.assertIn(b'idx1',result)
        s.start('next.avi');self.assertIsNone(s.frame);self.assertEqual(s.frames,[])

    def test_capture_bound(self):
        s=Storage();s.start('test.avi');s.bytes=32*1024*1024
        s.publish(JPEG);self.assertTrue(s.truncated);self.assertFalse(s.frames)

    def test_abandoned_player_sends_stop_not_recording_change(self):
        c=Controls('192.168.1.54');c.storage.start('test.avi');c.storage.lease-=9
        class Camera:
            def send_command(self,*args):self.sent=args;return 5
        camera=Camera();c.tick(camera)
        self.assertEqual(camera.sent,('play_record_file',207,{'type':0}))
        c.reply({'cmd':207,'result':0});self.assertIsNone(c.storage.playing)

    def test_failed_sd_read_invalidates_card(self):
        c=Controls('192.168.1.54');c.storage.sd={'sdstatu':1}
        c.active=dict(action='sd',cmd=109,fields={},done=threading.Event())
        c.reply({'cmd':109,'result':-1});self.assertEqual(c.storage.sd,{})

    def test_motion_settings_ranges_and_stop_without_card(self):
        s=Storage();s.sd={'sdstatu':1,'recMode':0};s.alarm={'pirvideo':0}
        valid=dict(sensitivity=3,duration=60,interval=30)
        self.assertEqual(s.prepare('record_motion_settings',valid)[2],dict(pirsensitive=3,pirvideotime=60,pirDelayTime=30))
        for key,value in [('sensitivity',4),('duration',61),('duration',9),('interval',29),('interval',241),('duration',True)]:
            with self.assertRaises(ValueError):s.prepare('record_motion_settings',dict(valid,**{key:value}))
        s.sd={}
        self.assertEqual(s.prepare('record_stop',{})[2],{'type':0})

    def test_playback_reduces_live_memory_and_restores_profile(self):
        c=Controls('192.168.1.54')
        class Camera:
            def __init__(self):self.sent=[]
            def send_command(self,*args):self.sent.append(args);return len(self.sent)
        camera=Camera()
        import time
        c.active=dict(action='record_play',pro='play_record_file',cmd=207,fields={'type':1,'filename':'test.avi'},index=None,done=threading.Event(),deadline=time.monotonic()+10)
        c.tick(camera)
        self.assertEqual(camera.sent,[('stream',111,{'video':2})])
        c.active['playback_ready']=0;c.tick(camera)
        self.assertEqual(len(camera.sent),1)
        c.live_dimensions=[320,240];c.tick(camera)
        c.reply({'cmd':207,'result':0})
        self.assertEqual(c.storage.playing,'test.avi')
        with self.assertRaises(ValueError):c.prepare('video',{'mode':1})
        c.storage.stop('done');c.tick(camera)
        self.assertEqual(camera.sent[-1],('stream',111,{'video':1}))
        self.assertEqual(c.video_mode,1)

    def test_export_timeline_excludes_pause(self):
        from unittest.mock import patch
        s=Storage();s.start('x.avi')
        with patch('storage.time.monotonic',return_value=100):s.publish(JPEG)
        with patch('storage.time.monotonic',return_value=101):s.reply('record_pause',{}, {'suspend':1})
        s.publish(JPEG);self.assertEqual(len(s.frames),1)
        with patch('storage.time.monotonic',return_value=111):s.reply('record_pause',{}, {'suspend':0})
        with patch('storage.time.monotonic',return_value=112):s.publish(JPEG)
        self.assertEqual(s.frames[-1][0]-s.frames[0][0],2)
