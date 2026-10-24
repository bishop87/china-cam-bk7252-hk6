import json
import struct
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from controls import Controls, BusyError, form_encode
from main import Latest, handler_for
from protocol import Responses, command, unpack, jpeg_size


class ControlsTests(unittest.TestCase):
    def test_wifi_payload_and_secrets(self):
        c = Controls('192.168.1.54')
        c.networks = [dict(ssid='casa + è', encryption=1, signal=-30)]
        c.updated['scan'] = time.monotonic()
        pro, cmd, fields = c.prepare('set_wifi', {'ssid':'casa + è', 'password':'secret +123'})
        wire = unpack(command('admin','secret',pro,cmd,fields,7))[1]
        value = json.loads(wire[12:])
        self.assertEqual(value['encwifissid'], 'casa+%2B+%C3%A8')
        self.assertEqual(value['encwifipwd'], 'secret+%2B123')
        self.assertEqual(value['encryption'], 1)
        self.assertEqual(form_encode('~*'), '%7E*')
        self.assertNotIn('secret', json.dumps(c.snapshot()))
        for data in ({'ssid':'other','password':'12345678'}, {'ssid':'casa + è','password':'short'}):
            with self.assertRaises(ValueError): c.prepare('set_wifi',data)
        c.updated['scan'] -= 200
        with self.assertRaises(ValueError): c.prepare('set_wifi',{'ssid':'casa + è','password':'12345678'})

    def test_only_supported_commands_and_values(self):
        c = Controls('192.168.1.54')
        c.parameters = {'rotmir':0, 'icut':0}
        for action, data in [('reset',{}), ('image',{'field':'reboot','value':1}),
                             ('image',{'field':'rotmir','value':True}),
                             ('image',{'field':'icut','value':2}), ('video',{'mode':0})]:
            with self.assertRaises(ValueError): c.prepare(action,data)
        self.assertEqual(c.prepare('image',{'field':'rotmir','value':3})[2], {'rotmir':3})

    def test_video_profiles_are_requested_dimensions(self):
        c = Controls('192.168.1.54')
        self.assertEqual(c.snapshot()['requested_dimensions'], [640,480])
        self.assertEqual([p['dimensions'] for p in c.snapshot()['profiles']], [[640,480],[320,240]])
        self.assertEqual(c.prepare('video',{'mode':1}), ('stream',111,{'video':1}))
        self.assertEqual(c.prepare('video',{'mode':2}), ('stream',111,{'video':2}))
        with self.assertRaises(ValueError): c.prepare('video',{'mode':3})

    def test_response_fragmentation_reorder_duplicates(self):
        parser = Responses()
        obj = {'cmd':101,'result':0,'sysver':'test'}
        data = json.dumps(obj).encode()
        wire = bytes.fromhex('060aa080') + struct.pack('<I',len(data)) + data
        self.assertEqual(parser.feed(1, wire[12:]), [])
        self.assertEqual(parser.feed(0, wire[:12]), [obj])
        self.assertEqual(parser.feed(0, wire[:12]), [])
        with self.assertRaises(ValueError): Responses().feed(0,b'badmagic')

    def test_completion_and_disconnect_do_not_replay(self):
        c = Controls('192.168.1.54'); c.connected(); result=[]
        t = threading.Thread(target=lambda: result.append(c.request('parameters',{})))
        t.start()
        deadline=time.monotonic()+1
        while c.active is None and time.monotonic()<deadline: time.sleep(.001)
        class Camera:
            def send_command(self,*args): return 1
        c.tick(Camera()); self.assertTrue(c.retry_read(1))
        c.reply({'cmd':112,'result':0})
        self.assertIsNotNone(c.active)
        c.reply({'cmd':101,'result':0,'sysver':'real','pwd':'hidden'})
        t.join(1)
        self.assertEqual(result[0]['state'],'confirmed')
        self.assertNotIn('pwd',c.parameters)
        self.assertFalse(c.retry_read(1))
        c.networks=[{'ssid':'test','encryption':1,'signal':-20}];c.updated['scan']=time.monotonic()
        t=threading.Thread(target=lambda:result.append(c.request('set_wifi',{'ssid':'test','password':'12345678'})))
        t.start()
        deadline=time.monotonic()+1
        while c.active is None and time.monotonic()<deadline:time.sleep(.001)
        c.tick(Camera());job=c.active;c.disconnected();t.join(1)
        self.assertEqual(result[-1]['state'],'unknown')
        self.assertEqual(job['fields'],{})
        self.assertIsNone(c.active)

    def test_http_rejects_cross_origin_and_bad_inputs(self):
        c=Controls('192.168.1.54')
        server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(Latest(),c));server.daemon_threads=True
        t=threading.Thread(target=server.serve_forever);t.start()
        base=f'http://127.0.0.1:{server.server_port}'
        try:
            for origin,token in [('http://evil.test',c.token),(base,'wrong')]:
                req=Request(base+'/api/action',data=b'{"action":"target","data":{"ip":"192.168.1.55"}}',headers={'Origin':origin,'X-Control-Token':token,'Content-Type':'application/json'})
                with self.assertRaises(HTTPError) as e:urlopen(req)
                self.assertEqual(e.exception.code,403);e.exception.close()
            self.assertEqual(c.host,'192.168.1.54')
            req=Request(base+'/api/action',data=b'{"action":"target","data":{"ip":"8.8.8.8"}}',headers={'Origin':base,'X-Control-Token':c.token,'Content-Type':'application/json'})
            with self.assertRaises(HTTPError) as e:urlopen(req)
            self.assertEqual(e.exception.code,400);e.exception.close()
            with urlopen(base+'/') as response:self.assertIn(b'Impostazioni',response.read())
        finally:
            server.shutdown();server.server_close();t.join()

    def test_sof_size(self):
        data=b'\xff\xd8\xff\xc0'+struct.pack('>H B H H',7,8,352,640)+b'\xff\xd9'
        self.assertEqual(jpeg_size(data),[640,352])
        self.assertIsNone(jpeg_size(b'\xff\xd8bad'))
