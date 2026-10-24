import sys,unittest,json,io,threading
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import ota_http as ota
class HTTPOTATests(unittest.TestCase):
 @unittest.skipUnless((Path(__file__).resolve().parents[1] / 'dist/hk6-stock-http1/hk6-stock-http1.rbl').is_file() and (Path(__file__).resolve().parents[1] / 'dist/hk6-stock-http1/rollback-exp2f.rbl').is_file(), "Private laboratory fixture not distributed; see docs/sviluppo.md")
 def test_pins_rollback_and_coverage(self):
  forward=ota.load_pair();back=ota.load_pair(True)
  self.assertEqual(forward,tuple(reversed(back)))
  target,source=forward;self.assertEqual(target[2]['version'],'2M.1220-LAN-HTTP1')
  covered=set(range(0xc9a44,len(target[1])))
  for a,n in ota.REGIONS:covered.update(range(a-65536,a-65536+n))
  self.assertTrue({i for i,(a,b) in enumerate(zip(target[1],source[1])) if a!=b}<=covered)
 def test_recording_guard(self):
  r={'getvalue recMode':'The recMode value is 0.','getvalue pirvideo':'The pirvideo value is 0.','list_fd':'fd type ref magic path\n0 file 1 fdfd /uart1'}
  ota.recording_guard(r)
  for key,value in [('getvalue pirvideo','The pirvideo value is 1.'),('getvalue recMode','not found'),('list_fd','fd type\n4 file 1 fdfd /sd/record/temp.avi')]:
   with self.assertRaises(ValueError):ota.recording_guard(dict(r,**{key:value}))
 def test_restricted_http(self):
  for path,client,allowed in [(ota.transport.ENDPOINT,'192.168.1.54',True),('/other','192.168.1.54',False),(ota.transport.ENDPOINT,'192.168.1.55',False)]:
   event=threading.Event();records=[];codes=[]
   h=object.__new__(ota.transport.make_handler(b'fixture','192.168.1.53','192.168.1.54',records,event))
   h.path=path;h.client_address=(client,1);h.command='GET';h.wfile=io.BytesIO();h.connection=type('C',(),{'settimeout':lambda *x:None})()
   h.send_response=codes.append;h.send_error=codes.append;h.send_header=lambda *x:None;h.end_headers=lambda:None
   h.handle_file(True);self.assertEqual(codes,[200 if allowed else 404]);self.assertEqual(event.is_set(),allowed)
if __name__=='__main__':unittest.main()
