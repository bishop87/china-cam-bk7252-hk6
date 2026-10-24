import io
import sys
import threading
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import ota_exp2b as ota

class EXP2BTests(unittest.TestCase):
    @unittest.skipUnless((Path(__file__).resolve().parents[1] / 'dist/hk6-stock-lan-exp2b/hk6-stock-lan-exp2b.rbl').is_file() and (Path(__file__).resolve().parents[1] / 'dist/hk6-stock-lan-exp2a/hk6-stock-lan-exp2a.rbl').is_file(), "Private laboratory fixture not distributed; see docs/sviluppo.md")
    def test_pins_and_complete_changed_byte_coverage(self):
        b=(ota.ROOT/'dist/hk6-stock-lan-exp2b/hk6-stock-lan-exp2b.rbl').read_bytes()
        p,_=ota.unpack(b)
        oldb=(ota.ROOT/'dist/hk6-stock-lan-exp2a/hk6-stock-lan-exp2a.rbl').read_bytes()
        old,_=ota.unpack(oldb)
        self.assertEqual(ota.sha(b),ota.RBL_SHA)
        self.assertEqual(ota.sha(p),ota.PAYLOAD_SHA)
        self.assertEqual(ota.sha(oldb),ota.EXP2A_RBL_SHA)
        self.assertEqual(ota.sha(old),ota.EXP2A_PAYLOAD_SHA)
        self.assertEqual(ota.header_info(b[:96])['version'],ota.VERSION)
        covered=set(range(0xc9a44,len(p)))
        for a,n in [(0x583b0,4),(0x584b0,4),(0x72222,4)]+ota.CLOCK_REGIONS:covered.update(range(a-0x10000,a-0x10000+n))
        self.assertTrue({i for i in range(len(old)) if old[i]!=p[i]}<=covered)
        self.assertNotEqual(ota.sha(p),ota.sha(old))
    def test_endpoint_restriction(self):
        for path,client,status in [(ota.ENDPOINT,'192.168.2.3',200),('/hk6-stock-lan-exp2a.rbl','192.168.2.3',404),(ota.ENDPOINT,'192.168.2.2',404)]:
            event=threading.Event();records=[];codes=[]
            h=object.__new__(ota.make_handler(b'fixture','192.168.2.1','192.168.2.3',records,event))
            h.path=path;h.client_address=(client,123);h.command='GET';h.wfile=io.BytesIO()
            h.connection=type('Conn',(),{'settimeout':lambda *args:None})()
            h.send_response=codes.append;h.send_error=codes.append;h.send_header=lambda *args:None;h.end_headers=lambda:None
            h.handle_file(True)
            self.assertEqual(codes,[status]);self.assertEqual(event.is_set(),status==200)

if __name__=='__main__':unittest.main()
