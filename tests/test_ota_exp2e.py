import io
import sys
import threading
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import ota_exp2e as ota

class EXP2ETests(unittest.TestCase):
    @unittest.skipUnless((Path(__file__).resolve().parents[1] / 'dist/hk6-stock-lan-exp2e/hk6-stock-lan-exp2e.rbl').is_file() and (Path(__file__).resolve().parents[1] / 'dist/hk6-stock-lan-exp2d/hk6-stock-lan-exp2d.rbl').is_file(), "Private laboratory fixture not distributed; see docs/sviluppo.md")
    def test_pins_and_complete_changed_byte_coverage(self):
        b=(ota.ROOT/'dist/hk6-stock-lan-exp2e/hk6-stock-lan-exp2e.rbl').read_bytes()
        p,_=ota.unpack(b)
        oldb=(ota.ROOT/'dist/hk6-stock-lan-exp2d/hk6-stock-lan-exp2d.rbl').read_bytes()
        old,_=ota.unpack(oldb)
        self.assertEqual(ota.sha(b),ota.RBL_SHA)
        self.assertEqual(ota.sha(p),ota.PAYLOAD_SHA)
        self.assertEqual(ota.sha(oldb),ota.EXP2D_RBL_SHA)
        self.assertEqual(ota.sha(old),ota.EXP2D_PAYLOAD_SHA)
        self.assertEqual(ota.header_info(b[:96])['version'],ota.VERSION)
        covered=set(range(0xc9a44,len(p)))
        for a,n in [(0x583b0,4),(0x584b0,4),(0x72222,4)]+ota.VERIFIED_REGIONS:covered.update(range(a-0x10000,a-0x10000+n))
        self.assertTrue({i for i in range(len(old)) if old[i]!=p[i]}<=covered)
        self.assertNotEqual(ota.sha(p),ota.sha(old))
    @unittest.skipUnless((Path(__file__).resolve().parents[1] / 'dist/hk6-stock-lan-exp2d/hk6-stock-lan-exp2d.bin').is_file() and (Path(__file__).resolve().parents[1] / 'dist/hk6-stock-lan-exp2e/hk6-stock-lan-exp2e.bin').is_file(), "Private laboratory fixture not distributed; see docs/sviluppo.md")
    def test_encoder_and_exact_diff(self):
        from build_exp2e_candidate import validate
        old=(ota.ROOT/'dist/hk6-stock-lan-exp2d/hk6-stock-lan-exp2d.bin').read_bytes()
        new=(ota.ROOT/'dist/hk6-stock-lan-exp2e/hk6-stock-lan-exp2e.bin').read_bytes()
        self.assertEqual(len(old),len(new))
        self.assertEqual([i for i in range(len(old)) if old[i]!=new[i]],[0x41750])
        self.assertEqual(validate(new)[1]['dimensions'],[640,480])

    def test_endpoint_restriction(self):
        for path,client,status in [(ota.ENDPOINT,'192.168.2.3',200),('/hk6-stock-lan-exp2d.rbl','192.168.2.3',404),(ota.ENDPOINT,'192.168.2.2',404)]:
            event=threading.Event();records=[];codes=[]
            h=object.__new__(ota.make_handler(b'fixture','192.168.2.1','192.168.2.3',records,event))
            h.path=path;h.client_address=(client,123);h.command='GET';h.wfile=io.BytesIO()
            h.connection=type('Conn',(),{'settimeout':lambda *args:None})()
            h.send_response=codes.append;h.send_error=codes.append;h.send_header=lambda *args:None;h.end_headers=lambda:None
            h.handle_file(True)
            self.assertEqual(codes,[status]);self.assertEqual(event.is_set(),status==200)

if __name__=='__main__':unittest.main()
