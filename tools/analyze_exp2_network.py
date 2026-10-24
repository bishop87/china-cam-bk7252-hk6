"""Decode stock server lists using original Thumb code; no firmware or network writes."""
import hashlib
import json
from pathlib import Path
import re
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from verify_stock_patch import machine, call

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'analysis/original/reverse'
BASE = 0x10000
EXPECTED_SHA = '8f2e8d40497634a801fffb4c28c54d1d19400c08a0286ba1e6b365997163d900'
LISTS = {
    0xb999d: '121.37.9.157,nms2.hdwificampro.com,nms3.hdwificampro.com,',
    0xb9a10: '43.157.66.246,snrjw_p2p2.heqilense.com,snrjw_p2p3.heqilense.com,',
    0xb9a91: '3.10.99.101,p2p2.hdwificampro.com,p2p3.hdwificampro.com,',
}
WINDOWS = [
 ('Initialization calls decoder', 0x797ac, 0x797c6),
 ('Initialization zeros three server sockaddr structures', 0x79830, 0x79852),
 ('PPCS send wrapper, inferred SendMessage', 0x7b624, 0x7b678),
 ('NTP setup and resolver', 0x583b0, 0x58428),
 ('Vendor DNS cache lookup and server array', 0x699e0, 0x69a2c),
]

def main():
    data = (ROOT/'analysis/original/app-logical.bin').read_bytes()
    assert hashlib.sha256(data).hexdigest() == EXPECTED_SHA
    decoded = []
    for address, expected in LISTS.items():
        uc = machine(data, BASE)
        # Canary around the destination; real machine code and libc execute.
        uc.mem_write(0x43fff0, b'Z'*16 + b'\0'*1024 + b'Z'*16)
        ret = call(uc, 0x7ba71, [address, 0x440000, 1024], count=3000000)
        result = bytes(uc.mem_read(0x440000, 1024)).split(b'\0')[0].decode('ascii')
        assert ret == 0 and result == expected
        assert bytes(uc.mem_read(0x43fff0, 16)) == b'Z'*16
        assert bytes(uc.mem_read(0x440400, 16)) == b'Z'*16
        decoded.append({'encoded_string_address':hex(address),'decoded':result,'return_value':ret,'bounds_canaries_intact':True})
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    targets = {0x638cc:'gethostbyname wrapper candidate',0x67a10:'lwIP resolver candidate',0x6872c:'lwIP sendto candidate',0x7b624:'PPCS SendMessage candidate'}
    calls = []
    # Halfword scan of possible BL encodings: not a complete executable CFG.
    for off in range(0, len(data)-4, 2):
        if data[off+1] & 0xf8 != 0xf0:
            continue
        ins = next(md.disasm(data[off:off+4], off+BASE), None)
        if ins and ins.mnemonic == 'bl':
            target = int(ins.op_str.lstrip('#'), 0)
            if target in targets:
                calls.append({'address':hex(ins.address),'target':hex(target),'candidate_name':targets[target]})
    lines=[]
    for label,start,end in WINDOWS:
        lines.append(f'\n; {label}\n')
        instructions=list(md.disasm(data[start-BASE:end-BASE],start))
        assert sum(i.size for i in instructions)==end-start
        for i in instructions:
            annotation=''
            match=re.search(r'\[pc, #(0x[0-9a-f]+|\d+)\]',i.op_str)
            if i.mnemonic=='ldr' and match:
                at=((i.address+4)&~3)+int(match[1],0)
                val=struct.unpack_from('<I',data,at-BASE)[0]
                annotation=' ; literal '+hex(val)
            lines.append(f'{i.address:08x} {i.bytes.hex():10s} {i.mnemonic:8s} {i.op_str}{annotation}\n')
    assert data[0xca3df-BASE:0xca3df-BASE+len(b'ntp1.aliyun.com\0')] == b'ntp1.aliyun.com\0'
    report={'source_sha256':EXPECTED_SHA,'decoder_thumb_entry':'0x7ba71','decoded_lists':decoded,
            'candidate_direct_calls':calls,'call_scan_limit':'Candidate Thumb BL instructions only; indirect calls, ARM code and data false positives require separate analysis',
            'ntp':{'routine':'0x583b0','host_string':'0xca3df','host':'ntp1.aliyun.com','port':123,'exp1':'disabled at entry'},
            'server_initialization':{'start':'0x79830','end':'0x79852','ram_base':'0x417d00','count':3,'stride':16,'initial_port':32100,'address_initial_value':'0.0.0.0'},
            'status':'research_only_no_new_firmware'}
    (OUT/'exp2-network-analysis.json').write_text(json.dumps(report,indent=2)+'\n')
    (OUT/'exp2-network-windows.asm').write_text(''.join(lines))
    print('Decoded 3 server lists with real Thumb code; assertions passed. No firmware modified.')

if __name__=='__main__':main()
