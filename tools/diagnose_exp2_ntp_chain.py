"""Reproduce installed EXP2 rejection of a valid NTP request in chained pbufs.
No camera access and no firmware edits. This records the defect, not a passing
acceptance test for a corrected firmware.
"""
import hashlib, json, struct, sys
from pathlib import Path
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R0
from verify_exp2_candidate import machine, prepare, PBUF, PAYLOAD, DEST, NETIF, STOP, run
ROOT=Path(__file__).resolve().parents[1]
def main():
    data=(ROOT/'dist/hk6-stock-lan-exp2/hk6-stock-lan-exp2.bin').read_bytes()
    assert hashlib.sha256(data).hexdigest()=='22fac7fbd7d3cd4328a93612d68d5ebbe8c556e65284728d9485d24c81cc224f'
    packet=struct.pack('!HHHH',20000,123,56,0)+b'\x1b'+b'\0'*47
    run(data,'203.0.113.10',True,raw=packet,dns_entry=(0,'europe.pool.ntp.org','203.0.113.10',3,60))
    u=machine(data,0x10000)
    u.mem_write(0x407630,struct.pack('<I',60)+bytes([203,0,113,10]))
    u.mem_write(0x40763a,b'\x03')
    u.mem_write(0x407640,b'europe.pool.ntp.org\0')
    u.mem_write(PBUF,struct.pack('<IIHHHH',PBUF+32,PAYLOAD,56,8,0,1))
    u.mem_write(PBUF+32,struct.pack('<IIHHHH',0,PAYLOAD+64,48,48,0,1))
    u.mem_write(PAYLOAD,packet[:8]);u.mem_write(PAYLOAD+64,packet[8:])
    u.mem_write(DEST,bytes([203,0,113,10]))
    u.mem_write(NETIF,struct.pack('<I',0)+bytes([192,168,2,3,255,255,255,0]))
    prepare(u,[PBUF,0,DEST,64,0,17,NETIF,0,0])
    u.emu_start(0x72221,STOP,count=3000)
    assert u.reg_read(UC_ARM_REG_PC)==STOP and u.reg_read(UC_ARM_REG_R0)==0xfffffffc
    result={'installed_payload_sha256':hashlib.sha256(data).hexdigest(),'contiguous_ntp_allowed':True,'identical_chained_ntp_rejected_ERR_RTE':True,'chain_lengths':[8,48],'scope':'Reproduced in actual installed Thumb code with synthetic pbuf/cache. Hardware pbuf layout not observed directly; consistent with SDK socket path and live ERROR writing to socket.'}
    out=ROOT/'analysis/uart/exp2-ntp-diagnostic';out.mkdir(exist_ok=True)
    (out/'chain-reproduction.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
