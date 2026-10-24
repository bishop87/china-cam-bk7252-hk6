"""Exercise injected machine code, ABI continuation, policy and captured packets."""
import hashlib,ipaddress,json,struct
from pathlib import Path
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_PC,UC_ARM_REG_SP,UC_ARM_REG_LR
from verify_stock_patch import machine, prepare, STACK, STOP, SAVED_REGS
from build_stock_patch import ROOT
OUT=ROOT/'analysis/exp2-candidate'
PBUF=0x440000; PAYLOAD=0x440100; DEST=0x440800; NETIF=0x440900

def run(data,dst,expected,own='192.168.2.3',mask='255.255.255.0',proto=17,sport=29741,dport=32100,short=False,raw=None,dns_entry=None,dns_server=None,chain=None,chain_fault=None):
    u=machine(data,0x10000)
    if dns_entry:
        slot,name,ip,state,ttl=dns_entry
        entry=0x407630+slot*272
        u.mem_write(entry,struct.pack('<I',ttl)+ipaddress.ip_address(ip).packed)
        u.mem_write(entry+10,bytes([state]))
        u.mem_write(entry+16,name.encode()+b'\0')
    if dns_server:u.mem_write(0x407a70,ipaddress.ip_address(dns_server).packed)
    packet=raw if raw is not None else struct.pack('!HHHH',sport,dport,8,0)
    u.mem_write(PBUF,struct.pack('<IIHHHH',0,PAYLOAD,len(packet),2 if short else len(packet),0,1))
    u.mem_write(PAYLOAD,packet)
    if chain is not None:
        offset=0
        for index,length in enumerate(chain):
            node=PBUF+index*16
            following=node+16 if index+1<len(chain) else 0
            u.mem_write(node,struct.pack('<IIHHHH',following,PAYLOAD+offset,len(packet)-offset,length,0,1))
            offset+=length
        if chain_fault=='cycle':u.mem_write(node,struct.pack('<I',PBUF))
        if chain_fault=='wrong_total':u.mem_write(PBUF+16+8,struct.pack('<H',47))
        if chain_fault=='null_payload':u.mem_write(PBUF+16+4,b'\0'*4)
        if chain_fault=='extra_node':u.mem_write(node,struct.pack('<I',PBUF+96))
    if dst is not None:u.mem_write(DEST,ipaddress.ip_address(dst).packed)
    u.mem_write(NETIF,struct.pack('<I',0)+ipaddress.ip_address(own).packed+ipaddress.ip_address(mask).packed)
    args=[PBUF,0,DEST if dst is not None else 0,64,0,proto,NETIF,0,0]
    prepare(u,args)
    for i,r in enumerate(SAVED_REGS):u.reg_write(r,0x12340000+i)
    before=bytes(u.mem_read(PBUF,0xa00)); stack_args=bytes(u.mem_read(STACK,20))
    u.hook_add(UC_HOOK_CODE, lambda uc, address, size, unused: uc.emu_stop() if address==STOP else None)
    u.emu_start(0x72221,0x72226,count=20000)
    pc=u.reg_read(UC_ARM_REG_PC)
    if expected:
        assert pc==0x72226,('not allowed',dst,hex(pc))
        assert u.reg_read(UC_ARM_REG_SP)==STACK-64
        assert [u.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]==args[:4]
        assert struct.unpack('<I',u.mem_read(STACK-44,4))[0]==64
    else:
        assert pc==STOP,('not rejected',dst,hex(pc))
        assert u.reg_read(UC_ARM_REG_R0)==0xfffffffc
        assert u.reg_read(UC_ARM_REG_SP)==STACK
    assert all(u.reg_read(r)==0x12340000+i for i,r in enumerate(SAVED_REGS))
    assert bytes(u.mem_read(PBUF,0xa00))==before
    assert bytes(u.mem_read(STACK,20))==stack_args


def complete_output(data, destination, protocol, sport, dport, length, own='192.168.2.3', driver_result=0):
    """Run original IPv4 header construction; mock only the netif driver callback."""
    u=machine(data,0x10000)
    packet=struct.pack('!HHHH',sport,dport,length,0)+bytes(i%251 for i in range(length-8))
    u.mem_write(PBUF,struct.pack('<IIHHHH',0,PAYLOAD,length,length,0,1))
    u.mem_write(PAYLOAD,packet)
    u.mem_write(DEST,ipaddress.ip_address(destination).packed)
    u.mem_write(NETIF,b'\0'*64)
    u.mem_write(NETIF+4,ipaddress.ip_address(own).packed+ipaddress.ip_address('255.255.255.0').packed)
    u.mem_write(NETIF+20,struct.pack('<I',STOP+0x101))
    prepare(u,[PBUF,NETIF+4,DEST,64,0,protocol,NETIF,0,0])
    for i,r in enumerate(SAVED_REGS):u.reg_write(r,0x12340000+i)
    output=[]
    def driver(uc,address,size,unused):
        if address==STOP+0x100:
            assert uc.reg_read(UC_ARM_REG_R0)==NETIF
            assert uc.reg_read(UC_ARM_REG_R1)==PBUF
            pointer=struct.unpack('<I',uc.mem_read(PBUF+4,4))[0]
            total=struct.unpack('<H',uc.mem_read(PBUF+8,2))[0]
            output.append(bytes(uc.mem_read(pointer,total)))
            uc.reg_write(UC_ARM_REG_R0,driver_result & 0xffffffff)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    u.hook_add(UC_HOOK_CODE,driver)
    u.emu_start(0x72221,STOP,count=10000)
    assert u.reg_read(UC_ARM_REG_PC)==STOP and u.reg_read(UC_ARM_REG_SP)==STACK
    assert all(u.reg_read(r)==0x12340000+i for i,r in enumerate(SAVED_REGS))
    assert len(output)==1
    return (u.reg_read(UC_ARM_REG_R0), output[0], bytes(u.mem_read(PBUF,16)))


def main():
    data=(OUT/'candidate-logical.bin').read_bytes(); manifest=json.loads((OUT/'manifest.json').read_text())
    assert hashlib.sha256(data).hexdigest()==manifest['candidate_sha256']
    cases=[
      ('LAN video','192.168.2.2',True,{}),
      ('public server','121.37.9.157',False,{}),
      ('anomalous public','35.35.35.35',False,{'dport':8995}),
      ('zero destination','0.0.0.0',False,{'dport':0}),
      ('gateway DNS UDP','192.168.2.1',False,{'dport':53}),
      ('gateway DNS TCP','192.168.2.1',False,{'proto':6,'dport':53}),
      ('public DNS','8.8.8.8',False,{'dport':53}),
      ('public NTP','1.1.1.1',False,{'dport':123}),
      ('local NTP transport','192.168.2.1',True,{'dport':123}),
      ('DHCP initial','255.255.255.255',True,{'own':'0.0.0.0','mask':'0.0.0.0','sport':68,'dport':67}),
      ('LAN discovery','255.255.255.255',True,{'dport':32108}),
      ('broadcast DNS','255.255.255.255',False,{'dport':53}),
      ('directed broadcast','192.168.2.255',True,{'dport':32108}),
      ('different subnet','192.168.1.2',False,{}),
      ('10 LAN','10.2.7.8',True,{'own':'10.2.0.3','mask':'255.255.0.0'}),
      ('10 external','10.3.7.8',False,{'own':'10.2.0.3','mask':'255.255.0.0'}),
      ('AP mode','192.168.4.2',True,{'own':'192.168.4.1'}),
      ('unconfigured mask','192.168.2.2',False,{'mask':'0.0.0.0'}),
      ('noncontiguous mask','192.168.2.2',False,{'mask':'255.0.255.0'}),
      ('unconfigured address','192.168.2.2',False,{'own':'0.0.0.0'}),
      ('multicast','224.0.0.251',False,{}),
      ('short transport','192.168.2.2',False,{'short':True}),
      ('header included',None,False,{}),
      ('ICMP local','192.168.2.2',True,{'proto':1}),
      ('ICMP public','1.1.1.1',False,{'proto':1}),
    ]
    for name,dst,allow,kwargs in cases:
        run(data,dst,allow,**kwargs)
    # NTP exception: exact outgoing DNS question and cache-bound standard request.
    name='europe.pool.ntp.org'; server='192.168.2.1'; ntp_ip='203.0.113.10'
    qname=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'
    dns=struct.pack('!HHHHHH',0x1234,0x0100,1,0,0,0)+qname+struct.pack('!HH',1,1)
    query=struct.pack('!HHHH',20000,53,len(dns)+8,0)+dns
    request=struct.pack('!HHHH',20000,123,56,0)+b'\x1b'+b'\0'*47
    good=(0,name,ntp_ip,3,60)
    ntp_cases=[]
    def check(label,dst,expected,**kw):
        run(data,dst,expected,**kw);ntp_cases.append(label)
    check('exact pool query to configured resolver',server,True,raw=query,dns_server=server)
    check('same query to other resolver','8.8.8.8',False,raw=query,dns_server=server)
    check('different domain',server,False,raw=query.replace(b'europe',b'cloudx'),dns_server=server)
    check('suffix domain',server,False,raw=query+b'x',dns_server=server)
    check('DNS response not query',server,False,raw=query[:10]+b'\x81'+query[11:],dns_server=server)
    check('wrong DNS class',server,False,raw=query[:-1]+b'\x02',dns_server=server)
    check('cached pool destination',ntp_ip,True,raw=request,dns_entry=good)
    check('different destination','203.0.113.11',False,raw=request,dns_entry=good)
    check('missing cache',ntp_ip,False,raw=request)
    for slot in range(4):
        check('cache slot '+str(slot),ntp_ip,True,raw=request,dns_entry=(slot,name,ntp_ip,3,60))
    check('wrong cached name',ntp_ip,False,raw=request,dns_entry=(0,'nms2.hdwificampro.com',ntp_ip,3,60))
    check('expired cache',ntp_ip,False,raw=request,dns_entry=(0,name,ntp_ip,3,0))
    check('pending cache',ntp_ip,False,raw=request,dns_entry=(0,name,ntp_ip,2,60))
    check('case insensitive cache',ntp_ip,True,raw=request,dns_entry=(0,name.upper(),ntp_ip,3,60))
    check('arbitrary data on port123',ntp_ip,False,raw=request[:-1]+b'x',dns_entry=good)
    check('wrong NTP mode',ntp_ip,False,raw=request[:8]+b'\x1c'+request[9:],dns_entry=good)
    check('wrong NTP length',ntp_ip,False,raw=request+b'\0',dns_entry=good)
    # Regression: UDP header and NTP payload can occupy separate pbufs.
    for split in range(8,56):
        check('chained NTP split '+str(split),ntp_ip,True,raw=request,dns_entry=good,chain=[split,56-split])
    check('three buffers',ntp_ip,True,raw=request,dns_entry=good,chain=[8,1,47])
    for fault,chain in [('truncated',[8,47]),('zero_length',[8,0,48]),
                        ('cycle',[8,48]),('wrong_total',[8,48]),
                        ('null_payload',[8,48]),('extra_node',[8,48])]:
        check('invalid chain '+fault,ntp_ip,False,raw=request,dns_entry=good,chain=chain,chain_fault=fault)
    for index in range(8,56):
        bad=bytearray(request);bad[index]^=1
        check('chained altered byte '+str(index),ntp_ip,False,raw=bytes(bad),dns_entry=good,chain=[8,48])
    for label,destination,entry in [('wrong destination','203.0.113.11',good),
        ('missing cache',ntp_ip,None),('expired',ntp_ip,(0,name,ntp_ip,3,0)),
        ('wrong name',ntp_ip,(0,'other.pool.ntp.org',ntp_ip,3,60)),
        ('pending',ntp_ip,(0,name,ntp_ip,2,60))]:
        check('chained '+label,destination,False,raw=request,dns_entry=entry,chain=[8,48])
    # The actual vendor DNS routine must read the same cache layout.
    from verify_stock_patch import call
    for slot in range(4):
        u=machine(data,0x10000);entry=0x407630+slot*272
        u.mem_write(entry,struct.pack('<I',60)+ipaddress.ip_address(ntp_ip).packed)
        u.mem_write(entry+10,b'\x03');u.mem_write(entry+16,name.encode()+b'\0')
        u.mem_write(0x440a00,name.encode()+b'\0')
        assert call(u,0x699ad,[0x440a00,0x440b00,0,0])==0
        assert bytes(u.mem_read(0x440b00,4))==ipaddress.ip_address(ntp_ip).packed
    # Follow the restored original NTP routine to its write call; model OS sockets.
    u=machine(data,0x10000);u.mem_write(0x440a0c,struct.pack('<II',4,0x440b00))
    u.mem_write(0x440b00,struct.pack('<I',0x440b10));u.mem_write(0x440b10,ipaddress.ip_address(ntp_ip).packed)
    observed=[]
    def ntp_os(uc,a,size,unused):
        if a==0x63ad0:uc.reg_write(UC_ARM_REG_R0,6)
        elif a==0x638cc:
            ptr=uc.reg_read(UC_ARM_REG_R0)
            assert bytes(uc.mem_read(ptr,20))==name.encode()+b'\0'
            observed.append('pool_name');uc.reg_write(UC_ARM_REG_R0,0x440a00)
        elif a==0x63a3a:
            ptr=uc.reg_read(UC_ARM_REG_R1)
            assert bytes(uc.mem_read(ptr+2,6))==struct.pack('!H',123)+ipaddress.ip_address(ntp_ip).packed
            observed.append('pool_socket');uc.reg_write(UC_ARM_REG_R0,0)
        else:return
        uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    u.hook_add(UC_HOOK_CODE,ntp_os);prepare(u)
    u.emu_start(0x583b1,0x5e7c8,count=200000)
    assert u.reg_read(UC_ARM_REG_PC)==0x5e7c8 and u.reg_read(UC_ARM_REG_R2)==48
    assert bytes(u.mem_read(u.reg_read(UC_ARM_REG_R1),48))==request[8:]
    assert observed==['pool_name','pool_socket']
    # Replay real camera IPv4/UDP packets captured before the Mac firewall.
    capture=ROOT/'analysis/network/hk6-lab/capture-20261018-102716/camera.pcap'
    raw=capture.read_bytes();assert raw[:4]==b'\xd4\xc3\xb2\xa1';pos=24;replayed=[]
    while pos<len(raw):
        _,_,n,_=struct.unpack_from('<IIII',raw,pos);pos+=16;frame=raw[pos:pos+n];pos+=n
        if frame[6:12]!=bytes.fromhex('0004b2147ba6') or frame[12:14]!=b'\x08\x00':continue
        ip=frame[14:];hlen=(ip[0]&15)*4
        if ip[9]!=17:continue
        dst=str(ipaddress.ip_address(ip[16:20]));udp=ip[hlen:];sport,dport=struct.unpack_from('!HH',udp)
        allow=sport==68 and dport==67 and dst=='255.255.255.255'
        run(data,dst,allow,raw=udp)
        replayed.append({'destination':dst,'port':dport,'allowed':allow})
    assert len(replayed)==13
    assert sum(x['allowed'] for x in replayed)==2
    original=(ROOT/'analysis/original/app-payload.bin').read_bytes()
    full_cases=[('192.168.2.2',17,2000,3000,1200,'192.168.2.3',0),
                ('192.168.2.2',6,2000,80,500,'192.168.2.3',0),
                ('255.255.255.255',17,68,67,300,'0.0.0.0',0),
                ('255.255.255.255',17,2000,32108,40,'192.168.2.3',0),
                ('192.168.2.2',17,2000,3000,1200,'192.168.2.3',-1)]
    for args in full_cases:
        assert complete_output(original,*args)==complete_output(data,*args),args
    report={'passed':True,'complete_output_comparisons':len(full_cases),'ntp_policy_cases':ntp_cases,'vendor_dns_cache_slots_verified':4,'original_ntp_request_verified':True,'candidate_sha256':manifest['candidate_sha256'],'synthetic_cases':len(cases),'synthetic_names':[x[0] for x in cases],'captured_packet_replay':replayed,'checks':['Real injected Thumb execution','Original argument registers restored at continuation','Original callee-saved registers and stack arguments preserved','Stack restored and ERR_RTE returned on rejection','pbuf/payload/netif unchanged at guard boundary'],'scope':'Bounded guard plus original IPv4 output compared up to mocked netif driver (header/checksum/pbuf/error propagation); not whole OS, radio or hardware','hardware_tested':False}
    (OUT/'emulation-validation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'{len(cases)} boundary cases + {len(replayed)} captured UDP packets and 5 complete IPv4 output comparisons, plus NTP exception tests passed; no hardware writes.')

if __name__=='__main__':main()
