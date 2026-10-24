"""Execute compiled HTTP hooks in Unicorn; stock OS/network calls are modeled."""
import hashlib,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
from verify_stock_patch import machine,call,prepare,STACK,SAVED_REGS
from build_stock_patch import ROOT
from build_exp2f_candidate import validate as validate_profiles
OUT=ROOT/'analysis/http-candidate'

def main():
 data=(OUT/'candidate-logical.bin').read_bytes();m=json.loads((OUT/'manifest.json').read_text())
 assert hashlib.sha256(data).hexdigest()==m['payload_sha256']
 raw=(ROOT/'dist/hk6-stock-lan-exp2f/hk6-stock-lan-exp2f.bin').read_bytes()
 allowed=set()
 for p in m['patches']:
  off=int(p['address'],16)-65536;after=bytes.fromhex(p['after']);allowed.update(range(off,off+len(after)))
  assert data[off:off+len(after)]==after
 assert all(a==b or i in allowed for i,(a,b) in enumerate(zip(raw,data)))
 sym=m['symbols'];state=0x440000;buf=0x441000;source=0x442000;results=[]
 def setup():
  u=machine(data,65536)
  for i,r in enumerate(SAVED_REGS):u.reg_write(r,0x12340000+i)
  return u
 def ret(u,value):u.reg_write(UC_ARM_REG_R0,value&0xffffffff);u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
 def base(u,a,size,unused):
  if a==sym['hk6_lookup']&~1:ret(u,state)
  elif a==0xb723c:ret(u,77)
  elif a==0xb7198:assert u.reg_read(UC_ARM_REG_R0)==77;ret(u,0)
 for active in (0,1):
  u=setup();u.mem_write(state,struct.pack('<7I',active,1,0,buf,0,0,0));u.hook_add(UC_HOOK_CODE,base)
  target=0x1a620 if active else 0x1a734
  def gate(u,a,s,x):
   if a==0x5c2e8:ret(u,0)
   elif a==target:u.emu_stop()
  u.hook_add(UC_HOOK_CODE,gate);prepare(u);u.emu_start(0x1a72f,0x300000,count=5000)
  assert u.reg_read(UC_ARM_REG_PC)==target and u.reg_read(UC_ARM_REG_SP)==STACK
  assert all(u.reg_read(r)==0x12340000+i for i,r in enumerate(SAVED_REGS))
  results.append(dict(test='patched_idle_gate',active=active,target=hex(target)))
 jpeg=bytes([255,216,1,2,3,255,217,0,7,0,0,0])
 for mode in ('capture','inactive','occupied','bad_trailer'):
  u=setup();u.mem_write(state,struct.pack('<7I',int(mode!='inactive'),1,3 if mode=='occupied' else 0,buf,0,0,0))
  frame=jpeg if mode!='bad_trailer' else jpeg[:-4]+b'\x08\0\0\0';u.mem_write(source,frame);u.hook_add(UC_HOOK_CODE,base)
  def read(u,a,s,x):
   if a==0x2837c:ret(u,len(frame))
  u.hook_add(UC_HOOK_CODE,read)
  assert call(u,sym['hk6_read'],[source,40928],count=10000)==len(frame)
  if mode=='capture':
   assert bytes(u.mem_read(buf,7))==jpeg[:7]
   assert struct.unpack('<I',bytes(u.mem_read(state+8,4)))[0]==2
  else:assert bytes(u.mem_read(buf,7))==b'\0'*7
  assert all(u.reg_read(r)==0x12340000+i for i,r in enumerate(SAVED_REGS))
  results.append(dict(test='compiled_capture',mode=mode))
 for mode in ('success','allocation_failed','thread_failed','already_present'):
  u=setup();events=[]
  def boot(u,a,s,x):
   if a==sym['hk6_lookup']&~1:ret(u,state if mode=='already_present' else 0)
   elif a==0x5c610:
    assert u.reg_read(UC_ARM_REG_R0)==0x40ec28
    assert u.reg_read(UC_ARM_REG_R1)==28
    events.append('alloc_main');ret(u,0 if mode=='allocation_failed' else state)
   elif a==0x5d0f8:
    assert bytes(u.mem_read(state,28))==b'\0'*28
    assert u.reg_read(UC_ARM_REG_R2)==state and u.reg_read(UC_ARM_REG_R3)==4096
    priority,tick=struct.unpack('<II',bytes(u.mem_read(u.reg_read(UC_ARM_REG_SP),8)))
    assert (priority,tick)==(21,10)
    events.append('create_initialized');ret(u,0 if mode=='thread_failed' else 0x443000)
   elif a==0x5c734:events.append('free');ret(u,0)
   elif a==0x1aca8:events.append('native_init');ret(u,0)
   elif a==0x5d2e0:events.append('start_http');ret(u,0)
  u.hook_add(UC_HOOK_CODE,boot);call(u,sym['hk6_boot'],count=10000)
  expected={'success':['alloc_main','create_initialized','native_init','start_http'],
   'allocation_failed':['alloc_main','native_init'],
   'thread_failed':['alloc_main','create_initialized','free','native_init'],
   'already_present':['native_init']}[mode]
  assert events==expected
  results.append(dict(test='compiled_boot',mode=mode,events=events))
 # Exercise compiled parser/HTTP response, not only the frame hook.
 for route,supply in [('/',True),('/snapshot.jpg',True),('/snapshot.jpg',False)]:
  u=setup();request=('GET '+route+' HTTP/1.1\r\nHost: camera\r\n\r\n').encode()
  io={'input':0,'output':bytearray(),'ticks':0,'allocations':0}
  def http(u,a,size,x):
   r0=u.reg_read(UC_ARM_REG_R0);r1=u.reg_read(UC_ARM_REG_R1);r2=u.reg_read(UC_ARM_REG_R2)
   if a==sym['hk6_now']&~1:ret(u,io['ticks'])
   elif a==sym['hk6_timeouts']&~1:ret(u,0)
   elif a==sym['hk6_alloc']&~1:assert r0==40928;io['allocations']+=1;ret(u,buf)
   elif a==sym['hk6_free']&~1:assert r0==buf;io['allocations']-=1;ret(u,0)
   elif a==sym['hk6_recv']&~1:
    chunk=request[io['input']:io['input']+min(7,r2)]
    u.mem_write(r1,chunk);io['input']+=len(chunk);ret(u,len(chunk))
   elif a==sym['hk6_send']&~1:
    n=min(r2,3);io['output'].extend(bytes(u.mem_read(r1,n)));ret(u,n)
   elif a==sym['hk6_delay']&~1:
    io['ticks']+=r0
    if supply and struct.unpack('<I',bytes(u.mem_read(state+4,4)))[0]:
     u.mem_write(buf,jpeg[:7]);u.mem_write(state+4,struct.pack('<II',0,2));u.mem_write(state+16,struct.pack('<I',7))
    ret(u,0)
  u.hook_add(UC_HOOK_CODE,base);u.hook_add(UC_HOOK_CODE,http)
  call(u,sym['hk6_serve'],[state,3],count=1000000)
  response=bytes(io['output']);assert io['allocations']==0
  assert (b'200 OK' if supply else b'503 Service Unavailable') in response
  if route=='/snapshot.jpg' and supply:assert response.endswith(jpeg[:7]) and b'Content-Length: 7\r\n' in response
  assert bytes(u.mem_read(state,8))==b'\0'*8
  results.append(dict(test='compiled_http',route=route,frame_available=supply,response_bytes=len(response)))
 profiles=validate_profiles(data)
 report=dict(passed=True,payload_sha256=m['payload_sha256'],cases=results,profiles=profiles,unchanged_stock_outside_declared_hooks=True,scope='Compiled Thumb code and patched gate; modeled OS/allocator/frame reader. Not hardware or whole-RTOS concurrency.')
 (OUT/'validation.json').write_text(json.dumps(report,indent=2)+'\n');print(f'{len(results)} compiled-hook cases and VGA/QVGA regression passed')
if __name__=='__main__':main()
