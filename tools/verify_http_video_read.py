"""Emulate EXP2F video reader; OS semaphore/IRQ calls mocked, no hardware writes."""
import json,struct,hashlib
from pathlib import Path
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_PC,UC_ARM_REG_LR
from verify_stock_patch import machine,call,ROOT

def main():
 b=(ROOT/'dist/hk6-stock-lan-exp2f/hk6-stock-lan-exp2f.bin').read_bytes()
 sha=hashlib.sha256(b).hexdigest()
 assert sha=='981d33db1b1af8b94bdcfc98e369214b312a2f4d00b82aacdcbc0a962f50ea5d'
 results=[]
 for case in ['null_buffer','zero_capacity','uninitialized','busy','frame_ready','wait_error']:
  u=machine(b,65536);state=0x440000;buf=0x441000;waits=[]
  u.mem_write(0x404870,struct.pack('<I',0 if case=='uninitialized' else state))
  if case=='busy':u.mem_write(state+4,struct.pack('<I',0x450000))
  def hook(uc,address,size,unused):
   if address==0x26278:
    timeout=uc.reg_read(UC_ARM_REG_R1);waits.append(timeout)
    if timeout==0:result=1 # no stale semaphore tokens
    else:
     assert struct.unpack('<II',bytes(uc.mem_read(state+4,8)))==(buf,40928)
     result=1 if case=='wait_error' else 0
     if result==0:uc.mem_write(state+24,struct.pack('<I',12345))
   elif address in (0xb723c,0xb7198,0x2525c):result=0
   else:return
   uc.reg_write(UC_ARM_REG_R0,result);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
  u.hook_add(UC_HOOK_CODE,hook)
  result=call(u,0x2837d,[0 if case=='null_buffer' else buf,0 if case=='zero_capacity' else 40928],count=1000)
  assert result==(12345 if case=='frame_ready' else 0)
  if case in ('frame_ready','wait_error'):
   assert waits==[0,0xffffffff]
   assert bytes(u.mem_read(state+4,8))==b'\0'*8
  else:assert waits==[]
  results.append(dict(case=case,returned=result,wait_timeouts=waits,passed=True))
 out=ROOT/'analysis/http-feasibility/video-read-validation.json'
 out.write_text(json.dumps(dict(source_sha256=sha,cases=results,scope='Real reader instructions; semaphore and interrupts mocked. No scheduling, DMA, radio or hardware validation.'),indent=2)+'\n')
 print(f'{len(results)} video-reader emulation cases passed')
if __name__=='__main__':main()
