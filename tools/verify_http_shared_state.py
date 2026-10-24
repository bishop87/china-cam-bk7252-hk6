"""Verify a no-new-global-RAM state lookup through a persistent RTOS thread."""
import hashlib,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
from verify_stock_patch import machine,call,ROOT

def main():
 b=(ROOT/'dist/hk6-stock-lan-exp2f/hk6-stock-lan-exp2f.bin').read_bytes()
 sha=hashlib.sha256(b).hexdigest()
 assert sha=='981d33db1b1af8b94bdcfc98e369214b312a2f4d00b82aacdcbc0a962f50ea5d'
 results=[];info=0x440000;thread=0x440100;state=0x441000;name=0x442000
 for active in (False,True):
  for present in (False,True):
   u=machine(b,65536);u.mem_write(0x40ecb4,struct.pack('<I',thread if active else 0))
   u.mem_write(info+4,struct.pack('<I',thread+12 if present else info+4))
   u.mem_write(thread,b'hk6http\0');u.mem_write(thread+12,struct.pack('<I',info+4))
   u.mem_write(thread+0x24,struct.pack('<I',state));u.mem_write(name,b'hk6http\0');locks=[]
   def hook(uc,a,s,x):
    if a==0x5cc6c:assert uc.reg_read(UC_ARM_REG_R0)==0;r=info
    elif a==0x5bf26:
     n=uc.reg_read(UC_ARM_REG_R2);assert n==8
     r=int(bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R0),n))!=bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R1),n)))
    elif a in (0x5cf68,0x5cf80):locks.append(hex(a));r=0
    else:return
    uc.reg_write(UC_ARM_REG_R0,r);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
   u.hook_add(UC_HOOK_CODE,hook);r=call(u,0x5d379,[name],count=500)
   assert r==(thread if present else 0)
   assert locks==(['0x5cf68','0x5cf80'] if active else [])
   results.append(dict(test='find',scheduler_thread=active,present=present,result=r,locks=locks))
 # Verify actual thread initializer stores parameter at +0x24.
 u=machine(b,65536)
 def hook(uc,a,s,x):
  if a in (0x5bdf8,0x5d3e4):r=0
  elif a==0x55f10:
   assert uc.reg_read(UC_ARM_REG_R1)==state;r=0x445000
  else:return
  uc.reg_write(UC_ARM_REG_R0,r);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 u.hook_add(UC_HOOK_CODE,hook);call(u,0x5d011,[thread,0x12345,state,0x444000,4096,20,10],count=500)
 assert struct.unpack('<I',bytes(u.mem_read(thread+0x24,4)))[0]==state
 results.append(dict(test='parameter_offset',offset='0x24',passed=True))
 (ROOT/'analysis/http-feasibility/shared-state-validation.json').write_text(json.dumps(dict(source_sha256=sha,cases=results,passed=True,scope='Real thread lookup/init instructions; registry, scheduler locks, stack initialization mocked. No concurrent lifetime validation.'),indent=2)+'\n')
 print('5 shared-state cases passed')
if __name__=='__main__':main()
