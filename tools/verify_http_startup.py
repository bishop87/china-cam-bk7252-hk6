"""Verify candidate startup seam, with original thread creation calls mocked."""
import hashlib,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
from verify_stock_patch import machine,call,ROOT

def main():
 b=(ROOT/'dist/hk6-stock-lan-exp2f/hk6-stock-lan-exp2f.bin').read_bytes()
 sha=hashlib.sha256(b).hexdigest()
 assert sha=='981d33db1b1af8b94bdcfc98e369214b312a2f4d00b82aacdcbc0a962f50ea5d'
 results=[]
 for fail in [None,0,1,2,3]:
  u=machine(b,65536);created=[];started=[]
  def hook(uc,a,s,x):
   if a==0x5d0f8:
    sp=uc.reg_read(UC_ARM_REG_SP);priority,tick=struct.unpack('<II',bytes(uc.mem_read(sp,8)))
    ptr=0 if len(created)==fail else 0x440000+256*len(created)
    created.append(dict(entry=hex(uc.reg_read(UC_ARM_REG_R1)),stack=uc.reg_read(UC_ARM_REG_R3),priority=priority,tick=tick,result=ptr));r=ptr
   elif a==0x5d2e0:started.append(uc.reg_read(UC_ARM_REG_R0));r=0
   elif a in (0x17288,0x5d27c,0x5c2e8):r=0
   else:return
   uc.reg_write(UC_ARM_REG_R0,r);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
  u.hook_add(UC_HOOK_CODE,hook);call(u,0x1aca9,[],count=1000)
  assert [c['entry'] for c in created]==['0x17489','0x1a2ad','0x1a571','0x1ab81']
  assert [c['stack'] for c in created]==[8192,8192,4096,1024]
  assert started==[c['result'] for c in created if c['result']]
  results.append(dict(failed_allocation=fail,created=created,started=started))
 (ROOT/'analysis/http-feasibility/startup-validation.json').write_text(json.dumps(dict(source_sha256=sha,cases=results,passed=True,scope='Real stock startup instructions with init, create, start, delay and log mocked. Does not prove once-only execution or network readiness.'),indent=2)+'\n')
 print('5 startup cases passed')
if __name__=='__main__':main()
