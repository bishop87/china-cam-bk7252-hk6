"""Exercise real EXP2B Thumb code against host Europe/Rome zoneinfo and hooks."""
import datetime as dt, hashlib,json,struct,sys
from zoneinfo import ZoneInfo
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
from verify_stock_patch import machine,call,prepare,STACK,STOP,SAVED_REGS
from build_stock_patch import ROOT,sha
from verify_exp2_candidate import run
OUT=ROOT/'analysis/exp2b-candidate'
def main():
 data=(OUT/'candidate-logical.bin').read_bytes();m=json.loads((OUT/'manifest.json').read_text());assert sha(data)==m['payload_sha256']
 zone=ZoneInfo('Europe/Rome');u=machine(data,0x10000)
 def expected(t):
  if t<820454400 or t>2147476447:return t
  return t+int(dt.datetime.fromtimestamp(t,dt.timezone.utc).astimezone(zone).utcoffset().total_seconds())
 times={0,1,820454399,820454400,2147476447,2147476448,0xffffffff}
 # Every week, leap years, and seconds on both sides of each DST transition.
 for year in range(1996,2038):
  for month in range(1,13):
   for day in (1,8,15,22,28):
    t=int(dt.datetime(year,month,day,12,tzinfo=dt.timezone.utc).timestamp())
    if t<=2147476447:times.add(t)
  for month in (3,10):
   last=dt.datetime(year,month,31,1,tzinfo=dt.timezone.utc)
   last-=dt.timedelta(days=(last.weekday()+1)%7)
   t=int(last.timestamp())
   if t<=2147476447:times.update(t+d for d in (-3601,-1,0,1,3599,3600))
 for t in sorted(times):
  for i,r in enumerate(SAVED_REGS):u.reg_write(r,0x12340000+i)
  got=call(u,m['symbols']['hk6_rome'],[t],count=20000)
  assert got==expected(t),(t,got,expected(t))
  assert all(u.reg_read(r)==0x12340000+i for i,r in enumerate(SAVED_REGS))
 # NTP wrapper: real entry, substitute only the network routine's result.
 hook_times=[0,1792347784,1792890000,1774746000,1767225600]
 for t in hook_times:
  v=machine(data,0x10000)
  def net(uc,a,size,unused):
   if a==0x583b0:
    uc.reg_write(UC_ARM_REG_R0,t);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
  v.hook_add(UC_HOOK_CODE,net)
  for i,r in enumerate(SAVED_REGS):v.reg_write(r,0x12340000+i)
  assert call(v,0x584d1)==expected(t)
  assert all(v.reg_read(r)==0x12340000+i for i,r in enumerate(SAVED_REGS))
 # App hook receives raw UTC. Test DST-blind and unrelated incoming tz values.
 for t in hook_times[1:]:
  for tz in (-3600,-7200,0,28800):
   v=machine(data,0x10000);prepare(v)
   v.mem_write(0x440014,struct.pack('<I',t));v.mem_write(STACK,b'X'*32)
   v.reg_write(UC_ARM_REG_R0,0x440000);v.reg_write(UC_ARM_REG_R2,tz&0xffffffff)
   for i,r in enumerate(SAVED_REGS):v.reg_write(r,0x12340000+i)
   v.emu_start(0x19b51,0x19b58,count=20000)
   assert v.reg_read(UC_ARM_REG_PC)==0x19b58
   assert v.reg_read(UC_ARM_REG_SP)==STACK and v.reg_read(UC_ARM_REG_R0)==STACK+12
   assert bytes(v.mem_read(STACK,12))==b'X'*12 and bytes(v.mem_read(STACK+16,16))==b'X'*16
   assert struct.unpack('<I',v.mem_read(STACK+12,4))[0]==expected(t)
   assert all(v.reg_read(r)==0x12340000+i for i,r in enumerate(SAVED_REGS))
 # Run the entire existing network regression suite against the new image,
 # in an isolated directory so EXP2A's evidence remains unchanged.
 import verify_exp2_candidate as network
 temp=OUT/'network-check';temp.mkdir(exist_ok=True)
 (temp/'candidate-logical.bin').write_bytes(data)
 (temp/'manifest.json').write_text(json.dumps({'candidate_sha256':sha(data)}))
 network.OUT=temp;network.main()
 report={'passed':True,'payload_sha256':sha(data),'zoneinfo_cases':len(times),'ntp_hook_cases':len(hook_times),'app_hook_cases':len(hook_times[1:])*4,'network_regression_passed':True,'scope':'Conversion on update only; real ARM/Thumb with mocked NTP call. No timer scheduling, whole-OS or hardware test.'}
 (OUT/'validation.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
