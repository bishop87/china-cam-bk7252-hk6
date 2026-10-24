"""Bounded emulation of stock socket ABI; no network and no firmware mutation."""
import hashlib,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
from verify_stock_patch import machine,call,ROOT

def main():
 data=(ROOT/'dist/hk6-stock-lan-exp2f/hk6-stock-lan-exp2f.bin').read_bytes()
 sha=hashlib.sha256(data).hexdigest()
 assert sha=='981d33db1b1af8b94bdcfc98e369214b312a2f4d00b82aacdcbc0a962f50ea5d'
 results=[]
 sock=0x440000;conn=0x440100;arg=0x441000;err=0x440200
 def setup():
  u=machine(data,65536);u.mem_write(sock,struct.pack('<I',conn));u.mem_write(conn,b'\x10');return u
 for option,field in [(0x1005,0x1c),(0x1006,0x20)]:
  for size in (8,4):
   u=setup();u.mem_write(arg,struct.pack('<ii',2,125000))
   def hook(uc,a,s,x):
    if a in (0x67f64,0x67d54):r=sock
    elif a in (0x65924,0x65932):r=0
    elif a==0xa9fb4:r=err
    elif a==0xb722c:r=uc.reg_read(UC_ARM_REG_R0)//uc.reg_read(UC_ARM_REG_R1)
    else:return
    uc.reg_write(UC_ARM_REG_R0,r);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
   u.hook_add(UC_HOOK_CODE,hook)
   r=call(u,0x68c7d,[3,0xfff,option,arg,size],count=2000)
   value=struct.unpack('<I',bytes(u.mem_read(conn+field,4)))[0]
   assert r==(0 if size==8 else 0xffffffff)
   assert value==(2125 if size==8 else 0)
   if size==4:assert struct.unpack('<I',bytes(u.mem_read(err,4)))[0]==22
   results.append(dict(test='timeout',option=hex(option),size=size,result=r,milliseconds=value))
 for family,length in [(2,16),(0,16),(2,8)]:
  u=setup();u.mem_write(arg,bytes([16,family,0,80,192,168,1,54])+b'\0'*8);bound=[]
  def hook(uc,a,s,x):
   if a==0x67f64:r=sock
   elif a==0x69368:
    v=uc.reg_read(UC_ARM_REG_R0);r=((v&255)<<8)|(v>>8)
   elif a==0x65ee4:
    bound.append({'address_bytes':bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R1),4)).hex(),'port':uc.reg_read(UC_ARM_REG_R2)});r=0
   elif a==0x6794c:r=22
   elif a==0xa9fb4:r=err
   elif a in (0x5c2e8,0x65a54):r=0 # log/assert diagnostic shim
   else:return
   uc.reg_write(UC_ARM_REG_R0,r);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
  u.hook_add(UC_HOOK_CODE,hook);r=call(u,0x682d9,[3,arg,length],count=2000)
  valid=family==2 and length==16
  assert r==(0 if valid else 0xffffffff)
  assert bound==([{'address_bytes':'c0a80136','port':80}] if valid else [])
  results.append(dict(test='bind',family=family,length=length,result=r,bound=bound))
 for written,error in [(1024,0),(127,0),(0,-7)]:
  u=setup();calls=[]
  def hook(uc,a,s,x):
   if a==0x67f64:r=sock
   elif a==0x661b0:
    p=struct.unpack('<I',bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_SP),4)))[0]
    uc.mem_write(p,struct.pack('<I',written));calls.append([uc.reg_read(UC_ARM_REG_R2),uc.reg_read(UC_ARM_REG_R3)]);r=error&0xffffffff
   elif a==0x6794c:r=0 if error==0 else 11
   elif a==0xa9fb4:r=err
   else:return
   uc.reg_write(UC_ARM_REG_R0,r);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
  u.hook_add(UC_HOOK_CODE,hook);r=call(u,0x68825,[3,arg,1024,0],count=2000)
  assert r==(written if not error else error&0xffffffff)
  assert calls==[[1024,1]] # NETCONN_COPY: caller buffer not retained by this path
  results.append(dict(test='send',written=written,netconn_error=error,result=r,write_calls=calls))
 out=ROOT/'analysis/http-feasibility/socket-abi-validation.json'
 out.write_text(json.dumps(dict(source_sha256=sha,cases=results,passed=True,scope='Real stock wrapper instructions; netconn/locking/errno/division mocked. Not a TCP or scheduler test.'),indent=2)+'\n')
 print(f'{len(results)} socket ABI cases passed')
if __name__=='__main__':main()
