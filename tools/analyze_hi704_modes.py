"""Trace vendor resolution dispatch with sensor I/O mocked; never access hardware."""
import json,struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_PC,UC_ARM_REG_LR
from verify_stock_patch import machine,call
from build_stock_patch import ROOT,sha

def main():
 b=(ROOT/'dist/hk6-stock-lan-exp2b/hk6-stock-lan-exp2b.bin').read_bytes()
 assert sha(b)=='d888eeedca55ea1aed55bf80390b0ce9c09eb1bc1e95a90b4d0738dd11f9d231'
 sensor=struct.unpack_from('<I',b,0x425ec)[0];results=[]
 for mode in (0,1,2,3):
  u=machine(b,65536);u.mem_write(sensor,struct.pack('<I',0x96));writes=[];messages=[];encoder=[]
  def hook(uc,a,size,unused):
   if a==0x51760:writes.append([uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R1)])
   elif a==0x2525c:
    ptr=uc.reg_read(UC_ARM_REG_R0);messages.append(bytes(uc.mem_read(ptr,80)).split(b'\0')[0].decode('ascii'))
   elif a==0x22970:encoder.append(uc.reg_read(UC_ARM_REG_R0))
   else:return
   uc.reg_write(UC_ARM_REG_R0,0);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
  u.hook_add(UC_HOOK_CODE,hook);call(u,0x522b5,[mode],count=10000)
  results.append({'mode':mode,'sensor_writes':writes,'messages':messages,'encoder_argument':encoder})
 assert len(results[0]['sensor_writes'])==len(results[1]['sensor_writes'])==11
 assert not results[2]['sensor_writes'] and not results[3]['sensor_writes']
 out=ROOT/'analysis/original/reverse/hi704-modes.json';out.write_text(json.dumps({'sensor_id':'0x96','dispatch':'0x522b4','hi704_branch':'0x525a6','cases':results,'scope':'Actual Thumb dispatch emulated, I2C and encoder callbacks mocked. Not live image dimensions.'},indent=2)+'\n');print(out)
if __name__=='__main__':main()
