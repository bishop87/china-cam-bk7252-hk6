"""Add UART attribution to pinned EXP2B without modifying executable code."""
import json,struct
from build_stock_patch import ROOT,sha
from verify_stock_patch import machine,prepare
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_PC
OUT=ROOT/'analysis/exp2c-candidate'
def main():
 raw=(ROOT/'dist/hk6-stock-lan-exp2b/hk6-stock-lan-exp2b.bin').read_bytes()
 assert sha(raw)=='d888eeedca55ea1aed55bf80390b0ce9c09eb1bc1e95a90b4d0738dd11f9d231'
 assert struct.unpack_from('<I',raw,0x42e50)[0]==0xc842d
 banner=b'HI704 init finish\r\npatched by Bishop87\r\n\0'
 address=65536+len(raw);data=bytearray(raw)+banner
 struct.pack_into('<I',data,0x42e50,address)
 assert {i for i in range(len(raw)) if raw[i]!=data[i]}<=set(range(0x42e50,0x42e54))
 u=machine(bytes(data),65536);prepare(u);u.emu_start(0x52c6f,0x52c70,count=1)
 assert u.reg_read(UC_ARM_REG_R0)==address
 assert bytes(u.mem_read(address,len(banner)))==banner and b'%' not in banner
 OUT.mkdir(exist_ok=True);(OUT/'candidate-logical.bin').write_bytes(data)
 m={'version':'2M.1220-LAN-EXP2C','status':'offline_candidate','payload_sha256':sha(data),'previous_sha256':sha(raw),'payload_bytes':len(data),'appended_address':hex(address),'appended_bytes':len(banner),'patches':[{'address':'0x52e50','before':raw[0x42e50:0x42e54].hex(),'after':bytes(data[0x42e50:0x42e54]).hex()}],'banner':banner[:-1].decode(),'scope':'Only a string pointer and appended string change; all executable bytes, sensor settings and network/timezone patches preserved'}
 (OUT/'manifest.json').write_text(json.dumps(m,indent=2)+'\n');(OUT/'validation.json').write_text(json.dumps({'passed':True,'payload_sha256':sha(data),'exact_diff_verified':True,'real_thumb_load_points_to_banner':True,'format_has_no_placeholders':True},indent=2)+'\n');print(json.dumps(m,indent=2))
if __name__=='__main__':main()
