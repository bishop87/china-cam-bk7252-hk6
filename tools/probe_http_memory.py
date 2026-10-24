import os,termios,select,time,re,subprocess,json,fcntl
from pathlib import Path
import argparse
parser=argparse.ArgumentParser(description='Read only UART free/list_thread; persist only filtered diagnostics.')
parser.add_argument('--port',required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--trace',action='store_true',help='Read memtrace block metadata instead of free/list_thread')
args=parser.parse_args()
p=args.port
r=subprocess.run(['/usr/sbin/lsof','-t',p],capture_output=True,text=True)
if r.stdout.strip():raise SystemExit('Seriale occupata')
f=os.open(p,os.O_RDWR|os.O_NOCTTY|os.O_NONBLOCK);old=termios.tcgetattr(f);a=termios.tcgetattr(f)
a[0]=a[1]=a[3]=0;a[2]=termios.CLOCAL|termios.CREAD|termios.CS8;a[4]=a[5]=termios.B115200;a[6][termios.VMIN]=0;a[6][termios.VTIME]=0
fcntl.ioctl(f,termios.TIOCEXCL)
termios.tcsetattr(f,termios.TCSANOW,a)
def read(seconds):
 b=b'';end=time.monotonic()+seconds
 while time.monotonic()<end:
  if select.select([f],[],[],.2)[0]:b+=os.read(f,65536)
 return b
try:
 read(1);os.write(f,b'\r');sync=read(2)
 if b'msh' not in sync:raise SystemExit('Nessun prompt msh: nessun comando diagnostico inviato')
 rows=[]
 for cmd in ([b'memtrace\r'] if args.trace else [b'free\r',b'list_thread\r',b'free\r']):
  for c in cmd:os.write(f,bytes([c]));time.sleep(.01)
  raw=read(8 if args.trace else 3).decode(errors='replace')
  # Never persist asynchronous application logs: retain only known diagnostic rows.
  lines=[]
  for line in raw.splitlines():
   line=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',line).strip()
   if re.search(r'password|passwd|pwd|ssid|user|cmd.*[{:]',line,re.I):continue
   if (args.trace and (re.match(r'^\[0x[0-9a-f]+ -',line,re.I) or re.match(r'^(start_addr|pool_size|cur_used|max_used|memory heap)',line))) or re.match(r'^(TCM\b|heap\b|memheap\b|total\b|used\b|maximum\b|thread\s|name\s|[- ]+$)',line,re.I) or re.match(r'^\S+\s+(?:0x)?[0-9a-f]+\s+(?:ready|suspend|running|init|close)\b',line,re.I) or re.match(r'^\S+\s+0x[0-9a-f]+\s+0x[0-9a-f]+',line,re.I):lines.append(line)
  rows.append({'command':cmd.decode().strip(),'diagnostic_lines':lines,'prompt_received':'msh' in raw})
 out={'captured_at_utc':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),'scope':'UART diagnostic metadata only; no allocation payloads or configuration changes','samples':rows}
 args.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
finally:termios.tcsetattr(f,termios.TCSANOW,old);os.close(f)
