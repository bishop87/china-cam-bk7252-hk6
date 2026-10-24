import urllib.request,json,time,hashlib
from pathlib import Path
import argparse
parser = argparse.ArgumentParser(description="Check MJPEG continuity on the local service; save counters, not images")
parser.add_argument('--seconds', type=float, default=65)
parser.add_argument('--port', type=int, default=8765)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
if not 1 <= args.seconds <= 3600 or not 1 <= args.port <= 65535:
 parser.error('Invalid duration or port')
base=f'http://127.0.0.1:{args.port}'; start=time.monotonic(); samples=[]; hashes=set();sizes=[]
with urllib.request.urlopen(base+'/stream.mjpg',timeout=15) as stream:
 while time.monotonic()-start<args.seconds:
  line=stream.readline()
  if not line:raise RuntimeError('Stream ended')
  if line!=b'--frame\r\n':continue
  headers={}
  while (line:=stream.readline())!=b'\r\n':
   if not line:raise RuntimeError('Truncated headers')
   k,v=line.decode().split(':',1);headers[k.lower()]=v.strip()
  frame=stream.read(int(headers['content-length']))
  if not (frame.startswith(b'\xff\xd8') and frame.endswith(b'\xff\xd9')):raise RuntimeError('Bad JPEG')
  hashes.add(hashlib.sha256(frame).hexdigest());sizes.append(len(frame))
  if not samples or time.monotonic()-start-samples[-1]['elapsed']>=10:
   with urllib.request.urlopen(base+'/status',timeout=5) as r:status=json.load(r)
   samples.append(dict(elapsed=round(time.monotonic()-start,2),**status));print(samples[-1],flush=True)
report=dict(duration_seconds=round(time.monotonic()-start,2),http_frames=len(sizes),unique_frame_hashes=len(hashes),min_jpeg_bytes=min(sizes),max_jpeg_bytes=max(sizes),samples=samples)
with args.output.open('x') as output:
 output.write(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
