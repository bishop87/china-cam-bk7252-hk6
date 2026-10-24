"""Read local MJPEG and fully decode each frame; retain counters, not images."""
import argparse, hashlib, io, json, time, urllib.request
from PIL import Image
p=argparse.ArgumentParser();p.add_argument('--seconds',type=int,default=180);p.add_argument('--output',required=True);a=p.parse_args()
start=time.monotonic();sizes=[];hashes=set();dims=set();samples=[]
with urllib.request.urlopen('http://127.0.0.1:8765/stream.mjpg',timeout=20) as s:
 while time.monotonic()-start<a.seconds:
  line=s.readline()
  if not line:raise RuntimeError('Stream ended')
  if line!=b'--frame\r\n':continue
  headers={}
  while True:
   line=s.readline()
   if not line:raise RuntimeError('Truncated headers')
   if line==b'\r\n':break
   k,v=line.decode().split(':',1);headers[k.lower()]=v.strip()
  n=int(headers['content-length']);chunks=bytearray()
  while len(chunks)<n:
   b=s.read(n-len(chunks))
   if not b:raise RuntimeError('Truncated body')
   chunks.extend(b)
  frame=bytes(chunks)
  with Image.open(io.BytesIO(frame)) as image:
   image.load()
   if image.size!=(640,480):raise RuntimeError(f'Unexpected dimensions {image.size}')
   dims.add(image.size)
  sizes.append(n);hashes.add(hashlib.sha256(frame).hexdigest())
  elapsed=time.monotonic()-start
  if not samples or elapsed-samples[-1]['elapsed']>=30:
   with urllib.request.urlopen('http://127.0.0.1:8765/status',timeout=5) as r:status=json.load(r)
   samples.append(dict(elapsed=round(elapsed,2),**status));print(json.dumps(samples[-1]),flush=True)
report=dict(passed=True,duration_seconds=round(time.monotonic()-start,2),fully_decoded_frames=len(sizes),unique_hashes=len(hashes),dimensions=sorted(dims),min_jpeg_bytes=min(sizes),max_jpeg_bytes=max(sizes),samples=samples,scope='Local HTTP MJPEG frames fully decoded with Pillow; no claim of motion or field-of-view verification.')
with open(a.output,'x') as f:json.dump(report,f,indent=2);f.write('\n')
print(json.dumps({k:v for k,v in report.items() if k!='samples'}))
