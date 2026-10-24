"""Validate camera-native HTTP without the Mac bridge; save metadata only."""
import argparse,hashlib,io,json,time,urllib.request
from pathlib import Path
from PIL import Image
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--camera',required=True);p.add_argument('--seconds',type=float,default=30);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
base='http://'+a.camera;opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));rpt={'camera':a.camera,'native_http_port':80,'bridge_used':False,'passed':False}
def jpeg(data):
 with Image.open(io.BytesIO(data)) as im:
  im.load()
  if im.format!='JPEG' or im.size not in ((640,480),(320,240)):raise ValueError('Unexpected image')
  return list(im.size)
try:
 with opener.open(base+'/',timeout=8) as r:
  page=r.read(4096);assert r.status==200 and b'/stream.mjpg' in page
 rpt['page_bytes']=len(page)
 with opener.open(base+'/snapshot.jpg',timeout=8) as r:
  data=r.read(40929);assert 0<len(data)<=40923
 rpt['snapshot']={'bytes':len(data),'dimensions':jpeg(data),'sha256':hashlib.sha256(data).hexdigest()}
 sizes=[];dimensions=set();hashes=set();start=time.monotonic()
 with opener.open(base+'/stream.mjpg',timeout=8) as r:
  assert 'multipart/x-mixed-replace' in r.headers['Content-Type']
  while time.monotonic()-start<a.seconds:
   line=r.readline(1024)
   if line!=b'--hk6\r\n':raise ValueError('Missing multipart boundary')
   headers={}
   for _ in range(8):
    line=r.readline(1024)
    if line==b'\r\n':break
    k,v=line.decode('ascii').split(':',1);headers[k.lower()]=v.strip()
   else:raise ValueError('Too many part headers')
   n=int(headers['content-length']);assert 0<n<=40923 and headers['content-type']=='image/jpeg'
   data=r.read(n);assert len(data)==n and r.read(2)==b'\r\n'
   dimensions.add(tuple(jpeg(data)));sizes.append(n);hashes.add(hashlib.sha256(data).hexdigest())
 elapsed=time.monotonic()-start
 rpt['stream']={'seconds':elapsed,'frames':len(sizes),'fps':len(sizes)/elapsed,'min_bytes':min(sizes),'max_bytes':max(sizes),'dimensions':sorted(dimensions),'unique_frames':len(hashes)}
 time.sleep(2) # allow native sender to observe the disconnected client
 with opener.open(base+'/snapshot.jpg',timeout=8) as r:rpt['snapshot_after_disconnect']=jpeg(r.read(40929))
 rpt['passed']=True
except Exception as e:rpt['error']=type(e).__name__+': '+str(e)
finally:a.output.write_text(json.dumps(rpt,indent=2)+'\n');print(json.dumps(rpt,indent=2))
raise SystemExit(0 if rpt['passed'] else 1)
