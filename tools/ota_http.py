"""Pinned HTTP1 <-> EXP2F UART-controlled OTA. --preflight never writes flash."""
import argparse,http.server,ipaddress,json,os,re,select,threading,time,urllib.request
from pathlib import Path
from build_stock_patch import ROOT,sha,PATCHES
from prepare_uart_recovery import BACKUP_SHA
from rbl import unpack
from uart_backup import Console,ANSI,PROMPT
import ota_exp2f as transport

HTTP_SHA='dbeb8d8d848f3504d33b444e9a651d53948f661d0e9395e8b70ed86ba558ddd9'
HTTP_PAYLOAD='59065131195ae6823e28858c0de3b61a6aa12d9f12768f8123d820f06922c4f7'
F_SHA='c65fe022b5e267525507685d50c837d6f95c8f952cf44361993e9fc5c7071c39'
F_PAYLOAD='981d33db1b1af8b94bdcfc98e369214b312a2f4d00b82aacdcbc0a962f50ea5d'
REGIONS=transport.VERIFIED_REGIONS+[(0x16da0,4),(0x1a628,4),(0x1a72e,6)]

def load_pair(rollback=False):
 folder=ROOT/'dist/hk6-stock-http1'
 h=(folder/'hk6-stock-http1.rbl').read_bytes();f=(folder/'rollback-exp2f.rbl').read_bytes()
 hp,hm=unpack(h);fp,fm=unpack(f)
 if (sha(h),sha(hp),sha(f),sha(fp))!=(HTTP_SHA,HTTP_PAYLOAD,F_SHA,F_PAYLOAD):raise ValueError('Pinned artifact mismatch')
 v=json.loads((folder/'validation.json').read_text())
 if not v['passed'] or v['payload_sha256']!=HTTP_PAYLOAD:raise ValueError('HTTP validation missing')
 if sha((ROOT/'analysis/backups/hk6-original/flash-2MiB.bin').read_bytes())!=BACKUP_SHA:raise ValueError('Recovery backup mismatch')
 trial=json.loads((ROOT/'analysis/uart/write-trial/20261017-175159/report.json').read_text())
 if not trial['passed']:raise ValueError('Recovery sector trial missing')
 return ((f,fp,fm),(h,hp,hm)) if rollback else ((h,hp,hm),(f,fp,fm))

def verify_installed(c,payload,blob,out,label):
 header=transport.logical_read(c,transport.UPDATED_HEADER_ADDR,96)
 if header!=blob[:96]:raise ValueError('Installed header differs from expected source/target')
 (out/(label+'-header.bin')).write_bytes(header)
 regions=[(p['address'],len(bytes.fromhex(p['after']))) for p in PATCHES]
 regions+=REGIONS+[(0x72222,4),(0x584b0,4),(0xd9a44,len(payload)-0xc9a44)]
 rows=[]
 for address,length in regions:
  expected=payload[address-65536:address-65536+length]
  actual=transport.logical_read(c,address,length)
  (out/(label+'-'+hex(address)+'.bin')).write_bytes(actual)
  rows.append(dict(address=hex(address),bytes=length,sha256=sha(actual),matches=actual==expected))
  if actual!=expected:raise ValueError('Flash mismatch at '+hex(address))
 return dict(header=transport.header_info(header),regions=rows,full_payload_readback=False)

def recording_guard(responses):
 for key in ('recMode','pirvideo'):
  if not re.search(r'The '+key+r' value is 0\.',responses['getvalue '+key]):
   raise ValueError('Recording setting not confirmed disabled: '+key)
 files=responses['list_fd']
 if 'fd type' not in files:raise ValueError('File descriptor diagnostics missing')
 if any(re.search(r'^\s*\d+\s+file\s+',line) and not line.rstrip().endswith('/uart1') for line in files.splitlines()):
  raise ValueError('An unexpected file is open; no OTA started')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--port',required=True)
 g=p.add_mutually_exclusive_group(required=True);g.add_argument('--preflight',action='store_true');g.add_argument('--execute',action='store_true')
 p.add_argument('--rollback',action='store_true');p.add_argument('--bind',required=True);p.add_argument('--camera',required=True);p.add_argument('--http-port',type=int,default=8088)
 a=p.parse_args()
 for value in (a.bind,a.camera):
  ip=ipaddress.IPv4Address(value)
  if not ip.is_private or ip.is_loopback or ip.is_unspecified:raise ValueError('Explicit private LAN addresses required')
 if a.bind==a.camera:raise ValueError('Camera and server must differ')
 (blob,payload,meta),(before_blob,before_payload,_)=load_pair(a.rollback)
 os.umask(0o077)
 out=ROOT/'analysis/uart/ota-http1'/time.strftime('%Y%m%d-%H%M%S');out.mkdir(parents=True,exist_ok=False)
 report={'ota_command_sent':False,'rollback':a.rollback,'rbl_sha256':sha(blob),'payload_sha256':sha(payload),'version':meta['version']}
 def save(): (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 c=Console(a.port,out/'serial.rx.bin');server=None;records=[]
 try:
  c.synchronize();transport.send_line(c,'ifconfig');config=transport.prompt_response(c)
  addresses=re.findall(r'ip address:\s*([0-9.]+)',config);report['ip_addresses']=addresses
  if a.camera not in addresses:raise ValueError('Camera IP mismatch')
  print('Checking installed flash/header and rollback artifacts...',flush=True)
  report['before']=verify_installed(c,before_payload,before_blob,out,'before')
  report['recording_diagnostics']={};recording_responses={}
  for command in ('getvalue recMode','getvalue pirvideo','list_fd'):
   transport.send_line(c,command);response=transport.prompt_response(c)
   # Persist locally for diagnosis; no arbitrary environment dump or secrets printed.
   (out/(command.replace(' ','-')+'.txt')).write_text(response)
   recording_responses[command]=response
   report['recording_diagnostics'][command]='captured; not assumed equivalent to runtime status'
  recording_guard(recording_responses);report['recording_guard_passed']=True
  transport.send_line(c,'ping '+a.bind);ping=transport.prompt_response(c,25)
  (out/'ping.txt').write_text(ping)
  if f'bytes from {a.bind} ' not in ping:raise ValueError('Camera cannot reach OTA host')
  report['preflight_passed']=True;save()
  if a.preflight:
   print('Read-only preflight passed; no OTA sent.',flush=True);return 0
  served=threading.Event();transport.ENDPOINT='/hk6-http-trial.rbl'
  server=http.server.ThreadingHTTPServer((a.bind,a.http_port),transport.make_handler(blob,a.bind,a.camera,records,served));server.daemon_threads=True
  threading.Thread(target=server.serve_forever,daemon=True).start()
  url=f'http://{a.bind}:{a.http_port}{transport.ENDPOINT}'
  opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
  with opener.open(urllib.request.Request(url,method='HEAD'),timeout=5) as r:
   if r.status!=200 or int(r.headers['Content-Length'])!=len(blob):raise ValueError('Endpoint check failed')
  c.synchronize();report.update(ota_command_sent=True,url=url);save()
  print('Starting '+meta['version']+' OTA; keep camera powered.',flush=True)
  transport.send_line(c,'http_ota '+url)
  received=bytearray();end=time.monotonic()+180;next_status=time.monotonic()+20
  while time.monotonic()<end:
   if select.select([c.fd],[],[],.2)[0]:
    data=os.read(c.fd,8192)
    if not data:raise OSError('Serial disconnected')
    c.log.write(data);received.extend(data)
    if served.is_set() and PROMPT.search(ANSI.sub(b'',received)):break
   if time.monotonic()>next_status:
    print('Waiting for boot; download complete='+str(served.is_set()),flush=True);next_status=time.monotonic()+20
  else:raise TimeoutError('No application prompt after OTA')
  if not served.is_set():raise ValueError('Camera did not fetch full package')
  report['download_complete']=True;c.synchronize()
  report['after']=verify_installed(c,payload,blob,out,'after')
  report['installed_verified_at_patch_points']=True;save()
  print('Installed header, hook sites and appended code verified.',flush=True)
 except (Exception,KeyboardInterrupt) as e:
  report['error']=type(e).__name__+': '+str(e);print(report['error'],flush=True)
 finally:
  if server:server.shutdown();server.server_close()
  c.close();report['http_requests']=records;save();print(out/'report.json',flush=True)
 return 0 if report.get('installed_verified_at_patch_points') else 1
if __name__=='__main__':raise SystemExit(main())
