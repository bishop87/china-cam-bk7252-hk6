'use strict';
function displayCameraClock(){
  const value=state?.parameters?.time;
  if(!Number.isFinite(value))return 'Orologio non disponibile.';
  // The HK6 RTC returns local wall time encoded as an epoch, not UTC.
  return `Ora camera: ${new Date(value*1000).toLocaleString('it-IT',{timeZone:'UTC'})} · Europe/Rome.`;
}
$('clock-read').onclick=()=>run(async()=>{const r=await command('parameters');await stateRead();if(r.state==='confirmed')$('clock-status').textContent=displayCameraClock();});
$('clock-sync').onclick=()=>run(async()=>{
  const r=await command('clock_sync');if(r.state!=='confirmed')return;
  const read=await command('parameters');await stateRead();
  const parts=new Intl.DateTimeFormat('sv-SE',{timeZone:'Europe/Rome',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'}).formatToParts(new Date());
  const p=Object.fromEntries(parts.map(x=>[x.type,x.value]));
  const expected=Date.parse(`${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}:${p.second}Z`)/1000;
  const ok=read.state==='confirmed' && Math.abs(state.parameters.time-expected)<6;
  $('clock-status').textContent=(ok?'Ora riletta e verificata. ':'Sincronizzazione accettata, ma ora non verificata. ')+displayCameraClock();
});
$('camera-reboot').onclick=()=>{$('reboot-confirm').showModal();};
$('reboot-confirm').addEventListener('close',()=>{
  if($('reboot-confirm').returnValue!=='confirm')return;
  run(async()=>{const r=await command('reboot');notice(r.state==='confirmed'?'Riavvio accettato. Attendi il ritorno del video.':'Esito del riavvio non confermato. Attendi il video prima di riprovare.',r.state==='confirmed'?'':'error');});
});
