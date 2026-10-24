'use strict';
const $ = id => document.getElementById(id);
let state = null, busy = false, previous = null, lastLive = false, loaded = false;
function notice(text, kind='') { $('notice').textContent=text; $('notice').className=kind; }
function renderState(s) {
  state=s; if(typeof renderStorage==='function')renderStorage(s); if(typeof renderAudio==='function')renderAudio(s.audio); $('camera-ip').textContent=s.camera;
  if (document.activeElement!==$('target')) $('target').value=s.camera;
  $('current-ssid').textContent=s.wifi.ssid || 'Non ancora letta';
  $('firmware').textContent=s.parameters.sysver || '—';
  $('mcu').textContent=s.parameters.mcuver || '—';
  $('battery').textContent=s.parameters.batValue===undefined?'—':`${s.parameters.batValue}%`;
  $('signal').textContent=s.parameters.signal===undefined?'—':String(s.parameters.signal);
  if(s.profiles) $('profile').replaceChildren(...s.profiles.map(p=>new Option(p.label,String(p.mode))));
  $('profile').value=String(s.video_mode);
  for (const form of document.querySelectorAll('.image-form')) {
    const field=form.dataset.field, select=form.querySelector('select');
    if(field==='icut' && s.parameters.isShowIcutAuto===1 && !select.querySelector('[value="2"]')) select.add(new Option('Automatica', '2'));
    for(const input of form.querySelectorAll('button,select')) input.disabled=!(field in s.parameters);
    if(field in s.parameters) select.value=String(s.parameters[field]);
  }
}
async function stateRead() {
  const r=await fetch('/api/state'); if(!r.ok) throw new Error('Servizio non disponibile'); renderState(await r.json());
}
async function command(action,data={}) {
  if(!state) await stateRead();
  const response=await fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json','X-Control-Token':state.token},body:JSON.stringify({action,data})});
  if(response.status===403) throw new Error('Il servizio è stato riavviato: ricarica la pagina.');
  const result=await response.json();
  if(!response.ok) throw new Error(result.error || 'Operazione non riuscita');
  notice(result.message, result.state==='confirmed'?'success':result.state==='sent'?'':'error');
  return result;
}
async function run(task) {
  if(busy) return; busy=true; document.body.setAttribute('aria-busy','true');
  notice('Operazione in corso…');
  try { await task(); } catch(error) { notice(error.message,'error'); }
  finally { busy=false; document.body.removeAttribute('aria-busy'); }
}
async function refresh() {
  await stateRead();
  if(!state.online) { notice('Camera non connessa. Il servizio sta tentando di riconnettersi.'); return; }
  const params=await command('parameters');
  if(params.state!=='confirmed') return;
  await command('wifi'); await stateRead();
}
$('refresh').onclick=()=>run(refresh);
for(const tab of document.querySelectorAll('[role=tab]')) {
  tab.onclick=()=>{
    for(const item of document.querySelectorAll('[role=tab]')) {item.setAttribute('aria-selected',String(item===tab));item.tabIndex=item===tab?0:-1;$('panel-'+item.dataset.tab).hidden=item!==tab;}
  };
  tab.onkeydown=e=>{
    if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;
    e.preventDefault();const tabs=[...document.querySelectorAll('[role=tab]')];
    const n=e.key==='Home'?0:e.key==='End'?tabs.length-1:(tabs.indexOf(tab)+(e.key==='ArrowRight'?1:tabs.length-1))%tabs.length;
    tabs[n].click();tabs[n].focus();
  };
}
$('profile-form').onsubmit=e=>{e.preventDefault();const mode=Number($('profile').value);run(async()=>{const r=await command('video',{mode});await stateRead();if(r.state==='sent')notice(r.message);});};
for(const form of document.querySelectorAll('.image-form')) form.onsubmit=e=>{
  e.preventDefault();const field=form.dataset.field, value=Number(form.querySelector('select').value);
  run(async()=>{const r=await command('image',{field,value});if(r.state==='confirmed'){
    const read=await command('parameters');await stateRead();
    notice(read.state==='confirmed' && state.parameters[field]===value?'Impostazione riletta e confermata.':'Valore non confermato dalla rilettura. Controlla il video e aggiorna i parametri.',read.state==='confirmed' && state.parameters[field]===value?'success':'error');
  }});
};
$('scan').onclick=()=>run(async()=>{
  const r=await command('scan'); if(r.state!=='confirmed')return;
  await stateRead();$('networks').replaceChildren(new Option(state.networks.length?'Scegli una rete':'Nessuna rete rilevata',''));
  for(const net of state.networks) $('networks').add(new Option(`${net.ssid} · ${net.signal} dBm`,net.ssid));
});
$('networks').onchange=()=>{
  const net=state?.networks.find(n=>n.ssid===$('networks').value);
  $('network-info').textContent=net?`Segnale ${net.signal} dBm · ${net.encryption===0?'rete aperta':'rete protetta'}`:'Scegli una rete rilevata.';
  $('wifi-password').required=!!net && net.encryption!==0;
};
$('wifi-form').onsubmit=e=>{e.preventDefault();if(busy)return;$('confirm-ssid').textContent=$('networks').value;$('wifi-confirm').showModal();};
$('wifi-confirm').addEventListener('close',()=>{
  if($('wifi-confirm').returnValue!=='confirm')return;
  const ssid=$('networks').value,password=$('wifi-password').value;$('wifi-password').value='';
  run(async()=>{const r=await command('set_wifi',{ssid,password});notice(r.state==='confirmed'?'La camera ha accettato la configurazione. Attendi il collegamento alla nuova rete: non è ancora verificato.':'Esito del cambio rete non verificato. Controlla la connessione della camera prima di riprovare.',r.state==='confirmed'?'':'error');});
});
$('target-form').onsubmit=e=>{e.preventDefault();const ip=$('target').value.trim();run(async()=>{await command('target',{ip});await stateRead();});};
$('reload-video').onclick=()=>{$('video').src='/stream.mjpg';};
async function poll(){
  try {
    const r=await fetch('/status');if(!r.ok)throw new Error();const s=await r.json();
    const live=s.state==='streaming' && s.age_seconds!==null && s.age_seconds<10;
    $('dot').classList.toggle('live',live);
    $('connection').textContent=s.playback?.filename?'Archivio in riproduzione':live?'In diretta':s.state==='stopped'?'Servizio fermo':'Riconnessione…';
    $('offline').hidden=live;$('frames').textContent=s.frames.toLocaleString('it-IT');
    $('age').textContent=s.age_seconds===null?'—':`${s.age_seconds.toFixed(1)} s`;
    $('resolution').textContent=s.dimensions?`${s.dimensions[0]} × ${s.dimensions[1]} px · MJPEG`:'In attesa del primo frame';
    if(typeof renderAudio==='function')renderAudio(s.audio);
    const expected=s.requested_dimensions;
    const mismatch=live && expected && s.dimensions && expected.some((n,i)=>n!==s.dimensions[i]);
    $('profile-result').textContent=!live?'In attesa del video per verificare la risoluzione.':mismatch?
      `Richiesti ${expected[0]} × ${expected[1]}, ricevuti ${s.dimensions[0]} × ${s.dimensions[1]}. Il firmware non sta restituendo la risoluzione richiesta.`:
      expected && s.dimensions?`Risoluzione ricevuta: ${s.dimensions[0]} × ${s.dimensions[1]}, corrispondente al profilo richiesto.`:'';
    $('profile-result').classList.toggle('mismatch',Boolean(mismatch));
    const now=performance.now();$('fps').textContent=previous && s.frames>=previous.frames?`${((s.frames-previous.frames)/((now-previous.now)/1000)).toFixed(1)} fps`:'—';previous={frames:s.frames,now};
    if(live && !lastLive) {
      $('video').src='/stream.mjpg';
      if(!busy) {if(!loaded){loaded=true;await run(refresh);}else{await stateRead();}}
    }
    lastLive=live;
  }catch(error){if(typeof stopListening==='function')stopListening();$('connection').textContent='Servizio non raggiungibile';$('dot').classList.remove('live');$('offline').hidden=false;lastLive=false;}
  setTimeout(poll,2000);
}
stateRead().catch(error=>notice(error.message,'error')).finally(poll);
