'use strict';
let archiveActive=false,archivePaused=false;
const dateCompact=()=>$('record-date').value.replaceAll('-','');
function renderStorage(s){
  const storage=s.storage;if(!storage)return;
  const sd=storage.sd,alarm=storage.alarm;
  $('sd-state').textContent=sd.sdstatu===1?`Scheda pronta · ${sd.free ?? '—'} MiB liberi / ${sd.total ?? '—'} MiB totali`:sd.sdstatu===0?'MicroSD assente o non riconosciuta':'Stato non ancora letto';
  if(document.activeElement!==$('record-mode'))$('record-mode').value=sd.recMode===1?'continuous':alarm.pirvideo===1?'motion':'off';
  $('alarm-state').textContent=alarm.pirsensitive===undefined?'':`Eventi: sensibilità ${alarm.pirsensitive} · durata ${alarm.pirvideotime} s · intervallo ${alarm.pirDelayTime} s (valori della camera).`;
  for(const [id,key] of [['event-sensitivity','pirsensitive'],['event-duration','pirvideotime'],['event-interval','pirDelayTime']])if(alarm[key]!==undefined && document.activeElement!==$(id))$(id).value=alarm[key];
  for(const button of $('record-mode-form').querySelectorAll('button,select'))button.disabled=sd.sdstatu!==1;
}
async function storageRefresh(){
  const sd=await command('sd');if(sd.state!=='confirmed')throw new Error('Stato microSD non confermato');
  const alarm=await command('alarm');if(alarm.state!=='confirmed')throw new Error('Parametri eventi non confermati');
  await stateRead();renderStorage(state);
}
$('sd-refresh').onclick=()=>run(storageRefresh);
$('record-mode-form').onsubmit=e=>{e.preventDefault();const mode=$('record-mode').value;
  run(async()=>{
    if(archiveActive)throw new Error('Ferma prima la riproduzione');
    let r=await command('record_motion',{enabled:mode==='motion'});if(r.state!=='confirmed')return;
    r=await command('record_continuous',{enabled:mode==='continuous'});if(r.state!=='confirmed')return;
    await storageRefresh();
    const sd=state.storage.sd,a=state.storage.alarm;
    const ok=sd.recMode===(mode==='continuous'?1:0) && a.pirvideo===(mode==='motion'?1:0) && a.pirenable===(mode==='motion'?1:0);
    notice(ok?'Modalità registrazione riletta e confermata.':'Configurazione parziale o non confermata: aggiorna e verifica.',ok?'success':'error');
  });
};
$('record-search').onclick=()=>run(async()=>{
  if(!$('record-date').value)throw new Error('Seleziona una data');
  const date=dateCompact();
  const days=await command('record_days',{year:Number(date.slice(0,4))});if(days.state!=='confirmed')return;
  const mask=Number(days.data[`month[${Number(date.slice(4,6))-1}]`])>>>0;
  const available=Array.from({length:31},(_,i)=>i+1).filter(day=>(mask & (1<<(day-1)))!==0);
  $('record-calendar').textContent=`Giorni con archivio nel mese: ${available.join(', ') || 'nessuno'}.`;
  const hours=await command('record_hours',{ymd:date});if(hours.state!=='confirmed')return;
  const bits=Number(hours.data.record_hour)>>>0;
  $('record-hour').replaceChildren(new Option('Seleziona un’ora',''));
  for(let h=0;h<24;h++)if(bits & (1<<h))$('record-hour').add(new Option(`${String(h).padStart(2,'0')}:00`,String(h).padStart(2,'0')));
  $('record-file').replaceChildren(new Option('Seleziona un’ora',''));
  if(!bits)$('record-calendar').textContent+=' Nessuna ora disponibile per questa data.';
});
$('record-hour').onchange=()=>run(async()=>{
  if(!$('record-hour').value)return;
  const r=await command('record_files',{ymdh:dateCompact()+$('record-hour').value});if(r.state!=='confirmed')return;
  $('record-file').replaceChildren(new Option('Scegli un filmato',''));
  for(const filename of r.data.files)$('record-file').add(new Option(filename,filename));
  if(!r.data.files.length)notice('Nessun filmato chiuso in quest’ora.');
});
$('record-play').onclick=()=>run(async()=>{
  if(!$('record-file').value)throw new Error('Seleziona un filmato');
  stopRecordAudio();archivePaused=false;$('record-pause').textContent='Pausa';
  stopListening();
  if(state?.audio?.enabled)await command('audio',{enabled:false});
  await storageRefresh();
  const r=await command('record_play',{filename:$('record-file').value});if(r.state!=='confirmed')return;
  archiveActive=true;$('record-export').hidden=true;$('record-player').hidden=false;$('record-player').src='/recording.mjpg';
});
$('record-stop').onclick=()=>run(async()=>{await command('record_stop');stopRecordAudio();archiveActive=false;$('record-player').hidden=true;$('record-player').removeAttribute('src');await storageRefresh();});
async function archivePoll(){
  try{
    if(archiveActive){
      const r=await fetch('/recording/status');if(!r.ok)throw new Error('Archivio non disponibile');const p=await r.json();
      archivePaused=Boolean(p.paused);$('record-pause').textContent=archivePaused?'Riprendi':'Pausa';
      if(!p.audio.enabled && recordAudioAbort)stopRecordAudio();
      $('record-audio-status').textContent=p.audio.enabled?(p.audio.receiving?'Audio filmato ricevuto · mono 8 kHz':'Audio richiesto: in attesa dei dati'):'Audio filmato spento. L’export AVI resta senza audio.';
      $('record-status').textContent=`${p.message} · ${p.frames} fotogrammi${p.truncated?' · limite esportazione raggiunto':''}`;
      $('record-export').hidden=!p.frames;
      if(!p.filename){stopRecordAudio();archiveActive=false;$('record-player').hidden=true;$('record-player').removeAttribute('src');await stateRead();renderStorage(state);}
    }
  }catch(error){archiveActive=false;$('record-status').textContent=error.message;}
  setTimeout(archivePoll,2000);
}
$('record-date').value=new Date().toLocaleDateString('sv-SE');
archivePoll();
window.addEventListener('pagehide',()=>{
  if(!archiveActive || !state?.token)return;
  fetch('/api/action',{method:'POST',keepalive:true,headers:{'Content-Type':'application/json','X-Control-Token':state.token},body:JSON.stringify({action:'record_stop',data:{}})}).catch(()=>{});
});

$('event-settings').onsubmit=e=>{e.preventDefault();
  const data={sensitivity:Number($('event-sensitivity').value),duration:Number($('event-duration').value),interval:Number($('event-interval').value)};
  run(async()=>{const r=await command('record_motion_settings',data);if(r.state!=='confirmed')return;await storageRefresh();
    const a=state.storage.alarm,ok=a.pirsensitive===data.sensitivity && a.pirvideotime===data.duration && a.pirDelayTime===data.interval;
    notice(ok?'Parametri evento riletti e confermati.':'Parametri evento non confermati.',ok?'success':'error');});
};

$('record-pause').onclick=()=>run(async()=>{const r=await command('record_pause',{enabled:!archivePaused});if(r.state==='confirmed'){archivePaused=!archivePaused;$('record-pause').textContent=archivePaused?'Riprendi':'Pausa';}});
