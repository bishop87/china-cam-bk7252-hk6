'use strict';
// Only the camera microphone is used. No browser microphone permission.
let audioContext = null, audioAbort = null, audioNext = 0, audioStarting = false;
const audioSources = new Set();
function stopListening() {
  if(audioAbort) audioAbort.abort();
  audioAbort = null;
  for(const source of audioSources) {try{source.stop();}catch(_){} }
  audioSources.clear();
  if(audioContext) {audioContext.close().catch(()=>{});audioContext=null;}
  $('audio-toggle').setAttribute('aria-checked','false');
  $('audio-toggle').textContent='Attiva audio';
}
function renderAudio(info) {
  if(!info)return;
  if(state)state.audio=info;
  if(!info.enabled && audioAbort && !audioStarting)stopListening();
  $('audio-status').textContent=info.error || (!info.enabled?'Audio spento':
    info.receiving?(audioAbort?'In ascolto · mono 8 kHz':'Audio attivo in un’altra scheda'):
    'Audio richiesto: in attesa dei dati dalla camera.');
}
async function receiveAudio(controller, context) {
  let after=0;
  try {
    while(!controller.signal.aborted) {
      const response=await fetch(`/audio.pcm?after=${after}`,{signal:controller.signal});
      if(!response.ok)throw new Error('Flusso audio non disponibile');
      after=Number(response.headers.get('X-Audio-Sequence'));
      const bytes=await response.arrayBuffer();
      if(controller.signal.aborted)break;
      if(!bytes.byteLength){await new Promise(resolve=>setTimeout(resolve,100));continue;}
      if(bytes.byteLength%2)throw new Error('Formato audio non valido');
      const view=new DataView(bytes), buffer=context.createBuffer(1,bytes.byteLength/2,8000);
      const samples=buffer.getChannelData(0);
      for(let i=0;i<samples.length;i++)samples[i]=view.getInt16(i*2,true)/32768;
      // Drop old backlog rather than increasing listening latency indefinitely.
      if(audioNext-context.currentTime>.5)continue;
      audioNext=Math.max(audioNext,context.currentTime+.04);
      const source=context.createBufferSource();source.buffer=buffer;source.connect(context.destination);
      audioSources.add(source);source.onended=()=>audioSources.delete(source);
      source.start(audioNext);audioNext+=buffer.duration;
    }
  } catch(error) {
    if(!controller.signal.aborted) {
      stopListening();$('audio-status').textContent=error.message;
      // The bridge also disables audio when its listener lease expires.
      command('audio',{enabled:false}).catch(()=>{});
    }
  }
}
$('audio-toggle').onclick=async()=>{
  if(busy && audioAbort){stopListening();notice('Ascolto fermato. La camera spegnerà il flusso entro 8 secondi senza un ascoltatore.');return;}
  if(busy || audioStarting)return;
  if(audioAbort || state?.audio?.enabled) {
    stopListening();
    await run(async()=>{const result=await command('audio',{enabled:false});await stateRead();
      if(result.state!=='sent')notice('Ascolto fermato sul Mac; spegnimento sulla camera non confermato.','error');});
    return;
  }
  audioStarting=true;
  try {
    // Resume synchronously from the user's click to satisfy autoplay policy.
    const context=new AudioContext();audioContext=context;
    await context.resume();
    await run(async()=>{
      const result=await command('audio',{enabled:true});
      if(result.state!=='sent')throw new Error('Attivazione audio non confermata');
      const controller=new AbortController();audioAbort=controller;audioNext=context.currentTime+.08;
      $('audio-toggle').setAttribute('aria-checked','true');$('audio-toggle').textContent='Spegni audio';
      receiveAudio(controller,context);await stateRead();
    });
    if(!audioAbort)stopListening();
  } catch(error){stopListening();notice(error.message,'error');}
  finally{audioStarting=false;}
};
window.addEventListener('pagehide',()=>{
  if(!audioAbort)return;
  stopListening();
  if(state?.token)fetch('/api/action',{method:'POST',keepalive:true,
    headers:{'Content-Type':'application/json','X-Control-Token':state.token},
    body:JSON.stringify({action:'audio',data:{enabled:false}})}).catch(()=>{});
});
