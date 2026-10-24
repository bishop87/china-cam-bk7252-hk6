'use strict';
let recordAudioContext=null,recordAudioAbort=null,recordAudioNext=0;
const recordAudioSources=new Set();
function stopRecordAudio(){
  recordAudioAbort?.abort();recordAudioAbort=null;
  for(const s of recordAudioSources){try{s.stop();}catch(_){}}recordAudioSources.clear();
  recordAudioContext?.close().catch(()=>{});recordAudioContext=null;
  $('record-audio').textContent='Ascolta audio filmato';$('record-audio').setAttribute('aria-pressed','false');
}
async function recordAudioLoop(controller,context){
  let after=0;
  try{
    while(!controller.signal.aborted){
      const r=await fetch(`/recording.pcm?after=${after}`,{signal:controller.signal});if(!r.ok)throw new Error('Audio filmato non disponibile');
      after=Number(r.headers.get('X-Audio-Sequence'));const bytes=await r.arrayBuffer();
      if(controller.signal.aborted)break;if(!bytes.byteLength){await new Promise(resolve=>setTimeout(resolve,100));continue;}
      if(bytes.byteLength%2)throw new Error('Formato audio non valido');
      const b=context.createBuffer(1,bytes.byteLength/2,8000),v=new DataView(bytes),a=b.getChannelData(0);
      for(let i=0;i<a.length;i++)a[i]=v.getInt16(i*2,true)/32768;
      if(recordAudioNext-context.currentTime>.5)continue;
      recordAudioNext=Math.max(recordAudioNext,context.currentTime+.04);
      const source=context.createBufferSource();source.buffer=b;source.connect(context.destination);
      recordAudioSources.add(source);source.onended=()=>recordAudioSources.delete(source);source.start(recordAudioNext);recordAudioNext+=b.duration;
    }
  }catch(e){if(!controller.signal.aborted){stopRecordAudio();$('record-audio-status').textContent=e.message;command('record_audio',{enabled:false}).catch(()=>{});}}
}
$('record-audio').onclick=async()=>{
  if(busy)return;
  if(recordAudioAbort){stopRecordAudio();await run(()=>command('record_audio',{enabled:false}));return;}
  if(!archiveActive){notice('Avvia prima un filmato.');return;}
  const context=new AudioContext();recordAudioContext=context;
  try{
    await context.resume();
    await run(async()=>{const r=await command('record_audio',{enabled:true});if(r.state!=='confirmed')throw new Error('Audio non confermato');
      const controller=new AbortController();recordAudioAbort=controller;recordAudioNext=context.currentTime+.08;
      $('record-audio').textContent='Spegni audio filmato';$('record-audio').setAttribute('aria-pressed','true');recordAudioLoop(controller,context);});
  }finally{if(!recordAudioAbort)stopRecordAudio();}
};
window.addEventListener('pagehide',stopRecordAudio);
