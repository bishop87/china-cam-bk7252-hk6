"""Validated native HK6 microSD commands. No arbitrary paths or destructive fallback."""
import datetime
import re
import threading
import time
from avi import export_avi
from audio_stream import AudioBuffer

READS = {'sd': ('get_sd',109), 'alarm': ('get_alarm',107),
         'record_days': ('get_record_day',205), 'record_hours': ('get_record_hour',401),
         'record_files': ('get_record_min',402)}
SD_KEYS = {'total','free','sdstatu','recMode','isShowCapacity'}
ALARM_KEYS = {'pirenable','pirvideo','pirvideotime','pirsensitive','pirDelayTime','pirPush'}

class Storage:
    def __init__(self):
        self.sd = {}
        self.alarm = {}
        self.days = {}
        self.hours = {}
        self.files = []
        self.playing = None
        self.paused = False
        self.pause_started = self.pause_total = 0
        self.audio = AudioBuffer()
        self.condition = threading.Condition()
        self.frame = None
        self.count = 0
        self.frames = []
        self.bytes = 0
        self.started = self.updated = self.lease = 0
        self.truncated = False
        self.message = ''

    def snapshot(self):
        return dict(sd=self.sd.copy(),alarm=self.alarm.copy(),days=self.days.copy(),
                    hours=self.hours.copy(),files=self.files[:],playing=self.playing,
                    delete_supported=False,download_supported=False, playback=self.playback_status())

    def prepare(self, action, data):
        if action in ('sd','alarm'):
            if data:raise ValueError('La lettura non accetta parametri')
            return (*READS[action],{})
        if action == 'record_days':
            if set(data)!={'year'} or type(data['year']) is not int or not 2000<=data['year']<=2099:
                raise ValueError('Anno non valido')
            return (*READS[action],data.copy())
        if action in ('record_hours','record_files'):
            key,fmt=('ymd','%Y%m%d') if action=='record_hours' else ('ymdh','%Y%m%d%H')
            if set(data)!={key} or not isinstance(data[key],str) or len(data[key])!=len(datetime.datetime.now().strftime(fmt)) or not data[key].isdigit():
                raise ValueError('Data non valida')
            try:datetime.datetime.strptime(data[key],fmt)
            except ValueError:raise ValueError('Data non valida') from None
            date=datetime.datetime.strptime(data[key],fmt)
            return (*READS[action],{key:date.strftime('%Y_%m_%d' if key=='ymd' else '%Y_%m_%d_%H')})
        if action=='record_stop':
            if data:raise ValueError('Stop non accetta parametri')
            return 'play_record_file',207,{'type':0}
        if action in ('record_pause','record_audio'):
            if not self.playing:raise ValueError('Avvia prima un filmato')
            if set(data)!={'enabled'} or type(data['enabled']) is not bool:raise ValueError('Specificare enabled booleano')
            key='suspend' if action=='record_pause' else 'audio'
            return 'play_record_file',207,{key:int(data['enabled'])}
        if self.playing and action in ('record_play','record_continuous','record_motion','record_motion_settings'):
            raise ValueError('Ferma prima la riproduzione in corso')
        if self.sd.get('sdstatu')!=1:
            raise ValueError('MicroSD non disponibile: aggiorna lo stato')
        if action=='record_continuous':
            if set(data)!={'enabled'} or type(data['enabled']) is not bool:raise ValueError('Modalità non valida')
            return 'set_sd',110,{'recMode':int(data['enabled'])}
        if action=='record_motion':
            if set(data)!={'enabled'} or type(data['enabled']) is not bool:raise ValueError('Modalità non valida')
            return 'set_alarm',108,{'pirenable':int(data['enabled']),'pirvideo':int(data['enabled'])}
        if action=='record_motion_settings':
            if set(data)!={'sensitivity','duration','interval'} or any(type(v) is not int for v in data.values()):
                raise ValueError('Parametri evento non validi')
            if data['sensitivity'] not in (1,2,3) or not 10<=data['duration']<=60 or not 30<=data['interval']<=240:
                raise ValueError('Sensibilità 1–3, durata 10–60 s, intervallo 30–240 s')
            return 'set_alarm',108,{'pirsensitive':data['sensitivity'],'pirvideotime':data['duration'],'pirDelayTime':data['interval']}
        if action=='record_play':
            if self.sd.get('recMode')!=0 or self.alarm.get('pirvideo')!=0:
                raise ValueError('Per riprodurre, aggiorna microSD e imposta la registrazione su Spenta: il firmware non ha memoria sufficiente per registrare e riprodurre insieme')
            if set(data)!={'filename'} or data['filename'] not in self.files:raise ValueError('Seleziona un filmato dall’elenco aggiornato')
            return 'play_record_file',207,{'filename':data['filename'],'type':1}
        raise ValueError('Operazione microSD non supportata dal firmware verificato')

    def reply(self, action, value, fields):
        if action in ('sd','alarm'):
            keys=SD_KEYS if action=='sd' else ALARM_KEYS
            public={k:v for k,v in value.items() if k in keys and type(v) is int}
            setattr(self,action,public)
            return public
        if action in ('record_days','record_hours'):
            prefix='month' if action=='record_days' else 'hour'
            public={k:v for k,v in value.items() if (re.fullmatch(prefix+r'\[\d{1,2}\]',k) or k=='record_hour') and type(v) in (int,str)}
            setattr(self,'days' if action=='record_days' else 'hours',public)
            return public
        if action=='record_files':
            count=value.get('record_num',0)
            if type(count) is not int or not 0<=count<=1000:raise ValueError('Elenco registrazioni non valido')
            files=[]
            for i in range(count):
                name=value.get(f'record_name[{i}]')
                if isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,63}',name) and '..' not in name:
                    files.append(name)
            self.files=files
            return {'files':files}
        if action=='record_pause':
            now=time.monotonic();paused=bool(fields['suspend'])
            if paused and not self.paused:self.pause_started=now
            if not paused and self.paused:self.pause_total+=now-self.pause_started
            self.paused=paused;self.updated=now
            self.message='Pausa richiesta alla camera' if self.paused else 'Ripresa richiesta alla camera'
        if action=='record_audio':self.audio.enable(bool(fields['audio']))
        if action=='record_play':self.start(fields['filename'])
        if action=='record_stop':self.stop('Stop accettato dalla camera. Aggiorna lo stato della registrazione.')
        return {}

    def start(self, filename):
        with self.condition:
            self.playing=filename
            self.paused=False;self.pause_started=self.pause_total=0;self.audio.enable(False)
            self.frame=None;self.frames=[];self.bytes=0;self.truncated=False
            self.started=self.lease=time.monotonic();self.updated=0
            self.message='In attesa del filmato'
            self.condition.notify_all()

    def stop(self, message):
        with self.condition:
            self.playing=None;self.message=message
            self.paused=False;self.audio.enable(False)
            self.condition.notify_all()

    def publish(self, frame):
        with self.condition:
            if not self.playing or self.paused:return
            self.frame=frame;self.count+=1;self.updated=time.monotonic()
            self.message='Riproduzione dalla microSD'
            if self.bytes+len(frame)<=32*1024*1024 and len(self.frames)<1800:
                self.frames.append((self.updated-self.pause_total,frame));self.bytes+=len(frame)
            else:self.truncated=True
            self.condition.notify_all()

    def playback_status(self, heartbeat=False):
        with self.condition:
            if heartbeat:self.lease=time.monotonic()
            return dict(filename=self.playing,paused=self.paused,audio=self.audio.snapshot(),frames=len(self.frames),truncated=self.truncated,
                        age_seconds=time.monotonic()-self.updated if self.updated else None,message=self.message)

    def avi(self):
        with self.condition:frames=self.frames[:]
        if not frames:raise ValueError('Riproduci prima un filmato')
        fps=(len(frames)-1)/(frames[-1][0]-frames[0][0]) if len(frames)>1 and frames[-1][0]>frames[0][0] else 10
        return export_avi([f for _,f in frames],max(1,min(30,fps)))
