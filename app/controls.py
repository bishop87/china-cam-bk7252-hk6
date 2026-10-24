"""Validated commands, one in-flight operation, no command replay across sessions."""
import ipaddress
import secrets
import threading
import time
from urllib.parse import quote_plus
from audio_stream import AudioBuffer
from storage import Storage, READS as STORAGE_READS

VIDEO_PROFILES = {
    1: {'label': '640 × 480 · VGA', 'dimensions': [640, 480]},
    2: {'label': '320 × 240 · QVGA', 'dimensions': [320, 240]},
}

READS = {'parameters': ('get_parms', 101), 'wifi': ('get_wifi', 112), 'scan': ('scan_wifi', 113)}
READS.update(STORAGE_READS)
PARAMS = {'tz', 'time', 'icut', 'batValue', 'batStatus', 'sysver', 'mcuver',
          'isShow4KMenu', 'isShowIcutAuto', 'rotmir', 'signal', 'lamp'}
LIMITS = {'rotmir': {0, 1, 2, 3}, 'icut': {0, 1}, 'lamp': {0, 1}}


def private_ip(value):
    try:
        ip = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise ValueError('Indirizzo IPv4 non valido') from None
    if not any(ip in ipaddress.IPv4Network(net) for net in
               ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
        raise ValueError('Usare un indirizzo IPv4 della rete privata')
    return str(ip)


def form_encode(value):
    # Java URLEncoder: alnum, '.', '-', '*', '_' are safe; spaces become '+'.
    return quote_plus(value, safe='*').replace('~', '%7E')


class BusyError(Exception):
    pass


class Controls:
    def __init__(self, host):
        self.host = host
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.RLock()
        self.active = None
        self.online = False
        self.restart = False
        self.video_mode = 1
        self.playback_video_mode = None
        self.live_dimensions = None
        self.audio = AudioBuffer()
        self.storage = Storage()
        self.parameters = {}
        self.wifi = {}
        self.networks = []
        self.updated = {}

    def snapshot(self):
        with self.lock:
            return dict(camera=self.host, online=self.online, video_mode=self.video_mode,
                        audio=self.audio.snapshot(), storage=self.storage.snapshot(),
                        profiles=[dict(mode=mode, **profile) for mode, profile in VIDEO_PROFILES.items()],
                        requested_dimensions=VIDEO_PROFILES[self.video_mode]['dimensions'],
                        parameters=self.parameters.copy(), wifi=self.wifi.copy(),
                        networks=[n.copy() for n in self.networks], updated=self.updated.copy(),
                        busy=self.active is not None, token=self.token)

    def connected(self):
        with self.lock:
            self.online = True

    def disconnected(self):
        with self.lock:
            self.online = False
            self.audio.enable(False)
            self.live_dimensions = None
            self.storage.stop('Connessione interrotta: esito del ripristino registrazione da verificare.')
            self.storage.sd = {}
            self.storage.files = []
            # A failing experimental stream must not trap every reconnection.
            self.video_mode = self.playback_video_mode or 1
            self.playback_video_mode = None
            if self.active:
                sent = self.active['index'] is not None
                self.finish('unknown' if sent else 'unavailable',
                            'Connessione interrotta. Esito non verificato; rileggere le impostazioni.'
                            if sent else 'Camera non disponibile. Comando non inviato.')

    def finish(self, state, message, data=None):
        job = self.active
        job['result'] = dict(state=state, message=message, data=data or {})
        job['fields'].clear()  # Wi-Fi password is not retained in history/cache.
        self.active = None
        job['done'].set()

    def prepare(self, action, data):
        if not isinstance(data, dict):
            raise ValueError('Parametri non validi')
        if action in ('clock_sync','reboot'):
            if data:raise ValueError('L’operazione non accetta parametri')
            if self.storage.playing:raise ValueError('Ferma prima la riproduzione')
            if action=='reboot':return 'dev_control',102,{'reboot':1}
            from datetime import datetime
            from zoneinfo import ZoneInfo
            now=int(time.time())
            if not 946684800<=now<=2147476447:raise ValueError('Ora del Mac fuori intervallo firmware')
            offset=int(datetime.fromtimestamp(now,ZoneInfo('Europe/Rome')).utcoffset().total_seconds())
            return 'set_datetime',126,{'time':now,'tz':-offset}
        if action in STORAGE_READS or action.startswith('record_'):
            return self.storage.prepare(action,data)
        if action in READS:
            if data:
                raise ValueError('La lettura non accetta parametri')
            return (*READS[action], {})
        if action == 'video':
            if self.storage.playing or self.playback_video_mode is not None:
                raise ValueError('Ferma prima la riproduzione del filmato')
            if set(data) != {'mode'} or type(data['mode']) is not int or data['mode'] not in VIDEO_PROFILES:
                raise ValueError('Profilo video non valido')
            return 'stream', 111, {'video': data['mode']}
        if action == 'audio':
            if self.storage.playing and data.get('enabled'):raise ValueError('Usa il controllo audio del filmato durante il playback')
            if set(data) != {'enabled'} or type(data['enabled']) is not bool:
                raise ValueError('Specificare audio attivo o disattivo')
            return 'stream', 111, {'audio': int(data['enabled'])}
        if action == 'image':
            if set(data) != {'field', 'value'}:
                raise ValueError('Impostazione immagine non valida')
            field, value = data['field'], data['value']
            if not isinstance(field, str) or field not in LIMITS or field not in self.parameters:
                raise ValueError('Impostazione non esposta dalla camera; aggiornare i parametri')
            allowed = LIMITS[field] | ({2} if field == 'icut' and self.parameters.get('isShowIcutAuto') == 1 else set())
            if type(value) is not int or value not in allowed:
                raise ValueError('Valore non valido')
            return 'dev_control', 102, {field: value}
        if action == 'set_wifi':
            if set(data) != {'ssid', 'password'}:
                raise ValueError('Specificare rete e password')
            ssid, password = data['ssid'], data['password']
            if not isinstance(ssid, str) or not 1 <= len(ssid.encode()) <= 32 or '\0' in ssid:
                raise ValueError('SSID non valido (massimo 32 byte)')
            network = next((n for n in self.networks if n['ssid'] == ssid), None)
            if network is None or time.monotonic() - self.updated.get('scan', 0) > 180:
                raise ValueError('Ripetere la ricerca e scegliere una rete rilevata negli ultimi 3 minuti')
            if not isinstance(password, str) or '\0' in password or len(password.encode()) > 63:
                raise ValueError('Password Wi-Fi non valida (massimo 63 byte)')
            if network['encryption'] != 0 and len(password.encode()) < 8:
                raise ValueError('Per la rete protetta servono almeno 8 byte di password')
            return 'set_wifi', 114, dict(wifissid=ssid, wifipwd=password,
                encwifissid=form_encode(ssid), encwifipwd=form_encode(password),
                encryption=network['encryption'])
        raise ValueError('Operazione non supportata')

    def request(self, action, data, timeout=12):
        with self.lock:
            if self.active:
                if action in READS and not data and self.active['action'] == action:
                    job = self.active  # Multiple tabs share the same read operation.
                else:
                    raise BusyError('Un comando è già in corso; attendere il risultato')
            else:
                if action == 'target':
                    if set(data) != {'ip'}:
                        raise ValueError('Specificare il nuovo IP della camera')
                    self.host = private_ip(data['ip'])
                    self.restart = True
                    self.online = False
                    self.video_mode = 1
                    self.parameters, self.wifi, self.networks, self.updated = {}, {}, [], {}
                    self.storage = Storage()
                    return dict(state='sent', message='Indirizzo locale aggiornato. Connessione in corso.')
                if not self.online or self.restart:
                    raise BusyError('Camera non connessa; attendere la riconnessione')
                pro, cmd, fields = self.prepare(action, data)
                job = dict(action=action, pro=pro, cmd=cmd, response_cmd=128 if action=='clock_sync' else cmd, fields=fields, index=None,
                           done=threading.Event(), result=None, deadline=time.monotonic()+timeout-1)
                self.active = job
        if not job['done'].wait(timeout):
            with self.lock:
                if self.active is job:
                    self.online = False
                    self.restart = True
                    self.finish('unknown', 'Nessuna conferma. Rileggere le impostazioni prima di riprovare.')
        return job['result']

    def retry_read(self, index):
        with self.lock:
            return bool(self.active and self.active['index'] == index and self.active['action'] in READS)

    def tick(self, camera):
        with self.lock:
            if self.audio.enabled and time.monotonic() - self.audio.lease > 8:
                self.audio.enable(False)
                camera.send_command('stream', 111, {'audio': 0})
            if self.restart:
                self.restart = False
                raise ConnectionError('Nuova connessione richiesta')
            storage = self.storage
            if self.playback_video_mode is not None and not storage.playing and not self.active:
                self.video_mode = self.playback_video_mode
                camera.send_command('stream',111,{'video':self.video_mode})
                self.playback_video_mode = None
            if storage.playing and not self.active and (time.monotonic()-storage.lease>8 or
                    (not storage.paused and time.monotonic()-storage.started>15 and (not storage.updated or time.monotonic()-storage.updated>4))):
                self.active=dict(action='record_stop',pro='play_record_file',cmd=207,fields={'type':0},
                    index=None,done=threading.Event(),result=None,deadline=time.monotonic()+10)
            if storage.audio.enabled and time.monotonic()-storage.audio.lease>8 and not self.active:
                self.active=dict(action='record_audio',pro='play_record_file',cmd=207,fields={'audio':0},index=None,done=threading.Event(),result=None,deadline=time.monotonic()+10)
            if self.active:
                job = self.active
                if time.monotonic() > job['deadline']:
                    self.online = False
                    self.finish('unknown', 'Nessuna conferma dalla camera. Esito non verificato.')
                    # Discard late replies before accepting a new operation with the same cmd.
                    raise ConnectionError('Timeout comando: ricreo la sessione')
                if job['index'] is None:
                    if job['action']=='record_play':
                        if self.playback_video_mode is None:
                            self.playback_video_mode = self.video_mode
                            self.video_mode = 2
                            camera.send_command('stream',111,{'video':2})
                            self.live_dimensions = None
                            job['playback_ready'] = time.monotonic()+1
                            return
                        if time.monotonic()<job.get('playback_ready',0) or self.live_dimensions != [320,240]:return
                    job['index'] = camera.send_command(job['pro'], job['cmd'], job['fields'])

    def acknowledged(self, index):
        with self.lock:
            if self.active and self.active['index'] == index and self.active['action'] == 'audio':
                self.audio.enable(bool(self.active['fields']['audio']))
                self.finish('sent', 'Comando audio ricevuto; verifica la ricezione del flusso.')
            if self.active and self.active['index'] == index and self.active['action'] == 'video':
                self.video_mode = self.active['fields']['video']
                width, height = VIDEO_PROFILES[self.video_mode]['dimensions']
                self.finish('sent', f'Richiesti {width} × {height} px. Verifica sotto il video la risoluzione ricevuta.')

    def reply(self, value):
        with self.lock:
            if not self.active or value.get('cmd') != self.active.get('response_cmd',self.active['cmd']):
                return
            if value.get('result') != 0:
                if self.active['action']=='sd':
                    self.storage.sd = {};self.storage.files = []
                self.finish('rejected', 'La camera non ha confermato il comando.')
                return
            action = self.active['action']
            if action == 'audio':
                self.audio.enable(bool(self.active['fields']['audio']))
                self.finish('sent', 'Comando audio accettato; verifica la ricezione del flusso.')
                return
            public = {}
            if action in STORAGE_READS or action.startswith('record_'):
                try:
                    public = self.storage.reply(action,value,self.active['fields'])
                except ValueError as exc:
                    self.finish('rejected',str(exc));return
            elif action == 'parameters':
                public = {k: v for k, v in value.items() if k in PARAMS and type(v) in (int, str)}
                self.parameters = public
            elif action == 'wifi':
                public = {k: value[k] for k in ('ssid', 'conmode') if k in value and type(value[k]) in (str, int)}
                self.wifi = public
            elif action == 'scan':
                count = value.get('count', 0)
                if type(count) is not int or not 0 <= count <= 100:
                    self.finish('rejected', 'Elenco reti non valido')
                    return
                networks = []
                for i in range(count):
                    ssid, enc, signal = (value.get(f'{key}[{i}]') for key in ('ssid', 'encryption', 'signal'))
                    if isinstance(ssid, str) and type(enc) is int and type(signal) is int:
                        networks.append(dict(ssid=ssid, encryption=enc, signal=signal))
                self.networks = networks
                public = {'networks': networks}
            self.updated[action] = time.monotonic()
            self.finish('confirmed', 'Risposta positiva della camera.' if action not in READS else 'Dati aggiornati.', public)
