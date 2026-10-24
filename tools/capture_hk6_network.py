#!/usr/bin/env python3
"""Interactive, read-only packet capture. Run with sudo from a local Terminal."""
import argparse
import select
import threading
import datetime
import json
import re
import os
from pathlib import Path
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
ANCHOR = 'com.apple/000.hk6-lab'
# Camera MAC supplied at runtime; captures remain private laboratory artifacts.


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def validate_guard(require_ntp=False):
    status = command('/sbin/pfctl', '-s', 'info')
    rules = command('/sbin/pfctl', '-a', ANCHOR, '-sr')
    root = command('/sbin/pfctl', '-sr')
    first = next(s for s in root.splitlines() if s.startswith(('anchor ', 'pass ', 'block ')))
    if 'Status: Enabled' not in status or first != 'anchor "com.apple/*" all':
        raise RuntimeError('PF/anchor principale cambiato: cattura annullata.')
    for label in ('HK6_block_ipv6', 'HK6_block_dns_proxy', 'HK6_block_nonlocal'):
        if not any('block drop in quick' in s and 'on bridge100 ' in s and label in s for s in rules.splitlines()):
            raise RuntimeError('Regole di isolamento mancanti: ' + label)
    if require_ntp:
        for label in ('HK6_allow_camera_dns', 'HK6_allow_camera_ntp'):
            if not any('pass in quick on bridge100 ' in line and label in line and 'from 192.168.2.3 ' in line for line in rules.splitlines()):
                raise RuntimeError('Eccezione DNS/NTP mancante: ' + label)
    table = command('/sbin/pfctl', '-a', ANCHOR, '-t', 'hk6_local_v4', '-T', 'show')
    entries = {s.strip() for s in table.splitlines() if s.strip() and s.strip()[0].isdigit()}
    if entries != {'192.168.2.0/24', '255.255.255.255'}:
        raise RuntimeError('Destinazioni locali cambiate.')
    if 'inet 192.168.2.1 netmask 0xffffff00' not in command('/sbin/ifconfig', 'bridge100'):
        raise RuntimeError('Rete HK6-LAB cambiata.')
    return status + '\n' + root + '\n' + rules + '\n' + table


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--camera-mac', required=True, help='MAC address of the camera under test')
    parser.add_argument('--uart', help='Optional UART device, passive logging only; close Screen first')
    parser.add_argument('--require-ntp', action='store_true', help='Require existing camera DNS/NTP firewall exceptions')
    args = parser.parse_args()
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', args.camera_mac):
        parser.error('Invalid camera MAC address')
    capture_filter = f'ether host {args.camera_mac} or (udp and (port 67 or port 68))'
    if os.geteuid() != 0:
        raise SystemExit('Eseguire: sudo python3 tools/capture_hk6_network.py')
    os.umask(0o077)
    initial = validate_guard(args.require_ntp)
    input('Chiudi completamente HDWifiCamPro e spegni la camera. Lascia il telefono su HK6-LAB senza dati mobili. Premi Invio quando pronto: ')
    initial = validate_guard(args.require_ntp)
    out = ROOT/'analysis/network/hk6-lab'/datetime.datetime.now().strftime('capture-%Y%m%d-%H%M%S')
    out.mkdir()
    (out/'guard-before.txt').write_text(initial + '\n' + command('/sbin/pfctl', '-a', ANCHOR, '-vvsr'))
    events = []
    proc = None
    result = 'interrupted'
    uart = None
    uart_thread = None
    uart_stop = threading.Event()
    uart_errors = []
    def record_uart():
        try:
            with (out/'uart-chunks.jsonl').open('w') as timing:
                offset = 0
                while not uart_stop.is_set():
                    if not select.select([uart.fd], [], [], .2)[0]:
                        continue
                    data = os.read(uart.fd, 8192)
                    if not data:
                        raise OSError('UART disconnected')
                    uart.log.write(data)
                    timing.write(json.dumps({'unix_time':time.time(),'offset':offset,'bytes':len(data)})+'\n')
                    timing.flush()
                    offset += len(data)
        except Exception as error:
            uart_errors.append(str(error))

    def mark(event):
        events.append({'event': event, 'unix_time': time.time(), 'local_time': datetime.datetime.now().astimezone().isoformat()})
        (out/'phases.json').write_text(json.dumps(events, indent=2)+'\n')
    def observe(name, seconds):
        mark(name + '_start')
        for remaining in range(seconds, 0, -1):
            if uart_errors:
                raise RuntimeError('Errore UART: ' + uart_errors[0])
            if proc.poll() is not None:
                raise RuntimeError('tcpdump terminato: vedere tcpdump.log')
            if remaining % 30 == 0:
                print(f'{name}: {remaining} secondi rimanenti', flush=True)
            time.sleep(1)
        validate_guard(args.require_ntp)
        mark(name + '_end')
    try:
        if args.uart:
            from uart_backup import Console
            uart = Console(args.uart, out/'uart.rx.bin')
            uart_thread = threading.Thread(target=record_uart, daemon=True)
            uart_thread.start()
            mark('uart_passive_ready')
        with (out/'tcpdump.log').open('wb') as log:
            proc = subprocess.Popen(['/usr/sbin/tcpdump', '-i', 'bridge100', '-nn', '-U', '-s', '512', '-w', str(out/'camera.pcap'), capture_filter], stdout=subprocess.DEVNULL, stderr=log)
            for _ in range(50):
                if proc.poll() is not None:
                    raise RuntimeError('tcpdump non avviato: vedere tcpdump.log')
                if 'listening on' in (out/'tcpdump.log').read_text(errors='replace'):
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('Avvio tcpdump non confermato.')
            mark('capture_ready')
            print('Cattura attiva. Ora accendi la camera, senza aprire l’app.', flush=True)
            input('Premi Invio subito dopo averla accesa: ')
            observe('boot_app_closed', 120)
            input('Ora apri HDWifiCamPro e il video. Premi Invio quando il video è visibile (o dopo un tentativo fallito): ')
            mark('video_attempt_user_ready')
            observe('video', 120)
            input('Chiudi completamente l’app e premi Invio: ')
            observe('app_closed_again', 60)
            result = 'completed'
    except KeyboardInterrupt:
        print('\nInterruzione: conservo la cattura parziale.', flush=True)
    finally:
        uart_stop.set()
        if uart_thread is not None:
            uart_thread.join(timeout=2)
        if uart is not None:
            uart.close()
        if proc is not None and proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        mark('capture_stopped')
        try:
            (out/'guard-after.txt').write_text(command('/sbin/pfctl', '-a', ANCHOR, '-vvsr'))
        finally:
            (out/'summary.json').write_text(json.dumps({'result': result, 'uart_device': args.uart, 'uart_errors': uart_errors, 'ntp_exceptions_required': args.require_ntp, 'filter': capture_filter, 'snaplen': 512, 'camera_mac': args.camera_mac, 'last_observed_camera_ip': '192.168.2.3', 'interface': 'bridge100', 'scope': 'Camera Ethernet traffic plus DHCP; video payload truncated; other phone traffic excluded; firewall unchanged; inspect guard-before.txt for active DNS/NTP exceptions'}, indent=2)+'\n')
            uid = int(os.environ.get('SUDO_UID', os.getuid()))
            gid = int(os.environ.get('SUDO_GID', os.getgid()))
            for p in out.iterdir():
                os.chown(p, uid, gid)
            os.chown(out, uid, gid)
        print('File salvati in: ' + str(out), flush=True)
        print('Il blocco HK6 resta attivo. Nessuna regola modificata.', flush=True)

if __name__ == '__main__':
    main()
