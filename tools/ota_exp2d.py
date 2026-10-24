"""Install the pinned EXP2D RBL over the verified EXP2C image from a restricted local HTTP endpoint.

--inspect only reads ifconfig. --execute checks original flash samples and LAN
reachability, serves only the pinned RBL to the specified camera, invokes the
original http_ota command, captures reboot and verifies patch bytes/header.
Does not claim full payload readback, working video or absence of cloud traffic.
"""
import argparse
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import struct
import threading
import time
import urllib.request
import zlib

from uart_backup import Console, ANSI, PROMPT
from build_stock_patch import ROOT, PATCHES, sha, SOURCE_SHA256
VERSION = '2M.1220-LAN-EXP2D'
CLOCK_REGIONS = [(0x19b50,8),(0x584da,6),(0xca46e,45),(0x52e50,4),(0x5c384,4)]
from prepare_uart_recovery import BACKUP_SHA
from analyze_backup import decode_crc_region
from rbl import unpack, HEADER

RBL_SHA = 'ee9247a104c099221902ada9302effa8e5417b20687c47070a4789e2a9b24f87'
EXP2C_RBL_SHA = '59ef607b811d0502f47a364fa2626d830fdea02d64330fdfba96733fbc3c8a44'
EXP2C_PAYLOAD_SHA = '35b076f7023f4e39d4799fe5afe101cac2c2e57aac3fc4b76157f5aad4a56caa'
PAYLOAD_SHA = '7e6e71eeb8463159d8638b25d6f18ef9f4beb290d657dbefe91b08a3ff0161c4'
ENDPOINT = '/hk6-stock-lan-exp2d.rbl'
# Factory image's header is at the old 1 MiB app boundary. The installed
# bootloader getter (ARM 0x87D0) reads new app headers at partition length-96:
# 0x10000 + 0x110000 - 96 = 0x11FFA0.
ORIGINAL_HEADER_ADDR = 0x10ffa0
UPDATED_HEADER_ADDR = 0x11ffa0


def send_line(console, text):
    # Only callers in this tool generate commands; never accept a shell string.
    if '\n' in text or '\r' in text:
        raise ValueError('Embedded command separator')
    for byte in (text+'\r').encode('ascii'):
        if os.write(console.fd, bytes([byte])) != 1:
            raise OSError('Partial console write')
        time.sleep(.003)


def prompt_response(console, timeout=15):
    received = bytearray()
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        if select.select([console.fd], [], [], .2)[0]:
            data = os.read(console.fd, 8192)
            if not data:
                raise OSError('Serial disconnected')
            console.log.write(data)
            received.extend(data)
            if PROMPT.search(ANSI.sub(b'', received)):
                return ANSI.sub(b'', received).replace(b'\r', b'').decode('utf-8', 'replace')
    raise TimeoutError('No console prompt')


def logical_read(console, address, length):
    cache = {}
    def physical(pos, size):
        result = bytearray()
        for at in range(pos, pos+size):
            block = at//256*256
            if block not in cache:
                cache[block] = console.read_block(block)
            result.append(cache[block][at-block])
        return bytes(result)
    first, last = address//32, (address+length-1)//32
    raw = b''.join(physical(index*34, 34) for index in range(first, last+1))
    decoded, stats = decode_crc_region(raw)
    if stats['invalid'] or stats['erased']:
        raise ValueError('CRC error or erased logical flash read')
    offset = address % 32
    return decoded[offset:offset+length]


def header_info(data):
    fields = HEADER.unpack(data)
    if fields[0] != b'RBL\0' or fields[3].split(b'\0')[0] != b'app':
        raise ValueError('Unexpected installed header')
    if zlib.crc32(data[:92]) != fields[-1]:
        raise ValueError('Installed header CRC invalid')
    return dict(version=fields[4].split(b'\0')[0].decode('ascii'), algorithm=fields[1],
                raw_bytes=fields[8], payload_fnv1a=hex(fields[7]), header_crc_valid=True)


def make_handler(blob, host, camera, records, served):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def handle_file(self, body):
            if self.client_address[0] not in (host, camera) or self.path != ENDPOINT:
                self.send_error(404)
                return
            self.connection.settimeout(15)
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(blob)))
            self.send_header('Connection', 'close')
            self.end_headers()
            count = 0
            try:
                if body:
                    for start in range(0, len(blob), 65536):
                        part = blob[start:start+65536]
                        self.wfile.write(part)
                        count += len(part)
                records.append(dict(client=self.client_address[0], method=self.command, bytes=count))
                if body and self.client_address[0] == camera and count == len(blob):
                    served.set()
            except OSError as error:
                records.append(dict(client=self.client_address[0], bytes=count, error=str(error)))
        def do_GET(self): self.handle_file(True)
        def do_HEAD(self): self.handle_file(False)
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--inspect', action='store_true')
    mode.add_argument('--execute', action='store_true')
    mode.add_argument('--preflight', action='store_true', help='Read-only EXP2C and LAN checks, no OTA')
    parser.add_argument('--bind')
    parser.add_argument('--camera')
    parser.add_argument('--http-port', type=int, default=8088)
    args = parser.parse_args()
    out = ROOT/'analysis/uart/ota-exp2d'/time.strftime('%Y%m%d-%H%M%S')
    out.mkdir(parents=True, exist_ok=False)
    report = dict(ota_command_sent=False, patch_points_verified=False)
    if args.execute or args.preflight:
        for value in (args.bind, args.camera):
            ip = ipaddress.IPv4Address(value)
            if not ip.is_private or ip.is_loopback or ip.is_unspecified:
                raise ValueError('Explicit private LAN IPv4 required')
        if args.bind == args.camera:
            raise ValueError('Host and camera must differ')
        blob = (ROOT/'dist/hk6-stock-lan-exp2d/hk6-stock-lan-exp2d.rbl').read_bytes()
        decoded, meta = unpack(blob)
        if sha(blob) != RBL_SHA or sha(decoded) != PAYLOAD_SHA or meta['partition'] != 'app':
            raise ValueError('Pinned EXP2D artifact mismatch')
        previous_blob = (ROOT/'dist/hk6-stock-lan-exp2c/hk6-stock-lan-exp2c.rbl').read_bytes()
        previous, _ = unpack(previous_blob)
        if sha(previous_blob) != EXP2C_RBL_SHA or sha(previous) != EXP2C_PAYLOAD_SHA:
            raise ValueError('Pinned EXP2C source mismatch')
        validation = json.loads((ROOT/'dist/hk6-stock-lan-exp2d/validation.json').read_text())
        if not validation['passed'] or validation['payload_sha256'] != PAYLOAD_SHA:
            raise ValueError('EXP2D emulation validation mismatch')
        original = (ROOT/'analysis/backups/hk6-original/flash-2MiB.bin').read_bytes()
        if sha(original) != BACKUP_SHA:
            raise ValueError('Original rollback backup missing or changed')
        trial = json.loads((ROOT/'analysis/uart/write-trial/20261017-175159/report.json').read_text())
        if not trial['passed']:
            raise ValueError('Sector restore trial not passed')
        if not (ROOT/'tools/uart_restore_original.py').is_file():
            raise ValueError('UART restore tool missing')
    console = Console(args.port, out/'serial.rx.bin')
    server, thread = None, None
    records = []
    try:
        console.synchronize()
        send_line(console, 'ifconfig')
        config = prompt_response(console)
        (out/'ifconfig.txt').write_text(config)
        report['ip_addresses'] = re.findall(r'ip address:\s*([0-9.]+)', config)
        print(json.dumps({'ip_addresses': report['ip_addresses']}), flush=True)
        if args.inspect:
            return 0
        if args.camera not in report['ip_addresses']:
            raise ValueError('Camera IP does not match live ifconfig')
        original_app = (ROOT/'analysis/original/app-payload.bin').read_bytes()
        if sha(original_app) != SOURCE_SHA256:
            raise ValueError('Original payload reference mismatch')
        for patch in PATCHES:
            actual = logical_read(console, patch['address'], len(bytes.fromhex(patch['after'])))
            if actual != previous[patch['address']-0x10000:patch['address']-0x10000+len(actual)]:
                raise ValueError('Camera does not have EXP2C opcodes: '+patch['name'])
        for address, expected in [(0x72222, previous[0x62222:0x62226]),
                                  (0x584b0, previous[0x484b0:0x484b4]),
                                  (0xd9a44, previous[0xc9a44:])]:
            if logical_read(console, address, len(expected)) != expected:
                raise ValueError('Unexpected EXP2C transition site: '+hex(address))
        for address, length in CLOCK_REGIONS:
            if logical_read(console,address,length) != previous[address-0x10000:address-0x10000+length]:
                raise ValueError('Unexpected clock patch source: '+hex(address))
        before = logical_read(console, UPDATED_HEADER_ADDR, 96)
        if before != previous_blob[:96]:
            raise ValueError('Installed header is not the pinned EXP2C header')
        report['before_header'] = header_info(before)
        staging = console.read_block(0x132000)
        (out/'download-head-before.bin').write_bytes(staging)
        # Existing EXP2C download is superseded by the authorized OTA. Preserve evidence.
        report['download_head_sha256'] = sha(staging)
        send_line(console, 'ping '+args.bind)
        ping = prompt_response(console, 25)
        (out/'ping.txt').write_text(ping)
        if f'bytes from {args.bind} ' not in ping:
            raise ValueError('Camera cannot ping the HTTP host; no OTA started')
        if args.preflight:
            report['preflight_passed'] = True
            print('Read-only EXP2C/EXP2D preflight passed. No OTA sent.', flush=True)
            return 0
        served = threading.Event()
        server = http.server.ThreadingHTTPServer((args.bind, args.http_port),
                    make_handler(blob, args.bind, args.camera, records, served))
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f'http://{args.bind}:{args.http_port}{ENDPOINT}'
        # Bypass ambient proxy configuration; this request must remain local.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(urllib.request.Request(url, method='HEAD'), timeout=5) as response:
            if response.status != 200 or int(response.headers['Content-Length']) != len(blob):
                raise ValueError('Local HTTP endpoint check failed')
        report.update(url=url, rbl_sha256=sha(blob), preflight_passed=True)
        (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        console.synchronize()
        print('Preflight passed. Starting local HTTP OTA; keep camera powered.', flush=True)
        report['ota_command_sent'] = True
        (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        send_line(console, 'http_ota '+url)
        received = bytearray()
        end, next_status = time.monotonic()+180, time.monotonic()+20
        while time.monotonic() < end:
            if select.select([console.fd], [], [], .2)[0]:
                data = os.read(console.fd, 8192)
                if not data: raise OSError('Serial disconnected during OTA')
                console.log.write(data)
                received.extend(data)
                if served.is_set() and PROMPT.search(ANSI.sub(b'', received)):
                    break
            if time.monotonic() >= next_status:
                print(f'Waiting for application boot; HTTP transfer complete={served.is_set()}', flush=True)
                next_status = time.monotonic()+20
        else:
            raise TimeoutError('No application prompt within 180 seconds')
        report['http_transfer_completed'] = served.is_set()
        console.synchronize()
        after = logical_read(console, UPDATED_HEADER_ADDR, 96)
        report['installed_header_logical_address'] = hex(UPDATED_HEADER_ADDR)
        report['after_header'] = header_info(after)
        (out/'installed-header.bin').write_bytes(after)
        report['patch_points'] = []
        # Include unchanged EXP2C sites, all new instructions/pointers, and every appended byte.
        regions = [(p['address'], len(bytes.fromhex(p['after']))) for p in PATCHES]
        regions += [(0x72222,4),(0x584b0,4),(0xd9a44,len(decoded)-0xc9a44)]
        regions += CLOCK_REGIONS
        for address, length in regions:
            actual = logical_read(console,address,length)
            expected = decoded[address-0x10000:address-0x10000+length]
            report['patch_points'].append(dict(address=hex(address),bytes=length,
                 actual_sha256=sha(actual),expected_sha256=sha(expected),matches=actual==expected))
            (out/('readback-'+hex(address)+'.bin')).write_bytes(actual)
        report['patch_points_verified'] = all(p['matches'] for p in report['patch_points'])
        expected_fields = HEADER.unpack_from(blob)
        report['installed_metadata_matches'] = (
            after == blob[:96]
            and report['after_header']['version'] == VERSION
            and report['after_header']['algorithm'] == expected_fields[1]
            and report['after_header']['raw_bytes'] == len(decoded)
            and report['after_header']['payload_fnv1a'] == hex(expected_fields[7]))
        if not report['patch_points_verified'] or not report['installed_metadata_matches']:
            raise ValueError('Post-install verification failed; retain logs and use rollback if necessary')
        report['installed_verified_at_patch_points'] = True
        print('EXP2D header, patch sites and entire appended code verified from flash.', flush=True)
    except (Exception, KeyboardInterrupt) as error:
        report['error'] = f'{type(error).__name__}: {error}'
    finally:
        if server:
            server.shutdown()
            server.server_close()
        console.close()
        report['http_requests'] = records
        (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))
        print(out/'report.json')
    return 0 if report.get('installed_verified_at_patch_points') else 1


if __name__ == '__main__':
    raise SystemExit(main())
