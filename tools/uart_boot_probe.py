"""Probe HK6 Beken UART boot protocol with link/flash reads only.

Optionally reboots the running msh firmware to catch the loader. Never erases,
writes flash, changes flash protection, changes baud rate or writes registers.
Protocol reference: tiancj/hid_download_py, commit 5d305a19964593f223f0c20fc7f59e758f40ee66.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import time

from uart_backup import Console

ROOT = Path(__file__).resolve().parents[1]
LINK = bytes.fromhex('01e0fc0100')
VERSION = bytes.fromhex('01e0fc0111')
MID = bytes.fromhex('01e0fcfff405000e9f000000')
REBOOT = bytes.fromhex('01e0fc020ea5')
ACK = bytes.fromhex('040e0501e0fc0100')
# The installed HK6 stage-one loader rejects reads below 0x2000 (0x0BBC).
ADDRESSES = (0x2000, 0x11000, 0x132000)


def read_command(address):
    if address not in ADDRESSES:
        raise ValueError('Read address outside probe allowlist')
    return bytes.fromhex('01e0fcfff4050009')+struct.pack('<I', address)


def extract_frame(buffer):
    while buffer:
        at = buffer.find(b'\x04\x0e')
        if at < 0:
            # Preserve a potential partial prefix.
            buffer[:] = buffer[-1:] if buffer[-1:] == b'\x04' else b''
            return None
        del buffer[:at]
        if len(buffer) < 7:
            return None
        if buffer[3:6] != bytes.fromhex('01e0fc'):
            del buffer[0]
            continue
        if buffer[2] == 255:
            if len(buffer) < 10:
                return None
            if buffer[6] != 0xf4:
                del buffer[0]
                continue
            size = 9+int.from_bytes(buffer[7:9], 'little')
            # Known off-by-one MID response length in some loaders.
            if buffer[9] == 0x0e:
                size = max(size, 15)
        else:
            size = 3+buffer[2]
        if not 7 <= size <= 8192:
            del buffer[0]
            continue
        if len(buffer) < size:
            return None
        frame = bytes(buffer[:size])
        del buffer[:size]
        return frame
    return None


class Probe:
    def __init__(self, console, journal):
        self.console, self.journal = console, journal
        self.buffer = bytearray()

    def send(self, data):
        allowed = (LINK, VERSION, MID, REBOOT, b'reboot\r') + tuple(map(read_command, ADDRESSES))
        if data not in allowed:
            raise ValueError('Command not allowed in read-only boot probe')
        self.journal.write(json.dumps({'tx_hex': data.hex(), 'monotonic': time.monotonic()})+'\n')
        self.journal.flush()
        if os.write(self.console.fd, data) != len(data):
            raise OSError('Partial serial write')

    def receive(self, seconds):
        deadline = time.monotonic()+seconds
        while time.monotonic() < deadline:
            frame = extract_frame(self.buffer)
            if frame is not None:
                return frame
            if select.select([self.console.fd], [], [], min(.02, max(0,deadline-time.monotonic())))[0]:
                data = os.read(self.console.fd, 8192)
                if not data:
                    raise OSError('Serial disconnected')
                self.console.log.write(data)
                self.buffer.extend(data)
        return None

    def request(self, command, seconds=2):
        self.send(command)
        deadline = time.monotonic()+seconds
        while time.monotonic() < deadline:
            result = self.receive(max(0, deadline-time.monotonic()))
            if result is None:
                break
            self.journal.write(json.dumps({'rx_header_hex': result[:15].hex(), 'rx_bytes': len(result)})+'\n')
            self.journal.flush()
            # A repeated link ACK may arrive after the handshake. Only accept
            # the requested command's reply, never mislabel stale packets.
            if command[3:5] == b'\xff\xf4':
                if len(result) >= 10 and result[2] == 255 and result[9] == command[7]:
                    return result
            elif result[2] != 255 and result[6] == command[4]:
                return result
        raise TimeoutError('No response to '+command.hex())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--reboot-from-console', action='store_true')
    mode.add_argument('--wait-reset', action='store_true')
    parser.add_argument('--link-interval', type=float, default=.003,
                        help='Seconds between link probes (0.003..0.1)')
    args = parser.parse_args()
    if not .003 <= args.link_interval <= .1:
        parser.error('--link-interval must be between 0.003 and 0.1')
    out = ROOT/'analysis/uart/recovery-check'
    out.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    report_path = out/f'boot-probe-{stamp}.json'
    report = dict(handshake=False, flash_writes=False, protection_changes=False,
                  mode='console-reboot' if args.reboot_from_console else 'external-reset',
                  link_interval_seconds=args.link_interval, reads=[])
    reference = (ROOT/'analysis/backups/hk6-original/flash-2MiB.bin').read_bytes()
    console = Console(args.port, out/f'boot-probe-{stamp}.rx.bin')
    try:
        with (out/f'boot-probe-{stamp}.transactions.jsonl').open('w') as journal:
            probe = Probe(console, journal)
            if args.reboot_from_console:
                console.synchronize()
                probe.send(b'reboot\r')
            print('Waiting for boot handshake (read-only)...', flush=True)
            end = time.monotonic()+(5 if args.reboot_from_console else 45)
            while time.monotonic() < end:
                probe.send(LINK)
                response = probe.receive(args.link_interval)
                if response == ACK:
                    report['handshake'] = True
                    print('Boot protocol handshake received.', flush=True)
                    break
            if not report['handshake']:
                raise TimeoutError('No boot handshake; no flash commands sent')
            # HK6's loader implements neither the version query nor the MID
            # query from newer Beken tools. Its idle loop resets the device;
            # waiting for these unsupported queries loses the recovery session.
            # Read immediately after the handshake instead.
            for address in ADDRESSES:
                samples = []
                for _ in range(2):
                    frame = probe.request(read_command(address), seconds=4)
                    if (len(frame) != 4111 or frame[:10] != bytes.fromhex('040eff01e0fcf4061009')
                            or frame[10] != 0 or int.from_bytes(frame[11:15], 'little') != address):
                        raise ValueError('Invalid sector read response: '+frame[:20].hex())
                    samples.append(frame[15:])
                if samples[0] != samples[1]:
                    raise ValueError('Repeated bootloader reads differ')
                data = samples[0]
                (out/f'boot-{stamp}-{address:06x}.bin').write_bytes(data)
                item = dict(physical_address=hex(address), bytes=len(data),
                            repeated_reads_match=True, matches_original=data==reference[address:address+4096],
                            sha256=hashlib.sha256(data).hexdigest())
                report['reads'].append(item)
                print(json.dumps(item), flush=True)
                if not item['matches_original']:
                    raise ValueError(f'Sector {address:#x} differs from original backup')
    except (OSError, RuntimeError, ValueError, TimeoutError) as error:
        report['error'] = str(error)
    finally:
        if report['handshake']:
            # Resume normal firmware; this command does not write flash.
            try:
                with (out/f'boot-probe-{stamp}.transactions.jsonl').open('a') as journal:
                    journal.write(json.dumps({'tx_hex': REBOOT.hex(), 'monotonic': time.monotonic()})+'\n')
                if os.write(console.fd, REBOOT) != len(REBOOT):
                    raise OSError('Partial reboot write')
                report['boot_reboot_sent'] = True
                time.sleep(3)
                console.timeout = 15
                console.synchronize()
                report['console_returned'] = True
            except Exception as error:
                report['console_return_error'] = str(error)
        console.close()
        report_path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    print(report_path)
    return 0 if (not report.get('error') and report.get('console_returned')
                 and len(report['reads']) == len(ADDRESSES)) else 1


if __name__ == '__main__':
    raise SystemExit(main())
