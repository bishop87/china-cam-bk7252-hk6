"""HK6: write/read/restore ONE initially erased download sector via UART.

All mutations are restricted to physical 0x1FC000..0x1FCFFF. The installed
loader automatically changes flash protection on erase; its CheckCRC command
reapplies its table-defined protection. No direct status-register writes.
Requires a manual power-on with --wait-reset, or a running shell for --reboot.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import time
import zlib

from uart_backup import Console
from uart_boot_probe import ACK, LINK, REBOOT, Probe
from prepare_uart_recovery import BACKUP_SHA, ROOT

TARGET = 0x1fc000
SIZE = 4096
ERASED = b'\xff'*SIZE
PATTERN = b''.join(hashlib.sha256(b'HK6 UART trial v1'+struct.pack('<I', i)).digest()
                   for i in range(SIZE//32))
GUARDS = (0x2000, 0x11000, 0x132000, TARGET-SIZE, TARGET+SIZE)
READS = (TARGET,)+GUARDS


def packet(opcode, body):
    return b'\x01\xe0\xfc\xff\xf4'+struct.pack('<H', len(body)+1)+bytes([opcode])+body


def read_cmd(address):
    if address not in READS:
        raise ValueError('Read address not in trial allowlist')
    return packet(9, struct.pack('<I', address))


ERASE = packet(15, b'\x20'+struct.pack('<I', TARGET))
WRITE = packet(7, struct.pack('<I', TARGET)+PATTERN)
CRC = b'\x01\xe0\xfc\x09\x10'+struct.pack('<II', TARGET, TARGET+SIZE-1)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Trial(Probe):
    def send(self, data):
        if data not in (LINK, REBOOT, ERASE, WRITE, CRC, b'reboot\r')+tuple(map(read_cmd, READS)):
            raise ValueError('Packet outside fixed HK6 trial allowlist')
        self.journal.write(json.dumps(dict(tx_prefix=data[:16].hex(), bytes=len(data),
                                          sha256=sha(data), monotonic=time.monotonic()))+'\n')
        self.journal.flush()
        offset = 0
        deadline = time.monotonic()+3
        while offset < len(data):
            if time.monotonic() > deadline:
                raise TimeoutError('Serial transmit timeout')
            if select.select([], [self.console.fd], [], .05)[1]:
                try:
                    offset += os.write(self.console.fd, data[offset:offset+256])
                except BlockingIOError:
                    continue

    def link(self, seconds=1):
        end = time.monotonic()+seconds
        while time.monotonic() < end:
            self.send(LINK)
            if self.receive(.003) == ACK:
                return
        raise TimeoutError('Boot link unavailable; no mutation attempted by link()')

    def sector(self, address):
        frame = self.request(read_cmd(address), seconds=2)
        expected = bytes.fromhex('040eff01e0fcf406100900')+struct.pack('<I', address)
        if len(frame) != SIZE+15 or frame[:15] != expected:
            raise ValueError('Invalid sector response: '+frame[:15].hex())
        return frame[15:]

    def erase(self):
        response = self.request(ERASE)
        if response != bytes.fromhex('040eff01e0fcf407000f0020')+struct.pack('<I', TARGET):
            raise ValueError('Invalid erase acknowledgement: '+response.hex())

    def write(self):
        response = self.request(WRITE)
        if response != bytes.fromhex('040eff01e0fcf406000700')+struct.pack('<I', TARGET):
            raise ValueError('Invalid write acknowledgement: '+response.hex())

    def protect_and_crc(self, data):
        # This is NOT a read-only operation: installed routine 0x195C invokes
        # 0x1664(1), selecting the loader's protected status-register value.
        response = self.request(CRC)
        expected = bytes.fromhex('040e0801e0fc10')+struct.pack('<I', zlib.crc32(data)^0xffffffff)
        if response != expected:
            raise ValueError('CRC/protection completion response mismatch: '+response.hex())


def run_trial(trial, reference, out, report, checkpoint):
    originals = {}
    for address in READS:
        a, b = trial.sector(address), trial.sector(address)
        if a != b or a != reference[address:address+SIZE]:
            raise ValueError(f'Preflight mismatch at {address:#x}; no writes allowed')
        originals[address] = a
    if originals[TARGET] != ERASED:
        raise ValueError('Trial sector is not erased; no writes allowed')
    with (out/'sector-before.bin').open('xb') as handle:
        handle.write(originals[TARGET])
        handle.flush()
        os.fsync(handle.fileno())
    report['preflight'] = {hex(a): sha(d) for a, d in originals.items()}
    report['original_saved'] = True
    checkpoint()
    trial.link()  # disk sync may have outlasted the bootloader idle timeout
    report['mutation_attempted'] = True
    # The original is already durable. No more disk syncs between boot requests.
    try:
        trial.erase()  # also invokes loader automatic unprotect
        if trial.sector(TARGET) != ERASED:
            raise ValueError('Erase verification failed')
        trial.write()
        a, b = trial.sector(TARGET), trial.sector(TARGET)
        if a != PATTERN or b != PATTERN:
            raise ValueError('Pattern readback mismatch')
        report['pattern_verified_twice'] = True
        report['pattern_sha256'] = sha(a)
        print('Pattern written and verified twice; restoring original sector.', flush=True)
    finally:
        # Even a partial/failed write must trigger restoration. The original
        # was all FF, so sector erase restores it exactly without reprogramming.
        try:
            trial.link()
            trial.erase()
            a, b = trial.sector(TARGET), trial.sector(TARGET)
            if a != originals[TARGET] or b != originals[TARGET]:
                raise ValueError('Original sector restoration mismatch')
            report['original_restored_twice'] = True
            report['restored_sha256'] = sha(a)
            for address in GUARDS:
                if trial.sector(address) != originals[address]:
                    raise ValueError(f'Guard changed at {address:#x}')
            report['guards_unchanged'] = True
        finally:
            # Applies loader-defined protection even if an earlier check failed.
            trial.link()
            current = trial.sector(TARGET)
            trial.protect_and_crc(current)
            report['loader_protect_and_crc_completed'] = True
            report['device_crc32_raw'] = hex(zlib.crc32(current)^0xffffffff)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--wait-reset', action='store_true')
    mode.add_argument('--reboot', action='store_true')
    args = parser.parse_args()
    reference = (ROOT/'analysis/backups/hk6-original/flash-2MiB.bin').read_bytes()
    if len(reference) != 0x200000 or sha(reference) != BACKUP_SHA:
        raise ValueError('Wrong original backup')
    # Tie the protocol analysis to the actual installed boot image as well.
    boot = (ROOT/'analysis/original/bootloader-logical.bin').read_bytes()
    if sha(boot) != '5bc9d1458fdbebba682947b0d11f231a74729522f7741cfab62d6a1cf445fac6':
        raise ValueError('Bootloader analysis source mismatch')
    out = ROOT/'analysis/uart/write-trial'/time.strftime('%Y%m%d-%H%M%S')
    out.mkdir(parents=True, exist_ok=False)
    report = dict(target=hex(TARGET), length=SIZE, backup_sha256=BACKUP_SHA,
                  handshake=False, mutation_attempted=False, pattern_verified_twice=False,
                  original_restored_twice=False, guards_unchanged=False,
                  loader_protect_and_crc_completed=False, console_returned=False)
    def checkpoint():
        (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    checkpoint()
    console = Console(args.port, out/'serial.rx.bin')
    with (out/'transactions.jsonl').open('w') as journal:
        trial = Trial(console, journal)
        try:
            if args.reboot:
                console.synchronize()
                trial.send(b'reboot\r')
            print('Waiting for bootloader. Mutations restricted to 0x1FC000 (4096 bytes).', flush=True)
            trial.link(45 if args.wait_reset else 5)
            report['handshake'] = True
            print('Boot connected; checking original and neighboring sectors.', flush=True)
            run_trial(trial, reference, out, report, checkpoint)
        except (Exception, KeyboardInterrupt) as error:
            report['error'] = f'{type(error).__name__}: {error}'
        finally:
            if report['handshake']:
                try:
                    # Original application is intact even if scratch restore
                    # failed. Resume it to restore its normal startup policy.
                    trial.send(REBOOT)
                    time.sleep(3)
                    console.timeout = 15
                    console.synchronize()
                    report['console_returned'] = True
                    # After normal boot, confirm the restored sector through
                    # the original application's independent read command too.
                    if report['original_restored_twice']:
                        restored = b''.join(console.read_block(a) for a in range(TARGET, TARGET+SIZE, 256))
                        report['postboot_original_sector_matches'] = restored == ERASED
                except Exception as error:
                    report['console_error'] = str(error)
            console.close()
            checkpoint()
    passed = all(report.get(k) for k in ('pattern_verified_twice', 'original_restored_twice',
                                         'guards_unchanged', 'loader_protect_and_crc_completed',
                                         'console_returned', 'postboot_original_sector_matches'))
    report['passed'] = passed and 'error' not in report
    checkpoint()
    print(json.dumps(report, indent=2))
    print(out/'report.json')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
