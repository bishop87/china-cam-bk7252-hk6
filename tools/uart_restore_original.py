"""Restore only original HK6 app+download physical sectors through its loader.

Requires explicit --execute. No bootloader/configuration writes, no mass erase.
Uses the protocol exercised by uart_write_trial.py; full restoration itself
is not yet hardware-tested. An interrupted restore can be restarted: sectors
are always read and compared before deciding whether they need writing.
"""
import argparse
import json
import os
import select
import struct
import time
import zlib

from uart_backup import Console
from uart_boot_probe import Probe, LINK, REBOOT
from uart_write_trial import packet, sha, Trial, SIZE, ERASED
from prepare_uart_recovery import ROOT, BACKUP_SHA, START, END

DOWNLOAD = 0x132000
CRC = b'\x01\xe0\xfc\x09\x10'+struct.pack('<II', START, START+SIZE-1)


def validate_packet(data, original):
    if data in (LINK, REBOOT, CRC):
        return
    if len(data) < 12 or data[:5] != bytes.fromhex('01e0fcfff4'):
        raise ValueError('Unknown recovery packet')
    if int.from_bytes(data[5:7], 'little') != len(data)-7:
        raise ValueError('Recovery packet size mismatch')
    opcode = data[7]
    address = int.from_bytes(data[9:13] if opcode == 15 else data[8:12], 'little')
    if address % SIZE or not START <= address < END:
        if not (opcode == 9 and address == 0x2000 and len(data) == 12):
            raise ValueError('Outside original app+download scope')
    if opcode == 9 and len(data) == 12:
        return
    if opcode == 15 and len(data) == 13 and data[8] == 0x20:
        return
    if opcode == 7 and len(data) == SIZE+12 and data[12:] == original[address:address+SIZE]:
        return
    raise ValueError('Only original bytes and sector erase are permitted')


class Restore(Probe):
    link = Trial.link

    def __init__(self, console, journal, original):
        super().__init__(console, journal)
        self.original = original

    def send(self, data):
        validate_packet(data, self.original)
        self.journal.write(json.dumps(dict(tx_prefix=data[:16].hex(), bytes=len(data),
                                          sha256=sha(data), monotonic=time.monotonic()))+'\n')
        self.journal.flush()
        offset, deadline = 0, time.monotonic()+3
        while offset < len(data):
            if time.monotonic() > deadline:
                raise TimeoutError('Serial transmit timeout')
            if select.select([], [self.console.fd], [], .05)[1]:
                try:
                    offset += os.write(self.console.fd, data[offset:offset+256])
                except BlockingIOError:
                    continue

    def sector(self, address):
        frame = self.request(packet(9, struct.pack('<I', address)), seconds=2)
        expected = bytes.fromhex('040eff01e0fcf406100900')+struct.pack('<I', address)
        if len(frame) != SIZE+15 or frame[:15] != expected:
            raise ValueError('Invalid recovery read response')
        return frame[15:]

    def replace(self, address, data):
        validate_packet(packet(7, struct.pack('<I', address)+data), self.original)
        self.link()
        result = self.request(packet(15, b'\x20'+struct.pack('<I', address)))
        if result != bytes.fromhex('040eff01e0fcf407000f0020')+struct.pack('<I', address):
            raise ValueError('Erase acknowledgement mismatch')
        if data != ERASED:
            result = self.request(packet(7, struct.pack('<I', address)+data))
            if result != bytes.fromhex('040eff01e0fcf406000700')+struct.pack('<I', address):
                raise ValueError('Write acknowledgement mismatch')
        if self.sector(address) != data or self.sector(address) != data:
            raise ValueError(f'Restored sector mismatch at {address:#x}')

    def protect(self):
        data = self.sector(START)
        frame = self.request(CRC)
        if frame != bytes.fromhex('040e0801e0fc10')+struct.pack('<I', zlib.crc32(data)^0xffffffff):
            raise ValueError('Protection/CRC response mismatch')


def restore_sectors(device, original, progress):
    changed = []
    # Remove staged OTA first so the patch cannot be reapplied after rollback.
    order = list(range(DOWNLOAD, END, SIZE))+list(range(START, DOWNLOAD, SIZE))
    for index, address in enumerate(order):
        expected = original[address:address+SIZE]
        if device.sector(address) != expected:
            device.replace(address, expected)
            changed.append(hex(address))
        progress(index+1, len(order), changed)
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    parser.add_argument('--execute', action='store_true', required=True)
    args = parser.parse_args()
    original = (ROOT/'analysis/backups/hk6-original/flash-2MiB.bin').read_bytes()
    if len(original) != 0x200000 or sha(original) != BACKUP_SHA:
        raise ValueError('Wrong original device backup')
    out = ROOT/'analysis/uart/restores'/time.strftime('%Y%m%d-%H%M%S')
    out.mkdir(parents=True, exist_ok=False)
    report = dict(complete=False, backup_sha256=BACKUP_SHA, changed=[], checked_sectors=0)
    def progress(done, total, changed):
        report.update(checked_sectors=done, total_sectors=total, changed=list(changed))
        if done % 16 == 0 or done == total:
            (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
            print(f'{done}/{total} sectors checked, {len(changed)} restored', flush=True)
            device.link()  # recheck after disk activity
    c = Console(args.port, out/'serial.rx.bin')
    with (out/'transactions.jsonl').open('w') as journal:
        device = Restore(c, journal, original)
        linked = False
        try:
            print('Power on camera within 45 seconds. Restoring original app+download only.', flush=True)
            device.link(45)
            linked = True
            if device.sector(0x2000) != original[0x2000:0x3000]:
                raise ValueError('Original bootloader sample mismatch; no restore')
            restore_sectors(device, original, progress)
            device.protect()
            report['loader_protection_completed'] = True
            device.send(REBOOT)
            time.sleep(3)
            c.timeout = 15
            c.synchronize()
            report['console_returned'] = True
            if c.read_block(START) != original[START:START+256]:
                raise ValueError('Postboot app sample differs')
            report['complete'] = True
        except (Exception, KeyboardInterrupt) as error:
            report['error'] = f'{type(error).__name__}: {error}'
            # Never deliberately boot a potentially incomplete application.
            if linked:
                try:
                    device.link()
                    device.protect()
                    report['loader_protection_completed'] = True
                except Exception as protect_error:
                    report['protection_error'] = str(protect_error)
        finally:
            c.close()
            (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
