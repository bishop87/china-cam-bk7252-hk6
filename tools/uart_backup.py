#!/usr/bin/env python3
"""Read HK6 flash through the original msh flash_dump command (macOS/POSIX).

Only sends an empty line and `flash_dump ADDRESS 256`. Never writes flash.
Requires an already booted camera, Screen closed, and a separate camera supply.
Uses the Python standard library; no serial packages or flashing tools required.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import sqlite3
import subprocess
import sys
import termios
import time

SIZE = 0x200000
BLOCK = 256
ANSI = re.compile(rb'\x1b\[[0-?]*[ -/]*[@-~]')
PROMPT = re.compile(rb'(?:^|[\r\n])msh />')


def status(message, stream=None):
    # Screen can leave the user's terminal without LF -> CRLF conversion.
    # Do not alter its termios settings; make our status lines self-contained.
    stream = sys.stdout if stream is None else stream
    if stream.isatty():
        stream.write('\r' + message.replace('\n', '\r\n') + '\r\n')
    else:
        stream.write(message + '\n')
    stream.flush()


def parse_dump(raw, address, size=BLOCK):
    """Reject missing/duplicate/reordered rows and wrong response headers."""
    raw = ANSI.sub(b'', raw).replace(b'\r', b'')
    headers = list(re.finditer(rb'^flash_dump 0x([0-9a-fA-F]{8}) (\d+)\s*$', raw, re.M))
    if len(headers) != 1:
        raise ValueError('Missing or ambiguous flash_dump response header')
    header = headers[0]
    if (int(header[1], 16), int(header[2])) != (address, size):
        raise ValueError('Response address/length does not match request')
    body = raw[header.end():]
    result = bytearray()
    for line in body.splitlines():
        match = re.match(rb'^([0-9A-Fa-f]{8}): (.*)$', line)
        if not match:
            continue  # asynchronous RTOS messages may appear between rows
        if int(match[1], 16) != len(result) or len(result) >= size:
            raise ValueError('Duplicate, missing or out-of-order dump row')
        n = min(16, size - len(result))
        cells = match[2][:3*n]
        if not re.fullmatch(rb'(?:[0-9A-Fa-f]{2} ){%d}' % n, cells):
            raise ValueError('Malformed hex dump row')
        result.extend(bytes.fromhex(cells.decode('ascii')))
    if len(result) != size:
        raise ValueError(f'Incomplete dump: {len(result)} of {size} bytes')
    return bytes(result)


class Console:
    timeout = 10
    character_delay = 0.003
    command_pause = 0.05
    retries = 3

    def __init__(self, port, transcript):
        lsof = shutil.which('lsof') or '/usr/sbin/lsof'
        check = subprocess.run([lsof, '-t', port], capture_output=True, text=True)
        if check.stdout.strip():
            raise RuntimeError('Porta occupata: chiudi Screen (Ctrl+A, :, quit, Invio).')
        if check.returncode not in (0, 1) or check.stderr.strip():
            raise RuntimeError('Impossibile verificare che la porta sia libera: ' + check.stderr)
        self.fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        self.log = None
        self.old = None
        try:
            fcntl.ioctl(self.fd, termios.TIOCEXCL)
            self.old = termios.tcgetattr(self.fd)
            attr = termios.tcgetattr(self.fd)
            attr[0] = attr[1] = attr[3] = 0
            attr[2] = termios.CLOCAL | termios.CREAD | termios.CS8
            attr[4] = attr[5] = termios.B115200
            attr[6][termios.VMIN] = 0
            attr[6][termios.VTIME] = 0
            termios.tcsetattr(self.fd, termios.TCSANOW, attr)
            self.log = transcript.open('ab', buffering=0)
        except BaseException:
            self.close()
            raise

    def close(self):
        try:
            if self.old is not None:
                termios.tcsetattr(self.fd, termios.TCSANOW, self.old)
        finally:
            os.close(self.fd)
            if self.log:
                self.log.close()

    def synchronize(self):
        # Drain stale output without issuing any commands, then get a fresh prompt.
        end = time.monotonic() + 2
        while time.monotonic() < end and select.select([self.fd], [], [], 0.2)[0]:
            data = os.read(self.fd, 8192)
            if not data:
                raise OSError('Seriale disconnessa')
            self.log.write(data)
        self.exchange(b'\r')

    def exchange(self, command):
        # Callers supply only fixed read commands or an empty line.
        if command != b'\r' and not re.fullmatch(rb'flash_dump [0-9]+ 256\r', command):
            raise ValueError('Comando non consentito')
        # The observed failure ended with command echo only, without CRLF or reply.
        # Pace commands and bytes to mitigate a possible dropped/unprocessed CR.
        time.sleep(self.command_pause)
        for value in command:
            if not select.select([], [self.fd], [], 3)[1]:
                raise TimeoutError('Serial write timeout')
            if os.write(self.fd, bytes([value])) != 1:
                raise OSError('Scrittura seriale incompleta')
            time.sleep(self.character_delay)
        response = bytearray()
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if not select.select([self.fd], [], [], 0.2)[0]:
                continue
            data = os.read(self.fd, 8192)
            if not data:
                raise OSError('Seriale disconnessa')
            self.log.write(data)
            response.extend(data)
            if len(response) > 131072:
                raise ValueError('Risposta troppo lunga, acquisizione fermata')
            if PROMPT.search(ANSI.sub(b'', response)):
                return bytes(response)
        raise TimeoutError(f'Nessun prompt entro {self.timeout:g} secondi '
                           f'({len(response)} byte ricevuti)')

    def read_block(self, address):
        if address % BLOCK or not 0 <= address < SIZE:
            raise ValueError('Indirizzo fuori intervallo')
        for attempt in range(self.retries):
            try:
                if attempt:
                    # An empty line completes a previously lost CR. Its response
                    # is discarded; only a fresh full read can be accepted.
                    self.synchronize()
                return parse_dump(self.exchange(f'flash_dump {address} {BLOCK}\r'.encode()), address)
            except (TimeoutError, ValueError) as error:
                if attempt + 1 == self.retries:
                    raise RuntimeError(f'Lettura 0x{address:06X} fallita dopo '
                                       f'{self.retries} tentativi: {error}') from error
                status(f'Lettura 0x{address:06X}: {error}. '
                       f'Risincronizzazione e tentativo {attempt+2}/{self.retries}.', sys.stderr)


def stored_chunks(db):
    rows = list(db.execute('SELECT address, data, sha256 FROM chunks ORDER BY address'))
    for index, (address, data, digest) in enumerate(rows):
        if address != index * BLOCK or len(data) != BLOCK or address >= SIZE:
            raise ValueError('Checkpoint non contiguo o dimensione non valida')
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Checksum checkpoint non valido')
    return rows


def acquire(db, reader, progress, max_blocks=None):
    rows = stored_chunks(db)
    # Detect an accidental change of target/content when resuming.
    for address, data, _ in ([rows[0], rows[-1]] if rows else []):
        if reader(address) != data:
            raise ValueError('La camera non coincide con il checkpoint; usare una nuova directory')
    stop = SIZE if max_blocks is None else min(SIZE, (len(rows) + max_blocks)*BLOCK)
    for address in range(len(rows)*BLOCK, stop, BLOCK):
        first = reader(address)
        second = reader(address)
        if len(first) != BLOCK or first != second:
            raise ValueError(f'Letture diverse a 0x{address:06x}; blocco non salvato')
        with db:
            db.execute('INSERT INTO chunks VALUES (?, ?, ?)',
                       (address, first, hashlib.sha256(first).hexdigest()))
        progress(address + BLOCK)


def export(db, output):
    rows = stored_chunks(db)
    raw = b''.join(data for _, data, _ in rows)
    if len(raw) != SIZE:
        raise ValueError('Backup incompleto: non esportato come immagine completa')
    digest = hashlib.sha256(raw).hexdigest()
    image = output / 'flash-2MiB.bin'
    if image.exists() and image.read_bytes() != raw:
        raise ValueError('Immagine esistente differente: non sovrascritta')
    if not image.exists():
        with image.open('xb') as f:
            f.write(raw)
    (output / 'SHA256SUMS').write_text(f'{digest}  {image.name}\n')
    (output / 'manifest.json').write_text(json.dumps({
        'bytes': len(raw), 'sha256': digest, 'method': 'msh flash_dump',
        'block_bytes': BLOCK, 'matching_reads_per_block': 2,
        'exported_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'format': 'Raw bytes returned by flash_dump, CRC bytes preserved',
        'physical_capacity_verified': False, 'restore_tested': False,
        'limitations': 'Not an atomic snapshot; live firmware can modify flash. '
                       'Double reads detect mismatches within each block, not all later changes.'
    }, indent=2)+'\n')
    return image, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    parser.add_argument('--output', type=Path, required=True,
                        help='New directory, or same directory to resume this camera')
    parser.add_argument('--max-blocks', type=int,
                        help='Read at most this many new blocks, then exit with a resumable checkpoint')
    args = parser.parse_args()
    if args.max_blocks is not None and args.max_blocks <= 0:
        parser.error('--max-blocks must be positive')
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        db = sqlite3.connect(args.output / 'checkpoint.sqlite3')
        try:
            db.execute('CREATE TABLE IF NOT EXISTS chunks '
                       '(address INTEGER PRIMARY KEY, data BLOB NOT NULL, sha256 TEXT NOT NULL)')
            rows = stored_chunks(db)
            if len(rows)*BLOCK < SIZE:
                status(f'Backup 2 MiB; ripartenza a {len(rows)*BLOCK} byte. '
                       'Solo lettura, due letture per blocco. Ctrl+C per interrompere.')
                console = Console(args.port, args.output / 'serial-transcript.bin')
                started = time.monotonic()
                initial = len(rows)*BLOCK
                last = [0.0]
                def progress(done):
                    now = time.monotonic()
                    if now-last[0] >= 5 or done == SIZE:
                        speed = (done-initial)/max(now-started, 0.001)
                        eta = (SIZE-done)/max(speed, 0.001)/60
                        status(f'{done}/{SIZE} byte ({done/SIZE:.1%}), '
                               f'{speed:.0f} B/s, circa {eta:.1f} min rimanenti')
                        last[0] = now
                try:
                    console.synchronize()
                    acquire(db, console.read_block, progress, args.max_blocks)
                finally:
                    console.close()
            done = len(stored_chunks(db))*BLOCK
            if done < SIZE:
                status(f'Prova limitata completata: {done}/{SIZE} byte nel checkpoint. '
                       'Rilancia senza --max-blocks per completare il backup.')
                return
            image, digest = export(db, args.output)
            status(f'Completato: {image}\nSHA256: {digest}\nRipristino non ancora collaudato.')
        finally:
            db.close()


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, Exception) as error:
        status(f'Interrotto: {error or "Ctrl+C"}. I blocchi già salvati restano nel checkpoint.',
               sys.stderr)
        sys.exit(1)
