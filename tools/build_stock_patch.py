"""Build an offline, experimental patch of the exact backed-up HK6 application.

No serial, network, flash writes, bootloader edits or configuration extraction.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile
import zlib

from rbl import HEADER, pack, unpack

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA256 = '831dc94bb967f84811c4ad8b8e7211f2b4ed364dc235a7f4e2dbfd44acba831c'
BOOT_SHA256 = '5bc9d1458fdbebba682947b0d11f231a74729522f7741cfab62d6a1cf445fac6'
BASE = 0x10000
VERSION = '2M.1220-LAN-EXP1'
STAMP = 1792195200  # 2026-10-17 00:00:00 UTC, deterministic build.
PATCHES = [
    dict(name='listen-mode-zero', address=0x1a36c, before='0123', after='0023',
         effect='Fourth argument to Listen changes from 1 to 0; known server-send guards are skipped.'),
    dict(name='skip-network-detect-after-init', address=0x17490, before='0b24', after='17e0',
         effect='Branch to existing thread epilogue after the original shared PPCS initialization returns.'),
    dict(name='ntp-return-failure', address=0x583b0, before='f0b53d4d', after='00207047',
         effect='NTP time query immediately returns zero, before socket creation or DNS resolution.'),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def apply_patch(raw):
    if sha(raw) != SOURCE_SHA256:
        raise ValueError('Wrong original payload SHA-256; refusing to patch')
    result = bytearray(raw)
    covered = set()
    for item in PATCHES:
        offset = item['address'] - BASE
        before, after = bytes.fromhex(item['before']), bytes.fromhex(item['after'])
        region = set(range(offset, offset + len(before)))
        if len(before) != len(after) or covered & region:
            raise ValueError('Invalid/overlapping patch specification')
        if offset < 0 or raw[offset:offset+len(before)] != before:
            raise ValueError('Unexpected original instruction: ' + item['name'])
        result[offset:offset+len(after)] = after
        covered |= region
    result = bytes(result)
    changed = {i for i, (a, b) in enumerate(zip(raw, result)) if a != b}
    if len(result) != len(raw) or not changed <= covered:
        raise ValueError('Unexpected payload changes')
    restored = bytearray(result)
    for item in PATCHES:
        off = item['address'] - BASE
        restored[off:off+len(bytes.fromhex(item['before']))] = bytes.fromhex(item['before'])
    if bytes(restored) != raw:
        raise ValueError('Patch reversal failed')
    return result, sorted(changed)


def build_package(raw, installed_header):
    package = pack(raw, VERSION, STAMP)
    fields = list(HEADER.unpack_from(package))
    old = HEADER.unpack(installed_header)
    if old[0] != b'RBL\0' or old[3].split(b'\0')[0] != b'app':
        raise ValueError('Unexpected installed header')
    # Keep the installed image serial field, rather than inventing another one.
    fields[5] = old[5]
    fields[-1] = 0
    header = HEADER.pack(*fields)
    header = header[:92] + struct.pack('<I', zlib.crc32(header[:92]))
    package = header + package[96:]
    decoded, meta = unpack(package)
    if decoded != raw or len(package) > 0xcc000:
        raise ValueError('Package round trip or download partition capacity check failed')
    if len(raw) + 96 > 0x110000:
        raise ValueError('Application exceeds installed partition size')
    return package, meta


def write_bundle(directory, files):
    files = dict(files)
    files.pop('SHA256SUMS', None)
    files['SHA256SUMS'] = ''.join(f'{sha(data)}  {name}\n' for name, data in files.items()).encode()
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (directory/name).write_bytes(data)
    archive = directory.with_suffix('.zip')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zipout:
        for name, data in files.items():
            info = zipfile.ZipInfo(directory.name+'/'+name, (2026, 10, 17, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zipout.writestr(info, data)
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'dist/hk6-stock-lan-exp1')
    args = parser.parse_args()
    source = ROOT/'analysis/original/app-payload.bin'
    raw = source.read_bytes()
    boot = (ROOT/'analysis/original/bootloader-logical.bin').read_bytes()
    app = (ROOT/'analysis/original/app-logical.bin').read_bytes()
    if sha(boot) != BOOT_SHA256 or sha(app) != '8f2e8d40497634a801fffb4c28c54d1d19400c08a0286ba1e6b365997163d900':
        raise ValueError('Bootloader or installed app differs from analyzed unit')
    # These public vendor constants are reached by the original key getter.
    from rbl import KEY, IV
    if boot[0x1f1c:0x1f2c] != IV or boot[0x1f2d:0x1f4d] != KEY:
        raise ValueError('OTA key/IV do not match the original bootloader')
    patched, changed = apply_patch(raw)
    package, meta = build_package(patched, app[0xfffa0:0x100000])
    spec = [dict(x, logical_address=hex(x['address']),
                 payload_offset=hex(x['address']-BASE)) for x in PATCHES]
    manifest = dict(
        name='HK6 stock LAN experiment 1', version=VERSION, ready_to_flash=False,
        status='experimental_files_only_hardware_untested',
        source_payload_sha256=SOURCE_SHA256, original_bootloader_sha256=BOOT_SHA256,
        payload_bytes=len(patched), payload_sha256=sha(patched),
        rbl_bytes=len(package), rbl_sha256=sha(package),
        actual_changed_bytes=len(changed), changed_payload_offsets=[hex(i) for i in changed],
        patches=spec, ota_algorithm='0x102 AES-256-CBC + gzip',
        offline_checks=['source hashes and original opcodes', 'exact diff and reversal',
                        'RBL CRC32/FNV-1a, AES/gzip round trip', 'partition size limits'],
        limitations=['LAN video on patched device untested', 'recovery untested',
                     'not a complete egress filter; all external traffic not proven absent',
                     'PPCS initialization and worker threads remain active',
                     'no RTSP/MJPEG; original app/protocol retained',
                     'automatic network time synchronization disabled',
                     'not an open-source firmware; modified proprietary application'],
        hardware_writes_performed=False,
    )
    readme = f'''# HK6 stock LAN — esperimento 1

**Non pronto da caricare: nessuna prova sulla camera o di recupero.**

Questo pacchetto è derivato esclusivamente dal payload originale HK6_IPC del 4 luglio 2023,
SHA-256 `{SOURCE_SHA256}`. Conserva driver e protocollo originali.

Tre modifiche: parametro Listen a zero; uscita del thread p2pinit dopo l’inizializzazione
condivisa e prima di NetworkDetect; NTP restituisce errore prima di aprire socket o fare DNS.
Cambiano {len(changed)} byte effettivi, in tre punti. Il resto del payload è identico.

`hk6-stock-lan-exp1.bin` è il payload logico, senza CRC interleaved e senza header installato.
`hk6-stock-lan-exp1.rbl` è il contenitore OTA cifrato/compresso, destinato alla partizione app.
Nessuno dei due è un dump fisico da 2 MiB. Non contiene le partizioni di configurazione o il bootloader.
L’etichetta {VERSION} è nell’header RBL; la versione mostrata dall’app potrebbe rimanere quella originale.

Il contenitore supera i controlli locali, ma questi non equivalgono a un aggiornamento riuscito.
Non caricare tramite procedure generiche, non scrivere alla cieca un offset flash.
Il percorso effettivo di installazione e il recupero devono essere verificati prima della scrittura.

Non è ancora dimostrato che il video funzioni con la patch o che ogni comunicazione esterna sia eliminata.
L’inizializzazione PPCS e i suoi worker restano attivi; non è un filtro completo del traffico.
NTP automatico è disabilitato: ora/timestamp possono essere errati, salvo aggiornamento tramite altri mezzi.
Rimangono HDWifiCamPro/protocollo proprietario; nessuna aggiunta RTSP/MJPEG e nessuna garanzia sul traffico dell’app.

Rigenerazione dal progetto: `.venv/bin/python tools/build_stock_patch.py`.
Verifica con emulazione: `.venv/bin/python tools/verify_stock_patch.py`.
`manifest.json` registra byte prima/dopo, hash e limiti. Il backup originale resta separato e intatto.
'''
    files = {'hk6-stock-lan-exp1.bin': patched, 'hk6-stock-lan-exp1.rbl': package,
             'manifest.json': (json.dumps(manifest, indent=2)+'\n').encode(),
             'readme.md': readme.encode()}
    archive = write_bundle(args.output, files)
    # Remove previous runtime verification, if this directory was regenerated.
    (args.output/'emulation-validation.json').unlink(missing_ok=True)
    print(json.dumps({k: manifest[k] for k in ('ready_to_flash','payload_bytes','rbl_bytes','actual_changed_bytes','payload_sha256','rbl_sha256')}, indent=2))
    print(archive)


if __name__ == '__main__':
    main()
