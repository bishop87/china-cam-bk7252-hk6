"""Package a built LocalCam image as an UNVALIDATED development artifact."""
import hashlib
import json
import shutil
import zipfile
from pathlib import Path
from elftools.elf.elffile import ELFFile
from rbl import pack, unpack

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'dist/localcam-0.1-experimental'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for source in (ROOT / 'firmware/localcam').glob('*'):
        if source.is_file() and source.read_bytes() != (ROOT / 'build/sdk/localcam' / source.name).read_bytes():
            raise ValueError('Application source differs from build tree; run tools/build.sh first')
    raw = (ROOT / 'build/sdk/rtthread.bin').read_bytes()
    if not 0 < len(raw) <= 1215*1024:
        raise ValueError('Image exceeds pinned linker flash region')
    with (ROOT / 'build/sdk/rtthread.elf').open('rb') as f:
        elf = ELFFile(f)
        if elf['e_machine'] != 'EM_ARM' or elf['e_entry'] != 0x10000:
            raise ValueError('Unexpected architecture or entry point')
    binary = OUT / 'localcam-app-EXPERIMENTAL.bin'
    binary.write_bytes(raw)
    package = pack(raw, 'LocalCam-0.1-EXPERIMENT', 1792108800)
    (OUT / 'localcam-EXPERIMENTAL.rbl').write_bytes(package)
    decoded, metadata = unpack(package)
    if decoded != raw:
        raise ValueError('OTA roundtrip differs from compiler output')
    for source, target in [('build/sdk/rtthread.elf', 'localcam.elf'),
                           ('build/sdk/rtthread.map', 'localcam.map'),
                           ('build/compile.log', 'compile.log'),
                           ('readme.md', 'readme.md')]:
        shutil.copy2(ROOT / source, OUT / target)
    (OUT / 'STATUS.txt').write_text(
        'EXPERIMENTAL — NON CARICARE ANCORA SULLA CAMERA\n'
        'Build ARM e integrita del contenitore RBL verificate offline.\n'
        'Avvio, sensore, pin, RAM, flash e bootloader HK6 NON verificati.\n'
        'Il .bin e un payload logico: non e una immagine UART/SPI con CRC interleaved.\n'
        'Non contiene bootloader, calibrazione RF, MAC o backup della tua scheda.\n'
        'Vedere readme.md per i controlli hardware necessari.\n')
    metadata.update(status='EXPERIMENTAL_NOT_HARDWARE_VALIDATED', ready_to_flash=False,
                    sdk_commit='266d54fd8965a093d345c1a1cdb6ca26da6a6488',
                    logical_entry='0x10000', flash_image_with_interleaved_crc=False,
                    network_mode=json.loads((ROOT / 'firmware/local-config.json').read_text())['mode'],
                    hardware_tests_performed=False)
    # Source/config fingerprints let us identify precisely what produced this local build.
    metadata['input_sha256'] = {str(p.relative_to(ROOT)): digest(p) for p in
        sorted((ROOT / 'firmware/localcam').glob('*')) +
        [ROOT / 'firmware/local-config.json', ROOT / 'tools/prepare_build.py', ROOT / 'tools/rbl.py'] if p.is_file()}
    metadata['files_sha256'] = {p.name: digest(p) for p in sorted(OUT.iterdir())
                                if p.is_file() and p.name not in ('manifest.json', 'SHA256SUMS')}
    (OUT / 'manifest.json').write_text(json.dumps(metadata, indent=2)+'\n')
    sums = ''.join(f'{digest(p)}  {p.name}\n' for p in sorted(OUT.iterdir()) if p.is_file() and p.name != 'SHA256SUMS')
    (OUT / 'SHA256SUMS').write_text(sums)
    archive = OUT.parent / (OUT.name + '.zip')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for p in sorted(OUT.iterdir()):
            if p.is_file(): z.write(p, OUT.name+'/'+p.name)
    print(json.dumps(dict(archive=str(archive), raw_bytes=len(raw), rbl_bytes=len(package), ready_to_flash=False), indent=2))


if __name__ == '__main__':
    main()
