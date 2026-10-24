"""Prepare original physical app+download bytes for a future UART restore.

Does not open a serial port or flash anything. Keeps the bootloader and both
configuration sectors outside the restore image. Actual write/restore untested.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKUP_SHA = 'b92beaf5a9500bccb4044905ab926fa82f25b88343443930f9459e6c253a4eed'
START, END = 0x11000, 0x1fe000


def main():
    source = ROOT/'analysis/backups/hk6-original/flash-2MiB.bin'
    backup = source.read_bytes()
    if len(backup) != 0x200000 or hashlib.sha256(backup).hexdigest() != BACKUP_SHA:
        raise ValueError('Original backup does not match the verified HK6 device')
    out = ROOT/'dist/hk6-uart-recovery'
    out.mkdir(parents=True, exist_ok=True)
    data = backup[START:END]
    name = 'hk6-original-app-and-download-physical.bin'
    (out/name).write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    manifest = dict(source=str(source.relative_to(ROOT)), source_sha256=BACKUP_SHA,
                    image=name, sha256=digest, bytes=len(data),
                    physical_start=hex(START), physical_end_exclusive=hex(END),
                    format='Physical flash bytes, existing CRC interleaving preserved',
                    includes=['app', 'download'],
                    excludes=['bootloader', 'gap before app', 'EasyFlash', 'param2'],
                    hardware_write_tested=False, hardware_restore_tested=False,
                    ready_to_flash=False)
    (out/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    (out/'readme.md').write_text('''# HK6: immagine originale per il recupero UART

Preparata dal backup originale verificato. **Scrittura di questa immagine e
ripristino dell'intera app non ancora collaudati; non caricarla adesso.**
La distinta prova di programmazione/ripristino di un singolo settore libero
è riuscita: vedere `analysis/uart/write-trial/README.md` nel progetto.

Il file `hk6-original-app-and-download-physical.bin` contiene i byte fisici
originali nell'intervallo `[0x11000, 0x1FE000)`: applicazione e area download.
I CRC fisici già presenti sono conservati: non applicare nuovamente CRC,
decifratura o decompressione. Non è un OTA RBL e non va scritto a indirizzo zero.

Includere download nel futuro ripristino elimina anche un eventuale OTA della
patch rimasto in staging, che altrimenti potrebbe reinstallarsi al riavvio.
Bootloader, spazio prima dell'app e settori EasyFlash/param2 sono esclusi:
nessuna cancellazione globale deve precedere questo ripristino.

Usare questa immagine soltanto per questa camera e con il percorso di scrittura
UART prima verificato. Se è danneggiato il caricatore iniziale, il collegamento
UART provato non è sufficiente. Il backup completo resta il riferimento.

Rigenerazione dal progetto: `python3 tools/prepare_uart_recovery.py`.
''')
    (out/'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256((out/f).read_bytes()).hexdigest()}  {f}\n'
        for f in (name, 'manifest.json', 'readme.md')))
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
