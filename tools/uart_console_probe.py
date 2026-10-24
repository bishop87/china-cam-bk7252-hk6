"""Read two original flash blocks through the running HK6 console. No flash writes."""
import argparse
import hashlib
import json
from pathlib import Path
from uart_backup import Console

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    args = parser.parse_args()
    out = ROOT/'analysis/uart/recovery-check'
    out.mkdir(parents=True, exist_ok=True)
    reference = (ROOT/'analysis/backups/hk6-original/flash-2MiB.bin').read_bytes()
    c = Console(args.port, out/'console-readonly.bin')
    try:
        c.synchronize()
        rows = []
        for address in (0, 0x11000):
            data = c.read_block(address)
            rows.append(dict(physical_address=hex(address),
                             matches_original=data == reference[address:address+256],
                             sha256=hashlib.sha256(data).hexdigest()))
        result = json.dumps(rows, indent=2)+'\n'
        (out/'initial-read-check.json').write_text(result)
        print(result)
    finally:
        c.close()


if __name__ == '__main__':
    main()
