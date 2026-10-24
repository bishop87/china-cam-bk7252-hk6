"""Audit indexed Git files; never inspect or print private laboratory contents."""
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def main():
    names = git('ls-files', '-z').decode().split('\0')
    names = {n for n in names if n}
    errors = []
    private = ('analysis/', 'dist/', 'build/', 'upstream/', '.venv/',
               'docs/local/', 'app/evidence/', 'tools/downloads/',
               'tools/gcc-arm-none-eabi-')
    forbidden = {'.bin', '.rbl', '.elf', '.pcap', '.pcapng', '.apk', '.apks',
                 '.sqlite', '.db', '.avi', '.wav', '.pcm', '.pem', '.key', '.zip'}
    patterns = [
        ('private key', rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        ('GitHub token', rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b'),
        ('AWS access key', rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
        ('personal workstation path', rb'/' + rb'Users/[^/\s]+/'),
        ('camera UID', rb'\bDGO[A-Z0-9]{8,}\b'),
    ]
    total = 0
    for name in sorted(names):
        p = PurePosixPath(name)
        if name.startswith(private) or p.suffix.lower() in forbidden or name == 'firmware/local-config.json' or p.name.startswith(('screenlog.', '.env')):
            errors.append(f'{name}: private/generated input must not be indexed')
        data = git('show', ':'+name)
        total += len(data)
        if len(data) > 10*1024*1024:
            errors.append(f'{name}: unexpectedly large file')
        if p.suffix.lower() == '.jpg':
            from strip_photo_metadata import clean
            if clean(data) != data:
                errors.append(f'{name}: unreviewed JPEG metadata; strip it before publishing')
            continue
        if b'\0' in data:
            errors.append(f'{name}: unexpected binary file')
            continue
        for label, pattern in patterns:
            if re.search(pattern, data):
                errors.append(f'{name}: {label}')
        if p.suffix.lower() == '.md':
            text = re.sub(r'```.*?```', '', data.decode('utf-8'), flags=re.S)
            text = re.sub(r'`[^`\n]*`', '', text)
            links = re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', text)
            links += re.findall(r'<img\b[^>]*\bsrc="([^"]+)"', text)
            for target in links:
                target = unquote(target.strip('<>').split('#')[0])
                if not target or re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', target):
                    continue
                resolved = (ROOT / p.parent / target).resolve()
                try:
                    rel = resolved.relative_to(ROOT).as_posix()
                except ValueError:
                    errors.append(f'{name}: link leaves the repository')
                    continue
                if rel not in names and not any(n.startswith(rel.rstrip('/')+'/') for n in names):
                    errors.append(f'{name}: link target not published: {target}')
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print(f'Public index checked: {len(names)} files, {total/1024/1024:.2f} MiB; no forbidden artifacts, metadata, secret patterns or missing local links.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
