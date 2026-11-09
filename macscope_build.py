"""Minimal dependency-free PEP 517 wheel builder; no engine redistribution."""
import base64
import csv
import hashlib
import io
from pathlib import Path
import zipfile


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    name = 'macscope-0.2.0-py3-none-any.whl'
    root = Path(__file__).parent
    files = {str(p.relative_to(root/'src')): p.read_bytes() for p in sorted((root/'src/macscope').rglob('*')) if p.is_file() and p.suffix in ('.py','.java','.json') and '__pycache__' not in str(p)}
    info = 'macscope-0.2.0.dist-info/'
    files[info+'METADATA'] = b'Metadata-Version: 2.1\nName: macscope\nVersion: 0.2.0\nRequires-Python: >=3.12\nSummary: Local Mach-O evidence CLI\n'
    files[info+'WHEEL'] = b'Wheel-Version: 1.0\nGenerator: macscope-build/1\nRoot-Is-Purelib: true\nTag: py3-none-any\n'
    files[info+'entry_points.txt'] = b'[console_scripts]\nmacscope = macscope.cli:main\n'
    rows = [[p, 'sha256='+base64.urlsafe_b64encode(hashlib.sha256(b).digest()).rstrip(b'=').decode(), str(len(b))] for p,b in sorted(files.items())]
    stream = io.StringIO(newline='')
    csv.writer(stream).writerows(rows+[[info+'RECORD','','']])
    files[info+'RECORD'] = stream.getvalue().encode()
    with zipfile.ZipFile(Path(wheel_directory)/name, 'w', zipfile.ZIP_DEFLATED) as z:
        for p,b in sorted(files.items()):
            zi = zipfile.ZipInfo(p, (2026, 11, 9, 0, 0, 0))
            zi.external_attr = 0o644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi,b)
    return name
