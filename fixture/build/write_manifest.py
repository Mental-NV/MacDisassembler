#!/usr/bin/env python3
"""Immutable fixture build provenance. Hash actual section bytes, not otool text."""
import hashlib
import json
import platform
import struct
import subprocess
import sys
from pathlib import Path


def run(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                          check=True).stdout.strip()


def sha256(p):
    h = hashlib.sha256()
    with Path(p).open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def text_bytes(macho):
    """Extract __TEXT,__text from one thin 64-bit little-endian Mach-O."""
    data = Path(macho).read_bytes()
    if len(data) < 32 or data[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('expected thin little-endian Mach-O 64')
    ncmds, sizeofcmds = struct.unpack_from('<II', data, 16)
    end = 32 + sizeofcmds
    if end > len(data) or ncmds > sizeofcmds // 8:
        raise ValueError('invalid load command bounds')
    off = 32
    for _ in range(ncmds):
        if off + 8 > end:
            raise ValueError('truncated load command')
        cmd, size = struct.unpack_from('<II', data, off)
        if size < 8 or off + size > end:
            raise ValueError('invalid load command size')
        if cmd == 0x19:
            if size < 72:
                raise ValueError('truncated segment')
            nsects = struct.unpack_from('<I', data, off + 64)[0]
            if nsects > (size - 72) // 80:
                raise ValueError('invalid section count')
            for i in range(nsects):
                sec = off + 72 + i * 80
                name, segment = struct.unpack_from('<16s16s', data, sec)
                if name.rstrip(b'\0') == b'__text' and segment.rstrip(b'\0') == b'__TEXT':
                    length = struct.unpack_from('<Q', data, sec + 40)[0]
                    pos = struct.unpack_from('<I', data, sec + 48)[0]
                    if pos > len(data) or length > len(data) - pos:
                        raise ValueError('section outside file')
                    return data[pos:pos + length]
        off += size
    raise ValueError('missing __TEXT,__text')


def text_hash(macho):
    return hashlib.sha256(text_bytes(macho)).hexdigest()


def provenance(repo):
    diff = subprocess.run(['git', 'diff', '--binary', 'HEAD', '--', 'fixture',
                           'docs/semantics.md'], cwd=repo, check=True,
                          capture_output=True).stdout
    paths = sorted([*Path(repo, 'fixture').rglob('*'), Path(repo, 'docs/semantics.md')])
    sources = {str(p.relative_to(repo)): sha256(p) for p in paths
               if p.is_file() and p.suffix in {'.c', '.h', '.m', '.py', '.sh',
                                               '.md', '.pbxproj', '.xcscheme', '.plist'}}
    source_digest = hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest()
    return {'git_revision': run('git', 'rev-parse', 'HEAD', cwd=repo),
            'dirty': bool(diff) or bool(run('git', 'ls-files', '--others', '--exclude-standard',
                                            'fixture', 'docs/semantics.md', cwd=repo)),
            'tracked_dirty_diff_sha256': hashlib.sha256(diff).hexdigest(),
            'source_tree_sha256': source_digest, 'source_files_sha256': sources,
            'semantics_version': '1.1',
            'note': 'revision plus diff and source-file hashes identify uncommitted inputs'}


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--text-hash':
        print(text_hash(sys.argv[2]))
        return
    repo = Path(sys.argv[1]).resolve()
    bld = Path(sys.argv[2]).resolve()
    manifest = {'schema': 'macscope-phase1-manifest/2', 'source': provenance(repo),
                'host': {'product': run('sw_vers', '-productName'),
                         'version': run('sw_vers', '-productVersion'),
                         'build': run('sw_vers', '-buildVersion'), 'arch': platform.machine()},
                'toolchain': {name: run(*argv) for name, argv in {
                    'xcode': ['xcodebuild', '-version'], 'sdk': ['xcrun', '--sdk', 'macosx', '--show-sdk-version'],
                    'clang': ['xcrun', 'clang', '--version'], 'llvm': ['xcrun', 'llvm-objdump', '--version'],
                    'python': [sys.executable, '--version']}.items()},
                'command_evidence': {'path': str(bld / 'build.log'),
                                     'format': 'bash set -x expanded argv; build logs retained per configuration'},
                'build_commands': [], 'artifacts': []}
    for cfg in ('DebugAnalysis', 'ReleaseAnalysis'):
        for arch in ('arm64', 'x86_64'):
            out = bld / 'evaluator' / f'{cfg}-{arch}'
            manifest['build_commands'].append(['xcodebuild', '-project', str(repo / 'fixture/CalculatorFixture.xcodeproj'),
                '-scheme', 'CalculatorFixture', '-configuration', cfg, '-derivedDataPath', str(bld / 'derived' / f'{cfg}-{arch}'),
                f'CONFIGURATION_BUILD_DIR={out}', f'ARCHS={arch}', 'ONLY_ACTIVE_ARCH=NO', 'build'])
            for state in ('sym', 'stripped'):
                d = bld / 'analyst' / f'{cfg}-{arch}-{state}'
                for name, rel in [('CalculatorFixture', 'CalculatorFixture.app/Contents/MacOS/CalculatorFixture'),
                                  ('CorpusFixture', 'CorpusFixture')]:
                    p = d / rel
                    manifest['artifacts'].append({'name': name, 'config': cfg, 'arch': arch,
                        'symbols': state, 'container': 'thin', 'path': str(p.relative_to(repo)),
                        'sha256': sha256(p), 'uuid': run('xcrun', 'dwarfdump', '--uuid', str(p)).split()[1],
                        'text_bytes_sha256': text_hash(p), 'text_bytes_size': len(text_bytes(p)),
                        'lipo': run('xcrun', 'lipo', '-info', str(p))})
        for state in ('sym', 'stripped'):
            p = bld / 'universal' / f'CalculatorFixture-{cfg}-{state}.app/Contents/MacOS/CalculatorFixture'
            manifest['artifacts'].append({'name': 'CalculatorFixture', 'config': cfg, 'arch': 'universal',
                'symbols': state, 'container': 'universal', 'path': str(p.relative_to(repo)),
                'sha256': sha256(p), 'lipo': run('xcrun', 'lipo', '-info', str(p)),
                'slices': {arch: {'text_bytes_sha256': text_hash(bld / f'slice-{cfg}-{state}-{arch}'),
                                   'sha256': sha256(bld / f'slice-{cfg}-{state}-{arch}')}
                           for arch in ('arm64', 'x86_64')}})
    manifest['reference_outputs'] = {cfg: {'path': str(bld / 'evaluator' / f'reference-outputs-{cfg}.txt'),
        'sha256': sha256(bld / 'evaluator' / f'reference-outputs-{cfg}.txt')}
        for cfg in ('DebugAnalysis', 'ReleaseAnalysis')}
    # Exclusive creation refuses completed evidence replacement.
    with (bld / 'manifest.json').open('x') as f:
        json.dump(manifest, f, indent=2); f.write('\n')
    print(f'wrote {bld / "manifest.json"} with {len(manifest["artifacts"])} artifacts')


if __name__ == '__main__':
    main()
