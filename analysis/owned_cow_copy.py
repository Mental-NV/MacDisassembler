"""Owned, quiescent copy experiment. No product imports, cleanup or native analysis."""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time

UNSUPPORTED = {errno.ENOTSUP, errno.EXDEV, errno.ENOSYS}


def safe_path(path):
    path = Path(os.path.abspath(path))
    for part in [*reversed(path.parents), path]:
        if part.is_symlink():
            raise ValueError('symlink path component')
    return path


def inventory(root):
    root = safe_path(root)
    if not root.is_dir():
        raise ValueError('input must be directory')
    start = time.perf_counter()
    paths = [root, *sorted(root.rglob('*'))]
    rows = []
    observations = []
    for path in paths:
        info = path.lstat()
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ValueError('nonregular input')
        observations.append({'path': str(path.relative_to(root)), 'mode': stat.S_IMODE(info.st_mode),
                             'device': info.st_dev, 'inode': info.st_ino, 'allocated_blocks': info.st_blocks})
        rows.append({'path': str(path.relative_to(root)), 'kind': 'directory' if path.is_dir() else 'file',
                     'length': info.st_size if path.is_file() else 0})
    traversal = time.perf_counter() - start
    start = time.perf_counter()
    for row, path in zip(rows, paths):
        if row['kind'] == 'file':
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError('input changed type')
                row['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    hashing = time.perf_counter() - start
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'rows': rows, 'observations': observations, 'logical_bytes': sum(r['length'] for r in rows),
            'allocated_blocks_not_unique_storage': sum(r['allocated_blocks'] for r in observations), 'sha256': digest, 'traversal_seconds': traversal, 'hash_seconds': hashing}


def clone_file(source, destination):
    if sys.platform != 'darwin':
        raise RuntimeError('native clone requires macOS')
    libc = ctypes.CDLL(None, use_errno=True)
    call = libc.clonefile
    call.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    call.restype = ctypes.c_int
    if call(os.fsencode(source), os.fsencode(destination), 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def ordinary_file(source, destination):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as src:
        if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
            raise ValueError('nonregular source')
        out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(out, 'wb') as dst:
            shutil.copyfileobj(src, dst)


def fallback_file(source, destination, clone):
    try:
        clone(source, destination)
    except OSError as error:
        if error.errno not in UNSUPPORTED or os.path.lexists(destination):
            raise
        ordinary_file(source, destination)
        return error.errno
    raise ValueError('injected unsupported control unexpectedly succeeded')


def injected_unsupported(source, destination):
    raise OSError(errno.ENOTSUP, 'injected unsupported control')


def copy_tree(source, destination, method, clone=clone_file):
    source, destination = safe_path(source), safe_path(destination)
    if source == destination or source in destination.parents or destination in source.parents:
        raise ValueError('overlapping trees')
    before = inventory(source)
    if destination.exists():
        raise FileExistsError(destination)
    events = []
    started = time.perf_counter()
    if method == 'baseline':
        shutil.copytree(source, destination)
    elif method in {'clone', 'injected-fallback'}:
        for row in before['rows']:
            src, dst = source / row['path'], destination / row['path']
            if row['kind'] == 'directory':
                dst.mkdir(mode=0o700)
                continue
            if method == 'injected-fallback':
                error = fallback_file(src, dst, injected_unsupported)
                events.append({'path': row['path'], 'errno': error, 'injected': True})
            else:
                clone(src, dst)
            shutil.copystat(src, dst, follow_symlinks=False)
    else:
        raise ValueError('unknown method')
    elapsed = time.perf_counter() - started
    after, copied = inventory(source), inventory(destination)
    if before['rows'] != after['rows'] or before['rows'] != copied['rows']:
        raise ValueError('content inventory mismatch')
    inode_pairs = distinct_inodes(source, destination, before['rows'])
    return {'method': method, 'copy_seconds': elapsed, 'source': before, 'destination': copied,
            'distinct_inodes': True, 'inode_pairs': inode_pairs, 'events': events}


def distinct_inodes(source, destination, rows):
    pairs = []
    for row in rows:
        if row['kind'] == 'file':
            a, b = (source / row['path']).stat(), (destination / row['path']).stat()
            left, right = [a.st_dev, a.st_ino], [b.st_dev, b.st_ino]
            if left == right:
                raise ValueError('shared inode')
            pairs.append({'path': row['path'], 'source': left, 'destination': right})
    return pairs


def mutate_and_verify(source, destination, selected, kind, expected_other):
    target = source if kind == 'source-byte' else destination
    other = destination if kind == 'source-byte' else source
    with (target / selected).open('r+b') as out:
        if kind == 'destination-append':
            out.seek(0, 2); out.write(b'owned-control')
        elif kind in {'destination-byte', 'source-byte'}:
            value = out.read(1)
            if len(value) != 1:
                raise ValueError('mutation requires nonempty file')
            out.seek(0); out.write(bytes([value[0] ^ 255]))
        else:
            raise ValueError('unknown mutation')
    actual_other = inventory(other)
    if actual_other['rows'] != expected_other['rows']:
        raise ValueError('mutation leaked to counterpart')
    changed = inventory(target)
    return {'selected_path': selected, 'operation': kind, 'counterpart_preserved': True,
            'counterpart_sha256': actual_other['sha256'], 'mutated_sha256': changed['sha256'],
            'distinct_inode_pairs_after': distinct_inodes(source, destination, expected_other['rows'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owned-source', required=True)
    parser.add_argument('--expected-inventory-sha256', required=True)
    parser.add_argument('--new-scratch-root', required=True)
    args = parser.parse_args()
    source, root = safe_path(args.owned_source), safe_path(args.new_scratch_root)
    original = inventory(source)
    if original['sha256'] != args.expected_inventory_sha256:
        raise ValueError('owned source identity mismatch')
    if source == root or source in root.parents or root in source.parents:
        raise ValueError('overlapping scratch root')
    root.mkdir(mode=0o700)
    report = {'schema': 'owned-copy-experiment/1', 'python': sys.version, 'platform': sys.platform,
              'original_inventory': original, 'samples': [], 'status': 'incomplete'}
    try:
        scratch_source = root / 'source-copy'
        copy_tree(source, scratch_source, 'baseline')
        for trial in range(3):
            order = ['baseline', 'clone'] if trial % 2 == 0 else ['clone', 'baseline']
            for method in order:
                destination = root / f'{trial}-{method}'
                sample = copy_tree(scratch_source, destination, method)
                # Mutations affect scratch copies only, never the original fixture.
                files = [r for r in sample['source']['rows'] if r['kind'] == 'file' and r['length']]
                if not files:
                    raise ValueError('no nonempty file for mutation control')
                chosen = files[0]['path']
                sample['mutation_observations'] = [
                    mutate_and_verify(scratch_source, destination, chosen, 'destination-byte', sample['source']),
                    mutate_and_verify(scratch_source, destination, chosen, 'destination-append', sample['source']),
                ]
                # A separate source scratch copy avoids changing the next trial input.
                reverse_source = root / f'{trial}-{method}-reverse-source'
                reverse_dest = root / f'{trial}-{method}-reverse-dest'
                copy_tree(scratch_source, reverse_source, 'baseline')
                copy_tree(reverse_source, reverse_dest, method)
                reverse_before = inventory(reverse_dest)
                sample['mutation_observations'].append(
                    mutate_and_verify(reverse_source, reverse_dest, chosen, 'source-byte', reverse_before))
                sample['two_way_mutation_isolation'] = True
                report['samples'].append(sample)
        report['injected_fallback'] = copy_tree(scratch_source, root / 'injected-fallback', 'injected-fallback')
        report['status'] = 'completed'
    except Exception as error:
        report['failure'] = {'type': type(error).__name__, 'message': str(error),
                             'errno': getattr(error, 'errno', None)}
        raise
    finally:
        report['original_preserved'] = inventory(source)['rows'] == original['rows']
        if not report['original_preserved']:
            report['status'] = 'source-changed'
        with (root / 'report.json').open('x') as out:
            json.dump(report, out, sort_keys=True, indent=2)
    if not report['original_preserved']:
        raise ValueError('original changed')


if __name__ == '__main__':
    main()
