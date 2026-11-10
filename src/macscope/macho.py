"""Bounded data-only preflight; never loads or executes input code.

Rejecting symlinks in every path component is intentional for this narrow MVP.
It is stricter than future in-bundle framework-link support.
"""
import errno
import hashlib
import os
import plistlib
import stat
import struct
from xml.parsers.expat import ExpatError
from pathlib import Path
from .chained_layout import require_engine_layout
from .errors import Error
from .export_trie import require_engine_trie
from .macho_load import ENCRYPTION_COMMANDS, bounded, details, encryption_region, require_engine_tables

MAX_INPUT = 256 * 1024 * 1024
MAX_COMMANDS = 8192
MAX_SECTIONS_PER_SLICE = 8192
MAX_PLIST = 1024 * 1024
ARCHES = {0x100000c: 'arm64', 0x1000007: 'x86_64'}


def checked_path(path, directory=False):
    p = Path(os.path.abspath(path))
    if len(str(p).encode()) > 4096:
        raise Error('path_limit', 'Path exceeds 4096 bytes')
    for component in [*reversed(p.parents), p]:
        try:
            s = component.lstat()
        except OSError as e:
            raise Error('path_unavailable', str(e)) from e
        if stat.S_ISLNK(s.st_mode):
            raise Error('symlink', 'Symlinks are not supported: ' + str(component))
    s = p.stat()
    if not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)):
        raise Error('file_type', 'Expected ' + ('directory' if directory else 'regular file'))
    return p


def open_directory(path):
    """Open an absolute directory path without following any symlinks."""
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            nextfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = nextfd
        return directory
    except BaseException:
        os.close(directory)
        raise


def read_regular(path, maximum=MAX_INPUT):
    p = checked_path(path)
    directory = None
    try:
        # A parent cannot be swapped for a symlink between lstat and open.
        directory = open_directory(p.parent)
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except OSError as e:
        raise Error('path_changed', 'Path changed or contains a symlink: '+str(e)) from e
    finally:
        if directory is not None:
            os.close(directory)
    try:
        return read_regular_fd(fd, maximum)
    finally:
        os.close(fd)


def read_regular_fd(fd, maximum):
    s = os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or s.st_size > maximum:
        raise Error('input_limit', 'Not a regular file or input exceeds byte limit')
    data = bytearray()
    while len(data) <= maximum:
        chunk = os.read(fd, min(1024 * 1024, maximum + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    after = os.fstat(fd)
    if len(data) > maximum or (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise Error('input_changed', 'Input changed while reading or exceeds limit')
    return bytes(data)


def resolve_input(path):
    p = Path(os.path.abspath(path))
    if p.suffix.lower() != '.app':
        return checked_path(p)
    p = checked_path(p, directory=True)
    raw_info = read_regular(p / 'Contents/Info.plist', MAX_PLIST)
    try:
        info = plistlib.loads(raw_info)
    except (plistlib.InvalidFileException, ValueError, OverflowError, RecursionError, LookupError, ExpatError) as e:
        raise Error('bundle_plist', 'Invalid bounded bundle property list') from e
    name = info.get('CFBundleExecutable') if isinstance(info, dict) else None
    if not isinstance(name, str) or not name or name in ('.', '..') or '/' in name or '\\' in name or '\x00' in name:
        raise Error('bundle_executable', 'CFBundleExecutable must be a single filename')
    binary = checked_path(p / 'Contents/MacOS' / name)
    if not binary.is_relative_to(p):
        raise Error('bundle_escape', 'Executable escapes bundle')
    return binary


def debug_companion_path(executable):
    return executable.with_name(executable.name + '.debug.dylib')


def thin(data, *, allow_arm64e=False, include_section_linkage=False, for_engine=False):
    if len(data) < 32 or data[:4] != b'\xcf\xfa\xed\xfe':
        raise Error('unsupported_format', 'Only little-endian 64-bit Mach-O images are supported', 3)
    _, cpu, subtype, filetype, ncmds, cmdbytes, flags, reserved = struct.unpack_from('<8I', data)
    arch = ARCHES.get(cpu)
    model = subtype & 0xffffff
    if arch == 'arm64' and model == 2 and allow_arm64e:
        arch = 'arm64e'
    elif not arch or (arch == 'arm64' and model != 0) or (arch == 'x86_64' and model != 3):
        raise Error('unsupported_arch', 'Unsupported CPU subtype for this operation', 3)
    if filetype not in (2, 6, 8):
        raise Error('unsupported_filetype', 'Only MH_EXECUTE, MH_DYLIB and MH_BUNDLE are supported', 3)
    if ncmds > MAX_COMMANDS or cmdbytes > 16 * 1024 * 1024 or ncmds * 8 > cmdbytes:
        raise Error('command_limit', 'Invalid or excessive load-command table')
    bounded(32, cmdbytes, len(data), 'Load commands')
    cursor, end = 32, 32 + cmdbytes
    segments, sections, commands, command_records = [], [], [], []
    warnings, uuid, encryption = [], None, None
    for _ in range(ncmds):
        bounded(cursor, 8, end, 'Load command header')
        cmd, size = struct.unpack_from('<2I', data, cursor)
        if size < 8 or size % 8:
            raise Error('command_size', 'Load command size must be aligned and at least 8')
        bounded(cursor, size, end, 'Load command')
        commands.append(hex(cmd))
        command_records.append((cmd,cursor,size))
        if cmd in ENCRYPTION_COMMANDS:
            if encryption is not None:
                raise Error('encryption_bounds', 'Duplicate encryption load command')
            encryption = encryption_region(data, cmd, cursor, size)
            if encryption["cryptid"]:
                raise Error('encrypted', 'Encrypted Mach-O is unsupported', 3,
                            partial={'arch': arch, 'encryption': encryption})
        if cmd == 0x1b:
            if size < 24:
                raise Error('uuid_bounds', 'Truncated UUID command')
            uuid = data[cursor+8:cursor+24].hex()
        if cmd == 0x19:
            if size < 72:
                raise Error('segment_bounds', 'Truncated LC_SEGMENT_64')
            name, va, vmsize, off, filesize, maxprot, prot, nsects, segflags = struct.unpack_from('<16s4Q4I', data, cursor+8)
            bounded(off, filesize, len(data), 'Segment file bytes')
            if filesize > vmsize or nsects > 4096 or 72 + nsects * 80 != size or va + vmsize > 2**64:
                raise Error('section_bounds', 'Invalid segment/section table')
            if len(sections) + nsects > MAX_SECTIONS_PER_SLICE:
                raise Error('section_limit', f'Mach-O slice exceeds {MAX_SECTIONS_PER_SLICE} sections', 7)
            segments.append({'name': name.split(b'\0')[0].decode('utf-8','backslashreplace'),
                             'va': hex(va), 'size': hex(vmsize),
                             'file_offset': hex(off) if filesize else None,
                             'file_size': hex(filesize), 'protections': prot,
                             'max_protections': maxprot, 'flags': hex(segflags)})
            for i in range(nsects):
                at = cursor + 72 + i * 80
                sn, sg, addr, sz, fo, align, reloff, nreloc, sf, r1, r2, r3 = struct.unpack_from('<16s16s2Q8I', data, at)
                zero = (sf & 0xff) in (1, 0xc, 0x12)
                if not zero:
                    bounded(fo, sz, len(data), 'Section bytes')
                    if fo < off or fo + sz > off + filesize:
                        raise Error('section_bounds', 'Section bytes escape owning segment')
                if addr + sz > 2**64 or addr < va or addr + sz > va + vmsize or align > 63:
                    raise Error('section_bounds', 'Invalid section virtual range')
                bounded(reloff, nreloc * 8, len(data), 'Relocations')
                section = {'name': sn.split(b'\0')[0].decode('utf-8', 'backslashreplace'), 'segment': sg.split(b'\0')[0].decode('utf-8', 'backslashreplace'), 'va': hex(addr), 'size': hex(sz), 'file_offset': None if zero else hex(fo), 'protections': prot}
                if include_section_linkage:
                    section.update(flags=hex(sf), reserved1=r1, reserved2=r2)
                sections.append(section)
        cursor += size
    if cursor != end:
        raise Error('command_size', 'Load-command count and byte size disagree')
    loader = details(data,command_records,segments,arch)
    if for_engine:
        require_engine_tables(loader, arch)
        require_engine_layout(data, loader, segments)
        require_engine_trie(data, loader)
    if encryption is not None:
        loader['encryption'] = encryption
    return {'arch': arch, 'cpu_type': cpu, 'cpu_subtype': subtype, 'file_type': filetype,
            'flags': hex(flags), 'uuid': uuid, 'segments': segments, 'sections': sections,
            'load_commands': commands, 'warnings': warnings,
            'loader': loader}


def with_loader_container_offsets(image):
    loader = image["loader"]
    locations = {}
    for key in ("entry_point", "encryption"):
        if (record := loader.get(key)) is not None:
            offset = record["slice_file_offset"]
            location = hex(int(image["offset"], 16) + int(offset, 16)) if offset is not None else None
            locations[key] = dict(record, container_file_offset=location)
    return dict(image, loader=dict(loader, **locations)) if locations else image


def inspect_bytes(data, *, allow_arm64e=False, for_engine=False):
    if len(data) > MAX_INPUT:
        raise Error('input_limit', 'Input exceeds 256 MiB')
    digest = hashlib.sha256(data).hexdigest()
    slices = []
    magic = data[:4]
    if magic in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf', b'\xbe\xba\xfe\xca', b'\xbf\xba\xfe\xca'):
        endian = '>' if magic[:2] == b'\xca\xfe' else '<'
        is64 = magic in (b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
        if len(data) < 8:
            raise Error('fat_header', 'Truncated universal header')
        n = struct.unpack_from(endian+'I', data, 4)[0]
        stride = 32 if is64 else 20
        if not 1 <= n <= 16:
            raise Error('fat_limit', 'Universal slice count must be 1..16')
        bounded(8, n*stride, len(data), 'Universal table')
        spans, arches = [], set()
        for i in range(n):
            record = struct.unpack_from(endian+('IIQQII' if is64 else 'IIIII'), data, 8+i*stride)
            cpu, subtype, off, size, align = record[:5]
            if align > 30 or off % (1 << align) or off < 8+n*stride or not size or (is64 and record[5] != 0):
                raise Error('fat_slice', 'Invalid universal alignment, reserved field or range')
            bounded(off, size, len(data), 'Universal slice')
            if any(off < b and a < off+size for a,b in spans):
                raise Error('fat_overlap', 'Universal slices overlap')
            spans.append((off, off+size))
            meta = thin(data[off:off+size], allow_arm64e=allow_arm64e, for_engine=for_engine)
            if (cpu, subtype) != (meta['cpu_type'], meta['cpu_subtype']) or meta['arch'] in arches:
                raise Error('fat_identity', 'Universal CPU mismatch or duplicate architecture')
            arches.add(meta['arch'])
            slices.append(dict(meta, offset=hex(off), size=hex(size), sha256=hashlib.sha256(data[off:off+size]).hexdigest()))
    else:
        slices.append(dict(thin(data, allow_arm64e=allow_arm64e, for_engine=for_engine), offset='0x0', size=hex(len(data)), sha256=digest))
    slices = [with_loader_container_offsets(s) for s in slices]
    for s in slices:
        s['image_id'] = hashlib.sha256((digest+':'+str(s['cpu_type'])+':'+str(s['cpu_subtype'])+':'+s['offset']+':'+s['size']+':'+s['sha256']).encode()).hexdigest()
    limitations = ['Bounded preflight is not authoritative Ghidra loading.',
                   'No dyld bind/chained-fixup decoding, signature validation or dependency loading in preflight.']
    if any(s['arch'] == 'arm64e' for s in slices):
        limitations.append('arm64e is available for data-only inspection.')
    return {'artifact_sha256': digest, 'size': hex(len(data)), 'slices': slices, 'limitations': limitations}


def inspect_debug_companion(root, executable, *, allow_arm64e):
    candidate = debug_companion_path(executable)
    relative = candidate.relative_to(root).as_posix()
    try:
        parent = open_directory(candidate.parent)
        try:
            info = os.stat(candidate.name, dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ENAMETOOLONG):
                return None
            raise
        finally:
            os.close(parent)
        if stat.S_ISLNK(info.st_mode):
            raise Error('symlink', 'The companion debug image must be a physical file')
        if not stat.S_ISREG(info.st_mode):
            raise Error('file_type', 'The companion debug image must be a regular file')
        evidence = inspect_bytes(read_regular(candidate), allow_arm64e=allow_arm64e)
        if any(image['file_type'] != 6 for image in evidence['slices']):
            raise Error('debug_companion_filetype', 'The companion must contain Mach-O dylib slices')
    except Error as error:
        return {'relative_path':relative, 'status':'unavailable', 'error_code':error.code}
    except OSError:
        return {'relative_path':relative, 'status':'unavailable', 'error_code':'path_unavailable'}
    return {'relative_path':relative, 'status':'verified', 'artifact_sha256':evidence['artifact_sha256'],
            'slices':[{key:image[key] for key in ('arch','image_id','sha256','uuid')}
                      for image in evidence['slices']]}


def inspect_path(path, *, allow_arm64e=False, include_companion=True, for_engine=False):
    root = Path(os.path.abspath(path))
    p = resolve_input(root)
    data = read_regular(p)
    result = inspect_bytes(data, allow_arm64e=allow_arm64e, for_engine=for_engine)
    result['warnings'] = []
    if include_companion and p != root:
        companion = inspect_debug_companion(root, p, allow_arm64e=allow_arm64e)
        if companion is not None:
            result['debug_companion'] = companion
            warning = ('Companion .debug.dylib verified. Use --include-images with its relative path to import it.'
                       if companion['status'] == 'verified' else 'Unable to verify the companion .debug.dylib.')
            result['warnings'].append(warning)
    result['input_name'] = p.name
    return result, data
