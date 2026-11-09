"""Bounded, data-only inventory of an application bundle."""
import hashlib
from itertools import islice
import os
from pathlib import Path, PurePosixPath
import stat

from .errors import Error
from .macho import MAX_INPUT, open_directory, resolve_input


MAX_ENTRIES = 10000
MAX_DEPTH = 16
MAX_HASH_BYTES = 512 * 1024 * 1024
THIN_MAGIC = {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
              b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"}
FAT_MAGIC = {b"\xca\xfe\xba\xbe": "big", b"\xca\xfe\xba\xbf": "big",
             b"\xbe\xba\xfe\xca": "little", b"\xbf\xba\xfe\xca": "little"}


def looks_like_image(header):
    magic = header[:4]
    if magic in THIN_MAGIC:
        return len(header) >= 28
    if magic in FAT_MAGIC and len(header) >= 8:
        return 1 <= int.from_bytes(header[4:8], FAT_MAGIC[magic]) <= 16
    return False


def fingerprint(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def inventory(path, kind):
    path = Path(os.path.abspath(path))
    if path.suffix.lower() != ".app":
        raise Error("bundle_required", "Select a macOS .app bundle", 2)
    executable, warnings = resolve_input(path)
    main = executable.relative_to(path).as_posix()
    rows = []
    gaps = set()
    seen = 0
    hashed = 0

    def file_record(directory, name, info, row):
        nonlocal hashed
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or fingerprint(before) != fingerprint(info):
                raise OSError("Bundle file changed during inventory")
            header = os.read(fd, min(32, before.st_size))
            if len(header) != min(32, before.st_size):
                raise OSError("Short bundle header read")
            is_image = looks_like_image(header)
            category = "images" if is_image else "resources"
            if fingerprint(os.fstat(fd)) != fingerprint(before):
                raise OSError("Bundle file changed during inventory")
            if kind not in ("all", category):
                return
            row["type"] = "macho_candidate" if is_image else "resource"
            row["size"] = before.st_size
            row["resource_type"] = None if is_image else Path(name).suffix.lower().lstrip(".") or "file"
            if before.st_size > MAX_INPUT or hashed + before.st_size > MAX_HASH_BYTES:
                row["status"] = "hash_limit"
                gaps.add("hash_limit")
                rows.append(row)
                return
            digest = hashlib.sha256(header)
            hashed += len(header)
            remaining = before.st_size - len(header)
            while remaining:
                block = os.read(fd, min(remaining, 1024 * 1024))
                if not block:
                    raise OSError("Short bundle file read")
                digest.update(block)
                hashed += len(block)
                remaining -= len(block)
            if fingerprint(os.fstat(fd)) != fingerprint(before):
                raise OSError("Bundle file changed during inventory")
            row.update(sha256=digest.hexdigest(), status="complete")
            rows.append(row)
        finally:
            os.close(fd)

    def walk(directory, parent, depth):
        nonlocal seen
        before = fingerprint(os.fstat(directory))
        allowance = MAX_ENTRIES - seen
        with os.scandir(directory) as entries:
            names = sorted(item.name for item in islice(entries, allowance + 1))
        if len(names) > allowance:
            gaps.add("entry_limit")
        for name in names[:allowance]:
            if seen >= MAX_ENTRIES:
                gaps.add("entry_limit")
                break
            seen += 1
            relative = parent / name
            relative_path = relative.as_posix()
            row = {"relative_path": relative_path, "main_executable": relative_path == main,
                   "sha256": None, "size": None, "resource_type": None}
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if info.st_dev != before[0]:
                        gaps.add("mount_boundary")
                        continue
                    if depth >= MAX_DEPTH:
                        gaps.add("depth_limit")
                        continue
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    try:
                        if fingerprint(os.fstat(child)) != fingerprint(info):
                            raise OSError("Bundle directory changed during inventory")
                        walk(child, relative, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    file_record(directory, name, info, row)
                elif kind == "all":
                    row.update(type="symlink" if stat.S_ISLNK(info.st_mode) else "special",
                               status="metadata_only")
                    rows.append(row)
            except OSError:
                gaps.add("entry_unavailable")
                if kind == "all":
                    row.update(type="unavailable", status="unavailable")
                    rows.append(row)
        if fingerprint(os.fstat(directory)) != before:
            gaps.add("bundle_changed")

    try:
        root = open_directory(path)
    except OSError as error:
        raise Error("bundle_path_changed", "Bundle directory changed before inventory") from error
    try:
        walk(root, PurePosixPath(), 0)
    except OSError as error:
        raise Error("bundle_unavailable", "Unable to enumerate the bundle directory") from error
    finally:
        os.close(root)
    rows.sort(key=lambda row: row["relative_path"])
    return {"bundle_name": path.name, "main_executable": main, "kind": kind,
            "entries_scanned": seen, "bytes_hashed": hashed, "warnings": warnings,
            "records": rows}, sorted(gaps)
