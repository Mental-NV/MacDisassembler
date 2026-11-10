"""Bounded, data-only inventory of an application bundle."""
import hashlib
from collections import deque
from contextlib import ExitStack, contextmanager
from itertools import islice
import os
from pathlib import Path, PurePosixPath
import stat

from .errors import Error
from .macho import MAX_INPUT, debug_companion_path, open_directory, resolve_input


MAX_ENTRIES = 10000
MAX_DEPTH = 16
MAX_HASH_BYTES = 512 * 1024 * 1024
MAX_SELECTED_IMAGES = 64
MAX_LINKS = 8
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


@contextmanager
def resource_scope(root, relative, gaps):
    """Pin every directory in the selected path while inventorying its subtree."""
    with ExitStack() as opened:
        directories = [root]
        try:
            device = os.fstat(root).st_dev
            for part in relative.parts:
                parent = directories[-1]
                info = os.stat(part, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or info.st_dev != device:
                    raise Error("resource_directory", "Resource scope must be a physical directory within the bundle filesystem", 5)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                opened.callback(os.close, child)
                if fingerprint(os.fstat(child)) != fingerprint(info):
                    raise Error("resource_directory", "Resource directory changed during selection", 5)
                directories.append(child)
        except OSError as error:
            raise Error("resource_directory", "Resource directory is missing, unreadable or changed during selection", 5) from error
        yield directories[-1]
        for parent, part, child in zip(directories, relative.parts, directories[1:]):
            try:
                current = os.stat(part, dir_fd=parent, follow_symlinks=False)
                if not os.path.samestat(current, os.fstat(child)):
                    gaps.add("bundle_changed")
            except OSError:
                gaps.add("bundle_changed")


def inventory(path, kind, *, resource_type=None, resource_directory=None):
    path = Path(os.path.abspath(path))
    if path.suffix.lower() != ".app":
        raise Error("bundle_required", "Select a macOS .app bundle", 2)
    if resource_directory is not None:
        relative = PurePosixPath(resource_directory)
        if (not relative.parts or relative.is_absolute() or relative.as_posix() != resource_directory
                or ".." in relative.parts or "\0" in resource_directory or len(relative.parts) > MAX_DEPTH
                or len(os.fsencode(resource_directory)) > 4096):
            raise Error("resource_directory", "Select an exact bundle-relative resource directory", 2)
    executable = resolve_input(path)
    main = executable.relative_to(path).as_posix()
    companion = debug_companion_path(executable).relative_to(path).as_posix()
    warnings = []
    rows = []
    gaps = set()
    seen = 0
    hashed = 0

    def file_record(directory, name, info, row):
        nonlocal hashed
        suffix = Path(name).suffix.lower().lstrip(".") or "file"
        if resource_type is not None and suffix != resource_type:
            return
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
            row["resource_type"] = None if is_image else suffix
            if is_image and row["relative_path"] == companion:
                row["debug_companion_candidate"] = True
                warnings.append("Companion .debug.dylib candidate found. Use inspect to verify it.")
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
        if resource_directory is None:
            walk(root, PurePosixPath(), 0)
        else:
            with resource_scope(root, relative, gaps) as directory:
                walk(directory, relative, len(relative.parts))
    except OSError as error:
        raise Error("bundle_unavailable", "Unable to enumerate the bundle directory") from error
    finally:
        os.close(root)
    rows.sort(key=lambda row: row["relative_path"])
    result = {"bundle_name": path.name, "main_executable": main, "kind": kind,
              "entries_scanned": seen, "bytes_hashed": hashed, "warnings": warnings, "records": rows}
    if resource_directory is not None:
        result["resource_directory"] = resource_directory
    return result, sorted(gaps)


def physical_image(root, requested):
    """Resolve relative framework links through directory descriptors anchored at the bundle."""
    relative = PurePosixPath(requested)
    if (not relative.parts or relative.is_absolute() or relative.as_posix() != requested
            or ".." in relative.parts or "\0" in requested or len(os.fsencode(requested)) > 4096
            or len(relative.parts) > MAX_DEPTH + 1):
        raise Error("bundle_image_path", "Select an exact bundle-relative image path", 2)
    remaining = deque(relative.parts)
    directories = []
    physical = []
    links = 0
    try:
        directories.append(open_directory(root))
        device = os.fstat(directories[0]).st_dev
        while remaining:
            part = remaining.popleft()
            if part == "..":
                if not physical:
                    raise Error("bundle_link_escape", "Embedded image link escapes the bundle", 5)
                os.close(directories.pop())
                physical.pop()
                continue
            directory = directories[-1]
            info = os.stat(part, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                target = PurePosixPath(os.readlink(part, dir_fd=directory))
                links += 1
                if target.is_absolute():
                    raise Error("bundle_link_escape", "Embedded image link must be relative to the bundle", 5)
                if links > MAX_LINKS or len(target.parts) + len(remaining) > 256:
                    raise Error("bundle_link_limit", "Embedded image link chain exceeds its bound", 7)
                remaining.extendleft(reversed(target.parts))
            elif remaining:
                if not stat.S_ISDIR(info.st_mode):
                    raise Error("bundle_image_path", "An embedded image parent is not a directory", 5)
                if len(physical) >= MAX_DEPTH:
                    raise Error("bundle_link_limit", "Embedded image path exceeds the directory depth limit", 7)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                directories.append(child)
                if fingerprint(os.fstat(child)) != fingerprint(info) or info.st_dev != device:
                    raise Error("bundle_image_path", "Embedded image directory changed or crosses a mount", 5)
                physical.append(part)
            else:
                if not stat.S_ISREG(info.st_mode):
                    raise Error("bundle_image_path", "Embedded image must be a regular file", 5)
                return PurePosixPath(*physical, part).as_posix(), info.st_size
        raise Error("bundle_image_path", "Embedded image link resolves to a directory", 5)
    except OSError as error:
        raise Error("bundle_image_path", "Embedded image is missing or changed during selection", 5) from error
    finally:
        for directory in reversed(directories):
            os.close(directory)


def select_images(path, requested):
    root = Path(os.path.abspath(path))
    if root.suffix.lower() != ".app":
        raise Error("bundle_required", "--include-images requires a macOS .app bundle", 2)
    main = resolve_input(root).relative_to(root).as_posix()
    if len(requested) >= MAX_SELECTED_IMAGES or ("all" in requested and requested != ["all"]):
        raise Error("bundle_image_selection", "Use all alone or select at most 63 embedded paths", 2)
    if requested == ["all"]:
        manifest, gaps = inventory(root, "images")
        if gaps:
            raise Error("bundle_inventory_incomplete", "Image inventory is partial; select explicit paths", 7)
        rows = {row["relative_path"]: row for row in manifest["records"]}
        if main not in rows:
            raise Error("bundle_image_path", "The bundle main executable is missing or has an unsupported header", 5)
        order = [main, *(path for path in rows if path != main)]
        if len(order) > MAX_SELECTED_IMAGES:
            raise Error("bundle_image_selection", "Bundle exceeds 64 images; select explicit paths", 7)
        return [(root / relative, relative, rows[relative]["sha256"]) for relative in order]
    selected = {}
    for relative in [main, *requested]:
        canonical, size = physical_image(root, relative)
        selected[canonical] = size
    if sum(selected.values()) > MAX_HASH_BYTES:
        raise Error("bundle_input_limit", "Selected bundle images exceed the 512 MiB aggregate limit", 7)
    return [(root / relative, relative, None) for relative in selected]
