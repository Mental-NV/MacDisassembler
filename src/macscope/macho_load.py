"""Bounded, data-only details from selected Mach-O load commands."""
import struct

from .errors import Error


DYLIBS = {0xC: "load", 0xD: "id", 0x80000018: "weak", 0x8000001F: "reexport",
          0x20: "lazy", 0x80000023: "upward"}
LINKEDIT = {0x1D: "code_signature", 0x26: "function_starts", 0x29: "data_in_code",
            0x80000033: "export_trie", 0x80000034: "chained_fixups"}
DYLD_STREAMS = ("rebase", "bind", "weak_bind", "lazy_bind", "export_trie")
# On-disk record widths from mach-o/loader.h and mach-o/reloc.h.
DYSYMTAB_TABLES = (
    ("Dynamic symbol table of contents", 8),
    ("64-bit dynamic module table", 56),
    ("External symbol reference table", 4),
    ("Indirect symbol table", 4),
    ("External relocation table", 8),
    ("Local relocation table", 8),
)
MAX_TABLE_ROWS = 10000
MAX_START_TABLE_BYTES = 1024 * 1024
THREAD_ENTRY = {"arm64": (6, 68, 32), "x86_64": (4, 42, 16)}
MAX_THREAD_STATES = 32
LEGACY_DEPLOYMENT = {0x24: ("LC_VERSION_MIN_MACOSX", "macos"), 0x25: ("LC_VERSION_MIN_IPHONEOS", "ios"),
                     0x2f: ("LC_VERSION_MIN_TVOS", "tvos"), 0x30: ("LC_VERSION_MIN_WATCHOS", "watchos")}
DEPLOYMENT_COMMANDS = (*LEGACY_DEPLOYMENT, 0x32)
ENCRYPTION_COMMANDS = {0x21: "LC_ENCRYPTION_INFO", 0x2c: "LC_ENCRYPTION_INFO_64"}
PLATFORMS = {
    1: "macos", 2: "ios", 3: "tvos", 4: "watchos", 5: "bridgeos", 6: "maccatalyst",
    7: "ios-simulator", 8: "tvos-simulator", 9: "watchos-simulator", 10: "driverkit",
    11: "visionos", 12: "visionos-simulator", 13: "firmware", 14: "sepos",
    15: "macos-exclavecore", 16: "macos-exclavekit", 17: "ios-exclavecore", 18: "ios-exclavekit",
    19: "tvos-exclavecore", 20: "tvos-exclavekit", 21: "watchos-exclavecore", 22: "watchos-exclavekit",
    23: "visionos-exclavecore", 24: "visionos-exclavekit",
}
TOOLS = {1: "clang", 2: "swift", 3: "ld", 4: "lld", 1024: "metal", 1025: "airlld",
         1026: "airnt", 1027: "airnt-plugin", 1028: "airpack", 1031: "gpuarchiver", 1032: "metal-framework"}
MAX_DEPLOYMENT_COMMANDS = 16
MAX_BUILD_TOOLS = 128


def bounded(off, size, total, label):
    if off < 0 or size < 0 or off > total or size > total - off:
        raise Error("macho_bounds", label + " exceeds file bounds")


def command_string(data, start, size, offset, minimum):
    if not minimum <= offset < size:
        raise Error("command_string", "Load-command string offset is out of bounds")
    position = start + offset
    end = data.find(b"\0", position, min(start+size, position+4097))
    if end <= position:
        raise Error("command_string", "Load-command string is empty, unterminated or exceeds its limit")
    return data[position:end].decode("utf-8", "backslashreplace")


def version(value):
    return f"{value >> 16}.{(value >> 8) & 255}.{value & 255}"


def deployment(data, command, cursor, size):
    if command in LEGACY_DEPLOYMENT:
        if size != 16:
            raise Error("deployment_bounds", "Invalid legacy minimum-version command size")
        minimum, sdk = struct.unpack_from("<II", data, cursor + 8)
        name, platform = LEGACY_DEPLOYMENT[command]
        return {"command": name, "platform": platform, "platform_id": None,
                "minimum_os": version(minimum), "sdk": version(sdk), "tools": []}
    if size < 24:
        raise Error("deployment_bounds", "Truncated LC_BUILD_VERSION header")
    platform, minimum, sdk, count = struct.unpack_from("<4I", data, cursor + 8)
    if size != 24 + count * 8:
        raise Error("deployment_bounds", "LC_BUILD_VERSION tool count disagrees with command size")
    if count > MAX_BUILD_TOOLS:
        raise Error("deployment_limit", "LC_BUILD_VERSION tool count exceeds its limit", 7)
    tools = []
    for at in range(cursor + 24, cursor + size, 8):
        tool, build = struct.unpack_from("<II", data, at)
        tools.append({"tool_id": tool, "name": TOOLS.get(tool), "version": version(build)})
    return {"command": "LC_BUILD_VERSION", "platform": PLATFORMS.get(platform), "platform_id": platform,
            "minimum_os": version(minimum), "sdk": version(sdk), "tools": tools}


def source_version(data, cursor, size):
    if size != 16:
        raise Error("source_version_bounds", "Invalid LC_SOURCE_VERSION command size")
    value, = struct.unpack_from("<Q", data, cursor + 8)
    parts = [value >> 40, *((value >> shift) & 0x3ff for shift in (30, 20, 10, 0))]
    return {"command": "LC_SOURCE_VERSION", "version": ".".join(map(str, parts)), "raw": hex(value)}


def encryption_region(data, command, cursor, size):
    if (command == 0x2c and size != 24) or (command == 0x21 and size < 20):
        raise Error("encryption_bounds", "Invalid encryption command size")
    offset, length, cryptid = struct.unpack_from("<3I", data, cursor + 8)
    bounded(offset, length, len(data), "Encrypted region")
    return {"command": ENCRYPTION_COMMANDS[command], "cryptid": cryptid,
            "slice_file_offset": hex(offset), "size": hex(length)}


def dylib(data, command, cursor, size):
    if size < 24:
        raise Error("dylib_bounds", "Truncated dylib load command")
    name_offset, timestamp, current, compatible = struct.unpack_from("<4I", data, cursor+8)
    use_encoding = command in (0xC, 0x80000018) and timestamp == 0x1A741800 and name_offset == 28
    path = command_string(data,cursor,size,name_offset,28 if use_encoding else 24)
    flags = hex(struct.unpack_from("<I",data,cursor+24)[0]) if use_encoding else None
    return {"kind": DYLIBS[command], "path": path, "timestamp": None if use_encoding else timestamp,
            "current_version": version(current), "compatibility_version": version(compatible),
            "use_flags": flags}


def uleb(data, position, end):
    result = 0
    for shift in range(0, 70, 7):
        if position >= end:
            raise ValueError("Truncated ULEB128")
        byte = data[position]
        position += 1
        if shift == 63 and byte > 1:
            raise ValueError("ULEB128 exceeds 64 bits")
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, position
    raise ValueError("ULEB128 exceeds 64 bits")


def function_starts(data, extent, text, *, selected=None):
    if not extent:
        return None
    if len(extent) != 1 or text is None:
        return {"status": "unavailable", "addresses": [], "reason": "Ambiguous table or __TEXT mapping"}
    offset, size = extent[0]
    if not size:
        return {"status": "complete", "addresses": []}
    if size > MAX_START_TABLE_BYTES:
        return {"status": "partial", "addresses": [], "reason": "Function-start byte limit"}
    end = offset+size
    address = int(text["va"],16)
    limit = address+int(text["file_size"],16)
    starts = []
    found = False
    try:
        while offset < end:
            delta, offset = uleb(data,offset,end)
            if not delta:
                if any(memoryview(data)[offset:end]):
                    raise ValueError("Nonzero bytes after function-start terminator")
                return {"status": "complete", "addresses": starts}
            address += delta
            if address >= limit:
                raise ValueError("Function start outside file-backed __TEXT")
            if selected is None:
                if len(starts) == MAX_TABLE_ROWS:
                    return {"status": "partial", "addresses": starts, "reason": "Function-start row limit"}
                starts.append(hex(address))
            elif found:
                starts.append(hex(address))
                found = False
            elif address == selected:
                starts.append(hex(address))
                found = True
        raise ValueError("Missing function-start terminator")
    except ValueError as error:
        return {"status": "malformed", "addresses": [], "reason": str(error)}


def data_in_code(data, extent):
    if not extent:
        return None
    if len(extent) != 1:
        return {"status": "unavailable", "records": [], "reason": "Ambiguous data-in-code table"}
    offset, size = extent[0]
    if size % 8:
        return {"status": "malformed", "records": [], "reason": "Misaligned data-in-code table"}
    count = size//8
    rows = []
    for at in range(offset,offset+min(count,MAX_TABLE_ROWS)*8,8):
        start, length, kind = struct.unpack_from("<IHH",data,at)
        if not length or start+length > len(data):
            return {"status": "malformed", "records": [], "reason": "Invalid data-in-code range"}
        rows.append({"slice_file_offset": hex(start), "length": length, "kind": hex(kind)})
    return {"status": "complete" if count==len(rows) else "partial", "records": rows, "total": count}


def map_entry(record, va, text, segments):
    record.update(va=hex(va) if va is not None else None, rva=None, slice_file_offset=None)
    if va is None:
        return dict(record, status="unavailable", reason="Preferred image base unavailable")
    if text is not None and va >= int(text["va"], 16):
        record["rva"] = hex(va - int(text["va"], 16))
    containing = [segment for segment in segments
                  if 0 <= va - int(segment["va"], 16) < int(segment["size"], 16)]
    if len(containing) != 1:
        return dict(record, status="unavailable", reason="Entry has no unique segment mapping")
    segment = containing[0]
    delta = va - int(segment["va"], 16)
    if not segment["protections"] & 4 or delta >= int(segment["file_size"], 16):
        return dict(record, status="unavailable", reason="Entry is outside executable file-backed bytes")
    return dict(record, status="complete", slice_file_offset=hex(int(segment["file_offset"], 16) + delta))


def main_entry(data, cursor, size, text, segments):
    if size != 24:
        raise Error("entry_command", "Invalid LC_MAIN command size")
    offset, stack = struct.unpack_from("<2Q", data, cursor + 8)
    va = int(text["va"], 16) + offset if text else None
    if va is not None and va >= 2**64:
        raise Error("entry_command", "LC_MAIN address exceeds the image address space")
    return map_entry({"source": "LC_MAIN", "declared_entry_offset": hex(offset), "stack_size": hex(stack)},
                     va, text, segments)


def thread_entry(data, cursor, size, arch, text, segments):
    at, end = cursor + 8, cursor + size
    states, pcs = [], []
    layout = THREAD_ENTRY.get(arch)
    while at < end:
        if states and end - at == 4 and not any(data[at:end]):
            break  # A 32-bit auxiliary state can leave one alignment word.
        if end - at < 8:
            raise Error("entry_thread_bounds", "Truncated LC_UNIXTHREAD state header")
        if len(states) == MAX_THREAD_STATES:
            raise Error("entry_thread_limit", "LC_UNIXTHREAD state count exceeds its limit", 7)
        flavor, count = struct.unpack_from("<II", data, at)
        payload = at + 8
        if not count or count * 4 > end - payload:
            raise Error("entry_thread_bounds", "Invalid LC_UNIXTHREAD state extent")
        state = {"flavor": flavor, "word_count": count, "slice_file_offset": hex(payload)}
        states.append(state)
        if layout is not None and flavor == layout[0]:
            _, expected, register = layout
            if count != expected:
                raise Error("entry_thread_bounds", "Unexpected LC_UNIXTHREAD general register state size")
            pc_offset = payload + register * 8
            pcs.append((len(states), struct.unpack_from("<Q", data, pc_offset)[0]))
            state["pc_slice_file_offset"] = hex(pc_offset)
        at = payload + count * 4
    if not states:
        raise Error("entry_thread_bounds", "Missing LC_UNIXTHREAD state")
    if len(pcs) > 1:
        raise Error("entry_command", "Duplicate LC_UNIXTHREAD general register state")
    record = {"source": "LC_UNIXTHREAD", "stack_size": None, "thread_states": states}
    if not pcs or pcs[0][0] != 1:
        return dict(record, status="unsupported", reason="Initial LC_UNIXTHREAD state layout is unsupported",
                    va=None, rva=None, slice_file_offset=None)
    return map_entry(record, pcs[0][1], text, segments)


def details(data, commands, segments, arch):
    text_segments = [s for s in segments if s["name"] == "__TEXT" and s["file_offset"] == "0x0"]
    text = text_segments[0] if len(text_segments) == 1 else None
    metadata = {"preferred_image_base": text["va"] if text else None, "entry_point": None,
                "dylibs": [], "rpaths": [], "linkedit": [], "dyld_streams": []}
    extents = {}
    symbol_groups = None
    for cmd, cursor, size in commands:
        if cmd in (0x80000028, 0x5):
            if metadata["entry_point"] is not None:
                raise Error("entry_command", "Multiple Mach-O process entry commands")
            metadata["entry_point"] = (main_entry(data, cursor, size, text, segments) if cmd == 0x80000028
                                       else thread_entry(data, cursor, size, arch, text, segments))
        elif cmd in DEPLOYMENT_COMMANDS:
            records = metadata.setdefault("deployment", [])
            if len(records) == MAX_DEPLOYMENT_COMMANDS:
                raise Error("deployment_limit", "Deployment command count exceeds its limit", 7)
            records.append(deployment(data, cmd, cursor, size))
        elif cmd == 0x2a:
            if "source_version" in metadata:
                raise Error("source_version_bounds", "Duplicate LC_SOURCE_VERSION command")
            metadata["source_version"] = source_version(data, cursor, size)
        elif cmd in DYLIBS:
            metadata["dylibs"].append(dylib(data,cmd,cursor,size))
        elif cmd == 0x8000001C:
            if size < 12:
                raise Error("rpath_bounds", "Truncated LC_RPATH")
            offset = struct.unpack_from("<I",data,cursor+8)[0]
            metadata["rpaths"].append(command_string(data,cursor,size,offset,12))
        elif cmd in LINKEDIT:
            if size < 16:
                raise Error("linkedit_bounds", "Truncated linkedit command")
            offset, length = struct.unpack_from("<2I",data,cursor+8)
            bounded(offset,length,len(data),"Linkedit payload")
            kind = LINKEDIT[cmd]
            extents.setdefault(kind,[]).append((offset,length))
            metadata["linkedit"].append({"kind": kind, "slice_file_offset": hex(offset), "size": hex(length)})
        elif cmd in (0x22,0x80000022):
            if size != 48:
                raise Error("dyld_info_bounds", "Invalid dyld info command size")
            for index,kind in enumerate(DYLD_STREAMS):
                offset,length = struct.unpack_from("<2I",data,cursor+8+index*8)
                bounded(offset,length,len(data),"Dyld "+kind)
                metadata["dyld_streams"].append({"kind": kind,"slice_file_offset": hex(offset),"size": hex(length)})
        elif cmd == 2:
            if size != 24 or "symbol_table" in metadata:
                raise Error("symtab_bounds", "Invalid or duplicate LC_SYMTAB command")
            offset,count,strings,length = struct.unpack_from("<4I",data,cursor+8)
            bounded(offset,count*16,len(data),"Symbol table")
            bounded(strings,length,len(data),"String table")
            metadata["symbol_table"] = {"slice_file_offset": hex(offset), "count": count,
                                        "strings_offset": hex(strings), "strings_size": hex(length)}
        elif cmd == 0xB:
            if size != 80 or "indirect_symbol_table" in metadata:
                raise Error("dysymtab_bounds", "Invalid or duplicate LC_DYSYMTAB command")
            fields = struct.unpack_from("<18I", data, cursor + 8)
            symbol_groups = fields[:6]
            for index, (label, entry_size) in enumerate(DYSYMTAB_TABLES):
                offset, count = fields[6 + 2 * index:8 + 2 * index]
                bounded(offset, count * entry_size, len(data), label)
            offset, count = fields[12:14]
            metadata["indirect_symbol_table"] = {"slice_file_offset": hex(offset), "count": count}
    if symbol_groups is not None:
        if "symbol_table" not in metadata:
            raise Error("dysymtab_bounds", "LC_DYSYMTAB requires LC_SYMTAB")
        symbol_count = metadata["symbol_table"]["count"]
        for start, count in zip(symbol_groups[::2], symbol_groups[1::2]):
            if start > symbol_count or count > symbol_count - start:
                raise Error("dysymtab_bounds", "Dynamic symbol group exceeds the symbol table")
    metadata["function_starts"] = function_starts(data,extents.get("function_starts"),text)
    metadata["data_in_code"] = data_in_code(data,extents.get("data_in_code"))
    return metadata
