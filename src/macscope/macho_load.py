"""Bounded, data-only details from selected Mach-O load commands."""
import struct

from .errors import Error


DYLIBS = {0xC: "load", 0xD: "id", 0x80000018: "weak", 0x8000001F: "reexport",
          0x20: "lazy", 0x80000023: "upward"}
LINKEDIT = {0x1D: "code_signature", 0x26: "function_starts", 0x29: "data_in_code",
            0x80000033: "export_trie", 0x80000034: "chained_fixups"}
DYLD_STREAMS = ("rebase", "bind", "weak_bind", "lazy_bind", "export_trie")
MAX_TABLE_ROWS = 10000
MAX_START_TABLE_BYTES = 1024 * 1024


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


def function_starts(data, extent, text):
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
            if len(starts) == MAX_TABLE_ROWS:
                return {"status": "partial", "addresses": starts, "reason": "Function-start row limit"}
            starts.append(hex(address))
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


def details(data, commands, segments):
    text_segments = [s for s in segments if s["name"] == "__TEXT" and s["file_offset"] == "0x0"]
    text = text_segments[0] if len(text_segments) == 1 else None
    metadata = {"preferred_image_base": text["va"] if text else None, "entry_point": None,
                "dylibs": [], "rpaths": [], "linkedit": [], "dyld_streams": []}
    extents = {}
    for cmd, cursor, size in commands:
        if cmd == 0x80000028:
            if size != 24 or metadata["entry_point"] is not None:
                raise Error("entry_command", "Invalid or duplicate LC_MAIN command")
            entry, stack = struct.unpack_from("<2Q",data,cursor+8)
            bounded(entry,1,len(data),"LC_MAIN entry")
            va = hex(int(text["va"],16)+entry) if text and entry<int(text["file_size"],16) else None
            metadata["entry_point"] = {"source": "LC_MAIN", "slice_file_offset": hex(entry),
                                       "va": va, "stack_size": hex(stack)}
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
            offset,count = struct.unpack_from("<2I",data,cursor+56)
            bounded(offset,count*4,len(data),"Indirect symbol table")
            metadata["indirect_symbol_table"] = {"slice_file_offset": hex(offset), "count": count}
    metadata["function_starts"] = function_starts(data,extents.get("function_starts"),text)
    metadata["data_in_code"] = data_in_code(data,extents.get("data_in_code"))
    return metadata
