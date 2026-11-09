"""Read ordinary pointer operations from legacy dyld opcode streams."""
import struct

from .errors import Error
from .macho_load import bounded, uleb


MAX_STREAM_BYTES = 1024 * 1024
POINTER_BYTES = 8
SPECIAL_LIBRARIES = {0: "self", -1: "main_executable", -2: "flat_lookup", -3: "weak_lookup"}


class UnsupportedOperation(Exception):
    pass


class Stream:
    def __init__(self, data, offset, size):
        self.data = data
        self.position = offset
        self.end = offset+size

    def byte(self):
        if self.position >= self.end:
            raise ValueError("Truncated dyld opcode stream")
        value = self.data[self.position]
        self.position += 1
        return value

    def unsigned(self):
        value, self.position = uleb(self.data,self.position,self.end)
        return value

    def signed(self):
        value = 0
        for shift in range(0,70,7):
            byte = self.byte()
            value |= (byte & 0x7F) << shift
            if byte < 0x80:
                if byte & 0x40:
                    value -= 1 << (shift+7)
                if -(1<<63) <= value < 1<<63:
                    return value
                break
        raise ValueError("SLEB128 exceeds 64 bits")

    def symbol(self):
        end = self.data.find(b"\0",self.position,min(self.end,self.position+4097))
        if end <= self.position:
            raise ValueError("Missing or oversized dyld bind symbol")
        result = self.data[self.position:end].decode("utf-8","backslashreplace")
        self.position = end+1
        return result

    def verify_padding(self):
        if any(memoryview(self.data)[self.position:self.end]):
            raise ValueError("Nonzero bytes after dyld DONE")


def library_for_ordinal(ordinal, libraries):
    if ordinal > len(libraries):
        raise Error("fixup_ordinal", "Bind library ordinal exceeds its load-command table")
    return libraries[ordinal-1] if ordinal>0 else SPECIAL_LIBRARIES.get(ordinal)


def advance(offset, delta, pointer_bytes=0):
    # ld can encode a backward move as a ULEB128 containing a 64-bit wrap.
    # Interpret that delta without permitting a pointer to wrap out of its segment.
    if delta >= 1<<63:
        delta -= 1<<64
    result = offset+delta+pointer_bytes
    if not 0 <= result < 1<<64:
        raise ValueError("Dyld offset advance exceeds its address space")
    return result


def location(segments, image_offset, segment_index, offset):
    if segment_index is None or segment_index >= len(segments):
        raise ValueError("Dyld opcode did not select a valid segment")
    segment = segments[segment_index]
    bounded(offset,POINTER_BYTES,int(segment["size"],16),"Legacy fixup in segment")
    file_offset = segment["file_offset"]
    at = None
    if file_offset is not None and offset+POINTER_BYTES <= int(segment["file_size"],16):
        at = int(file_offset,16)+offset
    return at, {"address_space":"ram", "va":hex(int(segment["va"],16)+offset),
                "slice_file_offset":hex(at) if at is not None else None,
                "container_file_offset":hex(image_offset+at) if at is not None else None}


def rebase_rows(stream, segments, image_offset):
    segment, offset, pointer_type = None, 0, 0
    while stream.position < stream.end:
        code = stream.byte()
        opcode, immediate = code&0xF0,code&0xF
        count = skip = 0
        if opcode==0x00:
            stream.verify_padding()
            return
        if opcode==0x10:
            pointer_type = immediate
        elif opcode==0x20:
            segment, offset = immediate, stream.unsigned()
        elif opcode==0x30:
            offset = advance(offset,stream.unsigned())
        elif opcode==0x40:
            offset += immediate*POINTER_BYTES
        elif opcode==0x50:
            count = immediate
        elif opcode==0x60:
            count = stream.unsigned()
        elif opcode==0x70:
            count, skip = 1, stream.unsigned()
        elif opcode==0x80:
            count, skip = stream.unsigned(), stream.unsigned()
        else:
            raise UnsupportedOperation("opcode_"+hex(opcode))
        for _ in range(count):
            if pointer_type!=1:
                raise UnsupportedOperation("type_"+str(pointer_type))
            at,row = location(segments,image_offset,segment,offset)
            if at is None:
                raise UnsupportedOperation("unbacked_rebase")
            target = hex(struct.unpack_from("<Q",stream.data,at)[0])
            yield dict(row,kind="rebase",stream="rebase",target_va=target,raw=target)
            offset = advance(offset,skip,POINTER_BYTES)
    raise ValueError("Missing dyld rebase DONE")


def bind_rows(stream, stream_name, segments, image_offset, libraries):
    lazy = stream_name=="lazy_bind"
    initial_ordinal = -3 if stream_name=="weak_bind" else None
    segment,offset,ordinal,symbol,addend,flags = None,0,initial_ordinal,None,0,0
    pointer_type = 1
    terminated = False
    while stream.position < stream.end:
        code = stream.byte()
        opcode, immediate = code&0xF0,code&0xF
        count = skip = 0
        if opcode==0x00:
            if not lazy:
                stream.verify_padding()
                return
            segment,offset,ordinal,symbol,addend,flags = None,0,initial_ordinal,None,0,0
            pointer_type = 1
            terminated = True
            continue
        terminated = False
        if opcode==0x10:
            ordinal = immediate
        elif opcode==0x20:
            ordinal = stream.unsigned()
        elif opcode==0x30:
            ordinal = immediate-16 if immediate else 0
        elif opcode==0x40:
            symbol,flags = stream.symbol(),immediate
        elif opcode==0x50:
            pointer_type = immediate
        elif opcode==0x60:
            addend = stream.signed()
        elif opcode==0x70:
            segment,offset = immediate,stream.unsigned()
        elif opcode==0x80:
            offset = advance(offset,stream.unsigned())
        elif opcode==0x90:
            count = 1
        elif opcode==0xA0:
            count,skip = 1,stream.unsigned()
        elif opcode==0xB0:
            count,skip = 1,immediate*POINTER_BYTES
        elif opcode==0xC0:
            count,skip = stream.unsigned(),stream.unsigned()
        else:
            raise UnsupportedOperation("opcode_"+hex(opcode))
        for _ in range(count):
            if pointer_type!=1:
                raise UnsupportedOperation("type_"+str(pointer_type))
            if symbol is None or ordinal is None:
                raise ValueError("Dyld bind did not select a symbol and library ordinal")
            _,row = location(segments,image_offset,segment,offset)
            library = library_for_ordinal(ordinal,libraries)
            yield dict(row,kind="bind",stream=stream_name,target_va=None,symbol=symbol,library=library,
                       library_ordinal=ordinal,symbol_flags=hex(flags),weak_import=bool(flags&1),
                       import_addend=addend,resolution="declared_symbol" if library else "unresolved_library_ordinal")
            offset = advance(offset,skip,POINTER_BYTES)
    if not terminated:
        raise ValueError("Missing dyld bind DONE")


def decode_legacy(data, image, parsed, streams, max_fixups):
    result = {"format":"legacy", "streams":[stream["kind"] for stream in streams]}
    if len(result["streams"])!=len(set(result["streams"])):
        raise Error("fixup_layout", "Ambiguous legacy dyld streams")
    libraries = [d["path"] for d in parsed["loader"]["dylibs"] if d["kind"]!="id"]
    segments = parsed["segments"]
    image_offset = int(image["offset"],16)
    records, gaps = [], []
    for extent in streams:
        name = extent["kind"]
        offset,size = int(extent["slice_file_offset"],16),int(extent["size"],16)
        if size>MAX_STREAM_BYTES:
            gaps.append(name+"_stream_limit")
            continue
        stream = Stream(data,offset,size)
        rows = (rebase_rows(stream,segments,image_offset) if name=="rebase"
                else bind_rows(stream,name,segments,image_offset,libraries))
        try:
            for row in rows:
                if len(records)==max_fixups:
                    return result,records,[*gaps,"fixup_limit"]
                records.append(row)
        except UnsupportedOperation as error:
            gaps.append(name+"_"+str(error))
        except ValueError as error:
            raise Error("legacy_fixup_stream", f"Malformed {name} stream: {error}") from error
    return result,records,gaps
