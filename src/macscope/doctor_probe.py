"""Generate the package-owned two-instruction Mach-O used by doctor."""
import struct


IMAGE_BASE = 0x100000000
CODE_OFFSET = 0x1000
ENTRY = hex(IMAGE_BASE + CODE_OFFSET)
INSTRUCTIONS = ("40058052", "c0035fd6")  # mov w0, #42; ret


def fixture():
    code = bytes.fromhex("".join(INSTRUCTIONS))
    # MH_MAGIC_64, CPU_TYPE_ARM64, MH_EXECUTE, LC_SEGMENT_64 and LC_MAIN.
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 2, 152 + 24, 0, 0)
    segment = struct.pack("<2I16s4Q4I", 0x19, 152, b"__TEXT", IMAGE_BASE, 0x4000,
                          0, CODE_OFFSET + len(code), 5, 5, 1, 0)
    section = struct.pack("<16s16s2Q8I", b"__text", b"__TEXT", IMAGE_BASE + CODE_OFFSET,
                          len(code), CODE_OFFSET, 2, 0, 0, 0x80000400, 0, 0, 0)
    entry = struct.pack("<2I2Q", 0x80000028, 24, CODE_OFFSET, 0)
    return (header + segment + section + entry).ljust(CODE_OFFSET, b"\0") + code
