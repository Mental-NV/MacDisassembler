"""Explicit native-host contracts, separate from the arm64 Mach-O analysis target.

Linux x86_64 is an experimental compatibility candidate, not a validated Ghidra
installation. Its exact JDK contract is OpenJDK 25.0.1+8 (no vendor suffix).
No Linux ARM support is advertised without a verified Ghidra native layout.
These static checks are not a loader, authenticity check, or security sandbox.
"""
from dataclasses import dataclass
import hashlib
import platform
import struct

from .errors import Error


@dataclass(frozen=True)
class HostPlatform:
    system: str
    machine: str
    native_path: str
    jvm_path: str
    java_build: str
    java_releases: tuple[str, ...]
    java_arch: str
    native_format: str

    def metadata(self):
        """JSON-ready compatibility contract, not evidence of runtime validation."""
        return {
            "system": self.system, "machine": self.machine,
            "native_path": self.native_path, "jvm_path": self.jvm_path,
            "java_build": self.java_build, "java_releases": list(self.java_releases),
            "java_arch": self.java_arch, "native_format": self.native_format,
        }


DARWIN_ARM64 = HostPlatform(
    "Darwin", "arm64", "Ghidra/Features/Decompiler/os/mac_arm_64/decompile",
    "lib/server/libjvm.dylib", "25.0.5.0.3", ("25.0.5", "25.0.5.0.3"),
    "aarch64", "macho")
LINUX_X86_64 = HostPlatform(
    "Linux", "x86_64", "Ghidra/Features/Decompiler/os/linux_x86_64/decompile",
    "lib/server/libjvm.so", "25.0.1+8", ("25.0.1",), "amd64", "elf")


def select_host(system=None, machine=None):
    system = platform.system() if system is None else system
    machine = platform.machine() if machine is None else machine
    for host in (DARWIN_ARM64, LINUX_X86_64):
        if (system, machine) == (host.system, host.machine):
            return host
    raise Error("unsupported_host", "Requires macOS arm64 or experimental Linux x86_64", 4)


def checked_host(host=None):
    """Keep legacy call sites on the exact Mac contract, never implicit detection."""
    if host is None:
        return DARWIN_ARM64
    if host not in (DARWIN_ARM64, LINUX_X86_64):
        raise Error("unsupported_host", "Unrecognized native-host contract", 4)
    return host


def elf_digest(data, *, shared_library=False):
    """Validate bounded ELF64 LE x86_64 load headers; return the whole-file hash.

    Accept ET_EXEC or PIE ET_DYN for executables, ET_DYN only for libjvm.
    Extended/oversized program-header tables and truncated file-backed segments
    fail closed. No native code is executed or external dependencies loaded.
    """
    def reject():
        raise Error("incompatible_elf", "Expected a bounded native ELF64 x86_64 component", 4)

    if not 64 <= len(data) <= 128 * 1024 * 1024:
        reject()
    if data[:7] != b"\x7fELF\x02\x01\x01" or data[7] not in (0, 3) or any(data[9:16]):
        reject()
    (kind, machine, version, entry, phoff, shoff, flags, ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    if (kind not in ((3,) if shared_library else (2, 3)) or machine != 62 or version != 1
            or flags != 0 or ehsize != 64 or phentsize != 56 or not 1 <= phnum <= 1024
            or phoff < 64 or phoff > len(data) or phnum * phentsize > len(data) - phoff):
        reject()
    executable_loads = []
    loads = 0
    for index in range(phnum):
        ptype, pflags, offset, vaddr, paddr, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phentsize)
        if (offset > len(data) or filesz > len(data) - offset
                or memsz > (1 << 64) - 1 - vaddr
                or (align not in (0, 1) and (align & (align - 1)))):
            reject()
        if ptype == 1:
            loads += 1
            if filesz > memsz or (align > 1 and vaddr % align != offset % align) or pflags & ~7:
                reject()
            if pflags & 1 and filesz:
                executable_loads.append((vaddr, vaddr + filesz))
    if not loads or not executable_loads:
        reject()
    if not shared_library and (not entry or not any(start <= entry < end for start, end in executable_loads)):
        reject()
    return hashlib.sha256(data).hexdigest()
