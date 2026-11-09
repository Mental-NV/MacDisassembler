"""Swift symbol-table candidates and an explicit native demangler."""
import hashlib
from pathlib import Path
import re
import struct
import subprocess

from .errors import Error
from .macho import thin


MAX_SCAN = 100000
MAX_NAMES = 10000
MAX_NAME_BYTES = 4096
PREFIXES = (b"$s",b"$S",b"$e",b"_T0",b"_Tt",b"@__swiftmacro_")
SAFE_NAME = re.compile(r"[A-Za-z0-9_$@.]+")
ASYNC_ENTRY = re.compile(rb"async_Main(?:T[YQ][0-9]+_|Tu)?")
DEMANGLER_SANDBOX = (
    '(version 1) (allow default) (deny network*) '
    '(deny file-read-data (subpath "/Users")) (deny file-write*)'
)
ENV = {"PATH":"/usr/bin:/bin","HOME":"/var/empty","LANG":"en_US.UTF-8"}


def swift_name(raw):
    candidate = raw[1:] if raw.startswith(b"_") else raw
    return raw.startswith(PREFIXES) or candidate.startswith(PREFIXES) or bool(ASYNC_ENTRY.fullmatch(candidate))


def demangleable(name):
    return bool(1<=len(name)<=MAX_NAME_BYTES and SAFE_NAME.fullmatch(name)
                and swift_name(name.encode("ascii")))


def symbols(data):
    parsed = thin(data)
    table = parsed["loader"].get("symbol_table")
    sections = [row for row in parsed["sections"] if row["name"].startswith("__swift")]
    result = {"swift_sections":sections,"source":"Mach-O symbol table","symbol_table_present":bool(table)}
    if not table:
        return result, [], ["symbol_table_unavailable"] if sections else []
    offset,count = int(table["slice_file_offset"],16),table["count"]
    strings,length = int(table["strings_offset"],16),int(table["strings_size"],16)
    strings_end = strings+length
    rows = []
    gaps = {"symbol_scan_limit"} if count>MAX_SCAN else set()
    for index in range(min(count,MAX_SCAN)):
        name_index,n_type,n_sect,n_desc,value = struct.unpack_from("<IBBHQ",data,offset+index*16)
        if not name_index or n_type&0xE0:
            continue
        if name_index>=length:
            gaps.add("invalid_symbol_name")
            continue
        start = strings+name_index
        end = data.find(b"\0",start,min(strings_end,start+MAX_NAME_BYTES+1))
        if end<0:
            gaps.add("invalid_symbol_name")
            continue
        raw = data[start:end]
        if not swift_name(raw):
            continue
        if len(rows)==MAX_NAMES:
            gaps.add("swift_symbol_limit")
            break
        kind = n_type&0xE
        rows.append({"mangled":raw.decode("utf-8","backslashreplace"),"demangled":None,
                     "demangle_status":"not_requested","symbol_index":index,
                     "kind":{0:"undefined",2:"absolute",0xA:"indirect",0xE:"section"}.get(kind,"other"),
                     "is_external":bool(n_type&1),"section_index":n_sect,"description":hex(n_desc),
                     "va":hex(value) if kind==0xE and n_sect else None,"raw_value":hex(value)})
    return result, rows, sorted(gaps)


def invoke(argv, *, stdin=None):
    try:
        proc = subprocess.run(argv,input=stdin,capture_output=True,timeout=10,cwd="/",env=ENV,check=False)
    except (OSError,subprocess.TimeoutExpired) as error:
        raise Error("demangler_unavailable","Unable to run the bounded Swift demangler",4) from error
    if proc.returncode or len(proc.stdout)>2*1024*1024:
        raise Error("demangler_failed","Swift demangler failed or exceeded its output bound",4)
    return proc.stdout.decode("utf-8","backslashreplace")


def demangle(names):
    if not names:
        return [], None
    if len(names)>1000 or any(not demangleable(name) for name in names):
        raise Error("swift_mangling","Expected bounded Swift symbol text without symbolic references",2)
    output = invoke(["/usr/bin/xcrun","--find","swift-demangle"]).strip()
    path = Path(output)
    if not path.is_absolute() or path.name!="swift-demangle" or not path.is_file():
        raise Error("demangler_unavailable","Xcode Swift demangler was not found",4)
    before = path.stat()
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream,"sha256").hexdigest()
    base = ["/usr/bin/sandbox-exec","-p",DEMANGLER_SANDBOX,str(path)]
    version = invoke([*base,"--version"]).strip()
    lines = invoke([*base,"--compact"],stdin=("\n".join(names)+"\n").encode("ascii")).splitlines()
    if len(lines)!=len(names):
        raise Error("demangler_output","Swift demangler returned an unexpected number of names",4)
    after = path.stat()
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) != (
            after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
        raise Error("demangler_changed","Swift demangler changed during the query",4)
    provenance = {"tool":"swift-demangle","version":version,"sha256":digest,"network":"denied"}
    records = []
    for name,line in zip(names,lines):
        unchanged = line in (name,name.removeprefix("_")) or not line
        records.append({"mangled":name,"demangled":None if unchanged else line,
                        "demangle_status":"unrecognized" if unchanged else "demangled"})
    return records, provenance
