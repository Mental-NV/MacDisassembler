"""Static compatibility checks for the selected full Ghidra distribution."""
import hashlib
import os
from pathlib import Path
import re
import zipfile
import zlib

from .errors import Error
from .host_platform import checked_host, elf_digest
from .macho import inspect_bytes, read_regular


GHIDRA_VERSION = "12.2"
JAVA_BUILD = "25.0.5.0.3"
NATIVE = "Ghidra/Features/Decompiler/os/mac_arm_64/decompile"
JARS = {
    "support/LaunchSupport.jar": ("LaunchSupport.class",),
    "Ghidra/Framework/Utility/lib/Utility.jar": ("ghidra/Ghidra.class", "ghidra/GhidraLauncher.class"),
    "Ghidra/Features/Base/lib/Base.jar": ("ghidra/app/util/headless/AnalyzeHeadless.class",
                                         "ghidra/app/util/headless/HeadlessScript.class",
                                         "ghidra/app/util/opinion/MachoLoader.class"),
    "Ghidra/Features/Decompiler/lib/Decompiler.jar": ("ghidra/app/decompiler/DecompInterface.class",),
    "Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar": ("ghidra/program/model/listing/Program.class",),
}
SCRIPTS = ("MacscopeBridge.java", "MacscopeProfile.java", "MacscopeFocus.java",
           "RecoverCallSignatures.java", "RecoverSwitchTable.java")


def read_dependency(path, maximum):
    try:
        return read_regular(path.resolve(), maximum)
    except (Error, OSError, RuntimeError) as error:
        raise Error("dependency_read", f"Cannot read required dependency: {path}", 4) from error


def properties(data, key):
    pattern = re.compile(r"^\s*" + re.escape(key) + r"(?=$|[\s=:])\s*[:=]?\s*(.*)$")
    values = []
    for line in data.decode("latin-1").splitlines():
        match = pattern.match(line)
        if match:
            values.append(match[1].strip())
    return values


def check_class_files(path, names):
    try:
        if path.stat().st_size > 128 * 1024 * 1024:
            raise ValueError("oversized JAR")
        with zipfile.ZipFile(path) as jar:
            for name in names:
                with jar.open(name) as source:
                    header = source.read(8)
                if (len(header) != 8 or header[:6] != b"\xca\xfe\xba\xbe\0\0"
                        or not 45 <= int.from_bytes(header[6:], "big") <= 69):
                    raise ValueError("incompatible class header")
    except (OSError, ValueError, KeyError, RuntimeError, EOFError, zipfile.BadZipFile, zlib.error) as error:
        raise Error("incompatible_ghidra_jar", f"Invalid or incompatible Ghidra component: {path}", 4) from error


def native_digest(path, file_type, code, host=None):
    host = checked_host(host)
    data = read_dependency(path, 128 * 1024 * 1024)
    if host.native_format == "elf":
        try:
            return elf_digest(data, shared_library=file_type == 6)
        except Error as error:
            raise Error(code, f"Expected a native ELF64 x86_64 component: {path}", 4) from error
    try:
        parsed = inspect_bytes(data)
    except Error as error:
        raise Error(code, f"Expected a native arm64 Mach-O component: {path}", 4) from error
    if not any(row["arch"] == "arm64" and row["file_type"] == file_type and row["segments"]
               for row in parsed["slices"]):
        raise Error(code, f"Expected a native arm64 Mach-O component: {path}", 4)
    return parsed["artifact_sha256"]


def layout(ghidra, java, bridge, host=None):
    host = checked_host(host)
    launchers = {ghidra / "support/analyzeHeadless": b"ghidra.app.util.headless.AnalyzeHeadless",
                 ghidra / "support/launch.sh": b"LaunchSupport"}
    application = ghidra / "Ghidra/application.properties"
    launch_properties = ghidra / "support/launch.properties"
    native = ghidra / host.native_path
    java_bin, javac, jvm = java / "bin/java", java / "bin/javac", java / host.jvm_path
    required = (*launchers, application, launch_properties, native, java_bin, javac, jvm, java / "lib/modules",
                *(ghidra / path for path in JARS), *(bridge / name for name in SCRIPTS))
    for path in required:
        if not path.is_file():
            raise Error("missing_dependency", f"Missing required dependency: {path}", 4)
    for path in (*launchers, native, java_bin, javac):
        if not os.access(path, os.X_OK):
            raise Error("dependency_permissions", f"Required dependency is not executable: {path}", 4)
    app = read_dependency(application, 65536)
    if properties(app, "application.version") != [GHIDRA_VERSION]:
        raise Error("incompatible_ghidra", f"Requires exactly full Ghidra {GHIDRA_VERSION}", 4)
    for path, entry in launchers.items():
        script = read_dependency(path, 65536)
        if not script.startswith(b"#!") or entry not in script:
            raise Error("incompatible_ghidra_launcher", f"Invalid Ghidra launcher: {path}", 4)
    overrides = properties(read_dependency(launch_properties, 65536), "JAVA_HOME_OVERRIDE")
    if len(overrides) > 1 or any(value and (not Path(value).is_absolute() or Path(value).resolve() != java)
                                 for value in overrides):
        raise Error("ghidra_java_override", "Ghidra launch properties select a different Java home", 4)
    for path, classes in JARS.items():
        check_class_files(ghidra / path, classes)
    native_digest(javac, 2, "incompatible_jdk_native", host)
    return {"native_decompiler_sha256": native_digest(native, 2, "incompatible_native_decompiler", host),
            "java_sha256": native_digest(java_bin, 2, "incompatible_jdk_native", host),
            "jvm_sha256": native_digest(jvm, 6, "incompatible_jdk_native", host),
            "application_properties_sha256": hashlib.sha256(app).hexdigest()}


def java_version_matches(output, host=None):
    host = checked_host(host)
    release = re.search(r'^openjdk version "([^"\r\n]+)"', output, re.M)
    build = re.search(r"^OpenJDK Runtime Environment[^\r\n]*\(build ([^\r\n)]+)\)$", output, re.M)
    return bool(release and release[1] in host.java_releases and build and build[1] == host.java_build)


def verify_runtime(runtime, expected_home, host=None):
    host = checked_host(host)
    try:
        valid = (isinstance(runtime, dict) and isinstance(runtime.get("home"), str)
                 and Path(runtime["home"]).resolve() == Path(expected_home)
                 and runtime.get("version") == host.java_build and runtime.get("arch") == host.java_arch)
    except (OSError, RuntimeError, ValueError):
        valid = False
    if not valid:
        raise Error("worker_jdk_mismatch", "Headless Ghidra did not run under the selected native JDK", 4)
