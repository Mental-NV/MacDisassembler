"""Authorize a worker only after its process group is durably recorded."""
from functools import lru_cache
import os
import re
import subprocess
import sys


PROTOCOL = "macscope-launch-gate/1"
STARTUP_EVIDENCE = "ghidra-12.2-headless-startup-log/1"
STARTUP_PREFIX_LIMIT = 256 * 1024
_STARTUP_LINE = re.compile(rb"(?m)^INFO  Headless startup complete \(([0-9]{1,12}) ms\) \(AnalyzeHeadless\)[ \t]*\r?\n")
_RELEASE = b"\x01"
_GATE = """import os, signal, sys
fd = int(sys.argv[1])
permission = os.read(fd, 1)
os.close(fd)
if permission != b"\\x01":
    sys.exit(125)
for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
    signum = getattr(signal, name, None)
    if signum is not None:
        signal.signal(signum, signal.SIG_DFL)
os.execv(sys.argv[2], sys.argv[2:])
"""


class StartupProbe:
    """Scan only complete lines in the bounded startup prefix of the owned log."""

    def __init__(self):
        self.offset = 0
        self.tail = b""

    def poll(self, fd):
        block = os.pread(fd, STARTUP_PREFIX_LIMIT - self.offset, self.offset)
        if not block:
            return None
        self.offset += len(block)
        data = self.tail + block
        end = data.rfind(b"\n") + 1
        self.tail = data[end:]
        match = _STARTUP_LINE.search(data, 0, end)
        return int(match[1]) if match else None


@lru_cache(maxsize=1)
def boot_session():
    try:
        probe = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
            capture_output=True, text=True, timeout=2, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    token = probe.stdout.strip()
    if probe.returncode == 0 and re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", token):
        return token.lower()
    return None


def start(argv, *, gated, cwd, env, log):
    options = dict(cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=log,
                   stderr=subprocess.STDOUT, start_new_session=True)
    if not gated:
        return subprocess.Popen(argv, **options), None
    reader, writer = os.pipe()
    try:
        gate_argv = [sys.executable, "-I", "-S", "-c", _GATE, str(reader), *argv]
        return subprocess.Popen(gate_argv, pass_fds=(reader,), **options), writer
    except BaseException:
        os.close(writer)
        raise
    finally:
        os.close(reader)


def release(fd):
    os.write(fd, _RELEASE)


def disconnected_exit_confirmed(record):
    """Check a gated job with no remaining supervisor lease."""
    if record.get("launch_protocol") != PROTOCOL:
        return False
    session = boot_session()
    if session is None or session != record.get("boot_session_id"):
        return False
    if record["status"] == "starting":
        # Without a durable running record the original supervisor could not
        # release the gate. Its closed pipe makes the waiting child exit.
        return "pid" not in record and "process_group" not in record
    group = record.get("process_group")
    if record["status"] != "running" or type(group) is not int or not 1 < group < 2**31:
        return False
    if type(record.get("pid")) is not int or record["pid"] != group:
        return False
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return True
    except OSError:
        pass
    return False
