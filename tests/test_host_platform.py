"""Synthetic host compatibility tests. Never start Java, Ghidra, or a sandbox."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from macscope import doctor_probe, engine_checks, host_platform
from macscope.errors import Error


def elf(kind=2):
    data = bytearray(256)
    data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16,
                     kind, 62, 1, 0x400080, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0x400000, 0, 256, 256, 4096)
    return data


class HostPlatformTests(unittest.TestCase):
    def test_explicit_host_selection(self):
        self.assertEqual(host_platform.select_host('Darwin', 'arm64'), host_platform.DARWIN_ARM64)
        self.assertEqual(host_platform.select_host('Linux', 'x86_64'), host_platform.LINUX_X86_64)
        self.assertEqual(host_platform.checked_host(), host_platform.DARWIN_ARM64)
        for system, arch in [('Linux', 'aarch64'), ('Darwin', 'x86_64'), ('Windows', 'AMD64')]:
            with self.assertRaises(Error):
                host_platform.select_host(system, arch)

    def test_metadata_is_json_ready_and_does_not_claim_validation(self):
        import json
        metadata = host_platform.LINUX_X86_64.metadata()
        self.assertEqual(json.loads(json.dumps(metadata)), metadata)
        self.assertEqual(metadata['java_build'], '25.0.1+8')
        self.assertEqual(metadata['java_arch'], 'amd64')
        self.assertNotIn('validated', metadata)

    def test_valid_elf_executable_pie_and_shared(self):
        for kind in (2, 3):
            data = elf(kind)
            self.assertEqual(host_platform.elf_digest(data), hashlib.sha256(data).hexdigest())
        self.assertEqual(host_platform.elf_digest(elf(3), shared_library=True),
                         hashlib.sha256(elf(3)).hexdigest())
        with self.assertRaises(Error):
            host_platform.elf_digest(elf(2), shared_library=True)

    def test_bad_elf_headers_and_segments(self):
        mutations = [
            (4, 'B', 1), (5, 'B', 2), (6, 'B', 0), (7, 'B', 255),
            (16, 'H', 1), (18, 'H', 183), (20, 'I', 0),
            (24, 'Q', 0), (24, 'Q', 0x500000),
            (32, 'Q', 2**64 - 1), (32, 'Q', 0),
            (52, 'H', 63), (54, 'H', 55), (56, 'H', 0), (56, 'H', 65535),
            (64, 'I', 0), (68, 'I', 4), (68, 'I', 9),
            (72, 'Q', 2**64 - 1), (96, 'Q', 257),
            (104, 'Q', 1), (112, 'Q', 3), (80, 'Q', 0x400001),
            (104, 'Q', 2**64 - 1),
        ]
        for offset, fmt, value in mutations:
            with self.subTest(offset=offset, value=value):
                data = elf()
                struct.pack_into('<' + fmt, data, offset, value)
                with self.assertRaises(Error):
                    host_platform.elf_digest(data)
        for size in (0, 63, 64, 119, 255):
            with self.subTest(size=size), self.assertRaises(Error):
                host_platform.elf_digest(elf()[:size])

    def test_jdk_contracts_are_exact_and_host_specific(self):
        mac = 'openjdk version "25.0.5"\nOpenJDK Runtime Environment Homebrew (build 25.0.5.0.3)'
        linux = 'openjdk version "25.0.1"\nOpenJDK Runtime Environment (build 25.0.1+8)'
        self.assertTrue(engine_checks.java_version_matches(mac))
        self.assertFalse(engine_checks.java_version_matches(linux))
        self.assertTrue(engine_checks.java_version_matches(linux, host_platform.LINUX_X86_64))
        for bad in (mac, linux.replace('+8', '+9'), linux.replace('+8', '+8-LTS'),
                    linux.replace('"25.0.1"', '"25.0.2"')):
            self.assertFalse(engine_checks.java_version_matches(bad, host_platform.LINUX_X86_64))

    def test_runtime_home_build_and_arch_must_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            runtime = dict(home=str(home), version='25.0.1+8', arch='amd64')
            engine_checks.verify_runtime(runtime, home, host_platform.LINUX_X86_64)
            for key, wrong in [('home', '/not-the-selected-jdk'), ('version', '25.0.1+9'),
                               ('arch', 'aarch64'), ('arch', 'x86_64')]:
                with self.subTest(key=key), self.assertRaises(Error):
                    engine_checks.verify_runtime({**runtime, key: wrong}, home, host_platform.LINUX_X86_64)
            with self.assertRaises(Error):
                engine_checks.verify_runtime(runtime, home)
            engine_checks.verify_runtime(dict(home=str(home), version=engine_checks.JAVA_BUILD,
                                              arch='aarch64'), home)

    def test_native_digest_keeps_macos_default_and_checks_linux_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'native'
            path.write_bytes(doctor_probe.fixture())
            engine_checks.native_digest(path, 2, 'bad_native')
            with self.assertRaises(Error):
                engine_checks.native_digest(path, 2, 'bad_native', host_platform.LINUX_X86_64)
            path.write_bytes(elf())
            engine_checks.native_digest(path, 2, 'bad_native', host_platform.LINUX_X86_64)
            with self.assertRaises(Error):
                engine_checks.native_digest(path, 6, 'bad_native', host_platform.LINUX_X86_64)
            with self.assertRaises(Error):
                engine_checks.native_digest(path, 2, 'bad_native')

    def test_linux_layout_uses_elf_and_so_without_mac_libraries(self):
        # Reuse only the synthetic fixture builder, without starting a process.
        from test_core import DependencyTests
        fixture = DependencyTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        native = fixture.g / host_platform.LINUX_X86_64.native_path
        native.parent.mkdir(parents=True)
        native.write_bytes(elf())
        native.chmod(0o700)
        (fixture.g / engine_checks.NATIVE).unlink()
        (fixture.j / 'lib/server/libjvm.dylib').unlink()
        (fixture.j / 'lib/server/libjvm.so').write_bytes(elf(3))
        for name in ('java', 'javac'):
            (fixture.j / 'bin' / name).write_bytes(elf(3))
        result = engine_checks.layout(fixture.g, fixture.j, fixture.bridge, host_platform.LINUX_X86_64)
        self.assertEqual(result['native_decompiler_sha256'], hashlib.sha256(elf()).hexdigest())
        with self.assertRaises(Error):
            engine_checks.layout(fixture.g, fixture.j, fixture.bridge)
        native.write_bytes(doctor_probe.fixture())
        with self.assertRaises(Error) as error:
            engine_checks.layout(fixture.g, fixture.j, fixture.bridge, host_platform.LINUX_X86_64)
        self.assertEqual(error.exception.code, 'incompatible_native_decompiler')


if __name__ == '__main__':
    unittest.main()
