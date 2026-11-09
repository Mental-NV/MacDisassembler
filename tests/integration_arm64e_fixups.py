#!/usr/bin/env python3
"""Compare owned arm64e metadata against Apple's static dyld_info output."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

from macscope.macho import thin


ROOT = Path(__file__).resolve().parents[1]
ADDRESS = r"0x[0-9A-Fa-f]+"
FIXUP = re.compile(rf"^\s*__\S+\s+__\S+\s+({ADDRESS})\s+(auth-bind|auth-rebase|bind|rebase)\s+(.+)$")
RAW = re.compile(rf"^\s*({ADDRESS}):\s+raw:\s+({ADDRESS})")
AUTH = re.compile(rf"\s+\(div=({ADDRESS}) ad=([01]) key=(IA|IB|DA|DB)\)$")


def xcrun(*args):
    return subprocess.check_output(["/usr/bin/xcrun", *map(str, args)], text=True, timeout=30)


def cli(*args):
    output = subprocess.check_output([sys.executable, "-m", "macscope", *map(str, args), "--json"], timeout=30)
    return json.loads(output)


def derived_variants(linked, records):
    metadata = thin(linked, allow_arm64e=True)
    base = int(metadata["loader"]["preferred_image_base"], 16)
    payload, = [int(row["slice_file_offset"], 16) for row in metadata["loader"]["linkedit"]
                if row["kind"] == "chained_fixups"]
    starts = payload + struct.unpack_from("<I", linked, payload + 4)[0]
    count = struct.unpack_from("<I", linked, starts)[0]
    segment, = [starts + offset for offset in struct.unpack_from(f"<{count}I", linked, starts + 4) if offset]
    assert struct.unpack_from("<H", linked, segment + 6)[0] == 12
    ordinary_rebase, = [int(row["slice_file_offset"], 16) for row in records
                        if row["kind"] == "rebase" and not row["authenticated"]]
    ordinary_bind, = [int(row["slice_file_offset"], 16) for row in records
                      if row["kind"] == "bind" and not row["authenticated"]]
    for kind in (1, 9):
        value = bytearray(linked)
        struct.pack_into("<H", value, segment + 6, kind)
        original = struct.unpack_from("<Q", linked, ordinary_rebase)[0]
        tagged = (original + (base if kind == 1 else 0)) | (0xAB << 43)
        struct.pack_into("<Q", value, ordinary_rebase, tagged)
        original = struct.unpack_from("<Q", linked, ordinary_bind)[0]
        signed = (original & ~(0x7FFFF << 32)) | ((-8 & 0x7FFFF) << 32)
        struct.pack_into("<Q", value, ordinary_bind, signed)
        yield kind, bytes(value)


def compare_apple(path, data):
    observed = xcrun("dyld_info", "-fixups", "-fixup_chain_details", "-fixup_chains", path)
    base = int(thin(path.read_bytes(), allow_arm64e=True)["loader"]["preferred_image_base"], 16)
    expected = {int(m[1], 16): (m[2], m[3]) for line in observed.splitlines() if (m := FIXUP.match(line))}
    raw = {base + int(m[1], 16): int(m[2], 16) for line in observed.splitlines() if (m := RAW.match(line))}
    formats = {int(value) for value in re.findall(r"pointer_format:\s+(\d+)", observed)}
    assert formats == set(data["pointer_formats"])
    actual = {int(row["va"], 16): row for row in data["records"]}
    assert set(actual) == set(raw) == set(expected) and len(actual) == 6
    for address, (kind, target) in expected.items():
        row = actual[address]
        assert int(row["raw"], 16) == raw[address] and row["kind"] == kind.removeprefix("auth-")
        auth = AUTH.search(target)
        assert row["authenticated"] == bool(auth)
        if auth:
            assert row["authentication"] == {
                "diversity": int(auth[1], 16), "address_diversity": auth[2] == "1", "key": auth[3],
            }
            target = target[:auth.start()]
        if row["kind"] == "rebase":
            assert int(row["target_va"], 16) == int(target, 16)
        else:
            symbol, _, encoded = target.partition(" + ")
            assert symbol == "libSystem/" + row["symbol"] and row["library"] == "/usr/lib/libSystem.B.dylib"
            addend = int(encoded, 16) if encoded else 0
            # dyld_info prints the raw 19-bit value. The loader sign-extends it.
            if 1 << 18 <= addend < 1 << 19:
                addend -= 1 << 19
            assert row["import_addend"] + row["inline_addend"] == addend
    path.with_suffix(".apple.txt").write_text(observed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    scratch = Path("/tmp").resolve()
    if output == scratch or not output.is_relative_to(scratch):
        raise ValueError("Choose a new output directory under canonical /tmp")
    output.mkdir(mode=0o700)
    source = ROOT / "analysis/arm64e_fixup_fixture.c"
    thin_arm, thin_auth, universal = (output / name for name in ("arm64", "arm64e", "universal"))
    for arch, path in (("arm64", thin_arm), ("arm64e", thin_auth)):
        xcrun("clang", "-arch", arch, "-O0", "-Wl,-fixup_chains", source, "-o", path)
    raw = thin_auth.read_bytes()
    result = cli("fixups", "--input", thin_auth)
    assert result["status"] == "complete" and result["data"]["arch"] == "arm64e"
    assert result["data"]["pointer_formats"] == [12]
    compare_apple(thin_auth, result["data"])
    for kind, binary in derived_variants(raw, result["data"]["records"]):
        path = output / f"derived-{kind}"
        path.write_bytes(binary)
        derived = cli("fixups", "--input", path)
        assert derived["status"] == "complete" and derived["data"]["pointer_formats"] == [kind]
        compare_apple(path, derived["data"])
    xcrun("lipo", "-create", thin_arm, thin_auth, "-output", universal)
    full = cli("inspect", universal)
    assert [s["arch"] for s in full["data"]["slices"]] == ["arm64", "arm64e"]
    first = cli("fixups", "--input", universal, "--arch", "arm64e", "--limit", 2)
    last = cli("fixups", "--input", universal, "--arch", "arm64e", "--cursor", first["coverage"]["next_cursor"])
    selected, = [s for s in full["data"]["slices"] if s["arch"] == "arm64e"]
    rows = first["data"]["records"] + last["data"]["records"]
    for row in rows:
        assert int(row.pop("container_file_offset"), 16) == int(selected["offset"], 16) + int(row["slice_file_offset"], 16)
    assert rows == [{k: v for k, v in row.items() if k != "container_file_offset"} for row in result["data"]["records"]]
    report = {"status": "passed", "formats": [1, 9, 12], "fixups_matched": 18,
              "linked_sha256": hashlib.sha256(raw).hexdigest(), "universal_pagination": True}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
