#!/usr/bin/env python3
"""Package one frozen unassisted calculator capture for a clean analyst."""
import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from evaluate import verify_freeze
from run_baseline import CASES, REPO
from macscope.errors import Error
from macscope.macho import read_regular

REVIEW = """# Review one unassisted capture

Use this archive as the only case evidence in a fresh analyst context.
Its files include one Mach-O input, Ghidra's frozen capture, and LLVM's
disassembly of the same input. The manifest identifies the condition.
Use static inspection and generic ISA or ABI references. Keep other
variants, source, debug data, and prior reviews out of this context.

For each function you review, report its entry address, your inferred
behavior, and the supporting machine addresses. Compare the pseudocode
with the assembly. Record material discrepancies and uncertainties
in control flow, calls, error paths, arithmetic width and signedness,
overflow, memory accesses, and observable state changes where applicable.
Distinguish unsupported inference from contradictory evidence. Record
truncated and unavailable facets and leave unreviewed functions explicit.

List each reviewed address as consistent in the inspected aspects,
discrepancy, or indeterminate. Report the number of eligible complete
functions, how many you reviewed, and which facets each judgment covers.
Freeze the review against this packet's SHA-256 before evaluator-side
comparison with ground truth.
"""

CASE_TAGS = [f'{case}-{kind}' for case in CASES for kind in ('app', 'tool')]


def checked_bytes(path, expected, limit):
    data = read_regular(path, limit)
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f'Digest mismatch or missing freeze entry for {path.name}')
    return data


def packet_members(workspace, tag):
    condition = 'binary-only' if '-stripped-' in tag else 'binary-plus-symbol-table'
    identity = json.loads(read_regular(workspace / 'identity.json', 1 << 20))
    summary = json.loads(read_regular(workspace / 'summary.json', 1 << 20))
    if (identity.get('isolation') != 'macscope-baseline-case/1' or identity.get('assisted_from')
            or summary.get('status') != 'complete'):
        raise ValueError('Review requires a completed isolated unassisted capture')
    matches = [row for row in summary['records'] if row['tag'] == tag]
    if len(matches) != 1 or matches[0]['condition'] != condition or matches[0]['status'] != 'complete':
        raise ValueError('Requested case is absent from the completed condition')
    record = matches[0]
    isolation = record['isolation_probe']
    if isolation['exit_code'] != 0 or isolation['failure']:
        raise ValueError('Requested case did not pass its isolation probe')
    frozen = verify_freeze(REPO, workspace)
    case = workspace / ('ghidra-' + tag)
    baseline_path = case / 'baseline.json'
    llvm_path = workspace / ('llvm-' + tag + '.txt')
    baseline = checked_bytes(baseline_path, frozen.get(baseline_path), 64 << 20)
    llvm = checked_bytes(llvm_path, frozen.get(llvm_path), 16 << 20)
    input_path = case / 'input.bin'
    binary = checked_bytes(input_path, record['input_sha256'], 64 << 20)
    capture = json.loads(baseline)
    if (capture.get('schema') != 'macscope-baseline/2' or capture.get('blind_profile') != 'binary-only-v2'
            or 'dsym' in capture or capture.get('executable_md5') != hashlib.md5(binary).hexdigest()):
        raise ValueError('Frozen capture does not identify this unassisted input')
    header, _, assembly = llvm.partition(b'\n')
    if header != os.fsencode(input_path) + b':' or not assembly:
        raise ValueError('Frozen LLVM output does not identify this input')

    members = {'REVIEW.md': REVIEW.encode(), 'input.bin': binary,
               'baseline.json': baseline, 'llvm.txt': assembly}
    manifest = {'schema': 'macscope-clean-review-packet/1', 'condition': condition,
                'case': tag, 'files': {name: hashlib.sha256(data).hexdigest()
                                      for name, data in members.items()}}
    members['manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    return members


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--case', choices=CASE_TAGS, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        members = packet_members(args.workspace.resolve(), args.case)
        with tempfile.NamedTemporaryFile(dir=args.output.parent, prefix='.review-', suffix='.zip') as temp:
            with ZipFile(temp, 'w') as archive:
                for name, data in members.items():
                    archive.writestr(ZipInfo(name), data, compress_type=ZIP_DEFLATED)
            temp.flush()
            os.fsync(temp.fileno())
            os.link(temp.name, args.output)
    except (Error, OSError, ValueError) as error:
        parser.exit(1, f'Clean review packet failed: {error}\n')
    print(args.output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
