#!/usr/bin/env python3
"""Build an isolated, distinctly identified arm64 app for visual review.

Leaves all existing app processes and earlier evidence untouched. Uses a
copied Info.plist and build overrides, never changes baseline bundle identity.
"""
import argparse
import importlib.util
import json
import os
import plistlib
import sys
from pathlib import Path

from write_manifest import provenance, sha256, run

REPO = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    out = args.output.resolve()
    os.umask(0o077)
    out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('baseline_process', REPO / 'analysis/run_baseline.py')
    baseline_process = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline_process)
    info = plistlib.loads((REPO / 'fixture/src/Info.plist').read_bytes())
    info['CFBundleIdentifier'] = 'org.macsdisassembler.CalculatorFixture.UIReview'
    info['CFBundleDisplayName'] = 'CalculatorFixture UI Review'
    copied_plist = out / 'UIReviewInfo.plist'
    copied_plist.write_bytes(plistlib.dumps(info))
    products = out / 'evaluator/DebugAnalysis-arm64'
    argv = ['xcodebuild', '-project', str(REPO / 'fixture/CalculatorFixture.xcodeproj'),
            '-scheme', 'CalculatorFixture', '-configuration', 'DebugAnalysis',
            '-derivedDataPath', str(out / 'derived'), f'CONFIGURATION_BUILD_DIR={products}',
            f'INFOPLIST_FILE={copied_plist}', f'PRODUCT_BUNDLE_IDENTIFIER={info["CFBundleIdentifier"]}',
            'ARCHS=arm64', 'ONLY_ACTIVE_ARCH=NO', 'build']
    source = provenance(REPO)
    # Xcode caches/build databases can exceed the analysis worker file cap.
    # Retain owned-group timeout and bounded captured log, not that file cap.
    result = baseline_process.bounded_command(argv, out / 'xcodebuild.log', 180, limit_child_files=False)
    app = products / 'CalculatorFixture.app'
    binary = app / 'Contents/MacOS/CalculatorFixture'
    metadata = {'schema': 'macscope-ui-review-build/1', 'source': source, 'command': result,
                'review_plist_sha256': sha256(copied_plist), 'app_path': str(app),
                'tools': {'xcode': run('xcodebuild', '-version'),
                          'sdk': run('xcrun', '--sdk', 'macosx', '--show-sdk-version'),
                          'clang': run('xcrun', 'clang', '--version'),
                          'python': sys.version},
                'scope': 'arm64 DebugAnalysis UI review only; no new analysis or quality gate result'}
    if result['exit_code'] == 0 and result['failure'] is None and binary.exists():
        built_info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
        for key in ('CFBundleIdentifier', 'CFBundleDisplayName'):
            if built_info.get(key) != info[key]:
                raise ValueError('disposable review identity mismatch: ' + key)
        metadata.update(status='complete', executable_sha256=sha256(binary),
                        bundle_id=built_info['CFBundleIdentifier'], display_name=built_info['CFBundleDisplayName'])
    else:
        metadata['status'] = 'failed'
    baseline_process.exclusive_json(out / 'manifest.json', metadata)
    print(json.dumps(metadata, indent=2))
    return 0 if metadata['status'] == 'complete' else 1


if __name__ == '__main__':
    sys.exit(main())
