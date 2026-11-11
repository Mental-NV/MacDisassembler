"""Replay the four owned return-channel receipts using an installed CLI.

Usage: python integration_native_send_origins.py PROJECT LEADS
No engine or app execution; supplied artifacts stay outside the repository.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

project = Path(sys.argv[1]).resolve()
leads = Path(sys.argv[2]).resolve()
cli = Path(sys.executable).parent / 'macscope'
assert cli.exists(), 'Use an installed wheel environment'

def hashes():
    return {str(p.relative_to(project)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in project.rglob('*') if p.is_file()}

before = hashes()
command = [str(cli), 'evidence', '--project', str(project), '--leads', str(leads),
           '--objc-sends', '--format', 'json']
outputs = []
for _ in range(2):
    result = subprocess.run(command, capture_output=True, cwd='/tmp')
    assert result.returncode == 6, result.stderr
    outputs.append(result.stdout)
assert outputs[0] == outputs[1]
context = json.loads(outputs[0])['data']['objc_send_context']
rows = {row['entry_va']: row for row in context['receipts']}
assert set(rows) == {'0x6f8', '0x700', '0x708', '0x724'}
for entry in ('0x6f8', '0x700', '0x724'):
    row = rows[entry]
    assert row['source_envelope_sha256'] and row['pin']
    assert len(row['sites']) == 1
    origin = row['sites'][0]['register_origins']
    assert origin['status'] == 'verified_conditional_register_origins'
    assert origin['receiver_register']['origin'] == {'kind':'entry_register', 'register':'x2'}
    assert origin['instructions'] == [{'va':entry, 'bytes':'e00302aa'}]
    assert row['sites'][0]['return_contract'] == 'unknown'
assert rows['0x708']['sites'][0]['register_origins']['reason'] == 'unsupported_prefix_instruction'
assert before == hashes()
print('Owned receiver origins and stack-prefix negative passed; immutable repeated replay.')
