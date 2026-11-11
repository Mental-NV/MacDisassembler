"""Installed actual native pseudocode token mapping; no engine or input execution."""
from pathlib import Path
import subprocess
import sys
import integration_native_terminal_thunk as native
import integration_native_callback_counterexamples as gate


def run(project,manifest):
    native.run(project,manifest)
    before=native.snapshot(project)
    args=[sys.executable,'-m','macscope','jobs','resume',manifest['job_id'],'--project',str(project),
          '--ghidra','/nonexistent/ghidra','--java-home','/nonexistent/java','--format','addressed']
    outputs=[subprocess.run(args,capture_output=True,text=True,check=True,timeout=60,stdin=subprocess.DEVNULL).stdout for _ in range(2)]
    gate.require(outputs[0]==outputs[1],'Nondeterministic addressed replay')
    text=outputs[0]
    gate.require('5 | 0xd78 |   func_0x00000bb0();' in text and '6 | 0xd78 |   return;' in text,'Wrong owned token mapping')
    gate.require('1 | — (no recorded token mapping) | ' in text,'Original leading blank line lost')
    gate.require('Token mapping coverage: complete' in text and 'not whole-line instruction ownership' in text,'Lost mapping limits')
    gate.require('Omitted functions: 0; code lines in shown functions: 0; ranges on shown lines: 0.' in text,'Unexpected omissions')
    gate.require(native.snapshot(project)==before,'Addressed replay changed saved files')
    print('PASS: actual native token-addressed pseudocode, exact original line positions and immutable offline replay')


if __name__=='__main__':run(Path(sys.argv[1]).resolve(),gate.bounded_json(Path(sys.argv[2]),gate.MAX_MANIFEST)[0])
