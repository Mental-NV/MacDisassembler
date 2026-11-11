"""Parse public guide examples and show help only. Never execute project commands."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import re
import shlex
import unittest
from unittest.mock import patch
from macscope import cli, engine

GUIDE=Path(__file__).parents[1]/'docs'/'hybrid-workflow.md'
VALUES={
    'GHIDRA':'/synthetic/ghidra','JAVA_HOME':'/synthetic/jdk',
    'MAIN_PROJECT':'/synthetic/main-project','SMALL_PROJECT':'/synthetic/small-project',
    'MAIN_BINARY':'/synthetic/main.macho','SMALL_BINARY':'/synthetic/library.macho',
    'MAIN_IMAGE':'1'*64,'SMALL_IMAGE':'2'*64,'FUNCTION':'0x1000','QUERY_JOB':'3'*32,
    'CLASS_SLOT':'0x4000','NAME_HINT':'owned_name','DATA_VA':'0x2000','SLOT_VA':'0x3000','LENGTH':'32',
}


def examples():
    text=GUIDE.read_text()
    for block in re.findall(r'```sh\n(.*?)```',text,re.S):
        for line in block.splitlines():
            if not line.startswith('macscope '):continue
            names=re.findall(r'\$([A-Z_]+)',line)
            if any(name not in VALUES for name in names):raise AssertionError('Undeclared guide placeholder')
            expanded=re.sub(r'\$([A-Z_]+)',lambda m:VALUES[m[1]],line)
            yield shlex.split(expanded)[1:]


class WorkflowDocsTests(unittest.TestCase):
    def test_all_commands_parse_and_help_without_execution(self):
        routes=set();commands=list(examples());self.assertGreaterEqual(len(commands),20)
        with patch.object(cli,'execute',side_effect=AssertionError('No command execution')) as execute, \
             patch.object(engine,'run',side_effect=AssertionError('No native worker')) as run, \
             patch.object(engine,'dependencies',side_effect=AssertionError('No runtime probing')) as dependencies:
            for words in commands:
                with self.subTest(command=words):
                    args=cli.parser().parse_args(words)
                    self.assertEqual(args.format,'json')
                    route=words[:2] if words[0] in {'jobs','project','functions','objc','swift'} else words[:1]
                    routes.add(tuple(route))
                    native=args.command in {'import','analyze'} or args.command=='decompile' and (
                        args.fresh or args.from_import and not args.preflight)
                    if native:
                        self.assertTrue(args.experimental_trusted_input)
                        self.assertEqual(args.jobs,1)
                        self.assertIn('--timeout',words);self.assertLessEqual(args.timeout,300)
                        self.assertIn('--startup-timeout',words);self.assertEqual(args.startup_timeout,120)
                        self.assertEqual(args.function_timeout,25);self.assertEqual(args.heap_mib,2048)
                    if args.command=='decompile' and args.from_import:
                        self.assertEqual(args.address,VALUES['FUNCTION']);self.assertEqual(args.image,VALUES['MAIN_IMAGE'])
                        self.assertFalse(args.fresh);self.assertFalse(args.recover_callee_parameters)
                    if args.command=='xrefs' and args.query_job:
                        self.assertEqual(args.address,VALUES['FUNCTION']);self.assertEqual(args.query_job,VALUES['QUERY_JOB'])
                        self.assertIsNone(args.xref_from);self.assertIsNone(args.xref_to)
                    if args.command=='bytes':self.assertEqual(args.byte_length,32)
            for route in routes:
                with redirect_stdout(io.StringIO()) as output,self.assertRaises(SystemExit) as caught:
                    cli.parser().parse_args([*route,'--help'])
                self.assertEqual(caught.exception.code,0);self.assertIn('usage:',output.getvalue())
            execute.assert_not_called();run.assert_not_called();dependencies.assert_not_called()

    def test_public_scope_and_link(self):
        text=GUIDE.read_text()
        self.assertNotIn('infer-parameters-from',text)
        self.assertNotIn('/Users/',text)
        self.assertNotIn('0x3f0',text)
        self.assertIn('hybrid-workflow.md',(GUIDE.parent/'cli.md').read_text())
        self.assertIn('not a hard whole-process memory limit',text)
        self.assertIn('existing quiescent project copy only',text)
        self.assertIn('exit code 6',text)
        self.assertIn('incoming_scope_not_global',text)
        self.assertIn('only with\na verified slot',text)
        self.assertIn('does not\nvalidate large-image cost or coverage',text)
        self.assertIn('Do not publish proprietary artifacts',text)
        self.assertIn('export MACSCOPE_GHIDRA="$GHIDRA" MACSCOPE_JAVA_HOME="$JAVA_HOME"',text)

if __name__=='__main__':unittest.main()
