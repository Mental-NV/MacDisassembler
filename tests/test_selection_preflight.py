"""Exact static selection preview; no engine or implicit analysis."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from macscope import cli, focused, macho, trust, engine
from macscope.errors import Error
import test_query_resume
from test_terminal_linker_boundary import fixture as terminal_fixture


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.f=test_query_resume.FocusedResumeTests(); self.f.setUp()
        self.addCleanup(self.f.doCleanups);self.p=self.f.workspace

    def args(self,*extra):
        return cli.parser().parse_args(['decompile','--project',str(self.p.path),
            '--from-import','--preflight','--address',self.f.entry,'--format','json',*extra])

    def hashes(self):
        return {str(p.relative_to(self.p.path)):hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.p.path.rglob('*') if p.is_file()}

    def add_image(self,raw):
        image=dict(macho.inspect_bytes(raw)['slices'][0],artifact_sha256=hashlib.sha256(raw).hexdigest())
        (self.p.path/'inputs'/(image['image_id']+'.macho')).write_bytes(raw)
        with self.p.db(False) as db:
            db.execute('INSERT INTO images VALUES(?,?,?,1,NULL)',(image['image_id'],image['arch'],json.dumps(image)))
        return image

    def test_exact_static_proof_without_engine_program_or_trust(self):
        before=self.hashes()
        with patch.object(cli,'check_engine_access',side_effect=AssertionError),patch.object(engine,'dependencies',side_effect=AssertionError),patch.object(trust,'require',side_effect=AssertionError),patch.object(cli,'focused_decompile',side_effect=AssertionError):
            a=cli.execute(self.args());b=cli.execute(self.args())
        self.assertEqual(a,b);self.assertEqual(self.hashes(),before)
        d=a['data'];self.assertEqual(a['status'],'complete');self.assertIsNone(a['analysis_id'])
        self.assertEqual(d['extent'],focused.select(self.p,self.f.image,self.f.entry)[0])
        self.assertEqual(d['policy'],'macscope-focused-selection-preflight/1')
        self.assertFalse(d['capture_performed']);self.assertEqual(d['native_readiness'],'not_checked')
        self.assertNotIn('pseudocode',d);self.assertNotIn('signature',d)
        self.assertEqual(d['slice_sha256'],hashlib.sha256(self.f.raw).hexdigest())

    def test_exact_selection_refusals_preserve_existing_errors(self):
        for entry in [hex(int(self.f.entry,16)+1),'0x0',hex(int(self.f.entry,16)+4)]:
            with self.subTest(entry=entry):
                with self.assertRaises(Error) as old:focused.select(self.p,self.f.image,entry)
                with self.assertRaises(Error) as new:cli.execute(self.args('--address',entry))
                self.assertEqual(new.exception.code,old.exception.code)
        with patch.object(focused,'MAX_BYTES',1),self.assertRaises(Error) as err:
            cli.execute(self.args())
        self.assertEqual(err.exception.code,'focused_extent_limit')

    def test_terminal_bound_proof_is_preserved(self):
        image=self.add_image(terminal_fixture())
        out=cli.execute(self.args('--image',image['image_id'],'--address','0x1210'))['data']
        self.assertEqual(out['extent'],focused.select(self.p,image,'0x1210')[0])
        self.assertIn('boundary',out['extent'])
        self.assertIn('tail_calls',out['extent'])

    def test_tampered_saved_bytes_fail(self):
        path=self.p.path/'inputs'/(self.f.image_id+'.macho')
        path.write_bytes(path.read_bytes()+b'x')
        with self.assertRaises(Error):cli.execute(self.args())

    def test_ambiguous_image_refuses_before_selection(self):
        self.add_image(terminal_fixture())
        with self.assertRaises(Error):cli.execute(self.args())

    def test_reject_nonpreflight_scope_and_formats(self):
        for extra in [['--format','addressed'],['--format','jsonl'],['--with-type-hints'],['--recover-callee-parameters']]:
            with self.subTest(extra=extra),self.assertRaises(Error):cli.execute(self.args(*extra))
        base=['decompile','--project',str(self.p.path),'--preflight','--format','json']
        for extra in [['--address',self.f.entry],['--fresh','--address',self.f.entry],['--from-import','--name','owned'],['--from-import','--all'],['--from-import','--rva','0x100']]:
            with self.subTest(extra=extra),self.assertRaises(Error):cli.execute(cli.parser().parse_args(base+extra))

    def test_ordinary_capture_still_routes_through_engine_access(self):
        a=self.args();a.preflight=False
        sentinel={'ordinary':'unchanged'}
        with patch.object(cli,'check_engine_access') as access,patch.object(cli,'focused_decompile',return_value=sentinel) as capture:
            self.assertIs(cli.execute(a),sentinel)
        access.assert_called_once();capture.assert_called_once()

    def test_entrypoint_no_engine_and_protected_output(self):
        before=self.hashes();env=os.environ|{'MACSCOPE_GHIDRA':'/nonexistent','MACSCOPE_JAVA_HOME':'/nonexistent','PYTHONDONTWRITEBYTECODE':'1'}
        cmd=[sys.executable,'-m','macscope','decompile','--project',str(self.p.path),'--from-import','--preflight','--address',self.f.entry]
        for fmt in ['json','text']:
            a=subprocess.run(cmd+['--format',fmt],capture_output=True,env=env)
            b=subprocess.run(cmd+['--format',fmt],capture_output=True,env=env)
            self.assertEqual(a.returncode,0,a.stderr);self.assertEqual(a.stdout,b.stdout)
            if fmt=='text':
                for item in [b'Static selection preflight only',b'native_readiness  not_checked',b'capture_performed  False',b'extent_sha256',b'end_va_exclusive',b'limitations',b'No Ghidra Program']:
                    self.assertIn(item,a.stdout)
                self.assertNotIn(b'Function ID  unavailable',a.stdout)
            else:
                self.assertEqual(json.loads(a.stdout)['data']['native_readiness'],'not_checked')
        blocked=subprocess.run(cmd+['--output',str(self.p.path/'index.sqlite'),'--force'],capture_output=True,env=env)
        self.assertNotEqual(blocked.returncode,0);self.assertEqual(self.hashes(),before)
