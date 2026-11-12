"""Queue tests use disposable git repositories and fake Muse/GitHub executables only."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import warnings
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'scripts/muse_queue/runner.py'
spec = importlib.util.spec_from_file_location('muse_queue_runner', MODULE)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class QueueTests(unittest.TestCase):
    def setUp(self):
        runner.STOP.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'queue-test@example.invalid')
        self.git('config', 'user.name', 'Queue Test')
        (self.repo / 'base.txt').write_text('base\n')
        self.git('add', 'base.txt')
        self.git('commit', '-qm', 'base')
        self.base = self.git('rev-parse', 'HEAD')
        self.remote = self.root / 'remote.git'
        subprocess.run(['git', 'init', '--bare', '-q', str(self.remote)], check=True)
        self.git('remote', 'add', 'origin', str(self.remote))
        self.state = self.root / 'state'
        self.state.mkdir()
        self.jobs_dir = self.root / 'jobs'
        self.jobs_dir.mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.ori = self.bin / 'ori'
        self.ori.write_text('#!' + sys.executable + '\nfrom pathlib import Path\nPath("result.txt").write_text("result\\n")\n')
        self.ori.chmod(0o755)
        self.gh = self.bin / 'gh'
        self.gh.write_text('''#!%s
import json, os, subprocess, sys
from pathlib import Path
p=Path(os.environ['FAKE_GH_STATE'])
if sys.argv[1:3]==['pr','list']:
    print(p.read_text() if p.exists() else '[]')
elif sys.argv[1:3]==['pr','create']:
    head=sys.argv[sys.argv.index('--head')+1]
    sha=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    p.write_text(json.dumps([{'url':'https://github.com/test/repo/pull/1','state':'OPEN','headRefName':head,'headRepositoryOwner':{'login':'test'},'headRefOid':sha,'baseRefName':'main'}]))
    count=p.with_suffix('.count')
    count.write_text(str(int(count.read_text())+1) if count.exists() else '1')
    if os.environ.get('FAKE_GH_LOST_RESPONSE')=='1': sys.exit(1)
else: sys.exit(1)
''' % sys.executable)
        self.gh.chmod(0o755)
        self.env = patch.dict(os.environ, {'PATH':str(self.bin)+os.pathsep+os.environ['PATH'], 'FAKE_GH_STATE':str(self.root/'prs.json')})
        self.env.start()
        self.args = SimpleNamespace(remote='origin', github_repo='test/repo', muse=str(self.ori), workers=2)

    def tearDown(self):
        self.env.stop()
        runner.STOP.clear()
        self.tmp.cleanup()

    def git(self, *args, cwd=None):
        return subprocess.check_output(['git','-C',str(cwd or self.repo),*args], text=True).strip()

    def job(self, name='one', **changes):
        j={'schema':1,'id':name,'task_id':name,'base_sha':self.base,'branch':'muse/'+name,
           'session_id':'00000000-0000-4000-8000-'+f'{len(name):012d}',
           'prompt':'prompt.md','prompt_text':'Write result.txt only.','allowed_paths':['result.txt'],
           'tests':[[sys.executable,'-c','from pathlib import Path; assert Path("result.txt").read_text()=="result\\n"']],
           'timeout_seconds':10,'resource_locks':[],'depends_on':[]}
        j.update(changes)
        return j

    def write_job(self, j):
        d=self.jobs_dir/j['id']; d.mkdir(exist_ok=True)
        value=dict(j); value.pop('prompt_text',None)
        (d/'job.json').write_text(json.dumps(value)); (d/'prompt.md').write_text(j['prompt_text'])

    def register(self, *jobs):
        runner.register(self.state, list(jobs))

    def row(self, jid='one'):
        return next(r for r in runner.status(self.state) if r['id']==jid)

    def run_one(self, j=None):
        j=j or self.job(); self.register(j)
        runner.set_status(self.state,j['id'],'running')
        with runner.exclusive(self.root/'lock') as fd, patch.object(runner,'verify_remote'):
            runner.run_job(self.repo,self.state,j,self.args,fd)
        return j

    def test_load_canonicalizes_uuid(self):
        j=self.job(session_id='AABBCCDD000040008000000000000001')
        self.write_job(j)
        self.assertEqual(runner.load_jobs(self.jobs_dir)[0]['session_id'],'aabbccdd-0000-4000-8000-000000000001')

    def test_same_session_alias_rejected_for_different_tasks(self):
        self.write_job(self.job('one',session_id='AABBCCDD000040008000000000000001'))
        self.write_job(self.job('two',session_id='aabbccdd-0000-4000-8000-000000000001'))
        with self.assertRaises(runner.QueueError): runner.load_jobs(self.jobs_dir)

    def test_prompt_cannot_escape_job_directory(self):
        j=self.job(prompt='../outside.md'); self.write_job(j)
        with self.assertRaises(runner.QueueError): runner.load_jobs(self.jobs_dir)

    def test_immutable_job_rejects_prompt_change(self):
        j=self.job(); self.register(j)
        changed=dict(j,prompt_text='changed')
        with self.assertRaises(runner.QueueError): self.register(changed)
        with runner.connect(self.state) as db:
            original=json.loads(db.execute('SELECT spec FROM jobs').fetchone()[0])
        self.assertEqual(original['prompt_text'],j['prompt_text'])

    def test_lock_excludes_second_runner(self):
        with runner.exclusive(self.root/'lock'):
            with self.assertRaises(runner.QueueError):
                with runner.exclusive(self.root/'lock'): pass

    def test_prepare_does_not_touch_dirty_original(self):
        (self.repo/'base.txt').write_text('user uncommitted\n')
        j=self.job(); self.register(j)
        wt=runner.prepare(self.repo,self.state,j,'origin')
        self.assertEqual((self.repo/'base.txt').read_text(),'user uncommitted\n')
        self.assertEqual((wt/'base.txt').read_text(),'base\n')
        self.assertEqual(self.git('branch','--show-current',cwd=wt),j['branch'])

    def test_dirty_followup_refused_without_reset(self):
        j=self.job(); self.register(j)
        wt=runner.prepare(self.repo,self.state,j,'origin')
        (wt/'result.txt').write_text('unsaved')
        follow=dict(j,id='one-fix',expected_head=self.base)
        with self.assertRaises(runner.QueueError): runner.prepare(self.repo,self.state,follow,'origin')
        self.assertEqual((wt/'result.txt').read_text(),'unsaved')

    def test_stale_followup_refused(self):
        j=self.job(); self.register(j)
        wt=runner.prepare(self.repo,self.state,j,'origin')
        follow=dict(j,id='one-fix',expected_head='1'*40)
        with self.assertRaises(runner.QueueError): runner.prepare(self.repo,self.state,follow,'origin')
        self.assertEqual(self.git('rev-parse','HEAD',cwd=wt),self.base)

    def test_out_of_scope_file_is_preserved_and_not_published(self):
        self.ori.write_text('#!'+sys.executable+'\nfrom pathlib import Path\nPath("outside.txt").write_text("keep")\n')
        self.run_one()
        self.assertEqual(self.row()['status'],'failed')
        self.assertEqual((self.state/'worktrees/one/outside.txt').read_text(),'keep')
        self.assertIsNone(runner.remote_head(self.repo,'origin','muse/one'))

    def test_staged_out_of_scope_change_cannot_hide_behind_restored_worktree(self):
        self.ori.write_text('#!'+sys.executable+'\nfrom pathlib import Path\nimport subprocess\nPath("base.txt").write_text("staged change\\n")\nsubprocess.run(["git","add","base.txt"],check=True)\nPath("base.txt").write_text("base\\n")\nPath("result.txt").write_text("result\\n")\n')
        self.run_one()
        self.assertEqual(self.row()['status'],'failed')
        self.assertIn('Out-of-scope',self.row()['detail'])
        wt=self.state/'worktrees/one'
        self.assertEqual((wt/'base.txt').read_text(),'base\n')
        self.assertEqual(self.git('show',':base.txt',cwd=wt),'staged change')
        self.assertIsNone(runner.remote_head(self.repo,'origin','muse/one'))

    def test_missing_required_file_prevents_tests_and_publication(self):
        j=self.job(required_files=['missing.txt'],tests=[[sys.executable,'-c','open("test-ran", "w").close()']])
        self.run_one(j)
        self.assertEqual(self.row()['status'],'failed')
        self.assertIn('Required deliverable missing: missing.txt',self.row()['detail'])
        self.assertFalse((self.state/'worktrees/one/test-ran').exists())
        self.assertIsNone(runner.remote_head(self.repo,'origin','muse/one'))

    def test_bundled_jobs_fail_on_zero_discovered_tests(self):
        # Execute the actual bundled test commands against an empty test suite,
        # not a string check: normal unittest discovery incorrectly returns 0.
        (self.root/'tests').mkdir()
        jobs=list((MODULE.parent/'jobs').glob('*/job.json'))
        self.assertEqual(len(jobs),4)
        for path in jobs:
            with self.subTest(job=path.parent.name):
                j=json.loads(path.read_text())
                self.assertTrue(j['required_files'])
                self.assertTrue(j['tests'])
                results=[subprocess.run([sys.executable,*argv[1:]],cwd=self.root,text=True,capture_output=True) for argv in j['tests']]
                self.assertTrue(any(r.returncode != 0 and 'No tests discovered' in r.stderr for r in results))

    def test_fake_muse_real_git_fake_gh_success_and_idempotent_publish(self):
        j=self.run_one()
        row=self.row(); self.assertEqual(row['status'],'awaiting_review',row)
        self.assertEqual(runner.remote_head(self.repo,'origin','muse/one'),row['commit_sha'])
        with patch.object(runner,'verify_remote'):
            runner.publish(self.repo,self.state,j,'origin','test/repo')
        self.assertEqual((self.root/'prs.count').read_text(),'1')
        self.assertEqual(self.row()['pr'],'https://github.com/test/repo/pull/1')

    def test_uncertain_pr_create_reconciles_without_duplicate(self):
        with patch.dict(os.environ,{'FAKE_GH_LOST_RESPONSE':'1'}):
            j=self.run_one()
        self.assertEqual(self.row()['status'],'publication_uncertain')
        with patch.object(runner,'verify_remote'):
            runner.publish(self.repo,self.state,j,'origin','test/repo')
        self.assertEqual(self.row()['status'],'awaiting_review')
        self.assertEqual((self.root/'prs.count').read_text(),'1')

    def test_wrong_pr_identity_blocks_reuse(self):
        j=self.run_one()
        prs=json.loads((self.root/'prs.json').read_text()); prs[0]['baseRefName']='other'
        (self.root/'prs.json').write_text(json.dumps(prs))
        with patch.object(runner,'verify_remote'), self.assertRaises(runner.QueueError):
            runner.publish(self.repo,self.state,j,'origin','test/repo')
        self.assertEqual(self.row()['status'],'publication_uncertain')

    def test_publish_validates_remote_destination(self):
        j=self.run_one()
        with self.assertRaises(runner.QueueError): runner.publish(self.repo,self.state,j,'origin','other/repo')

    def test_failed_test_never_pushes(self):
        self.run_one(self.job(tests=[[sys.executable,'-c','raise SystemExit(1)']]))
        self.assertEqual(self.row()['status'],'failed')
        self.assertIsNone(runner.remote_head(self.repo,'origin','muse/one'))
        self.assertTrue((self.state/'worktrees/one/result.txt').exists())

    def test_muse_cannot_commit_for_runner(self):
        self.ori.write_text('#!'+sys.executable+'\nfrom pathlib import Path\nimport subprocess\nPath("result.txt").write_text("result\\n")\nsubprocess.run(["git","add","result.txt"],check=True)\nsubprocess.run(["git","commit","-qm","unexpected"],check=True)\n')
        self.run_one()
        self.assertEqual(self.row()['status'],'failed')
        self.assertIn('committed',self.row()['detail'])
        self.assertIsNone(runner.remote_head(self.repo,'origin','muse/one'))

    def test_interrupted_jobs_are_not_automatically_reclaimed(self):
        j=self.job(); self.register(j); runner.set_status(self.state,j['id'],'interrupted')
        with self.assertRaises(runner.QueueError): runner.drain(self.repo,self.state,[j],self.args,0)

    def test_scheduler_parallelism_resource_lock_and_finite_drain(self):
        jobs=[self.job('one',resource_locks=['desktop']),self.job('two',resource_locks=['desktop'],session_id='00000000-0000-4000-8000-000000000002'),self.job('three',session_id='00000000-0000-4000-8000-000000000003')]
        self.register(*jobs)
        active=set(); seen=[]; mutex=threading.Lock(); maximum=0
        def fake(repo,state,j,args,fd):
            nonlocal maximum
            with mutex:
                self.assertFalse(j['resource_locks'] and active.intersection({'one','two'}))
                active.add(j['id']); maximum=max(maximum,len(active)); seen.append(j['id'])
            time.sleep(.3)
            with mutex: active.remove(j['id'])
            runner.set_status(state,j['id'],'awaiting_review')
        with patch.object(runner,'run_job',fake): runner.drain(self.repo,self.state,jobs,self.args,0)
        self.assertEqual(sorted(seen),['one','three','two'])
        self.assertEqual(maximum,2)
        self.assertTrue(all(r['status']=='awaiting_review' for r in runner.status(self.state)))

    def test_failed_dependency_remains_pending_and_queue_exits(self):
        one=self.job('one'); two=self.job('two',depends_on=['one'],session_id='00000000-0000-4000-8000-000000000002')
        self.register(one,two)
        def fake(repo,state,j,args,fd): runner.set_status(state,j['id'],'failed')
        with patch.object(runner,'run_job',fake): rows=runner.drain(self.repo,self.state,[one,two],self.args,0)
        self.assertEqual({r['id']:r['status'] for r in rows},{'one':'failed','two':'pending'})

    def test_stop_during_muse_prevents_tests_and_publication(self):
        j=self.job(); self.register(j)
        def stop_then_success(*args,**kwargs):
            (self.state/'worktrees/one/result.txt').write_text('result\n')
            runner.STOP.set(); return 0
        with runner.exclusive(self.root/'lock') as fd, patch.object(runner,'supervised',side_effect=stop_then_success), patch.object(runner,'publish') as publish:
            runner.run_job(self.repo,self.state,j,self.args,fd)
        self.assertEqual(self.row()['status'],'interrupted')
        publish.assert_not_called()

    def test_clean_followup_reuses_worktree_and_session(self):
        j=self.run_one()
        sha=self.row()['commit_sha']
        follow=dict(j,id='one-fix',expected_head=sha,prompt_text='Fix this task.')
        self.register(follow)
        wt=runner.prepare(self.repo,self.state,follow,'origin')
        self.assertEqual(wt,self.state/'worktrees/one')
        with runner.connect(self.state) as db:
            tasks=db.execute('SELECT * FROM tasks').fetchall()
        self.assertEqual(len(tasks),1)
        self.assertEqual(tasks[0]['session'],j['session_id'])

    def test_stop_during_tests_prevents_commit_and_publication(self):
        j=self.job(); self.register(j)
        calls=[]
        def fake(*args,**kwargs):
            calls.append(args[0])
            if len(calls)==1:
                (self.state/'worktrees/one/result.txt').write_text('result\n')
            else:
                runner.STOP.set()
            return 0
        with runner.exclusive(self.root/'lock') as fd, patch.object(runner,'supervised',side_effect=fake), patch.object(runner,'publish') as publish:
            runner.run_job(self.repo,self.state,j,self.args,fd)
        self.assertEqual(self.row()['status'],'interrupted')
        self.assertEqual(self.git('rev-parse','HEAD',cwd=self.state/'worktrees/one'),self.base)
        publish.assert_not_called()

    def test_supervised_tests_import_worktree_not_inherited_pythonpath(self):
        j=self.job(); self.register(j)
        src=self.repo/'src'; src.mkdir()
        (src/'queue_import_probe.py').write_text('ORIGIN="worktree"\n')
        other=self.root/'external'; other.mkdir()
        (other/'queue_import_probe.py').write_text('ORIGIN="external"\n')
        command=[sys.executable,'-c','import os,queue_import_probe; assert queue_import_probe.ORIGIN=="worktree"; assert os.environ["PYTHONNOUSERSITE"]=="1"']
        with patch.dict(os.environ,{'PYTHONPATH':str(other),'PYTHONNOUSERSITE':'0'}), (self.root/'import.log').open('wb') as log, runner.exclusive(self.root/'lock') as fd:
            code=runner.supervised(command,self.repo,log,5,fd,self.state,j['id'],test=True)
        self.assertEqual(code,0,(self.root/'import.log').read_text())

    def test_timeout_fails_closed_and_does_not_reclaim_process(self):
        j=self.job(); self.register(j)
        with (self.root/'log').open('wb') as log, runner.exclusive(self.root/'lock') as fd, warnings.catch_warnings():
            warnings.simplefilter('ignore', ResourceWarning)
            with self.assertRaises(runner.QueueError):
                runner.supervised([sys.executable,'-c','import time; time.sleep(0.6)'],self.repo,log,0.01,fd,self.state,j['id'])
            self.assertEqual(self.row()['status'],'interrupted')
            self.assertTrue(runner.STOP.is_set())
            # Let the exact short-lived synthetic child finish before test cleanup.
            time.sleep(0.8)

    def test_supervision_signal_death_fails_closed(self):
        j=self.job(); self.register(j)
        with (self.root/'log').open('wb') as log, runner.exclusive(self.root/'lock') as fd:
            with self.assertRaises(runner.QueueError):
                runner.supervised([sys.executable,'-c','import os,signal; os.kill(os.getpid(),signal.SIGTERM)'],self.repo,log,5,fd,self.state,j['id'])
        self.assertTrue(runner.STOP.is_set())
        self.assertEqual(self.row()['status'],'interrupted')


if __name__ == '__main__':
    unittest.main()
