#!/usr/bin/env python3
"""Finite trusted-local Muse queue. Not a sandbox; never auto-merges or cleans worktrees."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import uuid

SCHEMA = 1
SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
STOP = threading.Event()
ADMIN = threading.Lock()

class QueueError(Exception):
    pass

def digest(value):
    return hashlib.sha256(value).hexdigest()

def command(argv, cwd=None, timeout=60):
    p = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        raise QueueError(f"Command failed ({p.returncode}): {argv[0]} {argv[1:3]}\n{p.stderr[-3000:]}")
    return p.stdout.strip()

def git(repo, *args):
    return command(["git", "-C", str(repo), *args])

def connect(state):
    db = sqlite3.connect(state / "queue.sqlite", timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, fingerprint TEXT, spec TEXT, status TEXT, detail TEXT, commit_sha TEXT, pr TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, branch TEXT UNIQUE, session TEXT UNIQUE, worktree TEXT UNIQUE, base TEXT)")
    db.commit()
    return db

def safe_relative(value):
    p = Path(value)
    return bool(value) and not p.is_absolute() and '..' not in p.parts and '.git' not in p.parts

def load_jobs(directory):
    jobs = []
    for path in sorted(directory.glob("*/job.json")):
        j = json.loads(path.read_text())
        for field in ("id", "task_id"):
            if not SLUG.fullmatch(j.get(field, "")):
                raise QueueError(f"Invalid {field}: {path}")
        if j.get("schema") != SCHEMA or not SHA.fullmatch(j.get("base_sha", "")):
            raise QueueError(f"Invalid schema/base SHA: {path}")
        if j.get("expected_head") and not SHA.fullmatch(j["expected_head"]):
            raise QueueError("expected_head must be a full commit SHA")
        if j.get("branch") != "muse/" + j["task_id"]:
            raise QueueError("Branch must be muse/<task_id>")
        j["session_id"] = str(uuid.UUID(j["session_id"]))
        prompt = path.parent / j.get("prompt", "prompt.md")
        if prompt.resolve().parent != path.parent.resolve() or prompt.is_symlink():
            raise QueueError("Prompt must be an adjacent regular file")
        j["prompt_text"] = prompt.read_text()
        if not j.get("allowed_paths") or not all(safe_relative(x) for x in j["allowed_paths"]):
            raise QueueError("Explicit relative allowed_paths required")
        if not j.get("tests") or not all(isinstance(t, list) and t and all(isinstance(x, str) for x in t) for t in j["tests"]):
            raise QueueError("Tests must be nonempty argv arrays")
        if not all(SLUG.fullmatch(x) for x in j.get("resource_locks", [])):
            raise QueueError("Invalid resource lock")
        if not all(SLUG.fullmatch(x) for x in j.get("depends_on", [])):
            raise QueueError("Invalid dependency")
        if not all(safe_relative(x) for x in j.get("required_files", [])):
            raise QueueError("Invalid required_files")
        j["timeout_seconds"] = int(j.get("timeout_seconds", 3600))
        if not 1 <= j["timeout_seconds"] <= 86400:
            raise QueueError("Timeout must be 1..86400 seconds")
        jobs.append(j)
    owners = {}
    for j in jobs:
        for key in (j['branch'],j['session_id']):
            if key in owners and owners[key] != j['task_id']:
                raise QueueError('Branch/session assigned to multiple tasks')
            owners[key]=j['task_id']
    ids = {j["id"] for j in jobs}
    if len(ids) != len(jobs) or not jobs:
        raise QueueError("Empty queue or duplicate IDs")
    for j in jobs:
        if any(x not in ids or x == j["id"] for x in j.get("depends_on", [])):
            raise QueueError("Missing/self dependency")
    return jobs

@contextmanager
def exclusive(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise QueueError(f"Another runner owns {path.name}")
        yield fd
    finally:
        os.close(fd)

def register(state, jobs):
    with connect(state) as db:
        for j in jobs:
            spec = json.dumps(j, sort_keys=True)
            fp = digest(spec.encode())
            row = db.execute("SELECT fingerprint FROM jobs WHERE id=?", (j["id"],)).fetchone()
            if row and row[0] != fp:
                raise QueueError(f"Immutable job changed: {j['id']}; create a new job ID")
            db.execute("INSERT OR IGNORE INTO jobs VALUES(?,?,?,'pending','',NULL,NULL)", (j["id"], fp, spec))


def status(state):
    with connect(state) as db:
        return [dict(r) for r in db.execute("SELECT id,status,detail,commit_sha,pr FROM jobs ORDER BY id")]

def set_status(state, jid, value, detail="", sha=None, pr=None):
    with connect(state) as db:
        db.execute("UPDATE jobs SET status=?,detail=?,commit_sha=COALESCE(?,commit_sha),pr=COALESCE(?,pr) WHERE id=?", (value, detail, sha, pr, jid))

def remote_head(repo, remote, branch):
    value = git(repo, "ls-remote", "--heads", remote, "refs/heads/"+branch)
    return value.split()[0] if value else None

def prepare(repo, state, j, remote):
    with ADMIN, connect(state) as db:
        previous = db.execute("SELECT * FROM tasks WHERE id=?", (j["task_id"],)).fetchone()
        wt = state / "worktrees" / j["task_id"]
        if previous:
            if (previous["branch"], previous["session"], previous["base"]) != (j["branch"], j["session_id"], j["base_sha"]):
                raise QueueError("Task identity changed")
            if not j.get("expected_head"):
                raise QueueError("Follow-up job requires expected_head")
            if git(wt, "rev-parse", "HEAD") != j["expected_head"] or git(wt, "status", "--porcelain"):
                raise QueueError("Follow-up worktree is dirty or not at expected_head; preserved")
            if remote_head(repo, remote, j["branch"]) != j["expected_head"]:
                raise QueueError("Remote follow-up branch moved; reconcile explicitly")
        else:
            if j.get("expected_head") or wt.exists() or git(repo, "branch", "--list", j["branch"]):
                raise QueueError("New task must use an unused branch/worktree")
            if remote_head(repo, remote, j["branch"]):
                raise QueueError("Remote branch already exists")
            if git(repo, "rev-parse", j["base_sha"]+"^{commit}") != j["base_sha"]:
                raise QueueError("Pinned base missing; fetch it first")
            wt.parent.mkdir(parents=True, exist_ok=True)
            git(repo, "worktree", "add", "-b", j["branch"], str(wt), j["base_sha"])
            db.execute("INSERT INTO tasks VALUES(?,?,?,?,?)", (j["task_id"], j["branch"], j["session_id"], str(wt), j["base_sha"]))
        if git(wt, "branch", "--show-current") != j["branch"]:
            raise QueueError("Worktree branch changed")
        return wt

def check_paths(wt, j):
    # Includes committed and dirty changes; untracked paths included separately.
    paths = set()
    for argv in (("diff", "--name-only", "-z", j["base_sha"]),
                 ("diff", "--cached", "--name-only", "-z", j["base_sha"]),
                 ("diff", "--name-only", "-z"),
                 ("ls-files", "--others", "--exclude-standard", "-z")):
        paths.update(p for p in git(wt,*argv).split('\0') if p)
    def allowed(p):
        return any(p == a.rstrip('/') or (a.endswith('/') and p.startswith(a)) for a in j["allowed_paths"])
    bad = sorted(p for p in paths if not allowed(p))
    if bad:
        raise QueueError("Out-of-scope paths preserved, not published: " + ", ".join(bad))
    return paths

def verify_remote(repo, remote, gh_repo):
    url=git(repo,'remote','get-url',remote).removesuffix('.git').rstrip('/')
    if url not in (f'https://github.com/{gh_repo}',f'git@github.com:{gh_repo}'):
        raise QueueError('Remote URL does not match --github-repo')

def publish(repo, state, j, remote, gh_repo):
    verify_remote(repo, remote, gh_repo)
    with connect(state) as db:
        row = db.execute("SELECT * FROM jobs WHERE id=?", (j["id"],)).fetchone()
        task = db.execute("SELECT * FROM tasks WHERE id=?", (j["task_id"],)).fetchone()
    if not row or row["status"] not in ("ready_to_publish", "publication_uncertain", "awaiting_review"):
        raise QueueError("Job is not eligible for publication")
    wt = Path(task["worktree"])
    sha = row["commit_sha"]
    if git(wt, "rev-parse", "HEAD") != sha or git(wt, "status", "--porcelain"):
        raise QueueError("Worktree changed since tests; do not publish")
    check_paths(wt, j)
    set_status(state, j["id"], "publication_uncertain", "Reconciling remote branch and PR before mutation")
    current = remote_head(repo, remote, j["branch"])
    expected = j.get("expected_head")
    if current not in (None, expected, sha) or (expected and current is None):
        raise QueueError("Remote branch diverged; no force push")
    if STOP.is_set():
        raise QueueError("Stop requested; publication deferred")
    if current != sha:
        # Standard fast-forward push never overwrites unrelated remote work.
        git(wt, "push", remote, f"{sha}:refs/heads/{j['branch']}")
    if remote_head(repo, remote, j["branch"]) != sha:
        raise QueueError("Remote head verification failed")
    query = ["gh", "pr", "list", "--repo", gh_repo, "--head", j["branch"], "--state", "all", "--json", "url,state,headRefName,headRepositoryOwner,headRefOid,baseRefName"]
    def matching_prs():
        rows=json.loads(command(query,wt))
        selected=[p for p in rows if p.get('headRepositoryOwner',{}).get('login') == gh_repo.split('/')[0] and p.get('headRefName') == j['branch']]
        if any(p.get('baseRefName') != 'main' or p.get('headRefOid') != sha for p in selected):
            raise QueueError('PR identity/head/base mismatch')
        return selected
    prs = matching_prs()
    if len(prs) > 1 or (prs and prs[0]["state"] != "OPEN"):
        raise QueueError("Multiple or closed PRs require human reconciliation")
    if not prs:
        if STOP.is_set(): raise QueueError("Stop requested; PR creation deferred")
        command(["gh", "pr", "create", "--repo", gh_repo, "--head", j["branch"], "--base", "main", "--draft", "--title", j.get("title",j["id"]), "--body", f"Muse queue task {j['task_id']}; job {j['id']}. Automated checks passed. Awaiting independent review; not auto-merged."], wt)
        prs = matching_prs()
    if len(prs) != 1 or prs[0]["state"] != "OPEN":
        raise QueueError("PR outcome uncertain; inspect before retry")
    set_status(state, j["id"], "awaiting_review", "Pushed and draft PR verified; independent review pending", sha, prs[0]["url"])

def supervised(argv, wt, log, seconds, fd, state, jid, test=False):
    env=os.environ.copy()
    if test:
        env['PYTHONPATH']=str(wt/'src')
        env['PYTHONNOUSERSITE']='1'
    proc = subprocess.Popen(argv, cwd=wt, stdout=log, stderr=subprocess.STDOUT,
                            pass_fds=(fd,), start_new_session=True, env=env)
    receipt=state/'results'/jid/'process.json'
    receipt.parent.mkdir(parents=True,exist_ok=True)
    receipt.write_text(json.dumps({'pid':proc.pid,'pgid':proc.pid,'started':time.time(),'executable':argv[0]}))
    started = time.monotonic()
    while proc.poll() is None:
        if time.monotonic()-started > seconds:
            STOP.set()
            set_status(state,jid,"interrupted",f"Timeout; owned pid/pgid {proc.pid}. Inspect/stop descendants manually before recovery.")
            raise QueueError("interrupted: process teardown uncertain")
        time.sleep(.2)
    if proc.returncode < 0:
        STOP.set()
        set_status(state,jid,"interrupted",f"Owned pid {proc.pid} terminated by signal; descendant state uncertain")
        raise QueueError("interrupted: process teardown uncertain")
    return proc.returncode

def run_job(repo, state, j, args, lock_fd):
    wt = None
    try:
        if shutil.disk_usage(state).free < 512*1024*1024:
            raise QueueError('Less than512MiB free before job; free space first')
        wt = prepare(repo, state, j, args.remote)
        out = state / "results" / j["id"]
        out.mkdir(parents=True, exist_ok=False)
        prompt = out / "prompt.md"
        contract = f"\nRunner contract: task={j['task_id']} branch={j['branch']} session={j['session_id']}. Stay in this worktree. Allowed paths: {j['allowed_paths']}. Do not commit, push, create PRs, change git branches/worktrees/config, or run background processes. Runner executes tests and publishes. Do not touch other worktrees, credentials, local/private binaries or live apps. Do not alter tests to evade requirements. Stop after this task; report limitations.\n"
        prompt.write_text(j["prompt_text"] + contract)
        # Agent output is untrusted text, not authority for scheduling/publication.
        with (out / "muse.log").open("wb") as log:
            code = supervised([args.muse, "muse", "exec", "--yolo", "--session-id", j["session_id"], "--prompt-file", str(prompt)], wt, log, j["timeout_seconds"], lock_fd, state, j["id"])
            if code:
                raise QueueError(f"Muse exit {code}; see private log")
        if STOP.is_set():
            set_status(state,j["id"],"interrupted","Stopped after current Muse call; no tests/publication")
            return
        if git(wt,"branch","--show-current") != j["branch"]:
            raise QueueError("Muse changed branch")
        if git(wt,"rev-parse","HEAD") != (j.get("expected_head") or j["base_sha"]):
            raise QueueError("Muse committed despite runner contract; preserve and review manually")
        paths = check_paths(wt,j)
        for name in j.get('required_files',[]):
            if not (wt/name).is_file():
                raise QueueError(f'Required deliverable missing: {name}')
        with (out / "tests.log").open("w") as log:
            for argv in j["tests"]:
                if STOP.is_set():
                    set_status(state,j["id"],"interrupted","Stopped before tests completed; preserve changes")
                    return
                code = supervised(argv, wt, log, 600, lock_fd, state, j["id"], test=True)
                if code:
                    raise QueueError(f"Test failed: {argv}")
        if STOP.is_set():
            set_status(state,j["id"],"interrupted","Stopped after tests; preserve changes")
            return
        paths=check_paths(wt,j)
        git(wt,"diff","--check")
        if not paths:
            raise QueueError("No changes; no PR created")
        git(wt,"add","--",*sorted(paths))
        git(wt,"commit","-m",j.get("title",j["id"]))
        sha=git(wt,"rev-parse","HEAD")
        set_status(state,j["id"],"ready_to_publish","Tests passed; commit prepared",sha)
        publish(repo,state,j,args.remote,args.github_repo)
    except Exception as exc:
        with connect(state) as db:
            row=db.execute("SELECT status FROM jobs WHERE id=?",(j["id"],)).fetchone()
        if row and row[0] == "interrupted":
            return
        if row and row[0] == "publication_uncertain":
            set_status(state,j["id"],"publication_uncertain",str(exc))
        else:
            set_status(state,j["id"],"failed",str(exc))

def drain(repo,state,jobs,args,fd):
    # One queue runner per repository: this makes DB claims and resource locks local.
    with connect(state) as db:
        if db.execute("SELECT 1 FROM jobs WHERE status IN ('running','interrupted')").fetchone():
            raise QueueError("Prior running/interrupted jobs require manual process and worktree reconciliation; no automatic reclaim")
    active={}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        while True:
            for future in list(active):
                if future.done():
                    future.result(); del active[future]
            rows={r['id']:r for r in status(state)}
            busy={key for job in active.values() for key in (job['task_id'], job['branch'], job['session_id'],*job.get('resource_locks',[]))}
            added=False
            for j in jobs:
                if STOP.is_set() or len(active)>=args.workers: break
                if rows[j['id']]['status'] != 'pending': continue
                if any(rows[d]['status'] != 'awaiting_review' for d in j.get('depends_on',[])): continue
                keys={j['task_id'],j['branch'],j['session_id'],*j.get('resource_locks',[])}
                if keys & busy: continue
                with connect(state) as db:
                    changed=db.execute("UPDATE jobs SET status='running' WHERE id=? AND status='pending'",(j['id'],)).rowcount
                if changed:
                    active[pool.submit(run_job,repo,state,j,args,fd)]=j
                    busy |= keys; added=True
            if not active: break
            time.sleep(.2)
    return status(state)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['init','status','run','publish'])
    parser.add_argument('--repo',type=Path,default=Path.cwd())
    parser.add_argument('--jobs',type=Path,default=Path(__file__).parent/'jobs')
    parser.add_argument('--state',type=Path)
    parser.add_argument('--workers',type=int,default=2)
    parser.add_argument('--muse',default='ori')
    parser.add_argument('--remote',default='origin')
    parser.add_argument('--github-repo',default='Mental-NV/MacDisassembler')
    parser.add_argument('--job')
    parser.add_argument('--allow-agent-execution',action='store_true')
    args=parser.parse_args(argv)
    try:
        os.umask(0o077)
        repo=args.repo.resolve()
        common=Path(git(repo,'rev-parse','--path-format=absolute','--git-common-dir'))
        state=(args.state or common/'muse-queue').resolve()
        state.mkdir(parents=True,exist_ok=True)
        identity={'schema':SCHEMA,'git_common_dir':str(common.resolve()),'remote':args.remote,'github_repo':args.github_repo}
        identity_path=state/'identity.json'
        if identity_path.exists() and json.loads(identity_path.read_text()) != identity:
            raise QueueError('Queue state belongs to different repository/remote')
        if not identity_path.exists(): identity_path.write_text(json.dumps(identity,sort_keys=True))
        if not 1 <= args.workers <= 8: raise QueueError('workers must be1..8; start with2')
        jobs=load_jobs(args.jobs.resolve())
        if args.action == 'status':
            print(json.dumps(status(state),indent=2)); return 0
        with exclusive(common/'muse-queue.runner.lock') as fd:
            register(state,jobs)
            if args.action == 'init':
                print(json.dumps(status(state),indent=2));return 0
            if args.action == 'publish':
                if (common/'muse-queue.inflight').exists() or any(r['status'] in ('running','interrupted') for r in status(state)):
                    raise QueueError('Unfinished execution must be reconciled before publication')
                j=next((j for j in jobs if j['id']==args.job),None)
                if not j: raise QueueError('--job required')
                publish(repo,state,j,args.remote,args.github_repo)
            else:
                if not args.allow_agent_execution: raise QueueError('Read docs and supply --allow-agent-execution; Muse --yolo is not sandboxed')
                if not shutil.which(args.muse) or not shutil.which('gh'): raise QueueError('Install/configure ori and gh first')
                command(['gh','auth','status'])
                # Verify the remote is the intended GitHub repo, not a fork or local path.
                verify_remote(repo,args.remote,args.github_repo)
                for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,lambda *_: STOP.set())
                incident=common/'muse-queue.inflight'
                if incident.exists():
                    raise QueueError('Unfinished prior runner marker; inspect owned jobs/state before manual recovery')
                incident.write_text(json.dumps({'pid':os.getpid(),'state':str(state),'started':time.time()}))
                drain(repo,state,jobs,args,fd)
                if not any(r['status'] in ('running','interrupted') for r in status(state)):
                    incident.unlink()
            rows=status(state); print(json.dumps(rows,indent=2))
            return 0 if all(r['status']=='awaiting_review' for r in rows) else 1
    except (QueueError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print(str(exc),file=sys.stderr);return 2

if __name__=='__main__':
    sys.exit(main())
