# Finite Muse job queue

This repository now contains a local runner and four **queued prompts**, not
implementations of the export roadmap. It does not start itself and does not
merge PRs. The owner launches it once in a writable terminal on their Mac.
The prompts cover independent new modules; dot reviews their draft PRs later.

## First run

Use Python 3.12+, Git, authenticated `gh`, and configured `ori`/Muse. Fetch this
branch into a clean checkout (do not reset or discard another worktree):

```sh
git fetch origin
# Use the branch carrying this document, or main after it is merged.
git switch feature/muse-job-queue
gh auth status
python3 scripts/muse_queue/runner.py init --repo "$PWD"
python3 scripts/muse_queue/runner.py status --repo "$PWD"
# This explicitly permits Muse's --yolo execution and branch/PR publication:
python3 scripts/muse_queue/runner.py run --repo "$PWD" --workers 2 --allow-agent-execution
```

The bundled prompts are pinned to main commit
`81a80dd1b472a2525fa2596555b07f90920b9b09`. Run `git fetch origin` first so that
commit exists. Jobs do not follow a moving main. The shared index contract is
embedded in each prompt; they do not depend on unmerged sibling code. Review
that contract before starting. `--workers` permits 1–8; start with two.
Use a dedicated clone if another tool is manipulating Git administrative state.

Muse's installed skill documents this launch form:

```sh
ori muse exec --yolo --session-id UUID --prompt-file /absolute/prompt.md
```

The runner uses precisely that argv form, not shell interpolation. Test commands
run with PYTHONPATH pinned to the worktree src directory and user site packages
disabled, so they cannot silently test an installed macscope instead. The actual
Muse resume/settings behavior must be smoke-tested in the owner's writable
session. A read-only dot executor previously hit `ORI_CLI_HARNESS_SETTINGS_CONFLICT`
writing `~/.config/muse/settings.json`. Configure Muse normally first; this runner
neither changes those settings nor bypasses host permission restrictions.

**Security:** `--yolo` gives Muse broad execution authority available to its OS
account. Worktrees, prompts and `allowed_paths` are not a sandbox. The latter is
a publication check, not prevention of reads/writes/commands elsewhere. Use
narrow credentials, trusted owner-written jobs, and a dedicated environment.
Never put secrets, private TickTick binaries/pseudocode or credentials in prompts,
commits, PR descriptions or logs. Do not run third-party queue files as trusted
jobs. Tests are also arbitrary trusted commands. No budget enforcement is
provided; set provider limits separately. Muse/network bills are the owner's.

## Jobs and results

Each `scripts/muse_queue/jobs/<id>/job.json` has schema, immutable job ID, logical
task ID, `muse/<task_id>` branch, pinned base SHA, canonical session UUID, adjacent
prompt file, explicit allowed/required paths, test argv arrays, optional sequencing
`depends_on`, resource locks, and a finite Muse timeout (default one hour).
No prompt is interpolated into a shell command. On registration the manifest
and prompt bytes are stored together and SHA-256 pinned in SQLite. Editing a
registered job is rejected; use a new ID for a correction.

The default private state lives in the Git common directory's `muse-queue/`:
- SQLite jobs/tasks ledger, immutable queue repository identity;
- `worktrees/<task_id>`: retained branch/worktree per logical task;
- `results/<job_id>/prompt.md`, `muse.log`, `tests.log`.

The bundled jobs require their source, tests and documentation files and reject
zero-test discovery. Each job checks a512MiB free-disk floor before starting; it
is not a disk reservation. Treat logs as private, potentially sensitive and
unbounded in size. Monitor disk
and provider usage. This first version is for a finite, modest trusted batch,
not a daemon or hostile-agent sandbox.

A repository-wide OS lock prevents two copies of this runner from concurrently
using the same repository even with different state directories. Local workers
also serialize each task/branch/session and named resource lock. Git worktree
creation is serialized. Do not concurrently manipulate the runner's worktrees
from another tool. Builds and generated files must stay inside each worktree;
shared desktop, simulator, Ghidra cache and real application data are out of scope
for the bundled jobs. Only one runner can own the shared `mac-desktop` resource;
this is not a global lock against unrelated software.

The runner fills a finite pool, claims ready jobs atomically, waits for their
Muse call, independently runs manifest tests, rejects changes outside allowed
paths, commits, pushes without force, and creates/reuses one draft PR. Muse is
instructed not to commit/push/change branches or spawn background jobs. If it does
commit, the runner refuses automatic publication. A successful process is not
proof of correct implementation: final status is `awaiting_review`, never merged.

`depends_on` is **sequencing only**: it waits until preceding jobs have draft PRs,
not until they are approved or merged. It does not cherry-pick their code. All
bundled jobs can use the frozen embedded contract independently. Do not use this
field for code dependencies. After review/merge, create a new integration job
pinned to the resulting main SHA. This avoids silently combining unreviewed work.

## Corrections and publication recovery

For a review fix, add another folder with a **new job ID**, same `task_id`, branch,
base SHA and session UUID, plus `expected_head` equal to the current remote branch
SHA. Use the same queue state/worktree. The runner refuses dirty worktrees or a
moved local/remote head and preserves them. Reuse the original test/scope contract
unless the owner deliberately expands the task. Completed jobs never rerun.

Publication is staged: `ready_to_publish` → `publication_uncertain` →
`awaiting_review`. A network error may occur after the server acted. Inspect the
remote first; do not blindly rerun Muse or create another PR. To reconcile only
publication, use:

```sh
python3 scripts/muse_queue/runner.py publish --repo "$PWD" --job JOB_ID
```

It rechecks the clean tested commit, intended remote, remote branch and exact PR
owner/head/base/commit before mutation. It never force pushes, reopens closed
PRs or auto-merges. If the branch diverged or a PR was closed/merged, reconcile
manually and create a new appropriately pinned task. No automatic code retry,
rebase, reset, pruning or removal of worktrees is implemented.

## Interruption and failure

Ctrl-C/SIGTERM stops **new jobs** and waits for active commands (potentially the one-hour Muse deadline); it is not a
hard kill switch. No new tests/publication begin after the stop is observed.
A Muse call is bounded by its job deadline; tests have a ten-minute deadline.
On timeout or signal death, the runner fails closed: marks interruption, stops
scheduling, retains a repository-wide `muse-queue.inflight` marker and does **not**
auto-retry. It deliberately does not claim it can reliably kill every descendant
that detached into another process group. The error records the owned PID/PGID.
Inspect and stop only those owned processes, then inspect the worktree and ledger.

The runner OS lock is inherited by direct subprocesses. It may remain held until
those calls end. A crash can release OS locks while detached children live; the
inflight marker plus `running`/`interrupted` ledger states then block restart.
Do not remove the marker or alter ledger status merely to force a restart. There
is no automatic crash-recovery/reset command in this first version. After proving
owned processes are gone, preserve logs/work, reconcile the state deliberately
(or use a separate clone with new task identities). Never run another job against
the same branch/worktree/session while its process state is uncertain.

Failed tasks do not automatically retry. Independent ready tasks may finish;
blocked dependencies remain `pending` in the final summary, and exit is nonzero
unless every registered job is awaiting review. The runner exits when nothing
is runnable/running; it does not watch for new prompt files forever.

## Validation and limits

Run the runner tests without Muse/GitHub/network:

```sh
python3 -m unittest discover -s tests -p 'test_muse_queue.py' -v
```

Tests use owned temporary repositories and fake subprocesses. This is not a
claim that actual Muse concurrency/session resumption or real PR creation has
been smoke-tested on the Mac. Start with one worker for the first native run,
then two. The runner has no remote job polling service, distributed locks,
credential management, live desktop automation, hard resource sandbox or
automatic merging. See the [roadmap](export-readability-roadmap.md) for the actual
product work the prompts are intended to implement.

Validation for the initial implementation: 27 queue tests passed, including real
local Git commits/pushes to disposable bare repositories with fake Muse/gh,
publication-response uncertainty, scope masking, concurrency/resource locks,
interruption and worktree import isolation. The complete existing Python suite
passed 1,039 tests in the cloud. No real Muse process, real queued job or native
session-resumption smoke test was run to produce these results.
