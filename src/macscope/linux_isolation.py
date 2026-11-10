"""Reviewable Linux isolation requirements, deliberately not a worker launcher.

The namespace/mount portion alone cannot enforce the Mac worker's executable
allowlist. There is no opt-out, approval file, environment toggle, or unsafe
fallback which turns this plan into a runnable command. Linux execution stays
closed until executable confinement and the complete live canary matrix have
been implemented and verified on an explicitly pinned host.
"""
from pathlib import Path

from .errors import Error
from .storage import identity, is_digest


POLICY = "macscope-linux-isolation-plan/1"
BLOCKER = "linux_isolation_unverified"
REQUIRED_GATES = (
    "deny_network_including_loopback_and_host_unix_sockets",
    "allow_only_selected_runtime_executables",
    "deny_execution_from_inputs_jobs_and_other_paths",
    "read_only_input_and_query_database_files",
    "deny_reads_of_other_workspaces_home_and_source",
    "confine_writes_to_current_job",
    "verify_owned_process_cleanup_and_namespace_aware_restart_fencing",
    "fingerprint_runtime_and_auxiliary_libraries",
    "verify_full_ghidra_import_analyze_and_fresh_query",
)
SYSTEM_EXEC = (
    "/bin/bash", "/bin/sh", "/usr/bin/cat", "/usr/bin/expr", "/usr/bin/env",
    "/usr/bin/readlink", "/usr/bin/dirname", "/usr/bin/uname", "/usr/bin/true",
)


def require_worker():
    """Unconditional gate. A successful static preflight is not isolation proof."""
    raise Error(BLOCKER,
                "Linux engine execution is disabled: executable confinement and live isolation "
                "validation are incomplete. Static and cached queries remain available; "
                "doctor --host-only or --static does not start a worker.", 4)


def capability():
    return {"backend": "linux-namespace-plan", "policy": POLICY,
            "engine_execution": False, "status": "unvalidated",
            "blocker": BLOCKER, "required_gates": list(REQUIRED_GATES)}


def absolute_path(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or any(c in str(path) for c in ("\0", "\n", "\r")):
        raise Error("worker_isolation_scope", "Isolation paths must be absolute and unambiguous", 3)
    # This is planning only, but never describe a symbolic-link escape as scoped.
    try:
        if path.resolve() != path:
            raise ValueError("symbolic or noncanonical path")
    except (OSError, RuntimeError, ValueError) as cause:
        raise Error("worker_isolation_scope", "Isolation paths must be canonical without links", 3) from cause
    return path


def plan(project, dependencies, *, write_root, bridge, staged_image_id=None, read_only_program=False):
    """Return a deterministic requirements document, not bubblewrap arguments.

    System-library discovery/fingerprinting, execute-path enforcement, namespace
    creation and read-only database mounts are requirements, not implementations.
    Do not pass any of these records to a process launcher.
    """
    from . import host_platform, jobs

    root, job = absolute_path(project.path), absolute_path(write_root)
    if job.parent != root / "jobs" or not jobs.JOB_ID.fullmatch(job.name):
        raise Error("worker_isolation_scope", "Linux write scope must name one private job", 3)
    runtime = [absolute_path(dependencies[key]) for key in ("ghidra_path", "java_home")]
    scripts = absolute_path(bridge)
    for path in [*runtime, scripts]:
        # Never propose binding a root that would expose workspace siblings or
        # let a writable job replace its own trusted executable/script tree.
        if (path == root or root.is_relative_to(path) or path.is_relative_to(job)
                or path.is_relative_to(root / "inputs") or path.is_relative_to(root / "jobs")):
            raise Error("worker_isolation_scope", "Runtime paths overlap protected worker state", 3)
    if staged_image_id is not None and not is_digest(staged_image_id):
        raise Error("worker_isolation_scope", "Invalid staged input identity", 3)
    g, j = runtime
    executable_paths = [*SYSTEM_EXEC, str(g / "support/analyzeHeadless"), str(g / "support/launch.sh"),
                        str(g / host_platform.LINUX_X86_64.native_path), str(j / "bin/java"),
                        str(j / "lib/jspawnhelper")]
    document = {
        **capability(), "schema": POLICY,
        "filesystem": {
            "initial_root": "empty",
            "runtime_read_only": [str(path) for path in [*runtime, scripts]],
            "system_libraries": "explicit discovered and fingerprinted closure required",
            "input_read_only": None if staged_image_id is None else str(root / "inputs" / (staged_image_id + ".macho")),
            "writable": [str(job)], "required_host_home_visibility": "absent",
            "required_host_socket_visibility": "absent",
            "private_devices": ["null", "random", "urandom"], "proc": "private_pid_namespace_only",
            "query_database_write_denial": {"root": str(job / "program"), "suffix": ".gbf"}
                if read_only_program else None,
        },
        "namespaces": ["user", "mount", "pid", "ipc", "uts", "network"],
        "network": "deny_all", "capabilities": "drop_all",
        "exec_allowlist": executable_paths,
        "exec_denied_roots": [str(root / "inputs"), str(root / "jobs")],
        "runtime_implementation": "not_implemented",
    }
    return {**document, "plan_sha256": identity(document)}
