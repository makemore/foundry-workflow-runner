"""The runner image's start: root under tini -> the runner as uid 10001 that can start children as 10002.

A host's job runs this container as root (for example a Cloud Run job, 2nd generation). This file, run by
the image's Python in isolated mode, does the only root work there is and then becomes the runner in the
same process:

1. Makes sure ``/workspace`` (10001:10010, 2770, setgid) and the workload's home exist.
2. Drops every capability from the bounding set but CAP_SETUID and CAP_SETGID (best effort: it needs
   CAP_SETPCAP; with no_new_privs set below, the bounding set no longer matters for exec anyway).
3. Keeps capabilities across the uid change (PR_SET_KEEPCAPS), becomes uid/gid 10001 with the
   supplementary group ``workspace`` (10010), and leaves exactly CAP_SETUID and CAP_SETGID permitted
   and effective, with nothing inheritable or ambient.
4. Sets no_new_privs (inherited by every child: no setuid binary or file capability can raise them).
5. Checks all of that in /proc/self/status and refuses to go on if any of it isn't so.
6. Runs ``foundry_workflow_runner`` with this file's arguments (none: one hosted run from
   ``STUDIO_RUN_URL``/``STUDIO_RUN_TOKEN``; ``run /workspace``: a standalone run), or, with
   ``--egress-probe``, the egress smoke test's probe.

What that gives the runner's children: ``subprocess.Popen(..., user=10002, group=10010,
extra_groups=[], umask=0o007)`` works (CAP_SETUID/CAP_SETGID), and the child's ``execve`` of Claude
Code or the workflow's command clears every capability (no file capabilities, no ambient set), so
customer code runs as 10002 with none. It can't read the runner's ``/proc/<pid>/environ`` (another
uid, and the runner is not dumpable after its uid change), can't signal it, and can't switch to it.

Shared files: the runner and the workload share group 10010 through the setgid ``/workspace``; the
workload's umask 007 keeps what it writes readable by the runner (bundle, state). The runner's own
umask is 077, so anything it writes is private unless it opens it up on purpose.

Environment the runner can rely on: STUDIO_WORKLOAD_UID, STUDIO_WORKLOAD_GID, STUDIO_WORKLOAD_HOME.
Standard library only (ctypes for prctl/capset).
"""

from __future__ import annotations

import ctypes
import os
import runpy
import sys

RUNNER_UID = 10001
RUNNER_GID = 10001
WORKLOAD_UID = 10002
WORKSPACE_GID = 10010
WORKSPACE = "/workspace"
RUNNER_HOME = "/home/runner"
WORKLOAD_HOME = "/home/workload"

CAP_SETGID = 6
CAP_SETUID = 7
KEPT = (1 << CAP_SETGID) | (1 << CAP_SETUID)

PR_SET_KEEPCAPS = 8
PR_CAPBSET_DROP = 24
PR_SET_NO_NEW_PRIVS = 38
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4
_LINUX_CAPABILITY_VERSION_3 = 0x20080522


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]


_libc = ctypes.CDLL(None, use_errno=True)


def _prctl(option: int, arg2: int = 0) -> None:
    if _libc.prctl(option, ctypes.c_ulong(arg2), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"prctl({option}): {os.strerror(errno)}")


def _capset(effective: int, permitted: int, inheritable: int) -> None:
    header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapData * 2)()
    data[0].effective, data[0].permitted, data[0].inheritable = effective, permitted, inheritable
    if _libc.capset(ctypes.byref(header), data) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"capset: {os.strerror(errno)}")


def status() -> dict[str, str]:
    with open("/proc/self/status") as handle:
        return dict(line.rstrip("\n").split(":\t", 1) for line in handle if ":\t" in line)


def _prepare_dirs() -> None:
    os.makedirs(WORKSPACE, exist_ok=True)
    os.chown(WORKSPACE, RUNNER_UID, WORKSPACE_GID)
    os.chmod(WORKSPACE, 0o2770)
    os.makedirs(WORKLOAD_HOME, exist_ok=True)
    os.chown(WORKLOAD_HOME, WORKLOAD_UID, WORKSPACE_GID)
    os.chmod(WORKLOAD_HOME, 0o2770)
    os.makedirs(RUNNER_HOME, exist_ok=True)
    os.chown(RUNNER_HOME, RUNNER_UID, RUNNER_GID)
    os.chmod(RUNNER_HOME, 0o700)


def drop_privileges() -> list[str]:
    """Root -> the runner (see the module docstring). Returns value-free notes; raises if the
    result isn't exactly what it should be."""
    notes: list[str] = []
    if os.getuid() != 0:
        raise PermissionError("start.py must start as root (the image's default user)")
    _prepare_dirs()
    with open("/proc/sys/kernel/cap_last_cap") as handle:
        last_cap = int(handle.read())
    try:
        for cap in range(last_cap + 1):
            if not (KEPT >> cap) & 1:
                _prctl(PR_CAPBSET_DROP, cap)
    except OSError:
        notes.append("bounding set not narrowed (no CAP_SETPCAP); no_new_privs still applies")
    _prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)
    _prctl(PR_SET_KEEPCAPS, 1)
    os.setgroups([WORKSPACE_GID])
    os.setresgid(RUNNER_GID, RUNNER_GID, RUNNER_GID)
    os.setresuid(RUNNER_UID, RUNNER_UID, RUNNER_UID)
    _capset(KEPT, KEPT, 0)
    _prctl(PR_SET_KEEPCAPS, 0)
    _prctl(PR_SET_NO_NEW_PRIVS, 1)
    os.umask(0o077)

    st = status()
    expected = {
        "Uid": "\t".join([str(RUNNER_UID)] * 4),
        "Gid": "\t".join([str(RUNNER_GID)] * 4),
        "Groups": str(WORKSPACE_GID),
        "CapEff": f"{KEPT:016x}",
        "CapPrm": f"{KEPT:016x}",
        "CapInh": f"{0:016x}",
        "CapAmb": f"{0:016x}",
        "NoNewPrivs": "1",
    }
    wrong = [key for key, value in expected.items() if st.get(key, "").strip() != value]
    if wrong:
        raise PermissionError("privilege drop incomplete: " + ", ".join(wrong))
    return notes


def main(argv: list[str]) -> int:
    notes = drop_privileges()
    for note in notes:
        print(f"workflow-runner: {note}", file=sys.stderr, flush=True)
    os.environ.update({
        "HOME": RUNNER_HOME, "USER": "runner", "LOGNAME": "runner",
        "STUDIO_WORKLOAD_UID": str(WORKLOAD_UID), "STUDIO_WORKLOAD_GID": str(WORKSPACE_GID),
        "STUDIO_WORKLOAD_HOME": WORKLOAD_HOME,
    })
    os.chdir(WORKSPACE)
    if argv[:1] == ["--egress-probe"]:
        sys.argv = ["egress_probe.py", *argv[1:]]
        runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "egress_probe.py"),
                       run_name="__main__")
        return 0
    sys.argv = ["foundry_workflow_runner", *argv]
    runpy.run_module("foundry_workflow_runner", run_name="__main__", alter_sys=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except PermissionError as exc:
        print(f"workflow-runner: {exc}", file=sys.stderr, flush=True)
        sys.exit(70)
