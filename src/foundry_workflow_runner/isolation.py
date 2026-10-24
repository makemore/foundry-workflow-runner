"""The workflow runs as its own user, so it can't read the runner's memory, environment or files.

Three ways the runner can be started (``Identity.mode``):

``capabilities`` (the runner image)
    ``image/start.py`` starts as root under tini, then becomes the runner user (10001) keeping exactly
    CAP_SETUID and CAP_SETGID, with no_new_privs, and sets ``STUDIO_WORKLOAD_UID``/``_GID``/``_HOME``.
    Children are started with ``subprocess``'s ``user=``/``group=`` (umask 007) as the workload user (10002,
    group 10010), whose ``execve`` drops every capability. The shared working directory is setgid 10010
    (2770), so the runner reads what the workload saves. The runner has no CAP_KILL: it stops the workload's
    processes through a short helper started as the workload user.

``root``
    Started as root without ``start.py``: the runner drops to ``STUDIO_RUNNER_UID`` (10001) keeping a saved
    uid of 0, and takes root back only for the moment it starts a child as ``STUDIO_RUNNER_CHILD_UID`` (10002),
    gives that user a directory, or stops its processes.

``shared``
    One user for everything: a run on your own computer (``foundry-workflow-runner run``, a host's local dev
    run). Only an explicit ``STUDIO_RUNNER_SHARED_UID=1`` allows it; otherwise the runner refuses to start.

In ``capabilities`` and ``root`` modes the runner never reads customer files with privilege: every unpack or
pack of the workflow's files runs as the workload user too.
"""

import contextlib
import os
import signal
import subprocess
import sys
import threading

CAP_SETGID, CAP_SETUID = 6, 7

_KILL_HELPER = r"""
import os, signal, sys
mode, me = sys.argv[1], os.getpid()
if mode == "group":
    try:
        os.killpg(int(sys.argv[2]), int(sys.argv[3]))
    except (OSError, ProcessLookupError):
        pass
else:  # Every other process of this user: a daemon that left its session too.
    uid = os.getuid()
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) == me:
            continue
        try:
            with open(f"/proc/{name}/status") as handle:
                owner = next(int(line.split()[1]) for line in handle if line.startswith("Uid:"))
            if owner == uid:
                os.kill(int(name), signal.SIGKILL)
        except (OSError, ValueError, StopIteration, ProcessLookupError):
            pass
"""


class IsolationError(Exception):
    pass


def _has_setid_capabilities():
    try:
        with open("/proc/self/status", encoding="ascii", errors="replace") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    effective = int(line.split()[1], 16)
                    return bool(effective >> CAP_SETUID & 1 and effective >> CAP_SETGID & 1)
    except (OSError, ValueError, IndexError):
        pass
    return False


class Identity:
    def __init__(self, environ):
        self._lock = threading.RLock()
        self.home = None
        try:
            if os.geteuid() == 0:
                self.mode = "root"
                self.uid = int(environ.get("STUDIO_RUNNER_UID") or 10001)
                self.child_uid = int(environ.get("STUDIO_RUNNER_CHILD_UID") or 10002)
                self.child_gid = self.child_uid
            elif environ.get("STUDIO_WORKLOAD_UID") and _has_setid_capabilities():
                self.mode = "capabilities"
                self.uid = os.getuid()
                self.child_uid = int(environ["STUDIO_WORKLOAD_UID"])
                self.child_gid = int(environ.get("STUDIO_WORKLOAD_GID") or self.child_uid)
                self.home = environ.get("STUDIO_WORKLOAD_HOME") or None
            elif environ.get("STUDIO_RUNNER_SHARED_UID") == "1":
                self.mode = "shared"
                self.uid = self.child_uid = os.getuid()
                self.child_gid = os.getgid()
            else:
                raise IsolationError("The runner must start as root, or as the image's runner user, so the workflow "
                                     "runs as its own user (STUDIO_RUNNER_SHARED_UID=1 allows one user, for runs on "
                                     "your own computer only).")
        except ValueError:
            raise IsolationError("The runner's user ids must be numbers.") from None
        if self.isolated and (0 in (self.uid, self.child_uid) or self.uid == self.child_uid):
            raise IsolationError("The runner and the workflow need two different, unprivileged users.")

    @property
    def isolated(self):
        return self.mode != "shared"

    def drop(self):
        """``root`` mode: become the runner user (saved uid 0, for ``privileged()``)."""
        if self.mode != "root":
            return
        os.setgroups([])
        os.setresgid(self.uid, self.uid, self.uid)
        os.setresuid(self.uid, self.uid, 0)

    @contextlib.contextmanager
    def privileged(self):
        if self.mode != "root":
            yield
            return
        with self._lock:
            os.seteuid(0)
            try:
                yield
            finally:
                os.seteuid(self.uid)

    def popen(self, argv, **kwargs):
        """Start ``argv`` as the workflow's user (in its own session, so it can be stopped as a group)."""
        kwargs.setdefault("start_new_session", True)
        if self.mode == "shared":
            return subprocess.Popen(argv, **kwargs)
        options = {"user": self.child_uid, "group": self.child_gid, "extra_groups": [],
                   "umask": 0o007 if self.mode == "capabilities" else 0o022}
        with self.privileged():
            return subprocess.Popen(argv, **options, **kwargs)

    def give(self, path):
        """Create ``path`` (one directory, not a link) for the workflow's user."""
        with self.privileged():
            os.makedirs(path, exist_ok=True)
            if os.path.islink(path):
                raise IsolationError("The working directory is a link.")
            if self.mode == "root":
                os.chown(path, self.child_uid, self.child_gid, follow_symlinks=False)
                os.chmod(path, 0o755)
            elif self.mode == "capabilities" and os.stat(path).st_uid == os.getuid():
                os.chmod(path, 0o2770)  # The shared group (setgid) reads and writes; nobody else.

    def _helper(self, *args):
        try:
            process = self.popen([sys.executable, "-I", "-c", _KILL_HELPER, *map(str, args)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 env={"PATH": os.defpath}, cwd="/")
            process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def signal_group(self, pid, sig):
        if self.mode == "capabilities":
            return self._helper("group", pid, int(sig))
        with self.privileged():
            try:
                os.killpg(pid, sig)
            except (OSError, ProcessLookupError):
                pass

    def kill_leftovers(self):
        """Stop every process of the workflow's user (a daemon that left its session too)."""
        if self.mode == "capabilities":
            for _ in range(3):
                self._helper("all")
            return
        if self.mode != "root":
            return
        for _ in range(5):
            found = []
            for name in os.listdir("/proc"):
                if not name.isdigit():
                    continue
                try:
                    with open(f"/proc/{name}/status", encoding="ascii", errors="replace") as handle:
                        for line in handle:
                            if line.startswith("Uid:"):
                                if int(line.split()[1]) == self.child_uid:
                                    found.append(int(name))
                                break
                except (OSError, ValueError, IndexError):
                    continue
            if not found:
                return
            with self.privileged():
                for pid in found:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        pass
