"""Checks the runner image's privilege model end to end (scripts/check-image.sh and the isolation tests run it
as root, the image's default user; run it on your own platform too):

    /opt/workflow-runner/bin/python -I /opt/workflow-runner/privcheck.py

It drops privileges exactly as start.py does, then starts a child the way the runner does
(``user=10002, group=10010, extra_groups=[], umask=0o007``) and checks what each side can do.
Prints one JSON line per check and ``PRIVCHECK PASSED``; exit status 1 on any failure.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import start  # noqa: E402

CHILD = r"""
import json, os, sys
ppid = int(sys.argv[1])
def status():
    return dict(l.rstrip("\n").split(":\t", 1) for l in open("/proc/self/status") if ":\t" in l)
def refused(fn):
    try:
        fn()
    except (PermissionError, ProcessLookupError):
        return True
    return False
st = status()
os.makedirs("/workspace/project", exist_ok=True)
with open("/workspace/project/out.txt", "w") as f:
    f.write("written by the workload")
with open("/home/workload/.probe", "w") as f:
    f.write("home")
print(json.dumps({
    "uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(), "groups": os.getgroups(),
    "cap_eff": st["CapEff"], "cap_prm": st["CapPrm"], "cap_inh": st["CapInh"], "cap_amb": st["CapAmb"],
    "no_new_privs": st["NoNewPrivs"],
    "runner_environ_refused": refused(lambda: open(f"/proc/{ppid}/environ", "rb").read()),
    "pid1_environ_refused": refused(lambda: open("/proc/1/environ", "rb").read()),
    "runner_mem_refused": refused(lambda: open(f"/proc/{ppid}/mem", "rb").read(1)),
    "signal_runner_refused": refused(lambda: os.kill(ppid, 0)),
    "setuid_runner_refused": refused(lambda: os.setuid(10001)),
    "setuid_root_refused": refused(lambda: os.setuid(0)),
    "runner_home_refused": refused(lambda: os.listdir("/home/runner")),
    "runner_tmp_refused": refused(lambda: open(sys.argv[2]).read()),
}))
"""


def main() -> int:
    results: list[bool] = []

    def check(name: str, ok: bool, detail=None) -> None:
        results.append(bool(ok))
        print(json.dumps({"check": name, "ok": bool(ok), **({"detail": detail} if detail is not None else {})}))

    notes = start.drop_privileges()
    st = start.status()
    check("runner uid/gid 10001, group workspace", os.getuid() == 10001 and os.getgid() == 10001
          and os.getgroups() == [10010])
    check("runner caps: exactly SETUID+SETGID, none inheritable/ambient",
          st["CapEff"] == st["CapPrm"] == f"{start.KEPT:016x}" and int(st["CapInh"], 16) == 0
          and int(st["CapAmb"], 16) == 0, {k: st[k] for k in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")})
    check("runner no_new_privs", st["NoNewPrivs"] == "1")
    check("runner not dumpable (its /proc files belong to root)", os.stat(f"/proc/{os.getpid()}/environ").st_uid == 0)
    # Informational (not counted): narrowing needs CAP_SETPCAP, and with no_new_privs nothing can
    # gain capabilities through exec whatever the bounding set holds.
    print(json.dumps({"check": "bounding set narrowed (informational)", "ok": int(st["CapBnd"], 16) == start.KEPT,
                      "detail": st["CapBnd"]}))

    # A private runner file, as the runner would keep one (umask 077).
    secret = "/tmp/runner-private"
    with open(secret, "w") as handle:
        handle.write("runner only")

    proc = subprocess.run([sys.executable, "-I", "-c", CHILD, str(os.getpid()), secret], user=start.WORKLOAD_UID,
                          group=start.WORKSPACE_GID, extra_groups=[], umask=0o007, capture_output=True, text=True,
                          env={"HOME": start.WORKLOAD_HOME, "PATH": "/usr/local/bin:/usr/bin:/bin"}, cwd="/workspace")
    check("child ran", proc.returncode == 0, proc.stderr.strip()[-300:] or None)
    if proc.returncode == 0:
        child = json.loads(proc.stdout.strip().splitlines()[-1])
        check("child uid 10002, gid 10010, no extra groups",
              (child["uid"], child["euid"], child["gid"], child["groups"]) == (10002, 10002, 10010, [10010])
              or (child["uid"], child["euid"], child["gid"], child["groups"]) == (10002, 10002, 10010, []),
              {k: child[k] for k in ("uid", "gid", "groups")})
        check("child has no capabilities", all(int(child[k], 16) == 0 for k in ("cap_eff", "cap_prm", "cap_inh", "cap_amb")),
              {k: child[k] for k in ("cap_eff", "cap_prm", "cap_inh", "cap_amb")})
        check("child no_new_privs", child["no_new_privs"] == "1")
        for key in ("runner_environ_refused", "pid1_environ_refused", "runner_mem_refused", "signal_runner_refused",
                    "setuid_runner_refused", "setuid_root_refused", "runner_home_refused", "runner_tmp_refused"):
            check("child: " + key.replace("_", " "), child[key])
        path = "/workspace/project/out.txt"
        info = os.stat(path)
        check("workload file: owner 10002, group 10010, group-readable",
              info.st_uid == 10002 and info.st_gid == 10010 and info.st_mode & 0o040, oct(info.st_mode))
        try:
            with open(path) as handle:
                check("runner reads what the workload wrote (state, bundle)", handle.read() == "written by the workload")
        except OSError as exc:
            check("runner reads what the workload wrote (state, bundle)", False, type(exc).__name__)
    passed = sum(results)
    print(f"PRIVCHECK {'PASSED' if passed == len(results) else 'FAILED'}: {passed} of {len(results)}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
