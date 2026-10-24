"""Claude Code's workspace trust for the project directory.

Claude Code ignores a project's own ``.claude/settings.json`` permission rules (and its hooks and other
project-scoped settings) until that directory is trusted, which it records in its global config file
(``~/.claude.json``, or ``$CLAUDE_CONFIG_DIR/.claude.json``) as ``projects[<dir>].hasTrustDialogAccepted``. It
counts that flag on the directory itself or on a parent (up to the git root, if there is one).

- Isolated (the runner image, or the runner started as root): the workload user's home belongs to the run, so
  the runner marks exactly the project directory as trusted there, by running this file as the workload user
  (``python -I trust.py mark DIR``): the runner never writes the workload's files itself.
- On your own computer (one user): the global config is yours, so the runner only reads it and, if the project
  isn't trusted, says how to trust it (``trusted()``).
"""

import json
import os
import sys
import tempfile

CONFIG_NAME = ".claude.json"


def config_paths(environ):
    """The global config files Claude Code may read for this environment (the legacy one first)."""
    home = environ.get("HOME") or os.path.expanduser("~")
    paths = []
    legacy = os.path.join(environ.get("CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude"), ".config.json")
    if os.path.isfile(legacy):
        paths.append(legacy)
    paths.append(os.path.join(environ.get("CLAUDE_CONFIG_DIR") or home, CONFIG_NAME))
    return paths


def _git_root(path):
    current = path
    while True:
        if os.path.lexists(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def trusted(directory, environ):
    """True if Claude Code would count ``directory`` as trusted for this environment's user (read only)."""
    path = os.path.realpath(directory)
    root = _git_root(path)
    for config_path in config_paths(environ):
        try:
            with open(config_path, encoding="utf-8") as handle:
                projects = json.load(handle).get("projects")
        except (OSError, ValueError, AttributeError):
            continue
        if not isinstance(projects, dict):
            continue
        current = path
        while True:
            entry = projects.get(current)
            if isinstance(entry, dict) and entry.get("hasTrustDialogAccepted") is True:
                return True
            parent = os.path.dirname(current)
            if current == root or parent == current:
                break
            current = parent
    return False


def mark(directory, environ):
    """Mark exactly ``directory`` as trusted in this user's own global config, keeping everything else in it.
    Run as the workload user, in its own home. Refuses a config that is a link or isn't a JSON object."""
    config_dir = environ.get("CLAUDE_CONFIG_DIR") or environ.get("HOME")
    if not config_dir or not os.path.isabs(config_dir) or not os.path.isabs(directory):
        raise ValueError("needs an absolute home and project directory")
    os.makedirs(config_dir, mode=0o700, exist_ok=True)
    path = os.path.join(config_dir, CONFIG_NAME)
    config = {}
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        fd = None
    if fd is not None:
        with os.fdopen(fd, encoding="utf-8") as handle:
            config = json.load(handle)
        if not isinstance(config, dict):
            raise ValueError("the config isn't a JSON object")
    projects = config.get("projects") if isinstance(config.get("projects"), dict) else {}
    entry = projects.get(directory) if isinstance(projects.get(directory), dict) else {}
    projects[directory] = {**entry, "hasTrustDialogAccepted": True}
    config["projects"] = projects
    fd, temporary = tempfile.mkstemp(prefix=CONFIG_NAME + ".", dir=config_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(config, handle, indent=2)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv):
    if len(argv) != 2 or argv[0] != "mark":
        print("usage: trust.py mark DIR", file=sys.stderr)
        return 2
    try:
        mark(argv[1], os.environ)
    except (OSError, ValueError, UnicodeError):
        print("The project couldn't be marked as trusted.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
