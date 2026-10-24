"""tar.gz in and out, safely: no absolute paths, no ``..``, no links leaving the directory, no devices."""

import os
import tarfile


class ArchiveError(Exception):
    pass


def _inside(root, path):
    root = os.path.realpath(root)
    return os.path.commonpath([root, os.path.realpath(path)]) == root


def extract(archive, destination, *, outside_links=False):
    """Unpack ``archive`` into ``destination`` (created if needed). Refuses anything unsafe before writing.

    ``outside_links``: keep symbolic links that point outside (a built bundle's ``.venv/bin/python`` points at the
    image's Python). Nothing is ever written through a link either way."""
    os.makedirs(destination, exist_ok=True)
    try:
        with tarfile.open(archive, "r:gz") as tar:
            members = tar.getmembers()
            for member in members:
                name = member.name
                if name.startswith(("/", "\\")) or ".." in name.replace("\\", "/").split("/") or ":" in name:
                    raise ArchiveError("The archive has a path outside its directory.")
                if not (member.isfile() or member.isdir() or member.issym()):
                    raise ArchiveError("The archive has a special file.")
                if member.issym():
                    target = os.path.join(os.path.dirname(os.path.join(destination, name)), member.linkname)
                    if not outside_links and (member.linkname.startswith("/") or not _inside(destination, target)):
                        raise ArchiveError("The archive has a link outside its directory.")
            for member in members:
                path = os.path.join(destination, member.name)
                if not _inside(destination, os.path.dirname(path) or destination):
                    raise ArchiveError("The archive has a path outside its directory.")
                if member.isdir():
                    os.makedirs(path, exist_ok=True)
                elif member.issym():
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    if os.path.lexists(path):
                        os.unlink(path)
                    os.symlink(member.linkname, path)
                else:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    if os.path.islink(path):
                        os.unlink(path)
                    source = tar.extractfile(member)
                    with open(path, "wb") as out:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            out.write(chunk)
                    os.chmod(path, 0o755 if member.mode & 0o111 else 0o644)
    except (tarfile.TarError, EOFError, OSError):
        raise ArchiveError("The archive couldn't be unpacked.") from None


def create(source, archive, *, skip=(".git",)):
    """Pack the directory ``source`` (its contents, relative paths) into ``archive``; ``skip``: top-level names."""
    def keep(info):
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        return info

    with tarfile.open(archive, "w:gz", compresslevel=6) as tar:
        for top, directories, files in os.walk(source):
            relative = os.path.relpath(top, source)
            if relative == ".":
                directories[:] = [name for name in directories if name not in skip]
                files = [name for name in files if name not in skip]
            directories.sort()
            for name in sorted(directories) + sorted(files):
                path = os.path.join(top, name)
                tar.inodes.clear()  # Hard links go in as plain files; extract() takes no hard links.
                info = keep(tar.gettarinfo(path, arcname=os.path.normpath(os.path.join(relative, name))))
                if info.isfile():
                    with open(path, "rb") as handle:
                        tar.addfile(info, handle)
                elif info.isdir() or info.issym():
                    tar.addfile(info)
                if os.path.islink(path) and name in directories:
                    directories.remove(name)


def main(argv):
    """Run as the workflow's user by the runner (``python -I archive.py ...``), so customer files are only ever
    read and written by that user:

    - ``extract DEST [--outside-links]``: the tar.gz on stdin, unpacked into DEST;
    - ``create SRC [--skip NAME ...]``: SRC packed as tar.gz to stdout.

    Exit 0 when done, 3 with one fixed sentence on stderr when refused."""
    import shutil
    import sys
    import tempfile

    try:
        if len(argv) >= 2 and argv[0] == "extract":
            descriptor, path = tempfile.mkstemp(suffix=".tar.gz")
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    shutil.copyfileobj(sys.stdin.buffer, handle, 1024 * 1024)
                extract(path, argv[1], outside_links="--outside-links" in argv[2:])
            finally:
                os.unlink(path)
            return 0
        if len(argv) >= 2 and argv[0] == "create":
            skips = [argv[index + 1] for index, arg in enumerate(argv[:-1]) if arg == "--skip"]
            descriptor, path = tempfile.mkstemp(suffix=".tar.gz")
            os.close(descriptor)
            try:
                create(argv[1], path, skip=tuple(skips))
                with open(path, "rb") as handle:
                    shutil.copyfileobj(handle, sys.stdout.buffer, 1024 * 1024)
                sys.stdout.buffer.flush()
            finally:
                os.unlink(path)
            return 0
        print("usage: archive.py extract DEST | create SRC", file=sys.stderr)
        return 2
    except ArchiveError as error:
        print(str(error), file=sys.stderr)
        return 3
    except OSError:
        print("The files couldn't be read or written.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    import sys as _sys

    _sys.exit(main(_sys.argv[1:]))
