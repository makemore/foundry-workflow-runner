"""``foundry-workflow-runner``: run a workflow on your own computer, check its studio.yaml, or (no arguments,
the way a host's runner job starts it) run one hosted run from ``STUDIO_RUN_URL`` / ``STUDIO_RUN_TOKEN``."""

import argparse
import sys

from . import RUNNER_VERSION


def parser():
    root = argparse.ArgumentParser(prog="foundry-workflow-runner",
                                   description="Run Claude Code projects and scripts as workflows (studio.yaml).")
    root.add_argument("--version", action="version", version=f"foundry-workflow-runner (protocol {RUNNER_VERSION})")
    commands = root.add_subparsers(dest="command", metavar="COMMAND")
    run = commands.add_parser("run", help="Run a workflow here, with your own model key (no host needed)")
    run.add_argument("directory", metavar="DIR", help="The workflow's directory (with studio.yaml)")
    run.add_argument("--trigger", choices=("manual", "cron", "webhook"), default="manual",
                     help="Which trigger the run acts as (default manual)")
    run.add_argument("--payload", metavar="FILE", help="A JSON file as the trigger's payload (untrusted data)")
    run.add_argument("--env-file", metavar="FILE", help="Values for studio.yaml's secrets (default: this shell's)")
    run.add_argument("--non-interactive", action="store_true", help="Refuse every approvals.ask call instead of "
                                                                    "asking here")
    run.add_argument("--proxy", metavar="URL", help="The workflow's only egress: an http:// CONNECT proxy")
    run.add_argument("--model", help="Override studio.yaml's model")
    check = commands.add_parser("validate", help="Check a workflow's studio.yaml")
    check.add_argument("directory", metavar="DIR")
    commands.add_parser("host", help="One hosted run: STUDIO_RUN_URL and STUDIO_RUN_TOKEN (what a host's job runs)")
    return root


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    args = parser().parse_args(argv)
    if args.command in (None, "host"):
        from .runner import Runner

        return Runner().main()
    if args.command == "validate":
        from . import manifest

        try:
            _, normal = manifest.read(args.directory)
        except manifest.ManifestError as error:
            print("studio.yaml isn't valid:\n  " + "\n  ".join(error.errors), file=sys.stderr)
            return 2
        print(f"studio.yaml is valid: {normal['name']}")
        return 0
    from .local import run

    return run(args)
