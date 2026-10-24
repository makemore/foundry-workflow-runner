"""studio.yaml v1: the YAML subset, the rules and their wording (docs/MANIFEST.md)."""

import pytest

from foundry_workflow_runner import manifest as manifests


EXAMPLE = """\
version: 1
name: receipts                 # slug, unique per workspace
description: File receipts from the finance inbox to Drive
entry:
  claude: "/file-receipts"     # prompt or slash command
model: claude-opus-5-5
triggers:                      # manual runs are always allowed
  - cron: "0 7 * * *"
    tz: Europe/London
  - webhook: {}
connections: [google.gmail, google.drive, github]
google_account: personal
secrets: [XERO_TOKEN]
egress: [api.xero.com, "*.xero.com"]
approvals:
  ask: ["Bash(git push:*)", "mcp__studio__gmail_send"]
limits: { timeout: 30m, max_turns: 50 }
state: state/
"""


CRON_FLOOR = ("triggers: the cron triggers together may fire at most once every 15 minutes on this "
              "workspace's plan.")


def test_the_contract_example_parses_and_validates():
    manifest = manifests.load(EXAMPLE)
    assert manifest == {
        "version": 1, "name": "receipts", "description": "File receipts from the finance inbox to Drive",
        "entry": {"claude": "/file-receipts"}, "model": "claude-opus-5-5",
        "triggers": [{"cron": "0 7 * * *", "tz": "Europe/London"}, {"webhook": {}}],
        "connections": ["google.gmail", "google.drive", "github"], "google_account": "personal",
        "secrets": ["XERO_TOKEN"], "egress": ["api.xero.com", "*.xero.com"],
        "approvals": {"ask": ["Bash(git push:*)", "mcp__studio__gmail_send"]},
        "limits": {"timeout": "30m", "max_turns": 50}, "state": "state/"}
    normal = manifests.validate(manifest)
    assert normal["limits"] == {"timeout": 1800, "max_turns": 50} and normal["state"] == "state/"


def test_yaml_subset_details():
    text = ("version: 1\nname: a-b\nentry:\n  command:\n    - python\n    - 'main.py'\n"
            "description: >\n  Two lines\n  folded.\n# a comment\ntriggers:\n- cron: \"*/5 * * * *\"\n")
    value = manifests.load(text)
    assert value["entry"] == {"command": ["python", "main.py"]}
    assert value["description"] == "Two lines folded.\n" and value["triggers"] == [{"cron": "*/5 * * * *"}]
    assert manifests.load("version: 1\nflag: yes\nn: 1.5\nz: ~\n") == {"version": 1, "flag": "yes", "n": 1.5,
                                                                      "z": None}


@pytest.mark.parametrize("text, message", [
    ("version: 1\nname: x\nname: y\n", "studio.yaml line 3: duplicate key name."),
    ("version: 1\negress: [*.xero.com]\n", "studio.yaml line 2: anchors, aliases, tags and reserved characters "
                                           "aren't supported; quote the value."),
    ("version: 1\n\tname: x\n", "studio.yaml line 2: indent with spaces, not tabs."),
    ("version: 1\nlist: [a, b\n", "studio.yaml line 2: a [list] isn't closed."),
])
def test_yaml_errors_name_the_line(text, message):
    with pytest.raises(manifests.ManifestError) as caught:
        manifests.load(text)
    assert caught.value.errors == [message]


@pytest.mark.parametrize("change, message", [
    ({"colour": "blue"}, "colour: unknown key."),
    ({"version": 2}, "version: must be 1."),
    ({"name": "Receipts"}, "name: must match ^[a-z][a-z0-9-]{1,48}$ (lowercase letters, digits and dashes)."),
    ({"entry": {"claude": "x", "command": ["y"]}}, "entry: needs exactly one of claude or command."),
    ({"entry": {"command": []}}, "entry.command: must be a non-empty list of up to 64 non-empty strings."),
    ({"triggers": [{"cron": "0 7 * *"}]}, "triggers[0].cron: must be a five-field cron expression such as "
                                          "\"0 7 * * *\"."),
    ({"triggers": [{"cron": "0 7 * * *", "tz": "Mars/Base"}]},
     "triggers[0].tz: must be an IANA time zone such as Europe/London."),
    ({"triggers": [{"webhook": {"secret": "x"}}]}, "triggers[0].webhook: takes no options yet; write webhook: {}."),
    ({"triggers": [{"webhook": {}}, {"webhook": {}}]}, "triggers: at most one webhook trigger."),
    ({"secrets": ["ANTHROPIC_API_KEY"]}, "secrets[0]: ANTHROPIC_API_KEY is reserved for Studio."),
    ({"secrets": ["xero"]}, "secrets[0]: must be an UPPER_SNAKE_CASE name of at most 64 characters."),
    ({"egress": ["10.0.0.1"]}, "egress[0]: must be a host name such as api.xero.com or *.xero.com (no IP "
                               "addresses or ports)."),
    ({"google_account": "company"}, "google_account: must be personal or workspace."),
    ({"limits": {"timeout": "90m"}}, "limits.timeout: must be a duration from 1m to 60m, such as 30m."),
    ({"limits": {"max_turns": 0}}, "limits.max_turns: must be a whole number from 1 to 500."),
    ({"state": "../up"}, "state: must be a relative directory inside the project, such as state/."),
    ({"approvals": {"ask": ["Bash(git push:*"]}},
     "approvals.ask[0]: must be a Claude Code permission rule such as Bash(git push:*)."),
])
def test_validation_messages_match_studio(change, message):
    manifest = {"version": 1, "name": "receipts", "entry": {"claude": "/go"}, **change}
    with pytest.raises(manifests.ManifestError) as caught:
        manifests.validate(manifest)
    assert message in caught.value.errors


def test_cron_rules_match_the_runtime():
    assert manifests.cron_valid("0 7 * * 1-5") and manifests.cron_valid("*/15 0-23/2 1,15 * 0,7")
    assert not manifests.cron_valid("0 7 * * MON") and not manifests.cron_valid("0 7 31 2 *")
    assert not manifests.cron_valid("60 * * * *") and not manifests.cron_valid("@daily")


@pytest.mark.parametrize("host", ["metadata.google.internal", "foo.run.app", "*.googleapis.com",
                                  "printer.local"])
def test_egress_denylist_matches_studio(host):
    with pytest.raises(manifests.ManifestError) as caught:
        manifests.validate({"version": 1, "name": "receipts", "entry": {"claude": "/go"}, "egress": [host]})
    assert caught.value.errors == [f"egress[0]: {host} isn't allowed (Google, metadata, internal and Studio's own "
                                   "hosts are refused; Studio adds what runs need itself)."]
    manifests.validate({"version": 1, "name": "receipts", "entry": {"claude": "/go"},
                        "egress": ["api.xero.com", "*.xero.com"]})
    with pytest.raises(manifests.ManifestError):
        manifests.validate({"version": 1, "name": "r1", "entry": {"claude": "/go"}, "egress": ["studio.acme.test"]},
                           studio_hosts=("studio.acme.test",))


@pytest.mark.parametrize("triggers, refused", [
    ([{"cron": "*/15 * * * *"}], False),
    ([{"cron": "*/10 * * * *"}], True),
    ([{"cron": "0 7 * * *"}, {"cron": "5 7 * * *"}], True),  # Each alone is daily; together 5 minutes apart.
    # The same instant in winter (London is UTC then): the floor is across time zones.
    ([{"cron": "0 7 * * *", "tz": "Europe/London"}, {"cron": "0 7 * * *", "tz": "UTC"}], True),
    ([{"cron": "0 7 * * *", "tz": "Europe/London"}, {"cron": "0 8 * * *", "tz": "Europe/London"}], False),
    ([{"cron": "0 7 * * 1"}, {"cron": "0 7 * * 1"}], True),
])
def test_the_cron_floor_applies_to_all_cron_triggers_together(triggers, refused):
    normal = manifests.validate({"version": 1, "name": "receipts", "entry": {"claude": "/go"}, "triggers": triggers})
    errors = manifests.plan_errors(normal, {"min_cron_seconds": 900})
    assert errors == ([CRON_FLOOR] if refused else [])
    assert manifests.plan_errors(normal, {"min_cron_seconds": None}) == []


def test_the_plan_timeout_is_checked_early_only_when_set():
    base = {"version": 1, "name": "receipts", "entry": {"claude": "/go"}}
    normal = manifests.validate({**base, "limits": {"timeout": "30m"}})
    assert manifests.plan_errors({**normal, "_timeout_set": True}, {"max_timeout_seconds": 600}) == [
        "limits.timeout: at most 10m on this workspace's plan."]
    # Without a timeout Studio shortens the 30m default to the plan's cap instead of refusing.
    assert manifests.plan_errors(manifests.validate(base), {"max_timeout_seconds": 600}) == []
