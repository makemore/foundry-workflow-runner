#!/usr/bin/env bash
# Every test in local Docker, offline, with the checkout mounted read-only:
#   scripts/test-docker.sh pytest [3.10|3.11|3.12] [pytest args...]   the runner, manifest and standalone tests
#   scripts/test-docker.sh isolation [3.10|3.12]                        the uid split, as root (start.py, privcheck)
#   scripts/test-docker.sh proxy                                        the egress proxy's tests
#   scripts/test-docker.sh all                                          all of the above (3.10 and 3.12)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
action=${1:-all}; shift || true
python=3.12
if [[ "${1:-}" =~ ^3\.[0-9]+$ ]]; then python=$1; shift; fi
name="fwr-test-$$-$RANDOM"
case "$action" in
    pytest)
        docker build -q -f "$root/tests/Dockerfile.test" --build-arg "PYTHON=$python" -t "fwr-test:py$python" "$root/tests" >/dev/null
        [ $# -gt 0 ] || set -- tests
        docker run --rm --name "$name" --network none --read-only --tmpfs /tmp:exec --tmpfs /home/tester \
            --cap-drop ALL --security-opt no-new-privileges -v "$root":/src:ro "fwr-test:py$python" \
            python -m pytest -c /src/pyproject.toml -q --tb=short -p no:cacheprovider "$@" ;;
    isolation)
        docker build -q -f "$root/tests/Dockerfile.isolation" --build-arg "PYTHON=$python" -t "fwr-iso:py$python" "$root" >/dev/null
        # Root with the capabilities the runner image's start.py and the root-mode runner use.
        docker run --rm --name "$name" --network none --tmpfs /tmp:exec --user 0 --cap-drop ALL \
            --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add FOWNER --cap-add KILL --cap-add DAC_OVERRIDE \
            --security-opt no-new-privileges -v "$root":/src:ro "fwr-iso:py$python" \
            python -m pytest -c /src/pyproject.toml -q --tb=short -p no:cacheprovider tests/test_workflow_runner.py \
            -k "isolated or through_the_images or privilege_check or refuses" "$@" ;;
    proxy)
        docker build -q --target test -t fwr-proxy-test "$root/egress-proxy" >/dev/null
        # The end-to-end test's TLS server listens on 127.0.0.1:443 (the proxy only dials port 443).
        docker run --rm --init --name "$name" --network none --read-only --cap-drop ALL \
            --security-opt no-new-privileges --sysctl net.ipv4.ip_unprivileged_port_start=0 \
            --tmpfs /tmp:rw,nosuid,nodev,mode=1777 fwr-proxy-test "$@" ;;
    all)
        "$0" pytest 3.10 && "$0" pytest 3.12 && "$0" isolation 3.10 && "$0" isolation 3.12 && "$0" proxy ;;
    *)
        echo "usage: test-docker.sh pytest|isolation|proxy|all [3.10|3.11|3.12] [args...]" >&2; exit 2 ;;
esac
