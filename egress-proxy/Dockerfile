# The workflow egress proxy (egress_proxy.py; docs/SECURITY.md). Python standard library only, non-root,
# read-only at run time. It runs as `serve` (the default) with the key file mounted read-only, and, on a
# Google Cloud VM, once per boot/rotation as `fetch-key`.
#
# Build:  docker build -t workflow-egress-proxy egress-proxy/
# Tests:  scripts/test-docker.sh proxy   (the `test` target, no network)
FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    EGRESS_LISTEN=0.0.0.0:3128 \
    EGRESS_KEY_FILE=/run/secrets/workflow-egress-key/key

RUN useradd --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --uid 10001 egress
WORKDIR /app
COPY egress_proxy.py ./

USER 10001
EXPOSE 3128
ENTRYPOINT ["python", "/app/egress_proxy.py"]
CMD ["serve"]

# The proxy's own tests against this exact image (openssl, already in the base image, makes the
# end-to-end test's throwaway certificate).
FROM base AS test
ENV PYTHONPATH=/app
COPY tests ./tests
ENTRYPOINT []
CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-t", "tests", "-v"]

FROM base AS service
