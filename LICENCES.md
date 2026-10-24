# Licences

This repository's own code (the runner, `image/`, `egress-proxy/`, `claude-plugin/`, the docs and tests) is
Apache-2.0 ([LICENSE](LICENSE)). It has no runtime dependencies: Python's standard library only.

## No published image

No built image is published from this repository: no registry pushes and no CI that builds one for release.
The runner image you can build from `image/Dockerfile` contains:

- **Claude Code**, which is proprietary software under Anthropic's Commercial Terms of Service. `docker build`
  installs it from npm (`@anthropic-ai/claude-code`, an exact version), so whoever builds the image accepts
  Anthropic's terms for it themselves. We don't redistribute it.
- **Debian's separate GPL-2.0/GPL-3.0-or-later programs and LGPL libraries** from the base image (bash, coreutils,
  git and its dependencies, ...), unmodified. Nothing here links to them, but an image carrying them is a
  distribution of them with its own source-offer obligations, which we don't take on for you.

Build it yourself (`docker build -f image/Dockerfile .`), for your own use, under those terms. The tables below
are what the pinned build contains (checked 2026-10-24; `scripts/check-image.sh licences` lists every installed
Debian, npm and Python package with its licence). No AGPL anywhere.

## The runner image (`image/Dockerfile`)

| Component | Version | Licence |
| --- | --- | --- |
| Node.js (`node:22-bookworm-slim`, by digest) | 22.23.4 | MIT; bundles OpenSSL (Apache-2.0), ICU (Unicode-3.0), libuv, llhttp, nghttp2 (MIT), zlib (Zlib), c-ares (MIT), others listed in Node's LICENSE (all permissive) |
| npm (in the Node image) | 10.9.9 | **Artistic-2.0**; its 180 bundled packages are ISC, MIT, Apache-2.0, BSD-2/3-Clause, BlueOak-1.0.0, CC0-1.0, and CC-BY-3.0 (spdx-exceptions data) |
| corepack (in the Node image) | 0.36.0 | MIT |
| Claude Code (`@anthropic-ai/claude-code`, native linux binary) | 2.1.308 (exact) | **Proprietary**: Anthropic's Commercial Terms of Service ("SEE LICENSE IN README.md"), used unmodified as Anthropic distributes it |
| CPython (uv's python-build-standalone build) | 3.12.15 | PSF-2.0; bundles OpenSSL (Apache-2.0), libffi, expat (MIT), SQLite (public domain), zlib, bzip2, xz (0BSD), mpdecimal (BSD-2-Clause), ncurses (X11), **libedit (BSD-3-Clause) instead of GNU readline, and no gdbm**: no GPL code in the interpreter |
| uv / uvx (`ghcr.io/astral-sh/uv`, by digest) | 0.13.5 | MIT OR Apache-2.0 |
| foundry-workflow-runner (this repository) | | Apache-2.0; Python standard library only |
| tini (Debian) | 0.19.0 | MIT |
| git, git-man (Debian) | 2.39.5 | GPL-2.0-only (LGPL-2.1 parts); a separate program |
| perl, libperl, liberror-perl (Debian, required by git) | 5.36 | GPL-1.0-or-later OR Artistic-1.0 |
| libgdbm6, libgdbm-compat4 (Debian, required by perl) | 1.23 | **GPL-3.0-or-later**, used only by perl |
| libcurl3-gnutls and its libraries (Debian, required by git): GnuTLS, nettle, gmp, libidn2, libunistring, krb5, OpenLDAP, Cyrus SASL, libssh2, librtmp, nghttp2, brotli, libpsl | | curl (MIT-like), **LGPL-2.1-or-later** (GnuTLS, librtmp), **LGPL-3.0-or-later OR GPL-2.0-or-later** (nettle, gmp, libidn2, libunistring), MIT (krb5), OLDAP-2.8, BSD (SASL, libssh2), MIT (nghttp2, brotli, libpsl) |
| ca-certificates, openssl, libssl3 (Debian) | | MPL-2.0 (the CA data) and GPL-2.0-or-later (its scripts); Apache-2.0 |
| Debian bookworm base (in the Node image) | 12.15 | separate programs and libraries: bash, coreutils, tar, gzip, grep, sed, findutils, diffutils, util-linux parts and others under **GPL-2.0/GPL-3.0-or-later**; glibc and others under **LGPL-2.1-or-later**; the rest permissive |

Not installed: Debian's python3 (its stdlib links GNU readline and gdbm, GPL-3.0-or-later; the
uv-managed CPython above replaces it). Packages a workflow installs into its own `/workspace/.venv`
or `node_modules` are the workflow author's, installed from the author's lock files.

## The egress proxy image (`egress-proxy/Dockerfile`)

| Component | Version | Licence |
| --- | --- | --- |
| `egress_proxy.py` | | ours; Python standard library only |
| Python (`python:3.12-slim-bookworm`, by digest) | 3.12.15 | PSF-2.0 (with OpenSSL Apache-2.0, libffi MIT, SQLite public domain, expat MIT, zlib) |
| pip (in the base image, unused) | | MIT |
| Debian bookworm base | 12 | as above: separate GPL-2.0/GPL-3.0-or-later programs (bash, coreutils, ...) and LGPL-2.1 glibc, unmodified |

The proxy's tests use the base image's `openssl` command (Apache-2.0) to make a throwaway
certificate.
