#!/usr/bin/env bash
# bootstrap.sh -- the ONE-TIME setup for the gateway-hold demo.
#
# Separated from run.sh on purpose: this step downloads a LiteLLM proxy and a
# container image and takes MINUTES, and it is not part of what the demo
# demonstrates.  run.sh is the five-minute walk; this is what makes it five
# minutes.  Both are idempotent.
#
# What it needs from the machine:
#   * python3.12 (litellm[proxy] has no 3.9 release -- see RFX-248)
#   * docker, able to pull from ghcr.io
#   * network access to pypi.org and ghcr.io
#
# What it does NOT need: a Reeflex account, an API key, a real model, or any
# credential of ours.  The model in this demo is a mock that runs locally.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

VENV="${REEFLEX_DEMO_VENV:-/tmp/reeflex-gateway-hold-venv}"
PY_BIN="${REEFLEX_DEMO_PYTHON:-python3.12}"

# Pinned by DIGEST, not by tag.  `:latest` on this repository has been stale
# before, and `:v0.2.0` is a tag a publisher can move.  This digest is the
# image api-dev.reeflex.io was running when the demo was recorded -- compared
# on both hosts with `docker image inspect --format '{{.RepoDigests}}'`.
CORE_IMAGE="${REEFLEX_DEMO_CORE_IMAGE:-ghcr.io/reeflex-io/reeflex-core@sha256:58a0a531dfa1aa9bdfaf82baf94c4a1388303520cae755ffbbe1a28d9e64845b}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

say "1/4  python"
command -v "$PY_BIN" >/dev/null 2>&1 || die "$PY_BIN not found. litellm[proxy] needs >=3.12; set REEFLEX_DEMO_PYTHON."
"$PY_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
  || die "$PY_BIN is $($PY_BIN -V) -- this demo needs 3.12+."
echo "    $($PY_BIN -V) at $(command -v "$PY_BIN")"

say "2/4  venv at $VENV"
if [ ! -x "$VENV/bin/python" ]; then
  "$PY_BIN" -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install --quiet --upgrade pip setuptools wheel

say "3/4  litellm[proxy] + the two Reeflex packages FROM THIS CHECKOUT"
# From the checkout, deliberately, for both packages:
#   * reeflex-litellm -- the seat itself, and the point of the demo;
#   * reeflex-claude  -- the CLASSIFIER.  The wheel on PyPI is 0.1.7, uploaded
#     2026-07-06, which predates the RFX-144/145/146 fix; with that wheel
#     `echo starting && rm -rf /var/lib/pgsql` is priced reversible/single and
#     core ALLOWS it.  A demo that installed it from PyPI would be showing a
#     weaker gate than the code in this repository.  run.sh asserts the
#     vintage before it walks anything.
# litellm is PINNED, not floated.  Every number and every wire line in
# evidence/ was recorded against this exact version; a demo whose transcript
# cannot be reproduced is not evidence.  Override deliberately if you want to
# see whether a newer proxy still holds:
#   REEFLEX_DEMO_LITELLM='litellm[proxy]>=1.100.0' ./bootstrap.sh
LITELLM_SPEC="${REEFLEX_DEMO_LITELLM:-litellm[proxy]==1.100.0}"
"$VENV/bin/python" -m pip install --quiet \
  "$LITELLM_SPEC" pytest \
  -e "$REPO_ROOT/reeflex-claude" \
  -e "$REPO_ROOT/reeflex-litellm"
# NB: `litellm.__version__` does not exist on 1.100.0 (the module raises
# AttributeError from its own __getattr__).  importlib.metadata is the answer.
echo "    litellm    $("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("litellm"))')"
echo "    classifier $("$VENV/bin/python" -c 'import reeflex_claude, os; print(os.path.dirname(reeflex_claude.__file__))')"

say "4/4  reeflex-core v0.2.0, pinned by digest"
if ! docker image inspect "$CORE_IMAGE" >/dev/null 2>&1; then
  docker pull "$CORE_IMAGE"
fi
docker image inspect "$CORE_IMAGE" \
  --format '    image  {{.RepoTags}} {{.RepoDigests}} created {{.Created}}'

say "bootstrap OK -- now run ./run.sh"
