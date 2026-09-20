# buildinfo.py — what commit is this core? (RFX-89, core half)
#
# WHY THIS EXISTS. RFX-89: "a product that sells auditability cannot say what
# it is running." An operator or an auditor asking which build of the gate is
# deciding their actions had exactly one answer available — `docker inspect`
# on the VM, reading `org.opencontainers.image.revision`. That is a LABEL:
# release.yml's docker/metadata-action writes it, and nothing serves it.
#
# The bill for that is on record. reeflex-core on api-dev ran ~34 days / 44
# commits behind main with zero signal (RFX-88), and the daily deploy-drift
# job built to catch exactly that (RFX-90, reeflex-app) says in its own
# closing comment that it CANNOT watch api-dev, because core's /healthz
# answers with no revision. The one deployment whose drift is the reason the
# checker exists is the one deployment the checker cannot see.
#
# WHAT IT IS NOT, stated because the claims canon applies to our own surfaces
# first:
#
#   * It is NOT `CORE_VERSION`. That string read "0.1.13" across v0.1.13,
#     v0.1.14, v0.1.15 AND main (RFX-89's own measurement), so it cannot tell
#     two builds apart — which is the entire question being asked here. The
#     two values answer different questions and are deliberately separate:
#     _version.py says which RELEASE this claims to be, this says which
#     COMMIT it was built from.
#
#   * It is NOT an attestation. `revision` is a self-report by the build: a
#     compose file can set REEFLEX_BUILD_REVISION to anything, and the code
#     cannot tell that apart from an honest value. `docker inspect`'s label
#     stays the ground truth for anyone with shell access. What this buys is
#     that a build which says NOTHING, or which says something that is not a
#     commit on main, becomes visible to a check that has no shell access —
#     which is all RFX-90 needs.
#
#   * It is NOT a secret and must not become one. Build identity is exactly
#     the kind of fact hiding which produced RFX-88; /healthz is
#     unauthenticated and this key stays on it. Nothing else about the build
#     is disclosed — no framework version, no Python version, no hostname,
#     no path (RFX-89 requirement 3; core already scrubs its Server banner).

from __future__ import annotations

import os
import re

#: The environment variable the image sets. The Dockerfile takes it as
#: `ARG GIT_SHA` and freezes it into `ENV REEFLEX_BUILD_REVISION` at build
#: time, so the running container carries the commit it was built from with
#: no `.git` in the image and no recomputation at request time.
REVISION_ENV = "REEFLEX_BUILD_REVISION"

#: A git object name and nothing else. The point of the pattern is NOT
#: security — this value is a self-report either way (see above) — it is that
#: an UNSUBSTITUTED build arg must not be served as if it were a commit.
#: `docker build` with no `--build-arg GIT_SHA` leaves the literal empty
#: string; a careless deploy script leaves `$GIT_SHA` or `unknown`. Serving
#: any of those would make the drift checker report "revision X is not a
#: commit in this repository" — a FAIL whose message sends the reader hunting
#: for a lost branch instead of for a deploy step that forgot an argument.
#: Refusing to serve them collapses that case onto the one true statement:
#: this build will not say what it is.
_REVISION_RE = re.compile(r"\A[0-9a-f]{7,40}\Z")


def build_revision() -> str:
    """The commit this core was built from, or "" if the build did not say.

    "" is the honest answer and it is load-bearing: the consumer
    (scripts/check_core_deployment.py) reports an unidentifiable build as
    DRIFT, never as "unknown -> pass". A check that cannot go red is the
    defect it is meant to catch.
    """
    raw = (os.environ.get(REVISION_ENV) or "").strip().lower()
    if not _REVISION_RE.match(raw):
        return ""
    return raw
