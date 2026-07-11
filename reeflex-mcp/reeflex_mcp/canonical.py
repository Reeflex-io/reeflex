"""
canonical.py -- reimplementation of reeflex-core's `canonical_hash`
(reeflex-core/app/holds.py) so the gateway can recognize, WITHOUT calling
core, whether a retried `tools/call` is "the same action" as a hold it
already knows about -- the exact key core itself binds a hold's approval to
(design doc section 9 / SPEC section 5.1: "Each hold is bound to the sha256
of the action-defining projection of the original envelope... The `approval`
field is explicitly excluded from the projection, so the hash is stable
across the original submission and the resubmission.").

MUST stay byte-for-byte identical to core's algorithm:
  - same ALLOWLIST: action, axes, magnitude, target (NOT agent, meta, params,
    context, approval, trajectory_ref, reeflex_version)
  - same JSON serialization: json.dumps(projection, sort_keys=True,
    separators=(",", ":"))
  - same digest: sha256 hex

Deliberately DUPLICATED, not imported -- this project's boundary is that
reeflex-mcp never imports from reeflex-core (LIMIT: reeflex-mcp/ only, no
core changes/dependency). This is a documented cross-repo coupling risk: if
core's canonical_hash algorithm ever changes, this module must change with
it, or the gateway's resubmission-match (a local optimization only -- see
holds_tracker.py) silently stops recognizing retries as resubmissions
(harmless degradation: core is still the sole authority, a non-matching
gateway would just fail to auto-attach approval and the client's retry would
mint ANOTHER hold instead of resuming the pending one). A conformance-suite
cross-check pinning both algorithms to the same golden vectors is the correct
long-term guard; out of scope for this track.
"""

from __future__ import annotations

import hashlib
import json

# Verified against reeflex-core/app/holds.py `_HASH_ALLOWLIST` while building
# this package (commit landing decision_id: 92abbcb).
_HASH_ALLOWLIST: frozenset[str] = frozenset({"action", "axes", "magnitude", "target"})


def canonical_hash(envelope: dict) -> str:
    """Return sha256 hex of the action-defining projection of the envelope.

    Only the fields in _HASH_ALLOWLIST are included, sorted by key at every
    level for full determinism -- identical inputs (envelopes describing the
    same action) always produce the same hash, regardless of agent/meta/
    approval/context differences between the original submission and a
    resubmission.
    """
    projection = {k: envelope[k] for k in _HASH_ALLOWLIST if k in envelope}
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
