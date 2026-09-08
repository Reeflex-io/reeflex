"""
credentials.py -- where the portal-issued engine credential is kept, so that
the hook can find it and nothing else can see it (RFX-224).

WHAT IS STORED HERE. `reeflex-claude connect` exchanges the pasted registration
token and the portal's response carries one secret: an `rfx_ac_` credential for
that one gate, which is what `POST /v1/decide` wants on an engine that runs with
auth on.  Before this existed the pasted line worked only for someone who
already had the engine operator's own shared bearer -- which a stranger
following the onboarding does not -- so the line's first real decision came back
401 and the portal's "your agent said hello" panel stayed empty.

WHY A FILE OUTSIDE THE PROJECT, AND NOT ANY OF THE OBVIOUS PLACES.

  * NOT `.claude/settings.json`.  That file lives in the project directory, is
    world-readable by default, and is routinely committed -- half the point of
    it is that a team shares it.  A secret there is a secret in a repository,
    which is the failure this codebase's own rules exist to prevent.  What DOES
    go in settings.json is the gate id, which is not a secret.
  * NOT the shell profile / the environment.  `connect` cannot write a
    customer's shell profile without owning their shell, and an exported
    variable is visible to every child process and to `ps e` on some systems.
    An operator who WANTS that keeps it: `REEFLEX_CORE_TOKEN` in the
    environment takes precedence over this file (see enforce.py), because a
    self-hosted engine's own credential is the operator's business.
  * NOT the pasted line, which is the whole point.  The line ends up in shell
    history, scrollback, a screen recording and often a chat message.  It still
    carries only the 15-minute single-gate bootstrap token; this file is where
    the durable credential lands, having travelled over TLS.

  So: `~/.reeflex/credentials.json`, directory 0700, file 0600, written by a
  temporary file whose mode is set BEFORE the rename -- otherwise there is a
  window in which the secret exists at the default umask, and a window is all
  a shared build box needs.

IT IS NOT A KEYRING AND DOES NOT PRETEND TO BE.  A file readable by the user is
readable by anything running as that user, which includes the agent this is
governing.  That is a real limit and the honest framing of it is: this
credential is scoped to one gate, bounded in time, and revocable from the
portal -- so the answer to "the agent could read its own credential" is that
there is very little to gain by doing so and one click to take it back.  A
keyring integration is the upgrade path and is deliberately not here (YAGNI,
and `keyring` is a dependency this package does not have).

KEYED BY (core_url, gate_id), NOT BY EITHER ALONE.  One machine can onboard
several gates -- a staging gate and a production gate against the same engine
is the ordinary case -- and one gate can legitimately appear against two
engines.  A single-slot file would silently overwrite one with the other and
the symptom would be a 403 `gate_mismatch` from an engine, which is a long way
from the cause.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Overridable so the test suite (and a probe) can point at a temporary path
# instead of the real home directory.  Same reason `resolve_settings_path`
# takes a target: a suite that writes to `~` is a suite that fails differently
# on someone else's machine.
_PATH_ENV = "REEFLEX_CREDENTIALS_FILE"

_VERSION = 1


class CredentialStoreError(Exception):
    """The store exists and could not be used.  Raised by `store()` only --
    `lookup()` never raises, because it runs inside the hook and a hook that
    raises is a hook that stops governing."""


def credentials_path() -> Path:
    override = os.environ.get(_PATH_ENV, "").strip()
    if override:
        return Path(override)
    return Path.home() / ".reeflex" / "credentials.json"


def _load(path: Path) -> Dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {"version": _VERSION, "credentials": []}
    except OSError:
        return {"version": _VERSION, "credentials": []}
    try:
        parsed = json.loads(raw)
    except Exception:  # noqa: BLE001
        # A corrupt store is treated as empty on READ and refused on WRITE
        # (see `store`).  Reading is the hook's path and must degrade to "no
        # credential" -- core then answers 401 and the adapter fails closed,
        # which is the safe direction.  Writing is a human's path and gets to
        # hear about it rather than have the file silently replaced.
        return {"version": _VERSION, "credentials": []}
    if not isinstance(parsed, dict):
        return {"version": _VERSION, "credentials": []}
    entries = parsed.get("credentials")
    if not isinstance(entries, list):
        parsed["credentials"] = []
    return parsed


def store(
    *,
    core_url: str,
    gate_id: str,
    token: str,
    expires_at: Optional[str] = None,
    portal_url: Optional[str] = None,
    gate_name: Optional[str] = None,
    environment: Optional[str] = None,
) -> Path:
    """Write one credential, replacing any previous one for the same
    `(core_url, gate_id)`.  Returns the path written.

    Raises `CredentialStoreError` if an existing store is present but not
    parseable, rather than replacing it: the file may hold credentials for
    OTHER gates that are still in use, and losing those to a tidy-up would
    brick agents this run was never asked about.
    """

    path = credentials_path()
    if path.exists():
        try:
            raw = path.read_text(encoding="utf-8")
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("not a JSON object")
        except Exception as exc:  # noqa: BLE001
            raise CredentialStoreError(
                f"{path} exists but could not be read as JSON ({exc}). Refusing "
                "to replace it -- it may hold credentials for other gates. Move "
                "it aside and re-run."
            ) from exc

    data = _load(path)
    entries: List[Dict[str, Any]] = [
        e
        for e in data.get("credentials", [])
        if not (
            isinstance(e, dict)
            and e.get("core_url") == core_url
            and e.get("gate_id") == gate_id
        )
    ]
    entry: Dict[str, Any] = {
        "core_url": core_url,
        "gate_id": gate_id,
        "token": token,
        "written_at": datetime.now(timezone.utc).isoformat(),
    }
    # Non-secret context, so that a human who opens this file can tell which
    # of several credentials is which without pasting one anywhere.
    for key, value in (
        ("expires_at", expires_at),
        ("portal_url", portal_url),
        ("gate_name", gate_name),
        ("environment", environment),
    ):
        if value:
            entry[key] = value
    entries.append(entry)
    data["version"] = _VERSION
    data["credentials"] = entries

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, stat.S_IRWXU)
    except OSError as exc:
        raise CredentialStoreError(f"could not create {path.parent}: {exc}") from exc

    body = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    try:
        # mkstemp creates at 0600 already; chmod is belt-and-braces against a
        # platform whose tempfile does otherwise, and the mode is fixed BEFORE
        # the rename so the secret is never visible at the default umask.
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".credentials-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(body)
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise CredentialStoreError(f"could not write {path}: {exc}") from exc

    return path


def lookup(*, core_url: str, gate_id: str) -> Optional[str]:
    """The credential for this engine and gate, or None.

    NEVER RAISES and never prints.  It runs inside the PreToolUse hook, whose
    stdout is a JSON protocol and whose failure mode must be a decision, not a
    traceback: no credential means core answers 401 and `enforce` fails CLOSED,
    which is the direction a governance gate is allowed to fail in.

    A LOCALLY-EXPIRED CREDENTIAL IS STILL RETURNED, on purpose.  The authority
    on whether a credential is valid is the engine, not this machine's clock.
    Dropping it here would turn a 30-second clock skew into "no credential at
    all", and the two failures look identical from the outside while having
    completely different remedies.  Sending it gets the engine's own answer
    instead.
    """

    try:
        path = credentials_path()
        data = _load(path)
        for entry in data.get("credentials", []):
            if not isinstance(entry, dict):
                continue
            if entry.get("core_url") != core_url or entry.get("gate_id") != gate_id:
                continue
            token = entry.get("token")
            if isinstance(token, str) and token:
                return token
        return None
    except Exception:  # noqa: BLE001 - see the docstring
        return None
