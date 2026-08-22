# reeflex-core test package
#
# RFX-197 — THE SESSION LEDGER IS DURABLE NOW, SO THE SUITE HAS TO ISOLATE IT.
#
# Before RFX-197 the ledger was a process-local dict: every test run started
# from nothing whether it asked to or not, so no test needed to think about it.
# Now the ledger is an append-only file (that is the fix), and the default path
# is <repo>/reeflex-core/audit/ledger.jsonl -- inside the working tree.
#
# That makes cross-RUN contamination a real failure mode, and it is not
# hypothetical: tests/test_verb_canon.py uses the FIXED session_id
# "s-frag-test", and on a durable ledger its spend accumulates every time the
# suite is run. Measured on the first green run after the fix: 40 entries under
# that one session_id, i.e. the fragmentation assertions were being made
# against whatever history previous runs happened to leave. A suite whose
# outcome depends on how many times it has been run is worse than a red one,
# because it goes green for the wrong reason and then flakes months later.
#
# So the ledger is redirected ONCE, here, for the whole run:
#   - this module is imported by `unittest discover` before any test module, so
#     it lands before app.ledger reads the path;
#   - it is per-run (mkdtemp), so two concurrent runs -- an agent's and CI's --
#     cannot share a ledger either;
#   - an explicit REEFLEX_LEDGER_PATH already in the environment WINS, so a
#     test that deliberately points at its own file (and the release gate, and
#     a container run) keeps control;
#   - cleanup is atexit + ignore_errors, so a crashed run leaks a tmpdir
#     instead of failing the suite on teardown.
#
# Deliberately NOT done here: setting REEFLEX_LEDGER_PERSIST=0. Turning
# persistence off for the suite would make every test exercise the pre-RFX-197
# code path, so the durable path -- the thing that was broken -- would ship
# untested. The tests run against the real mechanism, just not the real file.

import atexit
import os
import shutil
import tempfile

if not os.environ.get("REEFLEX_LEDGER_PATH"):
    _LEDGER_TMPDIR = tempfile.mkdtemp(prefix="reeflex-core-test-ledger-")
    os.environ["REEFLEX_LEDGER_PATH"] = os.path.join(_LEDGER_TMPDIR, "ledger.jsonl")
    atexit.register(shutil.rmtree, _LEDGER_TMPDIR, ignore_errors=True)
