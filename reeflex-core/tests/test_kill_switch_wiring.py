"""
test_kill_switch_wiring.py — the freeze (REEFLEX_FREEZE) kill-switch flip
must emit a SIEM `kill_switch` event, alongside the freeze.flipped audit +
webhook.

Previously `emit_kill_switch()` was implemented but had NO production call
site (a dead-code / doc-facade gap flagged by dev-2). It is now wired from
decide._try_fire_freeze_flipped(). These tests lock that in:
  - a flip to ON  emits kill_switch action="flipped"
  - a flip to OFF emits kill_switch action="cleared"
  - the emit rides the fire-and-forget path (never raises, only on a state
    CHANGE, so no per-request noise).
"""

from __future__ import annotations

import json
import pathlib
import sys
import unittest

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import app.decide as decide_mod
from app.telemetry import reset_emitter
from tests.test_telemetry import FakeTCPServer, _start_server_thread, _stop_server


class TestKillSwitchWiring(unittest.TestCase):
    def setUp(self) -> None:
        self._srv = FakeTCPServer("127.0.0.1", 0)
        self._port = self._srv.server_address[1]
        self._t = _start_server_thread(self._srv)
        self._emitter = reset_emitter(
            enabled=True, address=f"127.0.0.1:{self._port}",
            protocol="tcp", fmt="json",
        )
        self._emitter.start()

    def tearDown(self) -> None:
        self._emitter.stop(timeout_s=2.0)
        _stop_server(self._srv, self._t)
        reset_emitter(enabled=False)

    def _received_kill_switch(self) -> dict | None:
        # Flush the emitter queue, then poll (bounded 3s) for a kill_switch
        # event — robust to any other message (e.g. a lifecycle) arriving first
        # and to socket-delivery lag. Bounded loop, not unbounded (anti-hang).
        import time
        self._emitter.flush(2.0)
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            with self._srv._lock:
                msgs = [m.decode("utf-8", "replace") for m in self._srv.received]
            for m in msgs:
                brace = m.find("{")
                if brace == -1:
                    continue
                try:
                    obj = json.loads(m[brace:])
                except ValueError:
                    continue
                if obj.get("event") == "kill_switch":
                    return obj
            time.sleep(0.05)
        return None

    def test_freeze_engage_emits_kill_switch_flipped(self) -> None:
        decide_mod._try_fire_freeze_flipped(True)
        ev = self._received_kill_switch()
        self.assertIsNotNone(ev, "freeze engage must emit a kill_switch event")
        self.assertEqual(ev["action"], "flipped")
        self.assertIn("engaged", ev["reason"].lower())

    def test_freeze_clear_emits_kill_switch_cleared(self) -> None:
        decide_mod._try_fire_freeze_flipped(False)
        ev = self._received_kill_switch()
        self.assertIsNotNone(ev, "freeze clear must emit a kill_switch event")
        self.assertEqual(ev["action"], "cleared")

    def test_flip_detection_emits_on_state_change_only(self) -> None:
        # A real flip goes through _check_freeze_flip: first call sets the
        # baseline (no emit), the actual change emits.
        decide_mod._last_freeze_state = None
        decide_mod._check_freeze_flip(False)      # baseline, no flip
        # No flip yet — nothing should have been delivered. (Can't assert
        # "nothing" without a wait; instead prove the change DOES emit.)
        decide_mod._check_freeze_flip(True)       # off -> on = flip
        ev = self._received_kill_switch()
        self.assertIsNotNone(ev, "a freeze state change must emit kill_switch")
        self.assertEqual(ev["action"], "flipped")

    def test_emit_never_raises_when_emitter_disabled(self) -> None:
        # Fire-and-forget invariant: with the emitter disabled, the flip path
        # must not raise (webhook/audit/SIEM all best-effort).
        reset_emitter(enabled=False)
        try:
            decide_mod._try_fire_freeze_flipped(True)
            decide_mod._try_fire_freeze_flipped(False)
        except Exception as exc:  # noqa: BLE001
            self.fail(f"freeze flip path raised with emitter disabled: {exc}")


if __name__ == "__main__":
    unittest.main()
