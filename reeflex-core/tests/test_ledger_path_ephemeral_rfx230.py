"""
test_ledger_path_ephemeral_rfx230.py — RFX-230: `durable: true` was reported on
a core whose ledger a container replacement discarded.

WHAT WAS MEASURED, on 192.168.25.118, against the published image
ghcr.io/reeflex-io/reeflex-core:v0.2.1, two arms differing in ONE line of
compose (dev-1 round 070; the deployed core there had .Mounts == []):

    arm         5th call      after `up -d --force-recreate`, SAME session
    --------------------------------------------------------------------
    no volume   held (R5)     ALLOW      ledger.jsonl + holds.jsonl gone
    volume      held (R5)     held (R5)  restored 5 entries across 1 session

    /healthz ledger.durable   true       true        <- in BOTH arms
    /healthz ledger.path      identical  identical   <- in BOTH arms

So the in-process guarantee RFX-197 shipped was intact, and a `docker compose
up -d` returned the product to the pre-RFX-197 behaviour anyway: the same
session_id got its full delete budget back, with no human, no privilege and
nothing in the audit log saying so. INSTALL.md names exactly this failure
("removing the volume ... silently returns the product to this behaviour") and
offers `curl /healthz | ...['ledger']` as the check for it — the check passes
in the arm where the budget resets.

WHY THE FIX IS A NEW FIELD AND NOT A CHANGE TO `durable`:
`durable` means "REEFLEX_LEDGER_PERSIST is not off". That is a real thing an
operator needs and nothing else reports it; overloading it to also mean "on
storage that outlives the container" would make one boolean answer two
questions and silently change what every existing reading of it meant.

These tests are the in-process equivalent of the two arms above:

  T_overlay_is_ephemeral        a directory on the container writable layer
                                reports ephemeral True — the production shape.
  T_volume_is_not_ephemeral     the same path, mounted, reports False.
  T_tmpfs_is_ephemeral          a mount is not enough: memory filesystems are
                                discarded with the container too.
  T_unreadable_mountinfo        no mount table -> None (unknown), never False.
                                An instrument that cannot see must not report
                                the reassuring answer.
  T_longest_mount_point_wins    /app/audit on a volume must not be read off the
                                "/" overlay row that also prefix-matches it.
  T_sibling_prefix_not_matched  "/app/audit-other" must not satisfy "/app/audit".
  T_persist_off_is_ephemeral    persistence off is ephemeral regardless of fs.
  T_epoch_carries_the_fields    the fields reach ledger_epoch(), which is what
                                /healthz and the audit marker both serve.

Run:
  cd reeflex-core
  python -m unittest tests.test_ledger_path_ephemeral_rfx230 -v
"""

import os
import pathlib
import sys
import unittest

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import app.ledger as ledger_mod  # noqa: E402

# Real /proc/self/mountinfo rows, trimmed, from the two arms measured on .118.
# Field 4 is the mount point; the fstype is the first field after " - ".
_MOUNTINFO_NO_VOLUME = (
    "1975 1974 0:120 / / rw,relatime - overlay overlay rw,lowerdir=/x,upperdir=/y\n"
    "1976 1975 0:123 / /proc rw,nosuid - proc proc rw\n"
    "1977 1975 0:124 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k\n"
)

_MOUNTINFO_WITH_VOLUME = _MOUNTINFO_NO_VOLUME + (
    "1990 1975 259:3 /var/lib/docker/volumes/reeflex-state/_data /app/audit "
    "rw,relatime - ext4 /dev/nvme0n1p3 rw\n"
)

_MOUNTINFO_TMPFS_AUDIT = _MOUNTINFO_NO_VOLUME + (
    "1991 1975 0:130 / /app/audit rw,relatime - tmpfs tmpfs rw,size=1024k\n"
)

_LEDGER = "/app/audit/ledger.jsonl"


class TestPathStorage(unittest.TestCase):
    def test_overlay_is_ephemeral(self):
        """T_overlay_is_ephemeral — the production shape: no volume, so the
        ledger sits on the container writable layer and dies with it."""
        got = ledger_mod.path_storage(_LEDGER, _MOUNTINFO_NO_VOLUME)
        self.assertEqual(got["fstype"], "overlay", got)
        self.assertEqual(got["mount_point"], "/", got)
        self.assertIs(got["ephemeral"], True, got)

    def test_volume_is_not_ephemeral(self):
        """T_volume_is_not_ephemeral — the same ledger path, mounted."""
        got = ledger_mod.path_storage(_LEDGER, _MOUNTINFO_WITH_VOLUME)
        self.assertEqual(got["fstype"], "ext4", got)
        self.assertEqual(got["mount_point"], "/app/audit", got)
        self.assertIs(got["ephemeral"], False, got)

    def test_tmpfs_is_ephemeral(self):
        """T_tmpfs_is_ephemeral — being a mount point is not the property. A
        tmpfs at /app/audit is a mount and is still discarded."""
        got = ledger_mod.path_storage(_LEDGER, _MOUNTINFO_TMPFS_AUDIT)
        self.assertEqual(got["fstype"], "tmpfs", got)
        self.assertIs(got["ephemeral"], True, got)

    def test_unreadable_mountinfo(self):
        """T_unreadable_mountinfo — unknown must read as unknown. Returning
        False here would be the RFX-230 defect in a new field."""
        for text in ("", "garbage with no separator\n", "1 2 3 4 5 6\n"):
            got = ledger_mod.path_storage(_LEDGER, text)
            self.assertIsNone(got["ephemeral"], (text, got))
            self.assertEqual(got["fstype"], "", (text, got))

    def test_longest_mount_point_wins(self):
        """T_longest_mount_point_wins — "/" prefix-matches every path, so a
        naive scan reads the overlay row and calls a mounted volume ephemeral.
        Order must not matter either, so the rows are also fed reversed."""
        reversed_rows = "\n".join(reversed(_MOUNTINFO_WITH_VOLUME.strip().splitlines())) + "\n"
        for text in (_MOUNTINFO_WITH_VOLUME, reversed_rows):
            got = ledger_mod.path_storage(_LEDGER, text)
            self.assertEqual(got["mount_point"], "/app/audit", got)
            self.assertIs(got["ephemeral"], False, got)

    def test_sibling_prefix_not_matched(self):
        """T_sibling_prefix_not_matched — a string prefix is not a path prefix:
        /app/audit-other must not be read as the mount for /app/audit."""
        text = _MOUNTINFO_NO_VOLUME + (
            "1992 1975 259:3 /v /app/audit-other rw,relatime - ext4 /dev/sda1 rw\n"
        )
        got = ledger_mod.path_storage(_LEDGER, text)
        self.assertEqual(got["mount_point"], "/", got)
        self.assertIs(got["ephemeral"], True, got)

    def test_nested_mount_below_is_ignored(self):
        """A mount INSIDE the directory does not describe the directory."""
        text = _MOUNTINFO_NO_VOLUME + (
            "1993 1975 259:3 /v /app/audit/sub rw,relatime - ext4 /dev/sda1 rw\n"
        )
        got = ledger_mod.path_storage(_LEDGER, text)
        self.assertEqual(got["mount_point"], "/", got)
        self.assertIs(got["ephemeral"], True, got)


class TestEpochCarriesTheFields(unittest.TestCase):
    """The fields have to reach ledger_epoch(): that dict is what /healthz
    serves and what the boot marker writes to the audit stream."""

    def setUp(self):
        self._env = {k: os.environ.get(k) for k in
                     ("REEFLEX_LEDGER_PERSIST", "REEFLEX_LEDGER_PATH")}
        ledger_mod._reset_for_tests()

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        ledger_mod._reset_for_tests()

    def test_epoch_carries_the_fields(self):
        epoch = ledger_mod.ledger_epoch()
        for key in ("path_mount_point", "path_fstype", "path_ephemeral"):
            self.assertIn(key, epoch, epoch)
        # Whatever this machine mounts, the flag is a tri-state and never a
        # string: /healthz consumers branch on it.
        self.assertIn(epoch["path_ephemeral"], (True, False, None), epoch)

    def test_persist_off_is_ephemeral(self):
        """T_persist_off_is_ephemeral — with persistence off there is no file
        to outlive anything, so the flag must say so rather than describe the
        filesystem of a path core is not writing to."""
        os.environ["REEFLEX_LEDGER_PERSIST"] = "off"
        ledger_mod._reset_for_tests()
        epoch = ledger_mod.ledger_epoch()
        self.assertFalse(epoch["durable"], epoch)
        self.assertIs(epoch["path_ephemeral"], True, epoch)


if __name__ == "__main__":
    unittest.main()
