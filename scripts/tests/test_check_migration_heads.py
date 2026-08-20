"""Unit tests for scripts/check_migration_heads.py (RFX-49).

Proves the RFX-49 incident class is actually caught: two files declaring
the same down_revision (fake "0010_a" / "0010_b" style names below) must
FAIL with 2 heads, and re-parenting one onto the other must PASS with 1.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import check_migration_heads as cmh  # noqa: E402


def write_migration(dirpath, filename, revision, down_revision):
    down_repr = "None" if down_revision is None else repr(down_revision)
    with open(os.path.join(dirpath, filename), "w", encoding="utf-8") as f:
        f.write(
            "revision: str = %r\n"
            "down_revision: str | None = %s\n" % (revision, down_repr)
        )


class CheckMigrationHeadsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="migration-heads-test-")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_single_head_passes(self):
        write_migration(self.tmp, "0001_a.py", "0001_a", None)
        write_migration(self.tmp, "0002_b.py", "0002_b", "0001_a")
        ok, lines = cmh.check([self.tmp])
        self.assertTrue(ok)
        self.assertTrue(any(l.startswith("MIGRATION-HEADS: PASS") for l in lines))

    def test_two_heads_from_shared_parent_fails(self):
        # The exact RFX-49 shape: two PRs both parent off the same revision.
        write_migration(self.tmp, "0009_base.py", "0009_base", None)
        write_migration(self.tmp, "0010_uuid_pk_server_defaults.py",
                         "0010_uuid_pk_server_defaults", "0009_base")
        write_migration(self.tmp, "0010_digest_settings.py",
                         "0010_digest_settings", "0009_base")
        ok, lines = cmh.check([self.tmp])
        self.assertFalse(ok)
        joined = "\n".join(lines)
        self.assertIn("MIGRATION-HEADS: FAIL (2 heads", joined)
        self.assertIn("head = 0010_uuid_pk_server_defaults", joined)
        self.assertIn("head = 0010_digest_settings", joined)
        # Same collision that made it easy to miss in review.
        self.assertIn("WARN duplicate numeric prefix 0010", joined)

    def test_reparenting_fixes_it(self):
        write_migration(self.tmp, "0009_base.py", "0009_base", None)
        write_migration(self.tmp, "0010_uuid_pk_server_defaults.py",
                         "0010_uuid_pk_server_defaults", "0009_base")
        # Re-parented + renumbered, exactly like PR #44 in the incident.
        write_migration(self.tmp, "0011_digest_settings.py",
                         "0011_digest_settings", "0010_uuid_pk_server_defaults")
        ok, lines = cmh.check([self.tmp])
        self.assertTrue(ok)
        joined = "\n".join(lines)
        self.assertIn("MIGRATION-HEADS: PASS (1 head: 0011_digest_settings)", joined)
        self.assertNotIn("WARN duplicate numeric prefix", joined)

    def test_zero_heads_is_a_cycle_and_fails(self):
        write_migration(self.tmp, "0001_a.py", "0001_a", "0002_b")
        write_migration(self.tmp, "0002_b.py", "0002_b", "0001_a")
        ok, lines = cmh.check([self.tmp])
        self.assertFalse(ok)
        self.assertIn("MIGRATION-HEADS: FAIL (0 heads", "\n".join(lines))

    def test_dangling_parent_fails(self):
        write_migration(self.tmp, "0001_a.py", "0001_a", "does_not_exist")
        ok, lines = cmh.check([self.tmp])
        self.assertFalse(ok)
        joined = "\n".join(lines)
        self.assertIn("ERROR 0001_a declares down_revision", joined)
        self.assertIn("MIGRATION-HEADS: FAIL (unparsable or broken migration graph)", joined)

    def test_merge_migration_tuple_down_revision_is_supported(self):
        write_migration(self.tmp, "0001_a.py", "0001_a", None)
        write_migration(self.tmp, "0001_b.py", "0001_b", None)
        with open(os.path.join(self.tmp, "0002_merge.py"), "w", encoding="utf-8") as f:
            f.write(
                "revision: str = '0002_merge'\n"
                "down_revision: tuple[str, ...] | None = ('0001_a', '0001_b')\n"
            )
        ok, lines = cmh.check([self.tmp])
        self.assertTrue(ok)
        self.assertIn("MIGRATION-HEADS: PASS (1 head: 0002_merge)", "\n".join(lines))

    def test_duplicate_revision_id_is_an_error(self):
        write_migration(self.tmp, "0001_a.py", "0001_a", None)
        write_migration(self.tmp, "0002_dup.py", "0001_a", "0001_a")
        ok, lines = cmh.check([self.tmp])
        self.assertFalse(ok)
        self.assertIn("duplicate revision id", "\n".join(lines))

    def test_missing_directory_fails(self):
        ok, lines = cmh.check([os.path.join(self.tmp, "does-not-exist")])
        self.assertFalse(ok)
        self.assertIn("directory not found", "\n".join(lines))

    def test_cli_exit_code(self):
        write_migration(self.tmp, "0001_a.py", "0001_a", None)
        write_migration(self.tmp, "0002_b.py", "0002_b", "0001_a")
        self.assertEqual(cmh.main([self.tmp]), 0)
        write_migration(self.tmp, "0002_c.py", "0002_c", "0001_a")
        self.assertEqual(cmh.main([self.tmp]), 1)


if __name__ == "__main__":
    unittest.main()
