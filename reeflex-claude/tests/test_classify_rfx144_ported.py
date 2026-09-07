"""
test_classify_rfx144_ported.py -- regression cover CARRIED OVER from PR #98.

PROVENANCE, because a test with no provenance is a test nobody dares delete.
PRs #98 and #99 were two agents' fixes for the same defect trio (RFX-144 /
RFX-145 / RFX-146).  dev-1 round 054 measured both over a shared 154-case
corpus and kept #99, because #98 bought its extra catches by inverting the
default -- anything absent from a ~130-entry allowlist became
`execute/irreversible/broad`, which cost 11 of 62 ordinary developer commands
(`make clean`, `docker run --rm`, `pytest | tee`).  A gate that blocks
`make clean` gets switched off, and then it gates nothing.

But #98's TESTS are an asset independent of its mechanism, and throwing them
away with the branch would have thrown away the only cover for the five cases
#99 missed.  These are the ones that pass unmodified against #99 plus the
three ports in this PR, copied with their reasoning intact.

DELIBERATELY NOT CARRIED, and this is a design decision rather than an
oversight:
  * `TestUnresolvedClass` and `TestStrictModeIsDecisionRelevant` -- they pin
    #98's inverted default, which is the mechanism that produced the 11
    over-blocks.  Importing them would import the mechanism through the back
    door.
  * the four `TestResourceDeletes` cardinality tests -- they pin #98's
    systemic-vs-broad model for cloud resource deletes.  That is a genuine
    open design question, not a defect in either PR, and it must not be
    settled in main by a test nobody argued about.

The assertions are on the AXES rather than the verb, because the axes are what
core decides on: `verb == "delete"` matters for R5's cumulative budget and
nothing else, while what stops one irreversible production destruction is
`reversibility == irreversible` AND `blast_radius in (broad, systemic)` --
R2/R3's body. A test asserting only the verb would have passed on main for
`kubectl delete namespace production` the moment someone added the word to a
list, while the decision stayed `allow`.
"""
from __future__ import annotations

import os
import unittest

from reeflex_claude.classify import classify


def _c(command: str) -> dict:
    return classify("Bash", {"command": command})


def _fires_r2_or_r3(r: dict) -> bool:
    """
    Would this classification reach a human (R2) or be refused (R3) on a
    production target?  This is reeflex.rego's R2/R3 body, restated.
    """
    return (r["reversibility"] == "irreversible"
            and r["blast_radius"] in ("broad", "systemic"))


# The 18 canonical cases from RFX-144, verbatim and in the ticket's order.  The
# first 16 were the fail-opens; D17/D18 fired on main and are kept so a
# regression in them is visible here too.
RFX144_DESTRUCTIVE = [
    "cd /srv/prod && rm -rf data",
    "echo cleaning up && rm -rf /srv/prod/data",
    "ls /srv/prod; rm -rf /srv/prod/data",
    "sh -c 'rm -rf /srv/prod/data'",
    "find /srv/prod/data -type f -delete",
    "cat /tmp/list.txt | xargs rm -rf",
    "python3 -c \"import shutil; shutil.rmtree('/srv/prod/data')\"",
    "kubectl delete namespace production",
    "aws s3 rm s3://acme-prod-backups --recursive",
    "terraform destroy -auto-approve",
    "docker volume rm acme_prod_pgdata",
    "psql -h prod-db -f /tmp/migrate.sql",
    "dd if=/dev/zero of=/srv/prod/db.sqlite",
    "gcloud sql instances delete acme-prod",
    "systemctl stop acme-prod && rm -rf /var/lib/acme",
    "> /srv/prod/db.sqlite",
    "rm -rf /srv/prod/data",
    "truncate -s 0 /srv/prod/db.sqlite",
]

# Ordinary agent work.  These must NOT reach R2/R3.  Nine of them share a
# leading command with a destructive case above, so they fail the moment a fix
# reaches for the command name instead of the action.
ORDINARY_WORK = [
    "ls -la",
    "pytest -q tests/",
    "npm install",
    "make build",
    "git status",
    "cat README.md",
    "python3 -m pip install requests",
    "echo hello world",
    "cd /srv/app && npm run build",
    "grep -rn TODO src/",
    "docker build -t myapp:dev .",
    "kubectl get pods -n production",
    "terraform plan",
    "aws s3 ls s3://acme-prod-backups",
    "systemctl status acme-prod",
    "git log --oneline -10",
    "psql -h prod-db -c 'SELECT count(*) FROM orders'",
    "docker ps",
    "rm /tmp/scratch.txt",
    "cd /srv/app && ls",
    "helm list -n production",
    "dd if=/dev/urandom of=/tmp/noise bs=1k count=1",
]


class TestRfx144TheEighteen(unittest.TestCase):
    """Every canonical irreversible production destruction must reach R2 or R3."""

    def test_all_eighteen_reach_a_rule(self):
        allowed = []
        for cmd in RFX144_DESTRUCTIVE:
            r = _c(cmd)
            if not _fires_r2_or_r3(r):
                allowed.append((cmd, r["verb"], r["reversibility"],
                                r["blast_radius"]))
        self.assertEqual([], allowed,
                         "these irreversible production destructions still fall "
                         "through R2 and R3:\n" + "\n".join(map(str, allowed)))

    def test_no_ordinary_command_is_over_blocked(self):
        """
        The other half of the measurement.  A fix that routes `npm install` to a
        human is not a fix -- RFX-142 is already a filed over-block ticket, and
        an adapter nobody leaves switched on governs nothing.
        """
        blocked = []
        for cmd in ORDINARY_WORK:
            r = _c(cmd)
            if _fires_r2_or_r3(r):
                blocked.append((cmd, r["verb"], r["reversibility"],
                                r["blast_radius"], r["danger_signature"]))
        self.assertEqual([], blocked,
                         "these ordinary commands now demand a human:\n"
                         + "\n".join(map(str, blocked)))



class TestR5CanCountIt(unittest.TestCase):
    """Carried from #98's TestResourceDeletes -- this one test only. It is the
    only test in either PR that ties classification to budgets.rego, and the
    cardinality tests around it are the ones NOT carried (see the module
    docstring)."""

    def test_verb_is_delete_so_r5_counts_it(self):
        """
        RFX-146: budgets.rego's `deletions` dimension reads
        input.action.verb == "delete".  A laundered destruction that is not
        classified a delete is invisible to the cumulative budget however many
        times it is repeated -- measured on main: 30 `kubectl delete namespace`
        in one session, never held.
        """
        for cmd in ("kubectl delete namespace prod-ns-1",
                    "aws s3 rm s3://acme-prod-backups/obj1",
                    "gcloud sql instances delete acme-prod",
                    "docker volume rm acme_prod_pgdata"):
            with self.subTest(cmd=cmd):
                self.assertEqual("delete", _c(cmd)["verb"], cmd)


class TestTruncatingOverwrite(unittest.TestCase):
    """An overwrite destroys the prior contents as irreversibly as an unlink."""

    def test_shell_redirect_over_a_data_container(self):
        r = _c("> /srv/prod/db.sqlite")
        self.assertEqual("delete", r["verb"])
        self.assertEqual("broad", r["blast_radius"])
        self.assertEqual("overwrite_container", r["danger_signature"])

    def test_dd_over_a_data_container(self):
        r = _c("dd if=/dev/zero of=/srv/prod/db.sqlite")
        self.assertEqual("broad", r["blast_radius"])

    def test_mkfs_over_a_block_device_is_systemic(self):
        r = _c("mkfs.ext4 /dev/sdb1")
        self.assertEqual("systemic", r["blast_radius"])

    def test_truncate_is_caught_as_an_overwrite_not_by_the_sql_regex(self):
        """
        On main this fired only because _SQL_TRUNCATE_RE (/\\bTRUNCATE\\b/i,
        written for SQL) happened to match the shell command NAME `truncate`.
        Right verdict, wrong reason -- it would have stopped working the day that
        regex was scoped to SQL.  Assert the reason, not just the verdict.
        """
        r = _c("truncate -s 0 /srv/prod/db.sqlite")
        self.assertEqual("overwrite_container", r["danger_signature"])
        self.assertEqual("broad", r["blast_radius"])

    def test_sql_truncate_still_reaches_the_sql_path(self):
        r = _c("psql -h prod-db -c 'TRUNCATE TABLE users'")
        self.assertEqual("delete", r["verb"])
        self.assertEqual("sql_drop_table", r["danger_signature"])

    def test_redirect_to_dev_null_is_not_a_destruction(self):
        self.assertNotEqual("delete", _c("pytest -q > /dev/null")["verb"])

    def test_redirect_of_build_output_is_not_a_destruction(self):
        """
        `pytest > out.log` truncates out.log.  Calling that a delete would push
        routine build output into R5's delete budget for no gain, so an ordinary
        file left of a `>` stays with the command that wrote it.
        """
        self.assertNotEqual("delete", _c("pytest -q > out.log")["verb"])

    def test_dd_to_an_ordinary_scratch_file_stays_single(self):
        r = _c("dd if=/dev/urandom of=/tmp/noise bs=1k count=1")
        self.assertEqual("single", r["blast_radius"])
        self.assertFalse(_fires_r2_or_r3(r))


class TestNoRegressionInTheKnownCases(unittest.TestCase):
    """The cases main already got right must not move."""

    def test_rm_rf_root_is_still_systemic(self):
        self.assertEqual("systemic", _c("rm -rf /")["blast_radius"])

    def test_drop_database_is_still_systemic(self):
        r = _c("psql -c 'DROP DATABASE acme'")
        self.assertEqual("systemic", r["blast_radius"])

    def test_fork_bomb_survives_the_pipe_split(self):
        """
        The fork bomb's body contains `:|:`, so the pipe split would tear it in
        half.  It is matched against the whole command string before any parse.
        """
        r = _c(":(){ :|:& };:")
        self.assertEqual("fork_bomb", r["danger_signature"])
        self.assertEqual("systemic", r["blast_radius"])

    def test_git_force_push_is_still_emit(self):
        r = _c("git push --force origin main")
        self.assertEqual("emit", r["verb"])
        self.assertEqual("git_force_push", r["danger_signature"])

    def test_plain_read_is_still_benign(self):
        r = _c("ls -la")
        self.assertEqual("read", r["verb"])
        self.assertEqual("benign", r["classification_tier"])

    def test_single_file_rm_is_still_single(self):
        r = _c("rm /tmp/scratch.txt")
        self.assertEqual("single", r["blast_radius"])

    def test_empty_command_does_not_become_a_prompt(self):
        r = _c("")
        self.assertEqual("execute", r["verb"])
        self.assertFalse(_fires_r2_or_r3(r))

    def test_unbalanced_quotes_do_not_crash_and_are_governed(self):
        r = _c("rm -rf '/srv/prod/data")
        self.assertEqual("delete", r["verb"])


if __name__ == "__main__":
    unittest.main()


class TestWrapperGapsClosedInRound054(unittest.TestCase):
    """NOT carried from #98 -- these two are this PR's own, and they are here
    because #98's suite had no direct cover for either.

    #98 reached both cases, but only as a side effect of its fail-closed
    default: a bare `sh` and a bare `FOO=1` are simply absent from its
    allowlist, so the whole line became UNRESOLVED. Neither PR PARSED these
    inputs -- `_shell_c_payload` dropped everything after the first token of a
    `sh -c` payload in BOTH branches. So a test that only asserted "this
    reaches a human" would have passed on #98 for the wrong reason, and these
    assert the mechanism instead: the payload is recovered, and the wrapper is
    peeled, so the DESTRUCTION is what gets priced.
    """

    def test_bare_assignment_prefix_is_peeled(self):
        r = _c("FOO=1 rm -rf /srv/prod/data")
        self.assertEqual("delete", r["verb"])
        self.assertEqual("rm_recursive", r["danger_signature"],
                         "priced as the rm it is, not as an unrecognised execute")
        self.assertTrue(_fires_r2_or_r3(r))

    def test_a_flag_with_an_equals_sign_is_not_mistaken_for_an_assignment(self):
        """The negative control for the clause above: `--flag=value` must not
        be peeled, or the command word would be misread."""
        r = _c("python3 -m venv --without-pip=yes /tmp/v")
        self.assertEqual("execute", r["verb"])
        self.assertFalse(_fires_r2_or_r3(r))

    def test_nested_shell_c_payload_is_recovered_whole(self):
        r = _c("sh -c 'sh -c \"rm -rf /srv/prod/data\"'")
        self.assertEqual("delete", r["verb"])
        self.assertEqual("rm_recursive", r["danger_signature"])
        self.assertTrue(_fires_r2_or_r3(r))

    def test_a_multiword_shell_c_payload_is_not_truncated(self):
        """The direct regression for the `tokens[i + 1]` bug: the destruction
        was in the part that got dropped."""
        r = _c("sh -c 'cd /srv/prod && rm -rf data'")
        self.assertEqual("delete", r["verb"])
        self.assertTrue(_fires_r2_or_r3(r))

    def test_a_benign_multiword_shell_c_payload_stays_benign(self):
        r = _c("sh -c 'cd /srv/app && npm run build'")
        self.assertFalse(_fires_r2_or_r3(r))


class TestContainerKindIsRaiseOnly(unittest.TestCase):
    """SPEC §4.2 permits a name to claim KIND and forbids it claiming
    CARDINALITY. The container check must therefore only ever RAISE."""

    def test_it_cannot_lower_a_systemic_reading(self):
        r = _c("rm -rf /")
        self.assertEqual("systemic", r["blast_radius"])

    def test_it_cannot_lower_an_enumerated_broad_set(self):
        files = " ".join(f"/srv/data/f{i}.db" for i in range(25))
        r = _c(f"rm {files}")
        self.assertEqual("broad", r["blast_radius"])

    def test_an_ordinary_single_file_is_still_single(self):
        self.assertEqual("single", _c("rm /srv/app/notes.txt")["blast_radius"])

    def test_a_dev_null_redirect_is_not_a_block_device_write(self):
        for cmd in ("echo hi > /dev/null", "echo hi > /dev/stdout"):
            with self.subTest(cmd=cmd):
                self.assertNotEqual("systemic", _c(cmd)["blast_radius"])
