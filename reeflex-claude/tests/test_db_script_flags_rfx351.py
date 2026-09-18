"""RFX-351 -- one flag set was answered for ten different database clients.

`_has_script_file` tested membership in a single shared set --
`{-f, --file, --init, -init, --source}` -- and that same set decided the
question for every member of `_DB_CLIENTS`.  A flag does not mean the same
thing in two different programs, so one uniform answer to a per-command
question is wrong in BOTH directions at once, and it was:

  fail-open   `sqlcmd -i`, `clickhouse-client --queries-file`,
              `redis-cli --eval`, `mongosh db drop.js` and sqlite3's `.read`
              each hand the client a script file under the spelling its own
              manual documents.  None is in the shared set, so the statements
              stayed invisible -- the entire reason the branch exists -- and
              the command fell through to the default Bash execute arm:
              execute / recoverable / scoped, `danger_signature` null,
              `target_ref` null.  No hold, no human, and the audit line could
              not name the database.

  fail-noisy  `-f` is `--force` for mysql and mariadb, and the CODEPAGE option
              for sqlcmd.  `mysql -f -e 'SELECT 1'` -- inline, fully visible,
              a read -- was priced irreversible / broad /
              `sql_script_unbounded`, the heaviest verdict that branch can
              produce.  The three `everyday_*` tests below are not decoration:
              a gate that asks on a SELECT gets switched off, and a
              switched-off gate protects nobody, which is the argument
              RFX-131 and RFX-145 make in classify.py itself.

GROUND TRUTH, for the one client executable on the devbox.  sqlite3 3.34.1 was
run against canary databases carrying five rows: `.read wipe.sql`, `-init
wipe.sql` and `< wipe.sql` each left the table gone, and `SELECT count(*)`
left all five -- so the discriminating control discriminates.  The other
clients' rows are documented flag semantics plus the measured verdict, and the
round report labels them that way rather than claiming an execution that did
not happen.  Evidence: code-reports/dev-1--166--20260918-evidence/02-.

The production-looking paths here are CLASSIFIER INPUT ONLY.  Nothing under
/srv or /tmp is created, opened, written or executed by this module.
"""

import unittest

from reeflex_claude.classify import (
    _DB_CLIENTS,
    _DB_POSITIONAL_SCRIPT_CLIENTS,
    _DB_SCRIPT_FLAGS_BY_CLIENT,
    classify,
)


def _c(command):
    return classify("Bash", {"command": command})


def _no_signature(r):
    """`danger_signature` is the STRING "none" when nothing fired, not None."""
    return r["danger_signature"] in (None, "none")


def _is_script_verdict(r):
    return (r["danger_signature"] == "sql_script_unbounded"
            and r["reversibility"] == "irreversible"
            and r["blast_radius"] == "broad")


class ScriptFileSpellingsThatWereInvisible(unittest.TestCase):
    """Each row is a real script-file invocation of a real client."""

    CASES = [
        ("sqlcmd -S prod -i /tmp/wipe.sql", "sqlcmd's script flag is -i"),
        ("sqlcmd -S prod --input-file /tmp/wipe.sql", "its long spelling"),
        ("clickhouse-client --queries-file /tmp/wipe.sql",
         "clickhouse-client has no -f"),
        ("clickhouse-client --queries-file=/tmp/wipe.sql", "with an equals"),
        ("redis-cli --eval /tmp/flush.lua", "a Lua script file"),
        ("mongosh prod /tmp/drop.js", "a bare positional script"),
        ("mongo prod /tmp/drop.js", "the legacy shell, same shape"),
        ("mongosh 'mongodb://db/prod' /tmp/drop.js", "with a connection URI"),
        ("sqlite3 /srv/prod/db.sqlite '.read /tmp/wipe.sql'",
         "sqlite3's in-client .read -- executed against a canary, it empties it"),
        ("mysql prod -e 'source /tmp/wipe.sql'", "source inside inline SQL"),
        ("mysql prod -e '\\. /tmp/wipe.sql'", "its one-character spelling"),
    ]

    def test_every_spelling_is_priced_as_an_unbounded_script(self):
        for command, why in self.CASES:
            with self.subTest(command=command):
                r = _c(command)
                self.assertTrue(
                    _is_script_verdict(r),
                    f"{why}: {command!r} priced {r['verb']}/"
                    f"{r['reversibility']}/{r['blast_radius']} "
                    f"sig={r['danger_signature']!r}")

    def test_the_spellings_that_already_worked_still_do(self):
        for command in [
            "psql -f /tmp/wipe.sql",
            "psql --file=/tmp/wipe.sql",
            "psql --file /tmp/wipe.sql",
            "cqlsh -f /tmp/wipe.cql",
            "mongosh --file /tmp/drop.js",
            "sqlite3 -init /tmp/wipe.sql /srv/prod/db.sqlite",
            "sqlite3 /srv/prod/db.sqlite < /tmp/wipe.sql",
        ]:
            with self.subTest(command=command):
                self.assertTrue(_is_script_verdict(_c(command)), command)


class FlagsThatAreNotScriptFiles(unittest.TestCase):
    """The other direction. `-f` is not a file for any of these three."""

    def test_mysql_dash_f_is_force_and_the_sql_is_visible(self):
        r = _c("mysql -f -e 'SELECT 1'")
        self.assertTrue(_no_signature(r), r["danger_signature"])
        self.assertEqual("recoverable", r["reversibility"])

    def test_mariadb_dash_f_is_force(self):
        r = _c("mariadb -f prod")
        self.assertTrue(_no_signature(r), r["danger_signature"])

    def test_sqlcmd_dash_f_is_a_codepage(self):
        r = _c("sqlcmd -f 65001 -Q 'SELECT 1'")
        self.assertTrue(_no_signature(r), r["danger_signature"])

    def test_visible_destructive_sql_is_still_caught_on_those_clients(self):
        """Narrowing the flag table must not reach the SQL patterns."""
        for command in [
            "mysql -f -e 'DROP DATABASE mydb'",
            "mariadb -f prod -e 'TRUNCATE orders'",
            "sqlcmd -f 65001 -Q 'DROP TABLE users'",
        ]:
            with self.subTest(command=command):
                r = _c(command)
                self.assertEqual("delete", r["verb"], command)
                self.assertEqual("irreversible", r["reversibility"], command)


class ThePositionalShapeIsNotEveryArgument(unittest.TestCase):
    """A database name is not a script, or every mongosh call is a hold."""

    def test_an_interactive_mongosh_is_not_a_script(self):
        for command in [
            "mongosh prod",
            "mongosh 'mongodb://db/prod'",
            "mongosh --eval 'db.stats()'",
        ]:
            with self.subTest(command=command):
                self.assertTrue(_no_signature(_c(command)), command)

    def test_a_js_argument_to_a_client_that_takes_none_is_not_a_script(self):
        """psql has no positional script shape; `.js` there means nothing."""
        self.assertTrue(_no_signature(_c("psql prod /tmp/drop.js")))


class TheTableIsKeyedByClient(unittest.TestCase):
    """The structural claim, so a future edit cannot quietly re-share the set."""

    def test_every_client_with_flags_is_a_known_client(self):
        for client in _DB_SCRIPT_FLAGS_BY_CLIENT:
            self.assertIn(client, _DB_CLIENTS, client)
        for client in _DB_POSITIONAL_SCRIPT_CLIENTS:
            self.assertIn(client, _DB_CLIENTS, client)

    def test_no_two_clients_are_forced_to_share_one_set(self):
        """The defect in one assertion: -f must not reach mysql or sqlcmd."""
        self.assertIn("-f", _DB_SCRIPT_FLAGS_BY_CLIENT["psql"])
        self.assertNotIn("-f", _DB_SCRIPT_FLAGS_BY_CLIENT.get("mysql", frozenset()))
        self.assertNotIn("-f", _DB_SCRIPT_FLAGS_BY_CLIENT.get("mariadb", frozenset()))
        self.assertNotIn("-f", _DB_SCRIPT_FLAGS_BY_CLIENT["sqlcmd"])
        self.assertIn("-i", _DB_SCRIPT_FLAGS_BY_CLIENT["sqlcmd"])


class TheClientStillHasToBeADatabaseClient(unittest.TestCase):
    """None of this arms outside _DB_CLIENTS."""

    def test_a_shell_script_named_like_a_query_file_is_not_a_db_script(self):
        for command in [
            "./deploy.sh -i /tmp/wipe.sql",
            "grep -f /tmp/patterns.txt src/",
            "cat /tmp/drop.js",
        ]:
            with self.subTest(command=command):
                self.assertNotEqual("sql_script_unbounded",
                                    _c(command)["danger_signature"], command)


if __name__ == "__main__":
    unittest.main()
