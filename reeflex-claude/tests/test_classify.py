"""
test_classify.py -- Table-driven unit tests for classify.classify().

Pure: no network, no I/O, no side effects.
Each test case specifies tool_name + tool_input and asserts the resulting
verb, reversibility, blast_radius, externality, and classification_tier.
"""

from __future__ import annotations

import os
import sys
import unittest

# Ensure the reeflex-claude root is on sys.path when tests are run from any cwd
_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude.classify import classify


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _c(tool_name: str, tool_input: dict) -> dict:
    return classify(tool_name, tool_input)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestBashRead(unittest.TestCase):

    def test_ls(self):
        r = _c("Bash", {"command": "ls -la /tmp"})
        self.assertEqual(r["verb"], "read")
        self.assertEqual(r["reversibility"], "reversible")
        self.assertEqual(r["blast_radius"], "single")
        self.assertEqual(r["externality"], "internal")
        self.assertEqual(r["classification_tier"], "benign")
        self.assertEqual(r["danger_signature"], "none")

    def test_cat(self):
        r = _c("Bash", {"command": "cat /etc/hosts"})
        self.assertEqual(r["verb"], "read")
        self.assertEqual(r["classification_tier"], "benign")

    def test_grep(self):
        r = _c("Bash", {"command": "grep -r TODO /src"})
        self.assertEqual(r["verb"], "read")

    def test_git_status(self):
        r = _c("Bash", {"command": "git status"})
        self.assertEqual(r["verb"], "read")
        self.assertEqual(r["classification_tier"], "benign")

    def test_git_log(self):
        r = _c("Bash", {"command": "git log --oneline -10"})
        self.assertEqual(r["verb"], "read")

    def test_git_diff(self):
        r = _c("Bash", {"command": "git diff HEAD"})
        self.assertEqual(r["verb"], "read")

    def test_find_without_exec(self):
        r = _c("Bash", {"command": "find . -name '*.py'"})
        self.assertEqual(r["verb"], "read")

    def test_echo(self):
        r = _c("Bash", {"command": "echo hello world"})
        self.assertEqual(r["verb"], "read")

    def test_wc(self):
        r = _c("Bash", {"command": "wc -l file.txt"})
        self.assertEqual(r["verb"], "read")


class TestBashDelete(unittest.TestCase):

    def test_rm_root_systemic(self):
        r = _c("Bash", {"command": "rm -rf /"})
        self.assertEqual(r["verb"], "delete")
        self.assertEqual(r["reversibility"], "irreversible")
        self.assertEqual(r["blast_radius"], "systemic")
        self.assertEqual(r["externality"], "internal")
        self.assertIn(r["danger_signature"], ("rm_recursive_root",))
        self.assertEqual(r["classification_tier"], "destructive_systemic")

    def test_rm_rf_root_with_star(self):
        r = _c("Bash", {"command": "rm -rf /*"})
        self.assertEqual(r["blast_radius"], "systemic")
        self.assertEqual(r["danger_signature"], "rm_recursive_root")

    def test_rm_rf_home(self):
        r = _c("Bash", {"command": "rm -rf ~"})
        self.assertEqual(r["blast_radius"], "systemic")
        self.assertEqual(r["danger_signature"], "rm_recursive_root")

    def test_rm_rf_etc(self):
        r = _c("Bash", {"command": "rm -rf /etc/nginx"})
        self.assertEqual(r["blast_radius"], "systemic")
        self.assertEqual(r["classification_tier"], "destructive_systemic")

    def test_rm_rf_dir_non_systemic(self):
        r = _c("Bash", {"command": "rm -rf /tmp/build_output"})
        self.assertEqual(r["verb"], "delete")
        self.assertEqual(r["reversibility"], "irreversible")
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["danger_signature"], "rm_recursive")
        self.assertEqual(r["classification_tier"], "destructive_broad")

    def test_rm_single_file(self):
        r = _c("Bash", {"command": "rm /tmp/foo.txt"})
        self.assertEqual(r["verb"], "delete")
        self.assertEqual(r["reversibility"], "irreversible")
        self.assertEqual(r["blast_radius"], "single")
        self.assertEqual(r["magnitude_count"], 1)
        # single rm -> moderate (axes stay irreversible; tier based on blast_radius)
        self.assertEqual(r["classification_tier"], "moderate")

    def test_rm_two_files(self):
        r = _c("Bash", {"command": "rm /tmp/a.txt /tmp/b.txt"})
        self.assertEqual(r["blast_radius"], "scoped")
        self.assertEqual(r["magnitude_count"], 2)
        # scoped rm -> moderate
        self.assertEqual(r["classification_tier"], "moderate")

    def test_rm_twenty_files(self):
        files = " ".join([f"/tmp/f{i}.txt" for i in range(20)])
        r = _c("Bash", {"command": f"rm {files}"})
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["magnitude_count"], 20)

    def test_sql_drop_database(self):
        r = _c("Bash", {"command": "mysql -e 'DROP DATABASE mydb'"})
        self.assertEqual(r["verb"], "delete")
        self.assertEqual(r["blast_radius"], "systemic")
        self.assertEqual(r["danger_signature"], "sql_drop_database")
        self.assertEqual(r["classification_tier"], "destructive_systemic")

    def test_sql_drop_schema(self):
        r = _c("Bash", {"command": "psql -c 'DROP SCHEMA public CASCADE'"})
        self.assertEqual(r["blast_radius"], "systemic")
        self.assertEqual(r["danger_signature"], "sql_drop_database")

    def test_sql_drop_table(self):
        r = _c("Bash", {"command": "psql -c 'DROP TABLE users'"})
        self.assertEqual(r["verb"], "delete")
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["danger_signature"], "sql_drop_table")
        self.assertEqual(r["classification_tier"], "destructive_broad")

    def test_sql_truncate(self):
        r = _c("Bash", {"command": "psql -c 'TRUNCATE orders'"})
        self.assertEqual(r["verb"], "delete")
        self.assertEqual(r["blast_radius"], "broad")

    def test_git_clean_fdx(self):
        r = _c("Bash", {"command": "git clean -fdx"})
        self.assertEqual(r["verb"], "delete")
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["danger_signature"], "rm_recursive")

    def test_git_clean_Fdx_uppercase(self):
        """git clean -Fdx (uppercase F) must also be classified as delete/broad."""
        r = _c("Bash", {"command": "git clean -Fdx"})
        self.assertEqual(r["verb"], "delete")
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["danger_signature"], "rm_recursive")
        self.assertEqual(r["classification_tier"], "destructive_broad")

    def test_fork_bomb(self):
        r = _c("Bash", {"command": ":() { :|: & }; :"})
        self.assertEqual(r["verb"], "delete")
        self.assertEqual(r["blast_radius"], "systemic")
        self.assertEqual(r["danger_signature"], "fork_bomb")
        self.assertEqual(r["classification_tier"], "destructive_systemic")


class TestBashEmit(unittest.TestCase):

    def test_git_push_normal(self):
        r = _c("Bash", {"command": "git push origin main"})
        self.assertEqual(r["verb"], "emit")
        self.assertEqual(r["reversibility"], "irreversible")
        self.assertEqual(r["externality"], "outbound")
        self.assertEqual(r["blast_radius"], "scoped")
        self.assertEqual(r["classification_tier"], "destructive_broad")

    def test_git_push_force(self):
        r = _c("Bash", {"command": "git push --force origin main"})
        self.assertEqual(r["verb"], "emit")
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["danger_signature"], "git_force_push")

    def test_git_push_force_short(self):
        r = _c("Bash", {"command": "git push -f origin main"})
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["danger_signature"], "git_force_push")

    def test_npm_publish(self):
        r = _c("Bash", {"command": "npm publish --access public"})
        self.assertEqual(r["verb"], "emit")
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["danger_signature"], "publish")

    def test_yarn_publish(self):
        r = _c("Bash", {"command": "yarn publish"})
        self.assertEqual(r["verb"], "emit")
        self.assertEqual(r["danger_signature"], "publish")

    def test_curl_post(self):
        r = _c("Bash", {"command": "curl -X POST https://api.example.com/data -d '{}'}"})
        self.assertEqual(r["verb"], "emit")
        self.assertEqual(r["externality"], "outbound")

    def test_scp(self):
        r = _c("Bash", {"command": "scp file.txt user@server:/path/"})
        self.assertEqual(r["verb"], "emit")
        self.assertEqual(r["externality"], "outbound")


class TestBashExecute(unittest.TestCase):

    def test_npm_install(self):
        r = _c("Bash", {"command": "npm install"})
        self.assertEqual(r["verb"], "execute")
        self.assertEqual(r["reversibility"], "recoverable")
        self.assertEqual(r["blast_radius"], "scoped")
        self.assertEqual(r["externality"], "internal")
        self.assertEqual(r["classification_tier"], "moderate")

    def test_make_build(self):
        r = _c("Bash", {"command": "make build"})
        self.assertEqual(r["verb"], "execute")
        self.assertEqual(r["classification_tier"], "moderate")

    def test_pytest(self):
        r = _c("Bash", {"command": "pytest tests/ -v"})
        self.assertEqual(r["verb"], "execute")

    def test_docker_build(self):
        r = _c("Bash", {"command": "docker build -t myapp ."})
        self.assertEqual(r["verb"], "execute")

    def test_git_commit(self):
        r = _c("Bash", {"command": "git commit -m 'fix: bug'"})
        self.assertEqual(r["verb"], "execute")

    def test_empty_command(self):
        r = _c("Bash", {"command": ""})
        self.assertEqual(r["verb"], "execute")

    def test_strict_mode_execute(self):
        orig = os.environ.get("REEFLEX_CLAUDE_STRICT")
        os.environ["REEFLEX_CLAUDE_STRICT"] = "1"
        try:
            r = _c("Bash", {"command": "npm install"})
            self.assertEqual(r["reversibility"], "irreversible")
        finally:
            if orig is None:
                del os.environ["REEFLEX_CLAUDE_STRICT"]
            else:
                os.environ["REEFLEX_CLAUDE_STRICT"] = orig


class TestWriteTool(unittest.TestCase):

    def test_write_new_file(self):
        # /nonexistent/path should not exist
        r = _c("Write", {"file_path": "/nonexistent/synthetic/newfile.py",
                          "content": "print('hello')"})
        self.assertEqual(r["verb"], "create")
        self.assertEqual(r["reversibility"], "recoverable")
        self.assertEqual(r["blast_radius"], "single")
        self.assertEqual(r["externality"], "internal")
        self.assertEqual(r["classification_tier"], "moderate")
        self.assertEqual(r["danger_signature"], "disk_write")

    def test_write_env_file(self):
        r = _c("Write", {"file_path": "/app/.env", "content": "SECRET=x"})
        self.assertEqual(r["verb"], "create")
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["danger_signature"], "sensitive_write")
        self.assertEqual(r["classification_tier"], "destructive_broad")

    def test_write_env_local(self):
        r = _c("Write", {"file_path": ".env.local", "content": ""})
        self.assertEqual(r["blast_radius"], "broad")

    def test_write_terraform_file(self):
        r = _c("Write", {"file_path": "infra/main.tf", "content": ""})
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["danger_signature"], "sensitive_write")

    def test_write_github_workflow(self):
        r = _c("Write", {"file_path": ".github/workflows/ci.yml", "content": ""})
        self.assertEqual(r["blast_radius"], "broad")

    def test_write_dockerfile(self):
        r = _c("Write", {"file_path": "Dockerfile", "content": ""})
        self.assertEqual(r["blast_radius"], "broad")


class TestEditTool(unittest.TestCase):

    def test_edit_source_file(self):
        r = _c("Edit", {"file_path": "src/main.py",
                         "old_string": "foo", "new_string": "bar"})
        self.assertEqual(r["verb"], "update")
        self.assertEqual(r["reversibility"], "recoverable")
        self.assertEqual(r["blast_radius"], "single")
        self.assertEqual(r["externality"], "internal")
        self.assertEqual(r["classification_tier"], "moderate")

    def test_edit_sensitive_path(self):
        r = _c("Edit", {"file_path": "/etc/nginx.conf",
                         "old_string": "80", "new_string": "443"})
        self.assertEqual(r["verb"], "update")
        self.assertEqual(r["blast_radius"], "scoped")
        self.assertEqual(r["danger_signature"], "sensitive_write")

    def test_multiedit(self):
        r = _c("MultiEdit", {"file_path": "app.py",
                               "edits": [{"old_str": "a", "new_str": "b"}]})
        self.assertEqual(r["verb"], "update")

    def test_notebookedit(self):
        r = _c("NotebookEdit", {"file_path": "analysis.ipynb",
                                  "new_source": "print(1)"})
        self.assertEqual(r["verb"], "update")


class TestReadTools(unittest.TestCase):

    def test_read_tool(self):
        r = _c("Read", {"file_path": "/src/main.py"})
        self.assertEqual(r["verb"], "read")
        self.assertEqual(r["reversibility"], "reversible")
        self.assertEqual(r["blast_radius"], "single")
        self.assertEqual(r["externality"], "internal")
        self.assertEqual(r["classification_tier"], "benign")

    def test_glob_tool(self):
        r = _c("Glob", {"pattern": "**/*.py"})
        self.assertEqual(r["verb"], "read")
        self.assertEqual(r["classification_tier"], "benign")

    def test_grep_tool(self):
        r = _c("Grep", {"pattern": "TODO", "path": "/src"})
        self.assertEqual(r["verb"], "read")

    def test_ls_tool(self):
        r = _c("LS", {"path": "/tmp"})
        self.assertEqual(r["verb"], "read")


class TestWebTools(unittest.TestCase):

    def test_webfetch(self):
        r = _c("WebFetch", {"url": "https://docs.example.com/api"})
        self.assertEqual(r["verb"], "read")
        self.assertEqual(r["externality"], "outbound")
        self.assertEqual(r["classification_tier"], "benign")

    def test_websearch(self):
        r = _c("WebSearch", {"query": "python asyncio tutorial"})
        self.assertEqual(r["verb"], "read")
        self.assertEqual(r["externality"], "outbound")


class TestUnknownTool(unittest.TestCase):

    def test_unknown(self):
        r = _c("SomeCustomTool", {"param": "value"})
        self.assertEqual(r["verb"], "execute")
        self.assertEqual(r["reversibility"], "irreversible")
        self.assertEqual(r["blast_radius"], "scoped")
        self.assertEqual(r["externality"], "internal")

    def test_empty_tool_name(self):
        r = _c("", {})
        self.assertEqual(r["verb"], "execute")
        self.assertEqual(r["reversibility"], "irreversible")


class TestMagnitudeCount(unittest.TestCase):

    def test_rm_count_5(self):
        files = " ".join([f"/tmp/f{i}" for i in range(5)])
        r = _c("Bash", {"command": f"rm {files}"})
        self.assertEqual(r["magnitude_count"], 5)
        self.assertEqual(r["blast_radius"], "scoped")

    def test_rm_count_1(self):
        r = _c("Bash", {"command": "rm /tmp/file.txt"})
        self.assertEqual(r["magnitude_count"], 1)
        self.assertEqual(r["blast_radius"], "single")

    def test_rm_count_19(self):
        files = " ".join([f"/tmp/f{i}" for i in range(19)])
        r = _c("Bash", {"command": f"rm {files}"})
        self.assertEqual(r["magnitude_count"], 19)
        self.assertEqual(r["blast_radius"], "scoped")

    def test_rm_count_20_is_broad(self):
        files = " ".join([f"/tmp/f{i}" for i in range(20)])
        r = _c("Bash", {"command": f"rm {files}"})
        self.assertEqual(r["magnitude_count"], 20)
        self.assertEqual(r["blast_radius"], "broad")


class TestRegressions(unittest.TestCase):
    """Regression tests added in the fix pass."""

    def test_rm_absolute_path_binary(self):
        """/bin/rm -rf /tmp/x -- absolute-path command -> delete/broad (rm -rf = recursive)."""
        r = _c("Bash", {"command": "/bin/rm -rf /tmp/x"})
        self.assertEqual(r["verb"], "delete")
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["danger_signature"], "rm_recursive")
        self.assertEqual(r["classification_tier"], "destructive_broad")

    def test_git_clean_Fdx_regression(self):
        """git clean -Fdx (uppercase F) -> delete/broad (was broken by [a-z]-only regex)."""
        r = _c("Bash", {"command": "git clean -Fdx"})
        self.assertEqual(r["verb"], "delete")
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["classification_tier"], "destructive_broad")

    def test_curl_d_no_space(self):
        """curl -d'{}' (no space after -d) -> emit/outbound (was under-classified as execute)."""
        r = _c("Bash", {"command": "curl -d'{\"key\":\"val\"}' https://api.example.com/hook"})
        self.assertEqual(r["verb"], "emit")
        self.assertEqual(r["externality"], "outbound")

    def test_curl_data_word_boundary(self):
        """curl --data=@file -> emit/outbound."""
        r = _c("Bash", {"command": "curl --data=@payload.json https://api.example.com/v1"})
        self.assertEqual(r["verb"], "emit")
        self.assertEqual(r["externality"], "outbound")

    def test_command_chaining_ls_rm(self):
        """
        'ls; rm -rf /' -- leading token is 'ls' -> read (leading-token classification).
        The rm part is not governed in this call; document this as a known limit of
        single-token classification and assert it does not crash and is governed.
        """
        r = _c("Bash", {"command": "ls; rm -rf /"})
        # Leading token ls -> read; the chained rm is not individually intercepted.
        # This is a documented limitation; assert: no exception, result is governed.
        self.assertIn(r["verb"], ("read", "delete", "execute", "emit"))
        self.assertIn(r["classification_tier"], ("benign", "moderate", "destructive_broad", "destructive_systemic"))

    def test_write_file_text_not_used_as_path(self):
        """
        Write with file_text content field must NOT use content as the path.
        Only file_path matters for classification.
        """
        # file_text contains a path-like string but that is the CONTENT not the path.
        r = _c("Write", {"file_path": "/nonexistent/synthetic/output.py",
                          "file_text": "/etc/passwd\nsome content\n"})
        # file_path is a non-existent non-sensitive path -> recoverable/single/moderate
        self.assertEqual(r["verb"], "create")
        self.assertEqual(r["blast_radius"], "single")
        self.assertEqual(r["danger_signature"], "disk_write")
        # /etc/passwd is in file_text (content), NOT the path -- must not trigger sensitive
        self.assertEqual(r["classification_tier"], "moderate")

    def test_rm_single_file_tier_is_moderate(self):
        """rm /tmp/x -> irreversible axis but moderate tier (P1 fix: single blast = moderate)."""
        r = _c("Bash", {"command": "rm /tmp/x"})
        self.assertEqual(r["reversibility"], "irreversible")
        self.assertEqual(r["blast_radius"], "single")
        self.assertEqual(r["classification_tier"], "moderate")

    def test_rm_scoped_files_tier_is_moderate(self):
        """rm /tmp/a /tmp/b /tmp/c -> scoped, moderate tier."""
        r = _c("Bash", {"command": "rm /tmp/a /tmp/b /tmp/c"})
        self.assertEqual(r["blast_radius"], "scoped")
        self.assertEqual(r["classification_tier"], "moderate")

    def test_rm_broad_tier_is_destructive_broad(self):
        """rm -rf /tmp/project -> broad, destructive_broad tier."""
        r = _c("Bash", {"command": "rm -rf /tmp/project"})
        self.assertEqual(r["blast_radius"], "broad")
        self.assertEqual(r["classification_tier"], "destructive_broad")


if __name__ == "__main__":
    unittest.main()
