import re
from dippy_windows.config.rules import Rule, compile_command_pattern, compile_path_pattern


class TestCommandPattern:
    def test_prefix_matches_bare(self):
        assert compile_command_pattern("git").match("git")

    def test_prefix_matches_with_args(self):
        assert compile_command_pattern("git").match("git push origin main")

    def test_prefix_does_not_match_other_word(self):
        assert not compile_command_pattern("git").match("gitk")

    def test_multiword_prefix(self):
        assert compile_command_pattern("git status").match("git status -s")

    def test_anchor_exact_only(self):
        pat = compile_command_pattern("git status|")
        assert pat.match("git status")
        assert not pat.match("git status -s")

    def test_star_wildcard(self):
        assert compile_command_pattern("rm -rf *").match("rm -rf /tmp/x")

    def test_question_wildcard(self):
        assert compile_command_pattern("rm?").match("rmx")
        assert not compile_command_pattern("rm?").match("rmxy")

    def test_charclass(self):
        assert compile_command_pattern("rm[xy]").match("rmx")
        assert not compile_command_pattern("rm[xy]").match("rmz")

    def test_case_insensitive(self):
        assert compile_command_pattern("Remove-Item").match("remove-item .")


class TestPathPattern:
    def test_double_star_recursive(self):
        assert compile_path_pattern("**/.env*").match("foo/bar/.env.local")

    def test_double_star_root(self):
        assert compile_path_pattern("**/.env*").match(".env")

    def test_single_star_one_segment(self):
        assert compile_path_pattern("secrets/*.key").match("secrets/id.key")
        assert not compile_path_pattern("secrets/*.key").match("secrets/sub/id.key")

    def test_backslash_normalized(self):
        assert compile_path_pattern("**/.env*").match("foo\\bar\\.env")

    def test_case_insensitive(self):
        assert compile_path_pattern("**/.ENV").match("x/.env")


class TestRule:
    def test_matches_delegates(self):
        r = Rule("command", "deny", compile_command_pattern("rm"), "no")
        assert r.matches("rm -rf /")
        assert not r.matches("ls")
