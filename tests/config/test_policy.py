# tests/config/test_policy.py
from dippy_windows.config.policy import EMPTY_POLICY, Policy
from dippy_windows.config.rules import Rule, compile_command_pattern, compile_path_pattern
from dippy_windows.types import Decision


def cmd(action, pat, msg=None):
    return Rule("command", action, compile_command_pattern(pat), msg)


def red(action, pat, msg=None):
    return Rule("redirect", action, compile_path_pattern(pat), msg)


def mcp(action, pat, msg=None):
    return Rule("mcp", action, compile_command_pattern(pat), msg)


class TestClassifyCommand:
    def test_no_rules_returns_none(self):
        assert EMPTY_POLICY.classify_command("rm -rf /") is None

    def test_match_returns_decision(self):
        p = Policy(command_rules=(cmd("deny", "rm", "no"),))
        d = p.classify_command("rm -rf /")
        assert d.action == "deny" and d.reason == "no"

    def test_last_match_wins(self):
        p = Policy(command_rules=(cmd("deny", "git"), cmd("allow", "git push")))
        assert p.classify_command("git push origin").action == "allow"
        assert p.classify_command("git status").action == "deny"

    def test_alias_applied_to_first_token(self):
        p = Policy(command_rules=(cmd("deny", "git"),), aliases=(("g", "git"),))
        assert p.classify_command("g push").action == "deny"

    def test_default_message_when_none(self):
        p = Policy(command_rules=(cmd("allow", "ls"),))
        assert p.classify_command("ls -la").reason


class TestResolveCommand:
    def test_config_overrides_builtin_deny(self):
        p = Policy(command_rules=(cmd("allow", "rm"),))
        builtin = Decision("deny", "dangerous command: rm")
        assert p.resolve_command("rm -rf /", builtin).action == "allow"

    def test_falls_back_to_builtin(self):
        p = Policy(command_rules=(cmd("allow", "git"),))
        builtin = Decision("deny", "dangerous command: rm")
        assert p.resolve_command("rm -rf /", builtin).action == "deny"


class TestDefaultForUnknown:
    def test_default_is_ask(self):
        assert EMPTY_POLICY.default_decision_for_unknown("frob").action == "ask"

    def test_set_default_deny(self):
        assert Policy(default_action="deny").default_decision_for_unknown("frob").action == "deny"


class TestRedirects:
    def test_no_targets_returns_command_decision(self):
        d = EMPTY_POLICY.resolve_redirects(Decision("allow", "ok"), [])
        assert d.action == "allow"

    def test_unmatched_target_is_ask(self):
        d = EMPTY_POLICY.resolve_redirects(Decision("allow", "ok"), ["out.txt"])
        assert d.action == "ask"

    def test_deny_redirect_overrides_allow_command(self):
        p = Policy(redirect_rules=(red("deny", "**/.env*", "no secrets"),))
        d = p.resolve_redirects(Decision("allow", "ok"), [".env"])
        assert d.action == "deny" and d.reason == "no secrets"

    def test_allow_redirect_relaxes_to_allow(self):
        p = Policy(redirect_rules=(red("allow", "build/*.log"),))
        d = p.resolve_redirects(Decision("allow", "ok"), ["build/x.log"])
        assert d.action == "allow"


class TestClassifyMcp:
    def test_match(self):
        p = Policy(mcp_rules=(mcp("deny", "mcp__github__*", "no"),))
        assert p.classify_mcp("mcp__github__create_issue").action == "deny"

    def test_no_match_none(self):
        p = Policy(mcp_rules=(mcp("deny", "mcp__github__*"),))
        assert p.classify_mcp("mcp__fs__read") is None
