# tests/bash/test_analyzer_config.py
from dippy_windows.bash.analyzer import analyze_bash
from dippy_windows.config.policy import Policy
from dippy_windows.config.rules import Rule, compile_command_pattern, compile_path_pattern


def cmd(action, pat, msg=None):
    return Policy(command_rules=(Rule("command", action, compile_command_pattern(pat), msg),))


def test_config_allows_builtin_deny():
    assert analyze_bash("rm -rf /tmp/x", cmd("allow", "rm")).action == "allow"


def test_config_message_surfaces():
    d = analyze_bash("rm -rf /tmp/x", cmd("deny", "rm", "use trash"))
    assert d.action == "deny" and d.reason == "use trash"


def test_config_denies_safe_command():
    assert analyze_bash("ls -la", cmd("deny", "ls")).action == "deny"


def test_default_for_unknown_changes_to_deny():
    p = Policy(default_action="deny")
    assert analyze_bash("frobnicator --x", p).action == "deny"


def test_deny_redirect_matches_target():
    p = Policy(redirect_rules=(Rule("redirect", "deny", compile_path_pattern("**/.env*"), "no secrets"),))
    d = analyze_bash("echo secret > .env", p)
    assert d.action == "deny" and d.reason == "no secrets"


def test_no_policy_unchanged():
    assert analyze_bash("ls -la").action == "allow"
    assert analyze_bash("rm -rf /").action == "deny"
