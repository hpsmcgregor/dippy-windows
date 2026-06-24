# tests/cmd/test_analyzer_config.py
from dippy_windows.cmd.analyzer import analyze_cmd
from dippy_windows.config.policy import Policy
from dippy_windows.config.rules import Rule, compile_command_pattern


def cmd(action, pat, msg=None):
    return Policy(command_rules=(Rule("command", action, compile_command_pattern(pat), msg),))


def test_config_allows_builtin_deny():
    assert analyze_cmd("del /q C:\\x", cmd("allow", "del")).action == "allow"


def test_config_message_surfaces():
    d = analyze_cmd("del C:\\x", cmd("deny", "del", "use Recycle Bin"))
    assert d.reason == "use Recycle Bin"


def test_default_for_unknown():
    assert analyze_cmd("somecustomtool --run", Policy(default_action="deny")).action == "deny"


def test_chain_still_denies_without_override():
    assert analyze_cmd("echo hi & del C:\\x").action == "deny"


def test_no_policy_unchanged():
    assert analyze_cmd("dir").action == "allow"
    assert analyze_cmd("del /q C:\\x").action == "deny"
