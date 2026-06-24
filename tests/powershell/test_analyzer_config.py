from dippy_windows.config.policy import Policy
from dippy_windows.config.rules import Rule, compile_command_pattern, compile_path_pattern
from dippy_windows.powershell.analyzer import analyze_ps


def cmd(action, pat, msg=None):
    return Policy(command_rules=(Rule("command", action, compile_command_pattern(pat), msg),))


def test_config_allows_builtin_deny():
    assert analyze_ps("Remove-Item -Force .", cmd("allow", "remove-item")).action == "allow"


def test_config_message_surfaces():
    d = analyze_ps("Remove-Item .", cmd("deny", "remove-item", "use Recycle Bin"))
    assert d.reason == "use Recycle Bin"


def test_config_denies_safe_cmdlet():
    assert analyze_ps("Get-ChildItem", cmd("deny", "get-childitem")).action == "deny"


def test_default_for_unknown():
    assert analyze_ps("Some-Unknown -X", Policy(default_action="deny")).action == "deny"


def test_deny_redirect_target():
    p = Policy(redirect_rules=(Rule("redirect", "deny", compile_path_pattern("**/.env*"), "no"),))
    assert analyze_ps("Get-ChildItem > .env", p).action == "deny"


def test_no_policy_unchanged():
    assert analyze_ps("Get-ChildItem C:\\src").action == "allow"
    assert analyze_ps("Remove-Item -Force .").action == "deny"
