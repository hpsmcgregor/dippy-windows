import json
import subprocess
import sys


def run_hook(payload: dict) -> dict:
    result = subprocess.run(
        [sys.executable, "-m", "dippy_windows.hook"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"hook exited non-zero: {result.stderr}"
    return json.loads(result.stdout)


def decision(out: dict) -> str:
    return out["hookSpecificOutput"]["permissionDecision"]


class TestPassthrough:
    def test_unknown_tool(self):
        assert run_hook({"tool_name": "Read", "tool_input": {}}) == {}

    def test_no_tool_name(self):
        assert run_hook({"tool_input": {"command": "ls"}}) == {}


class TestBash:
    def test_safe_ls(self):
        assert decision(run_hook({"tool_name": "Bash", "tool_input": {"command": "ls -la"}})) == "allow"

    def test_safe_git(self):
        assert decision(run_hook({"tool_name": "Bash", "tool_input": {"command": "git status"}})) == "allow"

    def test_rm_denied(self):
        assert decision(run_hook({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})) == "deny"

    def test_cmd_c_safe_nested_in_bash(self):
        assert decision(run_hook({"tool_name": "Bash", "tool_input": {"command": 'cmd /c "dir"'}})) == "allow"

    def test_cmd_c_dangerous_nested_in_bash(self):
        assert decision(run_hook({"tool_name": "Bash", "tool_input": {"command": 'cmd /c "del /f /s C:\\"'}})) == "deny"


class TestPowerShell:
    def test_safe(self):
        assert decision(run_hook({"tool_name": "PowerShell", "tool_input": {"command": "Get-ChildItem C:\\src"}})) == "allow"

    def test_dangerous(self):
        assert decision(run_hook({"tool_name": "PowerShell", "tool_input": {"command": "Remove-Item -Force C:\\src"}})) == "deny"

    def test_ask(self):
        assert decision(run_hook({"tool_name": "PowerShell", "tool_input": {"command": "New-Item foo.txt"}})) == "ask"

    def test_cmd_c_nested_in_ps(self):
        assert decision(run_hook({"tool_name": "PowerShell", "tool_input": {"command": 'cmd /c "format C:"'}})) == "deny"

    def test_reason_present(self):
        out = run_hook({"tool_name": "PowerShell", "tool_input": {"command": "Get-ChildItem"}})
        assert "permissionDecisionReason" in out["hookSpecificOutput"]


class TestPsHeuristicViaBash:
    def test_ps_command_via_bash_analyzed_as_ps(self):
        out = run_hook({"tool_name": "Bash", "tool_input": {"command": "Get-ChildItem C:\\src"}})
        assert decision(out) == "allow"


class TestOutputSchema:
    def test_hook_event_name_present(self):
        # Claude Code requires hookEventName="PreToolUse" for the permission
        # decision to be honored in a live session.
        out = run_hook({"tool_name": "PowerShell", "tool_input": {"command": "Get-ChildItem"}})
        assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
