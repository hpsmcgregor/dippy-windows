import json
import sys

from dippy_windows.bash.analyzer import analyze_bash
from dippy_windows.cmd.analyzer import analyze_cmd, extract_cmd_payload
from dippy_windows.config.loader import load_policy
from dippy_windows.config.policy import Policy
from dippy_windows.powershell.analyzer import analyze_ps, is_powershell_command
from dippy_windows.types import Decision

_BASH_TOOL = "Bash"
_PS_TOOL = "PowerShell"
_MCP_PREFIX = "mcp__"


def _apply_cmd_overlay(command: str, base: Decision, policy: Policy) -> Decision:
    payload = extract_cmd_payload(command)
    if payload is None:
        return base
    return analyze_cmd(payload, policy)


def _emit(decision: Decision) -> None:
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.action,
            "permissionDecisionReason": decision.reason,
        }
    }
    print(json.dumps(output))


def main() -> None:
    try:
        raw = sys.stdin.buffer.read().decode("utf-8-sig")
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        print("{}")
        return

    policy = load_policy()
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""

    if tool_name.startswith(_MCP_PREFIX):
        decision = policy.classify_mcp(tool_name)
        if decision is None:
            print("{}")
            return
    elif tool_name == _PS_TOOL:
        decision = _apply_cmd_overlay(command, analyze_ps(command, policy), policy)
    elif tool_name == _BASH_TOOL:
        if is_powershell_command(command):
            decision = _apply_cmd_overlay(command, analyze_ps(command, policy), policy)
        else:
            decision = _apply_cmd_overlay(command, analyze_bash(command, policy), policy)
    else:
        print("{}")
        return

    policy.log(decision, tool_name + ": " + command if command else tool_name)
    _emit(decision)


if __name__ == "__main__":
    main()
