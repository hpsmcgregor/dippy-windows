import json
import sys

from dippy_windows.bash.analyzer import analyze_bash
from dippy_windows.cmd.analyzer import analyze_cmd, extract_cmd_payload
from dippy_windows.powershell.analyzer import analyze_ps, is_powershell_command
from dippy_windows.types import Decision

_BASH_TOOL = "Bash"
_PS_TOOL = "PowerShell"


def _apply_cmd_overlay(command: str, base: Decision) -> Decision:
    """If *command* is a cmd /c call, return CMD analysis (ignoring outer-shell analysis of the wrapper)."""
    payload = extract_cmd_payload(command)
    if payload is None:
        return base
    return analyze_cmd(payload)


def main() -> None:
    try:
        raw = sys.stdin.buffer.read().decode('utf-8-sig')  # utf-8-sig strips BOM if present
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        print("{}")
        return

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""

    if tool_name == _PS_TOOL:
        decision = _apply_cmd_overlay(command, analyze_ps(command))
    elif tool_name == _BASH_TOOL:
        if is_powershell_command(command):
            decision = _apply_cmd_overlay(command, analyze_ps(command))
        else:
            decision = _apply_cmd_overlay(command, analyze_bash(command))
    else:
        print("{}")
        return

    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.action,
            "permissionDecisionReason": decision.reason,
        }
    }
    print(json.dumps(output))


if __name__ == "__main__":
    main()
