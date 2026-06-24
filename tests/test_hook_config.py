import json
import os
import subprocess
import sys
import tempfile


def run_hook(payload: dict, env_extra: dict | None = None) -> dict:
    env = dict(os.environ)
    env.pop("DIPPY_WINDOWS_CONFIG", None)  # never inherit a stray config file
    with tempfile.TemporaryDirectory() as isolated:
        # Isolate home (~/.dippy-windows/config) and cwd (.dippy-windows walk-up)
        env["USERPROFILE"] = isolated
        env["HOME"] = isolated
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, "-m", "dippy_windows.hook"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            cwd=isolated,
        )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def decision(out: dict) -> str:
    return out["hookSpecificOutput"]["permissionDecision"]


def test_config_overrides_via_env(tmp_path):
    cfg = tmp_path / "c.cfg"
    cfg.write_text("deny ls 'no listing'\n", encoding="utf-8")
    out = run_hook(
        {"tool_name": "Bash", "tool_input": {"command": "ls -la"}},
        {"DIPPY_WINDOWS_CONFIG": str(cfg)},
    )
    assert decision(out) == "deny"
    assert out["hookSpecificOutput"]["permissionDecisionReason"] == "no listing"


def test_mcp_no_rule_passthrough():
    out = run_hook({"tool_name": "mcp__github__create_issue", "tool_input": {}})
    assert out == {}


def test_mcp_rule_denies(tmp_path):
    cfg = tmp_path / "c.cfg"
    cfg.write_text("deny-mcp mcp__github__* 'no gh'\n", encoding="utf-8")
    out = run_hook(
        {"tool_name": "mcp__github__create_issue", "tool_input": {}},
        {"DIPPY_WINDOWS_CONFIG": str(cfg)},
    )
    assert decision(out) == "deny"


def test_unknown_tool_still_passthrough():
    assert run_hook({"tool_name": "Read", "tool_input": {}}) == {}
