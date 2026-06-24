import os
from pathlib import Path

from dippy_windows.config.parser import Directive, parse_line
from dippy_windows.config.policy import Policy
from dippy_windows.config.rules import Rule

_GLOBAL_REL = (".dippy-windows", "config")
_PROJECT_NAME = ".dippy-windows"
_ENV_VAR = "DIPPY_WINDOWS_CONFIG"


def _project_config(start: Path) -> Path | None:
    for directory in [start, *start.parents]:
        candidate = directory / _PROJECT_NAME
        if candidate.is_file():
            return candidate
    return None


def discover_paths() -> list[Path]:
    """Lowest precedence first (loaded earlier); last match wins overall."""
    paths: list[Path] = []
    global_path = Path.home().joinpath(*_GLOBAL_REL)
    if global_path.is_file():
        paths.append(global_path)
    project = _project_config(Path.cwd())
    if project is not None:
        paths.append(project)
    env = os.environ.get(_ENV_VAR)
    if env and Path(env).is_file():
        paths.append(Path(env))
    return paths


def build_policy(texts: list[str]) -> Policy:
    command: list[Rule] = []
    redirect: list[Rule] = []
    mcp: list[Rule] = []
    aliases: list[tuple[str, str]] = []
    default_action = "ask"
    log_path: str | None = None

    for text in texts:
        for line in text.splitlines():
            parsed = parse_line(line)
            if parsed is None:
                continue
            if isinstance(parsed, Rule):
                if parsed.kind == "command":
                    command.append(parsed)
                elif parsed.kind == "redirect":
                    redirect.append(parsed)
                elif parsed.kind == "mcp":
                    mcp.append(parsed)
            elif isinstance(parsed, Directive):
                if parsed.name == "alias":
                    aliases.append((parsed.args[0], parsed.args[1]))
                elif parsed.name == "set_default":
                    default_action = parsed.args[0]
                elif parsed.name == "set_log":
                    log_path = parsed.args[0]

    return Policy(
        command_rules=tuple(command),
        redirect_rules=tuple(redirect),
        mcp_rules=tuple(mcp),
        aliases=tuple(aliases),
        default_action=default_action,
        log_path=log_path,
    )


def load_policy() -> Policy:
    try:
        texts = []
        for path in discover_paths():
            try:
                texts.append(path.read_text(encoding="utf-8-sig"))
            except OSError:
                continue
        return build_policy(texts)
    except Exception:
        return Policy()
