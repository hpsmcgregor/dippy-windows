import re
from dataclasses import dataclass

from dippy_windows.config.rules import Rule, compile_command_pattern, compile_path_pattern

_COMMAND_KEYWORDS = {"allow": "allow", "ask": "ask", "deny": "deny"}
_REDIRECT_KEYWORDS = {"allow-redirect": "allow", "deny-redirect": "deny"}
_MCP_KEYWORDS = {"allow-mcp": "allow", "ask-mcp": "ask", "deny-mcp": "deny"}
_VALID_DEFAULTS = {"allow", "ask", "deny"}

# captures: <pattern up to optional trailing quoted message>
_RULE_RE = re.compile(r"""^(?P<pattern>.*?)(?:\s+(?P<q>['"])(?P<msg>.*)(?P=q))?\s*$""")


@dataclass(frozen=True)
class Directive:
    name: str
    args: tuple[str, ...]


def _split_keyword(line: str) -> tuple[str, str]:
    parts = line.strip().split(None, 1)
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[1]


def _make_rule(kind: str, action: str, remainder: str, compile_fn) -> Rule | None:
    m = _RULE_RE.match(remainder)
    if not m:
        return None
    pattern = m.group("pattern").strip()
    if not pattern:
        return None
    return Rule(kind, action, compile_fn(pattern), m.group("msg"))


def parse_line(line: str) -> Rule | Directive | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    keyword, remainder = _split_keyword(stripped)
    kw = keyword.lower()

    if kw in _COMMAND_KEYWORDS:
        return _make_rule("command", _COMMAND_KEYWORDS[kw], remainder, compile_command_pattern)
    if kw in _REDIRECT_KEYWORDS:
        return _make_rule("redirect", _REDIRECT_KEYWORDS[kw], remainder, compile_path_pattern)
    if kw in _MCP_KEYWORDS:
        return _make_rule("mcp", _MCP_KEYWORDS[kw], remainder, compile_command_pattern)

    if kw == "alias":
        toks = remainder.split()
        if len(toks) == 2:
            return Directive("alias", (toks[0].lower(), toks[1].lower()))
        return None

    if kw == "set":
        toks = remainder.split(None, 1)
        if len(toks) == 2 and toks[0].lower() == "default":
            action = toks[1].strip().lower()
            return Directive("set_default", (action,)) if action in _VALID_DEFAULTS else None
        if len(toks) == 2 and toks[0].lower() == "log":
            return Directive("set_log", (toks[1].strip(),))
        return None

    return None
