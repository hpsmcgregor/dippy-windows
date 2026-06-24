import re
from dataclasses import dataclass


def _translate_command(pattern: str) -> str:
    """Translate a command glob to a regex body (no anchors)."""
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch == "[":
            j = pattern.find("]", i)
            if j == -1:
                out.append(re.escape(ch))
            else:
                out.append("[" + pattern[i + 1:j] + "]")
                i = j
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def compile_command_pattern(pattern: str) -> re.Pattern:
    anchored = pattern.endswith("|")
    core = pattern[:-1] if anchored else pattern
    body = _translate_command(core.strip())
    tail = "$" if anchored else r"(?:\s.*)?$"
    return re.compile("^" + body + tail, re.IGNORECASE)


def _translate_path(pattern: str) -> str:
    """Translate a path glob (with **) to a regex body. Paths use '/'. """
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*" and pattern[i:i + 3] == "**/":
            out.append("(?:.*[/\\\\])?")
            i += 2  # consume the extra '*' and '/'
        elif ch == "*" and pattern[i:i + 2] == "**":
            out.append(".*")
            i += 1
        elif ch == "*":
            out.append("[^/\\\\]*")
        elif ch == "?":
            out.append("[^/\\\\]")
        elif ch == "[":
            j = pattern.find("]", i)
            if j == -1:
                out.append(re.escape(ch))
            else:
                out.append("[" + pattern[i + 1:j] + "]")
                i = j
        elif ch == "/":
            out.append("[/\\\\]")
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def compile_path_pattern(pattern: str) -> re.Pattern:
    body = _translate_path(pattern.strip().replace("\\", "/"))
    return re.compile("^" + body + "$", re.IGNORECASE)


@dataclass(frozen=True)
class Rule:
    kind: str
    action: str
    matcher: re.Pattern
    message: str | None

    def matches(self, text: str) -> bool:
        return bool(self.matcher.match(text))
