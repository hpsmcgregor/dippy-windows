import re
from pathlib import Path

_ASSIGNMENT_RE = re.compile(r"^\s*\$\{?[\w:]+\}?\s*=\s*")
_CALL_OP_RE = re.compile(r"^\s*&\s*['\"]?([^'\"\s]+)['\"]?\s*")


def ps_split_pipeline(command: str) -> list[str]:
    """Split on | operators, skipping those inside strings or $()."""
    segments: list[str] = []
    buf: list[str] = []
    depth = 0
    in_single = in_double = False
    i = 0
    while i < len(command):
        ch = command[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == '$' and not in_single and not in_double and i + 1 < len(command) and command[i + 1] == '(':
            depth += 1
        elif ch == '(' and not in_single and not in_double and depth > 0:
            depth += 1
        elif ch == ')' and not in_single and not in_double and depth > 0:
            depth -= 1
        elif ch == '|' and not in_single and not in_double and depth == 0:
            segments.append(''.join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    segments.append(''.join(buf))
    return segments


def ps_split_chain(segment: str) -> list[str]:
    """Split on ;, &&, || — skipping those inside strings."""
    parts: list[str] = []
    buf: list[str] = []
    in_single = in_double = False
    i = 0
    while i < len(segment):
        ch = segment[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if ch == ';':
                parts.append(''.join(buf))
                buf = []
                i += 1
                continue
            elif ch in ('&', '|') and i + 1 < len(segment) and segment[i + 1] == ch:
                parts.append(''.join(buf))
                buf = []
                i += 2
                continue
        buf.append(ch)
        i += 1
    parts.append(''.join(buf))
    return parts


def ps_extract_cmdlet(segment: str) -> str:
    """Return the leading cmdlet/command name from *segment*, lowercased."""
    segment = segment.strip()
    if not segment:
        return ""
    segment = _ASSIGNMENT_RE.sub("", segment).strip()
    if not segment:
        return ""
    m = _CALL_OP_RE.match(segment)
    if m:
        return Path(m.group(1)).name.lower()
    return segment.split()[0].lower()
