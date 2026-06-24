import re
import shlex

from dippy_windows.config.policy import EMPTY_POLICY, Policy
from dippy_windows.types import Decision, combine

_CMD_RE = re.compile(
    r"^\s*cmd(?:\.exe)?\s+/[cC]\s+",
    re.IGNORECASE,
)
_QUOTED_PAYLOAD_RE = re.compile(
    r'^\s*cmd(?:\.exe)?\s+/[cC]\s+"([^"]*)"',
    re.IGNORECASE,
)
_UNQUOTED_PAYLOAD_RE = re.compile(
    r"^\s*cmd(?:\.exe)?\s+/[cC]\s+(.+)$",
    re.IGNORECASE,
)

_CMD_SAFE: frozenset[str] = frozenset({
    "dir", "echo", "type", "where", "ver", "cls", "help",
    "date", "time", "path", "set", "title",
    "ping", "ipconfig", "netstat", "tracert", "nslookup", "arp",
    "hostname", "systeminfo", "tasklist", "sc", "wmic",
    "python", "python3", "pip", "node", "npm", "git",
})

_CMD_DENY: frozenset[str] = frozenset({
    "del", "erase",
    "rd", "rmdir",
    "format",
    "shutdown", "restart",
    "reg",
    "bcdedit",
    "cipher",
    "net",
    "icacls", "cacls", "attrib",
    "diskpart",
    "schtasks",
    "wevtutil",
})


def extract_cmd_payload(command: str) -> str | None:
    """If *command* is a `cmd /c ...` invocation, return the CMD payload string."""
    if not _CMD_RE.match(command):
        return None
    m = _QUOTED_PAYLOAD_RE.match(command)
    if m:
        return m.group(1)
    m = _UNQUOTED_PAYLOAD_RE.match(command)
    if m:
        return m.group(1).strip()
    return None


def _split_cmd_segments(command: str) -> list[str]:
    """Split on CMD separators (& && | ||), respecting double-quoted strings.

    CMD chains commands with these operators, so a dangerous command after any
    separator (e.g. `echo hi & del C:\\x`) must be analyzed on its own.
    """
    segments: list[str] = []
    buf: list[str] = []
    in_quote = False
    i = 0
    while i < len(command):
        ch = command[i]
        if ch == '"':
            in_quote = not in_quote
            buf.append(ch)
            i += 1
        elif not in_quote and ch in ("&", "|"):
            segments.append("".join(buf))
            buf = []
            i += 2 if i + 1 < len(command) and command[i + 1] == ch else 1
        else:
            buf.append(ch)
            i += 1
    segments.append("".join(buf))
    return segments


def _analyze_cmd_segment(command: str, policy: Policy) -> Decision:
    command = command.strip()
    if not command:
        return Decision("allow", "empty CMD segment")

    if ">" in command:
        return Decision("ask", "CMD output redirect")

    try:
        tokens = shlex.split(command, posix=False)
    except ValueError:
        tokens = command.split()

    if not tokens:
        return Decision("allow", "empty CMD segment")

    name = tokens[0].lower()
    if name.endswith(".exe"):
        name = name[:-4]

    if name in _CMD_DENY:
        builtin = Decision("deny", f"dangerous CMD command: {name}")
    elif any(t in ("/?", "/help") for t in tokens):
        builtin = Decision("allow", "CMD help flag")
    elif name in _CMD_SAFE:
        builtin = Decision("allow", f"safe CMD command: {name}")
    else:
        builtin = policy.default_decision_for_unknown(name)

    return policy.resolve_command(command, builtin)


def analyze_cmd(command: str, policy: Policy = EMPTY_POLICY) -> Decision:
    """Analyze a raw CMD command string (not a full `cmd /c` invocation)."""
    command = command.strip()
    if not command:
        return Decision("ask", "empty CMD command")

    segments = [s for s in _split_cmd_segments(command) if s.strip()]
    if not segments:
        return Decision("ask", "empty CMD command")

    return combine([_analyze_cmd_segment(s, policy) for s in segments])
