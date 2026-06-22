import re
import shlex

from dippy_windows.types import Decision

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


def analyze_cmd(command: str) -> Decision:
    """Analyze a raw CMD command string (not a full `cmd /c` invocation)."""
    command = command.strip()
    if not command:
        return Decision("ask", "empty CMD command")

    if ">" in command:
        return Decision("ask", "CMD output redirect")

    try:
        tokens = shlex.split(command, posix=False)
    except ValueError:
        tokens = command.split()

    if not tokens:
        return Decision("ask", "empty CMD command")

    name = tokens[0].lower()
    if name.endswith(".exe"):
        name = name[:-4]

    if name in _CMD_DENY:
        return Decision("deny", f"dangerous CMD command: {name}")

    if any(t in ("/?", "/help") for t in tokens):
        return Decision("allow", "CMD help flag")

    if name in _CMD_SAFE:
        return Decision("allow", f"safe CMD command: {name}")

    return Decision("ask", f"unknown CMD command: {name}")
