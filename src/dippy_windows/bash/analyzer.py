from dippy_windows.bash.allowlists import BASH_SAFE, BASH_WRAPPERS
from dippy_windows.types import Decision, combine
from dippy_windows.vendor import parable

_BASH_DENY: frozenset[str] = frozenset({
    "rm", "rmdir", "dd", "shred", "mkfs", "fdisk", "parted", "wipefs",
    "shutdown", "reboot", "halt", "poweroff", "init",
    "kill", "killall", "pkill",
    "sudo", "su", "doas",
    "chmod", "chown", "chgrp",
    "passwd", "useradd", "userdel", "usermod",
    "iptables", "ip6tables", "nftables",
    "crontab", "at",
})

_OUTPUT_OPS: frozenset[str] = frozenset({">", ">>", "&>", "&>>"})


def _analyze_cmdsub(cs) -> Decision:
    # cs.command is a single Command node, not a list
    return _analyze_node(cs.command)


def _word_sub_decisions(word) -> list[Decision]:
    """Collect decisions from any CommandSubstitution parts in a word."""
    return [_analyze_cmdsub(p) for p in (word.parts or []) if hasattr(p, "command")]


def _analyze_node(node) -> Decision:
    kind = getattr(node, "kind", "")

    if kind == "command":
        for redirect in (node.redirects or []):
            if getattr(redirect, "op", None) in _OUTPUT_OPS:
                return Decision("ask", "output redirect detected")

        words = node.words or []
        if not words:
            return Decision("allow", "empty command")

        name = (words[0].value or "").lower()
        if not name:
            return Decision("allow", "empty command name")

        sub_decisions: list[Decision] = []
        for word in words:
            sub_decisions.extend(_word_sub_decisions(word))

        if name in _BASH_DENY:
            return Decision("deny", f"dangerous command: {name}")

        tokens = [w.value for w in words]
        if any(t in ("--version", "--help", "-h", "-v") for t in tokens):
            return combine(sub_decisions + [Decision("allow", "version/help flag")])

        if name in BASH_WRAPPERS:
            if len(words) > 1:
                wrapped = (words[1].value or "").lower()
                if wrapped in _BASH_DENY:
                    return combine(sub_decisions + [Decision("deny", f"dangerous wrapped: {wrapped}")])
                if wrapped in BASH_SAFE:
                    return combine(sub_decisions + [Decision("allow", f"safe wrapped: {wrapped}")])
            return combine(sub_decisions + [Decision("ask", "unknown wrapped command")])

        if name in BASH_SAFE:
            return combine(sub_decisions + [Decision("allow", f"safe: {name}")])

        return combine(sub_decisions + [Decision("ask", f"unknown command: {name}")])

    if kind == "pipeline":
        return combine([_analyze_node(c) for c in (node.commands or [])])

    # List (&&, ||, ;) and other compound nodes use .parts
    parts = getattr(node, "parts", None)
    if parts:
        return combine([_analyze_node(p) for p in parts])

    return Decision("allow", "leaf node")


def analyze_bash(command: str) -> Decision:
    """Analyze a bash command string and return a Decision."""
    if not command.strip():
        return Decision("ask", "empty command")
    try:
        nodes = parable.parse(command)
    except Exception:
        return Decision("ask", "parse error — could not analyze")
    if not nodes:
        return Decision("ask", "empty parse result")
    return combine([_analyze_node(n) for n in nodes])
