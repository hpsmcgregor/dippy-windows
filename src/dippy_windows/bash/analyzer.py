from dippy_windows.bash.allowlists import BASH_SAFE, BASH_WRAPPERS
from dippy_windows.config.policy import EMPTY_POLICY, Policy
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


def _analyze_cmdsub(cs, policy) -> Decision:
    return _analyze_node(cs.command, policy)


def _word_sub_decisions(word, policy) -> list[Decision]:
    return [_analyze_cmdsub(p, policy) for p in (word.parts or []) if hasattr(p, "command")]


def _redirect_targets(node) -> list[str]:
    targets: list[str] = []
    for redirect in (node.redirects or []):
        if getattr(redirect, "op", None) in _OUTPUT_OPS:
            target = getattr(redirect, "target", None)
            value = getattr(target, "value", None) if target is not None else None
            targets.append(value if isinstance(value, str) else "")
    return targets


def _segment_text(words) -> str:
    return " ".join((w.value or "") for w in words)


def _analyze_node(node, policy: Policy) -> Decision:
    kind = getattr(node, "kind", "")

    if kind == "command":
        words = node.words or []
        if not words:
            return Decision("allow", "empty command")

        name = (words[0].value or "").lower()
        if not name:
            return Decision("allow", "empty command name")

        sub_decisions: list[Decision] = []
        for word in words:
            sub_decisions.extend(_word_sub_decisions(word, policy))

        raw_segment = _segment_text(words)
        targets = _redirect_targets(node)

        builtin = _builtin_command_decision(name, words, policy)
        resolved = policy.resolve_command(raw_segment, builtin)
        with_redirects = policy.resolve_redirects(resolved, targets)
        return combine(sub_decisions + [with_redirects])

    if kind == "pipeline":
        return combine([_analyze_node(c, policy) for c in (node.commands or [])])

    parts = getattr(node, "parts", None)
    if parts:
        return combine([_analyze_node(p, policy) for p in parts])

    return Decision("allow", "leaf node")


def _builtin_command_decision(name: str, words, policy: Policy) -> Decision:
    if name in _BASH_DENY:
        return Decision("deny", f"dangerous command: {name}")

    tokens = [w.value for w in words]
    if any(t in ("--version", "--help", "-h", "-v") for t in tokens):
        return Decision("allow", "version/help flag")

    if name in BASH_WRAPPERS:
        if len(words) > 1:
            wrapped = (words[1].value or "").lower()
            if wrapped in _BASH_DENY:
                return Decision("deny", f"dangerous wrapped: {wrapped}")
            if wrapped in BASH_SAFE:
                return Decision("allow", f"safe wrapped: {wrapped}")
        return policy.default_decision_for_unknown(f"wrapped:{name}")

    if name in BASH_SAFE:
        return Decision("allow", f"safe: {name}")

    return policy.default_decision_for_unknown(name)


def analyze_bash(command: str, policy: Policy = EMPTY_POLICY) -> Decision:
    """Analyze a bash command string and return a Decision."""
    if not command.strip():
        return Decision("ask", "empty command")
    try:
        nodes = parable.parse(command)
    except Exception:
        return Decision("ask", "parse error — could not analyze")
    if not nodes:
        return Decision("ask", "empty parse result")
    return combine([_analyze_node(n, policy) for n in nodes])
