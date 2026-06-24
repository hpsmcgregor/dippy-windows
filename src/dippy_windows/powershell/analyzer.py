import re

from dippy_windows.config.policy import EMPTY_POLICY, Policy
from dippy_windows.powershell.allowlists import (
    PS_ASK_CMDLETS, PS_DANGEROUS_CMDLETS, PS_SAFE_CMDLETS, resolve_alias,
)
from dippy_windows.powershell.tokenizer import (
    ps_extract_cmdlet, ps_split_chain, ps_split_pipeline,
)
from dippy_windows.types import Decision, combine

_PS_VERB_RE = re.compile(
    r"(?:Get|Set|New|Remove|Add|Clear|Copy|Move|Rename|Start|Stop|Invoke|Write|"
    r"Read|Select|Where|Sort|Group|Measure|Format|Out|Import|Export|Convert|"
    r"Enable|Disable|Register|Unregister|Test|Update|Install|Uninstall|"
    r"Push|Pop|Split|Join|Resolve|Enter|Exit)-\w+",
    re.IGNORECASE,
)
_PS_DOLLAR_RE = re.compile(r"\$[A-Za-z_]")
_REDIRECT_TARGET_RE = re.compile(r">>?\s*([^\s|;&>]+)")


def is_powershell_command(command: str) -> bool:
    return bool(_PS_VERB_RE.search(command) or _PS_DOLLAR_RE.search(command))


def _redirect_targets(segment: str) -> list[str]:
    targets: list[str] = []
    in_single = in_double = False
    i = 0
    while i < len(segment):
        ch = segment[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == ">" and not in_single and not in_double:
            m = _REDIRECT_TARGET_RE.match(segment, i)
            if m:
                targets.append(m.group(1).strip("'\""))
                i = m.end()
                continue
        i += 1
    return targets


def _subexpr_decisions(segment: str, policy: Policy) -> list[Decision]:
    results: list[Decision] = []
    i = 0
    while i < len(segment):
        if segment[i] == '$' and i + 1 < len(segment) and segment[i + 1] == '(':
            depth, j = 1, i + 2
            while j < len(segment) and depth:
                if segment[j] == '(':
                    depth += 1
                elif segment[j] == ')':
                    depth -= 1
                j += 1
            results.append(analyze_ps(segment[i + 2: j - 1], policy))
            i = j
        else:
            i += 1
    return results


def _builtin_segment_decision(segment: str, cmdlet: str, policy: Policy) -> Decision:
    if cmdlet in PS_DANGEROUS_CMDLETS:
        return Decision("deny", f"dangerous cmdlet: {cmdlet}")

    tokens = segment.split()
    if any(t in ("--version", "-v", "--help", "-h", "-?") for t in tokens):
        return Decision("allow", "version/help flag")

    if cmdlet in PS_ASK_CMDLETS:
        return Decision("ask", f"requires confirmation: {cmdlet}")
    if cmdlet in PS_SAFE_CMDLETS:
        return Decision("allow", f"safe cmdlet: {cmdlet}")
    return policy.default_decision_for_unknown(cmdlet)


def _analyze_segment(segment: str, policy: Policy) -> Decision:
    segment = segment.strip()
    if not segment:
        return Decision("allow", "empty segment")

    sub = _subexpr_decisions(segment, policy)
    targets = _redirect_targets(segment)
    cmdlet_raw = ps_extract_cmdlet(segment)
    if not cmdlet_raw:
        base = combine(sub) if sub else Decision("allow", "empty cmdlet")
        return policy.resolve_redirects(base, targets)

    cmdlet = resolve_alias(cmdlet_raw)
    builtin = _builtin_segment_decision(segment, cmdlet, policy)
    resolved = policy.resolve_command(segment, builtin)
    with_redirects = policy.resolve_redirects(resolved, targets)
    return combine(sub + [with_redirects])


def analyze_ps(command: str, policy: Policy = EMPTY_POLICY) -> Decision:
    if not command.strip():
        return Decision("ask", "empty command")
    decisions: list[Decision] = []
    for pseg in ps_split_pipeline(command):
        for part in ps_split_chain(pseg):
            decisions.append(_analyze_segment(part, policy))
    return combine(decisions)
