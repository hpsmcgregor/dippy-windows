import re

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


def is_powershell_command(command: str) -> bool:
    return bool(_PS_VERB_RE.search(command) or _PS_DOLLAR_RE.search(command))


def _has_redirect(segment: str) -> bool:
    in_single = in_double = False
    for ch in segment:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == '>' and not in_single and not in_double:
            return True
    return False


def _subexpr_decisions(segment: str) -> list[Decision]:
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
            results.append(analyze_ps(segment[i + 2: j - 1]))
            i = j
        else:
            i += 1
    return results


def _analyze_segment(segment: str) -> Decision:
    segment = segment.strip()
    if not segment:
        return Decision("allow", "empty segment")
    if _has_redirect(segment):
        return Decision("ask", "output redirect")

    sub = _subexpr_decisions(segment)
    cmdlet_raw = ps_extract_cmdlet(segment)
    if not cmdlet_raw:
        return combine(sub) if sub else Decision("allow", "empty cmdlet")

    cmdlet = resolve_alias(cmdlet_raw)

    # Deny check must precede the help/version short-circuit: a dangerous cmdlet
    # invoked with -v/-h/--help/-? (e.g. "Remove-Item -v ." where -v abbreviates
    # -Verbose) still runs and must not be allowed through.
    if cmdlet in PS_DANGEROUS_CMDLETS:
        return Decision("deny", f"dangerous cmdlet: {cmdlet}")

    tokens = segment.split()
    if any(t in ("--version", "-v", "--help", "-h", "-?") for t in tokens):
        return combine(sub + [Decision("allow", "version/help flag")])

    if cmdlet in PS_ASK_CMDLETS:
        return combine(sub + [Decision("ask", f"requires confirmation: {cmdlet}")])
    if cmdlet in PS_SAFE_CMDLETS:
        return combine(sub + [Decision("allow", f"safe cmdlet: {cmdlet}")])
    return combine(sub + [Decision("ask", f"unknown command: {cmdlet}")])


def analyze_ps(command: str) -> Decision:
    if not command.strip():
        return Decision("ask", "empty command")
    decisions: list[Decision] = []
    for pseg in ps_split_pipeline(command):
        for part in ps_split_chain(pseg):
            decisions.append(_analyze_segment(part))
    return combine(decisions)
