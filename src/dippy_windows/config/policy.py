# src/dippy_windows/config/policy.py
from dataclasses import dataclass

from dippy_windows.config.rules import Rule
from dippy_windows.types import Decision, combine


def _last_match(rules: tuple[Rule, ...], text: str) -> Rule | None:
    found = None
    for rule in rules:
        if rule.matches(text):
            found = rule
    return found


@dataclass(frozen=True)
class Policy:
    command_rules: tuple[Rule, ...] = ()
    redirect_rules: tuple[Rule, ...] = ()
    mcp_rules: tuple[Rule, ...] = ()
    aliases: tuple[tuple[str, str], ...] = ()
    default_action: str = "ask"
    log_path: str | None = None

    def _normalize_command(self, raw_segment: str) -> str:
        toks = raw_segment.strip().split()
        if not toks:
            return ""
        alias_map = dict(self.aliases)
        head = alias_map.get(toks[0].lower(), toks[0].lower())
        return " ".join([head] + toks[1:])

    def classify_command(self, raw_segment: str) -> Decision | None:
        norm = self._normalize_command(raw_segment)
        if not norm:
            return None
        rule = _last_match(self.command_rules, norm)
        if rule is None:
            return None
        return Decision(rule.action, rule.message or f"config {rule.action}: {norm}")

    def classify_redirect(self, target_path: str) -> Decision | None:
        norm = target_path.replace("\\", "/")
        rule = _last_match(self.redirect_rules, norm)
        if rule is None:
            return None
        return Decision(rule.action, rule.message or f"config {rule.action}-redirect: {target_path}")

    def classify_mcp(self, tool_name: str) -> Decision | None:
        rule = _last_match(self.mcp_rules, tool_name)
        if rule is None:
            return None
        return Decision(rule.action, rule.message or f"config {rule.action}-mcp: {tool_name}")

    def resolve_command(self, raw_segment: str, builtin: Decision) -> Decision:
        override = self.classify_command(raw_segment)
        return override if override is not None else builtin

    def default_decision_for_unknown(self, name: str) -> Decision:
        return Decision(self.default_action, f"unknown command: {name}")

    def resolve_redirects(self, command_decision: Decision, targets: list[str]) -> Decision:
        decisions = [command_decision]
        for tgt in targets:
            r = self.classify_redirect(tgt)
            decisions.append(r if r is not None else Decision("ask", f"output redirect: {tgt}"))
        return combine(decisions)

    def log(self, decision: Decision, context: str) -> None:
        if not self.log_path:
            return
        try:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(f"{decision.action}\t{context}\t{decision.reason}\n")
        except OSError:
            pass


EMPTY_POLICY = Policy()
