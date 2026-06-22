from dataclasses import dataclass, field
from typing import Literal

_PRIORITY: dict[str, int] = {"deny": 2, "ask": 1, "allow": 0}


@dataclass
class Decision:
    action: Literal["allow", "ask", "deny"]
    reason: str
    children: list["Decision"] = field(default_factory=list)


def combine(decisions: list[Decision]) -> Decision:
    """Return the most restrictive decision. deny > ask > allow."""
    if not decisions:
        return Decision("allow", "no commands")
    top = max(decisions, key=lambda d: _PRIORITY[d.action])
    return Decision(top.action, top.reason, list(decisions))
