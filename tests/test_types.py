from dippy_windows.types import Decision, combine


def test_fields():
    d = Decision("allow", "safe")
    assert d.action == "allow"
    assert d.reason == "safe"
    assert d.children == []


def test_combine_empty():
    assert combine([]).action == "allow"


def test_combine_all_allow():
    assert combine([Decision("allow", "a"), Decision("allow", "b")]).action == "allow"


def test_deny_wins():
    decisions = [Decision("allow", "a"), Decision("deny", "b"), Decision("ask", "c")]
    assert combine(decisions).action == "deny"


def test_ask_beats_allow():
    assert combine([Decision("allow", "a"), Decision("ask", "b")]).action == "ask"


def test_children_preserved():
    decisions = [Decision("allow", "a"), Decision("deny", "b")]
    assert len(combine(decisions).children) == 2
