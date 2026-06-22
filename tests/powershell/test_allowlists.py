from dippy_windows.powershell.allowlists import (
    PS_ASK_CMDLETS, PS_DANGEROUS_CMDLETS, PS_SAFE_CMDLETS, resolve_alias,
)


def test_all_lowercase():
    for s in (PS_SAFE_CMDLETS, PS_ASK_CMDLETS, PS_DANGEROUS_CMDLETS):
        assert all(c == c.lower() for c in s)


def test_sets_disjoint():
    assert PS_SAFE_CMDLETS.isdisjoint(PS_DANGEROUS_CMDLETS)
    assert PS_SAFE_CMDLETS.isdisjoint(PS_ASK_CMDLETS)
    assert PS_DANGEROUS_CMDLETS.isdisjoint(PS_ASK_CMDLETS)


def test_resolve_aliases():
    assert resolve_alias("ls") == "get-childitem"
    assert resolve_alias("rm") == "remove-item"
    assert resolve_alias("iex") == "invoke-expression"
    assert resolve_alias("curl") == "invoke-webrequest"


def test_resolve_case_insensitive():
    assert resolve_alias("LS") == "get-childitem"
    assert resolve_alias("Rm") == "remove-item"


def test_resolve_passthrough():
    assert resolve_alias("get-childitem") == "get-childitem"
    assert resolve_alias("something-unknown") == "something-unknown"


def test_well_known_safe():
    for name in ("get-childitem", "get-content", "select-object", "test-path"):
        assert name in PS_SAFE_CMDLETS


def test_well_known_dangerous():
    for name in ("remove-item", "invoke-expression", "stop-process"):
        assert name in PS_DANGEROUS_CMDLETS


def test_well_known_ask():
    for name in ("new-item", "set-content", "invoke-webrequest"):
        assert name in PS_ASK_CMDLETS
