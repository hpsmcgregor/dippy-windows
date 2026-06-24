# tests/config/test_parser.py
from dippy_windows.config.parser import Directive, parse_line
from dippy_windows.config.rules import Rule


def test_blank_and_comment():
    assert parse_line("") is None
    assert parse_line("   ") is None
    assert parse_line("# a comment") is None


def test_command_rule_no_message():
    r = parse_line("allow git")
    assert isinstance(r, Rule) and r.kind == "command" and r.action == "allow"
    assert r.message is None
    assert r.matches("git push")


def test_command_rule_with_message():
    r = parse_line("deny rm -rf 'Use trash instead'")
    assert r.kind == "command" and r.action == "deny"
    assert r.message == "Use trash instead"
    assert r.matches("rm -rf /")


def test_double_quoted_message():
    r = parse_line('deny dd "dangerous"')
    assert r.message == "dangerous"
    assert r.matches("dd if=/dev/zero")


def test_ask_rule():
    assert parse_line("ask npm").action == "ask"


def test_redirect_rules():
    r = parse_line("deny-redirect **/.env* 'no secrets'")
    assert r.kind == "redirect" and r.action == "deny" and r.message == "no secrets"
    assert r.matches("foo/.env.local")
    assert parse_line("allow-redirect build/*.log").action == "allow"


def test_mcp_rules():
    r = parse_line("deny-mcp mcp__github__* 'no gh writes'")
    assert r.kind == "mcp" and r.action == "deny"
    assert r.matches("mcp__github__create_issue")
    assert parse_line("allow-mcp mcp__fs__read").action == "allow"
    assert parse_line("ask-mcp mcp__x__y").action == "ask"


def test_alias_directive():
    d = parse_line("alias g git")
    assert isinstance(d, Directive) and d.name == "alias" and d.args == ("g", "git")


def test_set_default_directive():
    d = parse_line("set default deny")
    assert d.name == "set_default" and d.args == ("deny",)


def test_set_log_directive():
    d = parse_line("set log C:/logs/dippy.log")
    assert d.name == "set_log" and d.args == ("C:/logs/dippy.log",)


def test_unknown_keyword_is_none():
    assert parse_line("frobnicate foo") is None


def test_malformed_set_is_none():
    assert parse_line("set default bogus") is None
    assert parse_line("set") is None


def test_unclosed_quote_is_none():
    assert parse_line("deny rm 'use trash") is None
    assert parse_line('allow git "oops') is None


def test_quote_in_pattern_is_none():
    assert parse_line("deny ec\"ho") is None


def test_alias_preserves_value_case():
    d = parse_line("alias g Git-Thing")
    assert d.args == ("g", "Git-Thing")


def test_set_log_without_arg_is_none():
    assert parse_line("set log") is None


def test_alias_wrong_token_count_is_none():
    assert parse_line("alias g") is None
    assert parse_line("alias g git extra") is None
