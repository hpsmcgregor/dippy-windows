from dippy_windows.config.loader import build_policy, discover_paths, load_policy
from dippy_windows.config.policy import Policy


def test_build_empty():
    p = build_policy([])
    assert isinstance(p, Policy) and p.command_rules == ()


def test_build_collects_rules_in_order():
    p = build_policy(["allow git\ndeny rm 'no'"])
    assert len(p.command_rules) == 2
    assert p.command_rules[0].action == "allow"
    assert p.command_rules[1].action == "deny"


def test_later_text_appends_after_earlier():
    # global then project: project rules come later -> win under last-match
    p = build_policy(["deny git", "allow git"])
    assert p.command_rules[0].action == "deny"
    assert p.command_rules[1].action == "allow"


def test_redirect_and_mcp_separated():
    p = build_policy(["deny-redirect **/.env*\ndeny-mcp mcp__x__*"])
    assert len(p.redirect_rules) == 1
    assert len(p.mcp_rules) == 1
    assert p.command_rules == ()


def test_directives_applied():
    p = build_policy(["set default deny\nset log C:/l.log\nalias g git"])
    assert p.default_action == "deny"
    assert p.log_path == "C:/l.log"
    assert ("g", "git") in p.aliases


def test_last_set_default_wins():
    p = build_policy(["set default deny", "set default allow"])
    assert p.default_action == "allow"


def test_malformed_lines_skipped():
    p = build_policy(["allow git\nfrobnicate x\nset default bogus\ndeny rm"])
    assert len(p.command_rules) == 2  # only allow git, deny rm


def test_discover_paths_env_last(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".dippy-windows").mkdir(parents=True)
    (home / ".dippy-windows" / "config").write_text("allow ls\n", encoding="utf-8")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".dippy-windows").write_text("allow cat\n", encoding="utf-8")
    env_file = tmp_path / "env.cfg"
    env_file.write_text("allow echo\n", encoding="utf-8")

    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    monkeypatch.chdir(proj)
    monkeypatch.setenv("DIPPY_WINDOWS_CONFIG", str(env_file))

    paths = discover_paths()
    assert paths[0] == home / ".dippy-windows" / "config"
    assert paths[1] == proj / ".dippy-windows"
    assert paths[-1] == env_file


def test_load_policy_never_raises(monkeypatch, tmp_path):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "nonexistent")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DIPPY_WINDOWS_CONFIG", raising=False)
    assert isinstance(load_policy(), Policy)
