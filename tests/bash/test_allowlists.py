from dippy_windows.bash.allowlists import BASH_SAFE, BASH_WRAPPERS, is_safe_bash_command, is_wrapper


def test_all_lowercase():
    assert all(c == c.lower() for c in BASH_SAFE)
    assert all(c == c.lower() for c in BASH_WRAPPERS)


def test_well_known_safe():
    for cmd in ("ls", "cat", "grep", "git", "echo", "pwd", "ps", "diff", "jq"):
        assert is_safe_bash_command(cmd), f"{cmd} should be safe"


def test_dangerous_not_safe():
    for cmd in ("rm", "dd", "chmod", "chown", "kill", "sudo", "curl", "wget"):
        assert not is_safe_bash_command(cmd), f"{cmd} should not be safe"


def test_wrappers():
    for cmd in ("time", "timeout", "nice", "nohup"):
        assert is_wrapper(cmd)


def test_safe_not_wrapper():
    assert not is_wrapper("ls")


def test_wrapper_not_safe():
    # wrappers are not in BASH_SAFE — they need special handling
    for cmd in BASH_WRAPPERS:
        assert cmd not in BASH_SAFE
