from dippy_windows.bash.analyzer import analyze_bash


class TestAllowedCommands:
    def test_simple_safe(self):
        assert analyze_bash("ls -la").action == "allow"

    def test_git_status(self):
        assert analyze_bash("git status").action == "allow"

    def test_echo(self):
        assert analyze_bash("echo hello").action == "allow"

    def test_safe_pipeline(self):
        assert analyze_bash("ls | grep foo").action == "allow"

    def test_version_flag(self):
        assert analyze_bash("unknown-tool --version").action == "allow"

    def test_help_flag(self):
        assert analyze_bash("unknown-tool --help").action == "allow"

    def test_wrapper_around_safe(self):
        assert analyze_bash("time ls").action == "allow"

    def test_empty(self):
        assert analyze_bash("   ").action == "ask"


class TestAskCommands:
    def test_unknown_command(self):
        assert analyze_bash("frobnicator --config foo").action == "ask"

    def test_redirect_to_file(self):
        assert analyze_bash("ls > output.txt").action == "ask"

    def test_append_redirect(self):
        assert analyze_bash("date >> log.txt").action == "ask"

    def test_safe_then_unknown_in_pipeline(self):
        assert analyze_bash("ls | frobnicator").action == "ask"


class TestDeniedCommands:
    def test_rm(self):
        assert analyze_bash("rm -rf /tmp/x").action == "deny"

    def test_dd(self):
        assert analyze_bash("dd if=/dev/zero of=/dev/sda").action == "deny"

    def test_subshell_deny_propagates(self):
        assert analyze_bash("echo $(rm -rf .)").action == "deny"

    def test_backtick_deny_propagates(self):
        assert analyze_bash("echo `rm .`").action == "deny"
