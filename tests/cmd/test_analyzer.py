from dippy_windows.cmd.analyzer import analyze_cmd, extract_cmd_payload


class TestExtractPayload:
    def test_cmd_c_quoted(self):
        assert extract_cmd_payload('cmd /c "dir C:\\src"') == "dir C:\\src"

    def test_cmd_c_unquoted(self):
        assert extract_cmd_payload("cmd /c dir") == "dir"

    def test_cmd_exe(self):
        assert extract_cmd_payload('cmd.exe /c "echo hello"') == "echo hello"

    def test_uppercase_c(self):
        assert extract_cmd_payload('cmd /C "dir"') == "dir"

    def test_not_cmd(self):
        assert extract_cmd_payload("git status") is None

    def test_cmd_without_c(self):
        assert extract_cmd_payload("cmd /k dir") is None


class TestAnalyzeCmd:
    def test_safe_dir(self):
        assert analyze_cmd("dir").action == "allow"

    def test_safe_echo(self):
        assert analyze_cmd("echo hello").action == "allow"

    def test_safe_where(self):
        assert analyze_cmd("where python").action == "allow"

    def test_safe_type(self):
        assert analyze_cmd("type file.txt").action == "allow"

    def test_dangerous_del(self):
        assert analyze_cmd("del /f /s /q C:\\important").action == "deny"

    def test_dangerous_rd(self):
        assert analyze_cmd("rd /s /q C:\\important").action == "deny"

    def test_dangerous_format(self):
        assert analyze_cmd("format C:").action == "deny"

    def test_dangerous_shutdown(self):
        assert analyze_cmd("shutdown /s /t 0").action == "deny"

    def test_unknown_asks(self):
        assert analyze_cmd("somecustomtool --run").action == "ask"

    def test_redirect_asks(self):
        assert analyze_cmd("dir > output.txt").action == "ask"
