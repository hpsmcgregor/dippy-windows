from dippy_windows.powershell.analyzer import analyze_ps, is_powershell_command


class TestIsPs:
    def test_verb_noun(self):
        assert is_powershell_command("Get-ChildItem C:\\src")

    def test_dollar_var(self):
        assert is_powershell_command("$x = Get-ChildItem")

    def test_git_not_ps(self):
        assert not is_powershell_command("git status")

    def test_unix_ls_not_ps(self):
        assert not is_powershell_command("ls -la /tmp")


class TestAnalyzePs:
    def test_safe(self):             assert analyze_ps("Get-ChildItem C:\\src").action == "allow"
    def test_alias_ls(self):         assert analyze_ps("ls C:\\src").action == "allow"
    def test_pipeline_safe(self):    assert analyze_ps("Get-ChildItem | Select-Object Name").action == "allow"
    def test_version(self):          assert analyze_ps("thing --version").action == "allow"
    def test_empty(self):            assert analyze_ps("").action == "ask"
    def test_new_item(self):         assert analyze_ps("New-Item foo.txt").action == "ask"
    def test_redirect(self):         assert analyze_ps("Get-ChildItem > out.txt").action == "ask"
    def test_out_file(self):         assert analyze_ps("Get-ChildItem | Out-File r.txt").action == "ask"
    def test_unknown(self):          assert analyze_ps("Some-Unknown -Arg").action == "ask"
    def test_remove(self):           assert analyze_ps("Remove-Item -Force .").action == "deny"
    def test_alias_rm(self):         assert analyze_ps("rm -Recurse .").action == "deny"
    def test_iex(self):              assert analyze_ps("iex 'rm .'").action == "deny"
    def test_deny_in_pipeline(self): assert analyze_ps("Get-ChildItem | Remove-Item").action == "deny"
    def test_subexpr_deny(self):     assert analyze_ps("Write-Host $(Remove-Item .)").action == "deny"
    def test_chained_deny(self):     assert analyze_ps("Get-Date; Remove-Item ./tmp").action == "deny"


class TestHelpFlagDoesNotBypassDeny:
    """A help/version flag must not allow a dangerous cmdlet through."""

    def test_dangerous_with_v(self):    assert analyze_ps("Remove-Item -v .").action == "deny"
    def test_dangerous_with_h(self):    assert analyze_ps("Stop-Process -h").action == "deny"
    def test_dangerous_with_help(self): assert analyze_ps("Remove-Item --help .").action == "deny"
    def test_dangerous_with_qmark(self): assert analyze_ps("Remove-Item -?").action == "deny"
