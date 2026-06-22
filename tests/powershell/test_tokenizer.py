from dippy_windows.powershell.tokenizer import (
    ps_extract_cmdlet, ps_split_chain, ps_split_pipeline,
)


class TestSplitPipeline:
    def test_single(self):
        assert ps_split_pipeline("Get-ChildItem") == ["Get-ChildItem"]

    def test_simple(self):
        assert len(ps_split_pipeline("Get-ChildItem | Select-Object Name")) == 2

    def test_no_split_in_double_string(self):
        assert ps_split_pipeline('Write-Output "a | b"') == ['Write-Output "a | b"']

    def test_no_split_in_single_string(self):
        assert ps_split_pipeline("Write-Output 'a | b'") == ["Write-Output 'a | b'"]

    def test_no_split_in_subexpr(self):
        assert len(ps_split_pipeline("Write-Output $(Get-Date | Select Year)")) == 1

    def test_three_stages(self):
        assert len(ps_split_pipeline("a | b | c")) == 3


class TestSplitChain:
    def test_semicolon(self):
        assert len(ps_split_chain("cd C:\\src; ls")) == 2

    def test_and_and(self):
        assert len(ps_split_chain("cd C:\\src && ls")) == 2

    def test_or_or(self):
        assert len(ps_split_chain("Test-Path x || Write-Host missing")) == 2

    def test_no_split(self):
        assert ps_split_chain("Get-ChildItem -Path C:\\src") == ["Get-ChildItem -Path C:\\src"]


class TestExtractCmdlet:
    def test_simple(self):
        assert ps_extract_cmdlet("Get-ChildItem C:\\src") == "get-childitem"

    def test_assignment(self):
        assert ps_extract_cmdlet("$files = Get-ChildItem") == "get-childitem"

    def test_call_operator(self):
        assert ps_extract_cmdlet("& 'C:\\tools\\foo.exe' arg") == "foo.exe"

    def test_external(self):
        assert ps_extract_cmdlet("git status") == "git"

    def test_empty(self):
        assert ps_extract_cmdlet("   ") == ""
