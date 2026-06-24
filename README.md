# dippy-windows

A [Claude Code](https://claude.ai/code) `PreToolUse` hook that automatically approves safe shell commands and blocks dangerous ones on Windows, across all three shell environments Claude uses:

- **Bash (Git Bash)** — full AST analysis via the vendored [Parable](https://github.com/ldayton/Dippy) parser
- **PowerShell** — verb-noun cmdlet allowlist + recursive tokenizer (handles pipelines, chains, `$(...)` subexpressions)
- **CMD** — detects `cmd /c "..."` calls nested inside Bash or PowerShell invocations and analyses the payload

## How it works

When Claude Code runs a Bash or PowerShell command, the hook reads the JSON from Claude's `PreToolUse` stdin, routes it to the appropriate analyser, and returns a permission decision:

| Decision | Meaning |
|----------|---------|
| `allow`  | Command runs silently, no prompt |
| `ask`    | Claude Code prompts you to confirm |
| `deny`   | Command is blocked outright |

Deny always wins when combining decisions across a pipeline or chain (`rm foo \| tee bar` is denied even though `tee` is safe).

## Installation

**Requires Python 3.14+.**

```powershell
pip install git+https://github.com/hpsmcgregor/dippy-windows.git
```

Or clone and install in editable mode for development:

```powershell
git clone https://github.com/hpsmcgregor/dippy-windows.git C:\src\dippy-windows
cd C:\src\dippy-windows
pip install -e ".[dev]"
```

## Configuration

Add the following to `%USERPROFILE%\.claude\settings.json` (merge with any existing content):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "dippy-windows" }]
      },
      {
        "matcher": "PowerShell",
        "hooks": [{ "type": "command", "command": "dippy-windows" }]
      }
    ]
  }
}
```

Then open a new Claude Code session for the hook to take effect.

## What's allowed / blocked

### Bash (via Parable AST)

Safe commands (auto-allowed): `ls`, `cat`, `grep`, `git`, `echo`, `diff`, `jq`, `ps`, `ping`, `find`, `python`, `pip`, `npm`, `node`, and ~100 others.

Blocked: `rm`, `dd`, `chmod`, `chown`, `kill`, `sudo`, `shutdown`, `mkfs`, and related destructive commands.

Output redirects (`>`, `>>`) return `ask`. Unknown commands return `ask`. Commands with `--version` or `--help` are always allowed.

### PowerShell (via cmdlet allowlist)

Safe: all `Get-*` read-only cmdlets, `Select-Object`, `Where-Object`, `Format-*`, `Test-Path`, `ConvertTo-Json`, and similar read/display cmdlets. Common aliases (`ls`, `cat`, `echo`, `dir`, `pwd`) are resolved before classification.

Ask: `New-Item`, `Set-Content`, `Copy-Item`, `Move-Item`, `Invoke-WebRequest`, `Install-Module`, `Start-Process`, and similar write/network cmdlets.

Blocked: `Remove-Item`, `Stop-Process`, `Invoke-Expression`, `Invoke-Command`, `Clear-Content`, `Format-Volume`, `Set-ExecutionPolicy`, and other destructive cmdlets.

### CMD (nested detection)

When Claude calls `cmd /c "..."` inside a Bash or PowerShell command, the payload is extracted and analysed as a CMD command. Safe: `dir`, `echo`, `where`, `type`. Blocked: `del`, `rd`, `format`, `shutdown`.

## User Configuration

dippy-windows works with zero config, but you can override its built-in policy and
attach custom messages that steer Claude. Rules are read from (lowest to highest
precedence): `~/.dippy-windows/config`, a `.dippy-windows` file in your project (found
by walking up from the working directory), and `$DIPPY_WINDOWS_CONFIG`. Rules are
evaluated in order and the **last matching rule wins** — so a user rule can override a
built-in decision, including a built-in deny.

```text
allow git                          # allow git and all subcommands
deny rm -rf 'Use trash instead'    # block with a message shown to Claude
ask  npm install                   # force a confirmation prompt
deny-redirect **/.env* 'No secrets' # block writes (> / >>) to matching paths
deny-mcp mcp__github__*            # block matching MCP tools
alias g git                        # matching alias
set default ask                    # decision for unknown commands
set log C:/path/dippy.log          # audit log
```

Patterns are prefix matches by default (`git` matches `git push`); append `|` for an
exact match (`git status|`). Wildcards `*`, `?`, `[abc]` are supported, plus `**` for
recursive path matching in redirect rules. A full example is in
[`docs/config-example.dippy-windows`](docs/config-example.dippy-windows).

To gate MCP tools, add an `mcp__.*` matcher to the `PreToolUse` hooks in your
`settings.json` (see install instructions); without a matching `*-mcp` rule, MCP tools
pass through untouched.

## Keeping Parable in sync

The bash parser ([Parable](https://github.com/ldayton/Dippy/blob/main/src/dippy/vendor/parable.py)) is vendored in `src/dippy_windows/vendor/parable.py`. A GitHub Action runs every Monday and opens a pull request automatically if the upstream file has changed:

```
.github/workflows/sync-parable.yml
```

To check manually:

```powershell
python scripts/sync_parable.py        # interactive
python scripts/sync_parable.py --ci   # CI mode: updates file, exits 1 if changed
```

## Development

```powershell
pytest tests/        # run all 99 tests
pytest tests/bash/   # bash analyser only
pytest tests/powershell/
pytest tests/cmd/
```

## Acknowledgements

**[Dippy](https://github.com/ldayton/Dippy)** by [ldayton](https://github.com/ldayton) — the original Mac/Linux Claude Code hook that inspired this project. The bash allowlist (`BASH_SAFE`) is ported from Dippy's `SIMPLE_SAFE`, and the Parable bash parser is vendored from Dippy's vendor directory.

**[Parable](https://github.com/ldayton/Dippy/blob/main/src/dippy/vendor/parable.py)** — a lightweight bash AST parser bundled with Dippy, used here for full syntactic analysis of bash commands including pipelines, redirects, and command substitutions.

## Licence

MIT
