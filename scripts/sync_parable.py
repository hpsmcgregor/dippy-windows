#!/usr/bin/env python3
"""Check whether vendored parable.py has drifted from upstream Dippy and update if so."""
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

UPSTREAM_URL = "https://raw.githubusercontent.com/ldayton/Dippy/main/src/dippy/vendor/parable.py"
COMMITS_URL = (
    "https://api.github.com/repos/ldayton/Dippy/commits"
    "?path=src/dippy/vendor/parable.py&per_page=1"
)
VENDOR_PATH = Path(__file__).parent.parent / "src" / "dippy_windows" / "vendor" / "parable.py"
HEADER_LINES = 5  # 4 comment lines + 1 blank separator line


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fetch(url: str, headers: dict[str, str] | None = None) -> bytes:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "dippy-windows"})
    with urllib.request.urlopen(req) as r:
        return r.read()


def _upstream_commit_sha() -> str:
    data = json.loads(_fetch(COMMITS_URL, {"Accept": "application/vnd.github.v3+json", "User-Agent": "dippy-windows"}))
    return data[0]["sha"][:7]


def _current_body() -> bytes:
    """Return vendored file with header lines stripped, CRLF normalized to LF."""
    lines = VENDOR_PATH.read_bytes().splitlines(keepends=True)
    body = b"".join(lines[HEADER_LINES:])
    return body.replace(b"\r\n", b"\n")


def _write(upstream_content: bytes, sha: str) -> None:
    header = (
        f"# vendored from https://github.com/ldayton/Dippy\n"
        f"# source: src/dippy/vendor/parable.py\n"
        f"# synced-from-commit: {sha}\n"
        f"# run: python scripts/sync_parable.py  to check for updates\n\n"
    )
    VENDOR_PATH.write_bytes(header.encode() + upstream_content)


def main(ci: bool = False) -> int:
    upstream = _fetch(UPSTREAM_URL)

    if _sha256(_current_body()) == _sha256(upstream):
        print("parable.py is up to date.")
        return 0

    print("parable.py has changed upstream.")

    if ci:
        sha = _upstream_commit_sha()
        _write(upstream, sha)
        print(f"Updated to {sha}.")
        return 1  # signals "changed" to the GitHub Action step

    answer = input("Update vendored parable.py? [y/N] ").strip().lower()
    if answer == "y":
        sha = _upstream_commit_sha()
        _write(upstream, sha)
        print(f"Updated to {sha}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(ci="--ci" in sys.argv))
