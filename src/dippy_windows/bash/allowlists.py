# Ported from ldayton/Dippy src/dippy/core/allowlists.py
BASH_SAFE: frozenset[str] = frozenset({
    # File viewing
    "cat", "head", "tail", "less", "more", "bat", "tac", "od", "hexdump", "strings",
    # Compressed file inspection
    "bzcat", "bzmore", "funzip", "lz4cat", "xzcat", "xzless", "xzmore",
    "zcat", "zless", "zmore", "zstdcat", "zstdless",
    # Archive inspection (read-only)
    "zipinfo",
    # Binary analysis
    "dwarfdump", "dyld_info", "ldd", "lsbom", "nm", "objdump", "otool",
    "pagestuff", "readelf", "size",
    # Directory listing
    "ls", "ll", "la", "tree", "exa", "eza", "dir", "vdir",
    # File / disk info
    "stat", "file", "wc", "du", "df",
    # Path utilities
    "basename", "dirname", "pathchk", "pwd", "cd", "readlink", "realpath",
    # Search
    "grep", "rg", "ripgrep", "ag", "ack", "locate", "look", "mdfind", "mdls",
    # Text processing
    "uniq", "cut", "col", "colrm", "column", "comm", "cmp", "diff", "diff3",
    "diffstat", "expand", "fmt", "fold", "jot", "join", "lam", "nl", "paste",
    "pr", "rev", "rs", "seq", "tr", "tsort", "ul", "unexpand", "unvis", "vis", "what",
    # Calculators
    "bc", "dc", "expr", "units",
    # Structured data
    "jq", "xq",
    # Encoding / checksums
    "base64", "md5sum", "sha1sum", "sha256sum", "sha512sum", "b2sum",
    "cksum", "md5", "shasum", "sum",
    # User / system info
    "whoami", "hostname", "hostinfo", "uname", "sw_vers", "id", "finger",
    "groups", "last", "locale", "logname", "users", "w", "who", "klist",
    # Date / time
    "date", "cal", "ncal", "uptime",
    # System config (read-only)
    "getconf", "machine", "pagesize", "uuidgen",
    # Process monitoring
    "atos", "btop", "footprint", "free", "fs_usage", "fuser", "heap", "htop",
    "ioreg", "iostat", "ipcs", "leaks", "lskq", "lsmp", "lsof", "lsvfs",
    "lpstat", "nettop", "pgrep", "powermetrics", "ps", "system_profiler",
    "top", "vm_stat", "vmmap", "vmstat",
    # Environment
    "printenv", "echo", "printf",
    # Network diagnostics (read-only)
    "ping", "host", "dig", "nslookup", "traceroute", "mtr", "netstat", "ss",
    "arp", "route", "whois",
    # Command lookup
    "which", "whereis", "type", "command", "hash", "apropos", "man",
    "help", "info", "tldr", "whatis",
    # Code quality
    "cloc", "flake8", "mypy",
    # Media / image info
    "afinfo", "afplay", "ffprobe", "heif-info", "identify", "opj_dump",
    "rdjpgcom", "sndfile-info", "tiffdump", "tiffinfo", "webpinfo",
    # Shell utilities
    "true", "false", "getopt", "getopts", "shopt", "sleep", "read",
    "test", "yes",
    # Terminal
    "banner", "clear", "pbpaste", "reset", "tabs", "tput", "tty",
    # Version control (read-only)
    "git",
    # Package managers / build tools (read-only ops handled by analyzer)
    "pip", "npm", "node", "python", "python3", "uv",
})

# "command" kept in BASH_SAFE only; wrappers must not overlap BASH_SAFE
BASH_WRAPPERS: frozenset[str] = frozenset({
    "time", "timeout", "nice", "nohup", "strace", "ltrace", "builtin",
})


def is_safe_bash_command(name: str) -> bool:
    return name.lower() in BASH_SAFE


def is_wrapper(name: str) -> bool:
    return name.lower() in BASH_WRAPPERS
