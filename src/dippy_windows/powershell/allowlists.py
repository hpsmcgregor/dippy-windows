PS_SAFE_CMDLETS: frozenset[str] = frozenset({
    "get-childitem", "get-content", "get-item", "get-itemproperty",
    "get-process", "get-service", "get-command", "get-help",
    "get-module", "get-psdrive", "get-location", "get-date",
    "get-host", "get-history", "get-member", "get-variable",
    "get-alias", "get-eventlog", "get-winevent", "get-acl",
    "get-culture", "get-uiculture", "get-job", "get-package",
    "get-netadapter", "get-netipaddress",
    "select-object", "select-string", "where-object",
    "sort-object", "group-object", "measure-object",
    "compare-object", "tee-object", "foreach-object",
    "format-list", "format-table", "format-wide", "format-custom",
    "out-string", "out-default", "out-null",
    "write-output", "write-host", "write-verbose",
    "write-debug", "write-information",
    "resolve-path", "split-path", "join-path", "convert-path",
    "test-path", "push-location", "pop-location", "set-location",
    "convertto-json", "convertfrom-json", "convertto-csv",
    "convertfrom-csv", "convertto-html", "convertfrom-string", "convertto-xml",
    "import-csv", "import-clixml",
    "measure-command", "start-sleep", "clear-host",
    "get-random", "new-guid", "new-object", "invoke-history",
})

PS_ASK_CMDLETS: frozenset[str] = frozenset({
    "new-item", "set-item", "set-itemproperty",
    "set-content", "add-content", "out-file",
    "export-csv", "export-clixml",
    "copy-item", "move-item", "rename-item",
    "compress-archive", "expand-archive",
    "invoke-webrequest", "invoke-restmethod",
    "install-package", "install-module", "update-module",
    "start-service", "restart-service", "suspend-service",
    "start-process",
    "set-variable", "remove-variable",
    "set-clipboard",
})

PS_DANGEROUS_CMDLETS: frozenset[str] = frozenset({
    "remove-item", "remove-itemproperty", "remove-psdrive",
    "remove-module", "remove-job",
    "stop-process", "stop-service", "stop-computer",
    "clear-content", "clear-item", "clear-itemproperty",
    "clear-history", "clear-recyclebin",
    "format-volume",
    "invoke-expression",
    "invoke-command",
    "restart-computer", "reset-computer",
    "set-executionpolicy",
    "register-scheduledtask", "unregister-scheduledtask",
    "disable-netadapter", "remove-netipaddress",
})

PS_ALIASES: dict[str, str] = {
    "ls": "get-childitem", "dir": "get-childitem", "gci": "get-childitem",
    "cat": "get-content", "gc": "get-content", "type": "get-content",
    "pwd": "get-location", "gl": "get-location",
    "cd": "set-location", "sl": "set-location", "chdir": "set-location",
    "rm": "remove-item", "del": "remove-item", "erase": "remove-item",
    "ri": "remove-item", "rd": "remove-item",
    "cp": "copy-item", "copy": "copy-item", "ci": "copy-item",
    "mv": "move-item", "move": "move-item", "mi": "move-item",
    "ni": "new-item", "mkdir": "new-item", "md": "new-item",
    "ps": "get-process", "gps": "get-process",
    "kill": "stop-process", "spps": "stop-process",
    "echo": "write-output", "man": "get-help", "help": "get-help",
    "measure": "measure-object", "select": "select-object",
    "sort": "sort-object", "where": "where-object", "?": "where-object",
    "foreach": "foreach-object", "%": "foreach-object",
    "iex": "invoke-expression", "ii": "invoke-item", "icm": "invoke-command",
    "iwr": "invoke-webrequest", "wget": "invoke-webrequest", "curl": "invoke-webrequest",
    "irm": "invoke-restmethod",
    "cls": "clear-host", "clear": "clear-host",
    "gi": "get-item", "si": "set-item", "sc": "set-content",
    "sv": "set-variable", "set": "set-variable",
    "gv": "get-variable", "gm": "get-member", "gal": "get-alias",
    "fl": "format-list", "ft": "format-table", "fw": "format-wide", "fc": "format-custom",
    "saps": "start-process", "start": "start-process",
    "gcm": "get-command", "which": "get-command",
    "of": "out-file",
}


def resolve_alias(name: str) -> str:
    """Return canonical lowercase cmdlet name, or *name* lowercased if not an alias."""
    lower = name.lower()
    return PS_ALIASES.get(lower, lower)
