"""Allow-list parser for sed scripts.

The policy engine only lets a sed script through when this parser accepts
every command in it. Anything it does not understand is rejected, so a gap
between this parser and GNU sed fails closed.
"""

ALLOWED_SIMPLE = set("pdnNqQ=hHgGxDPl")
ALLOWED_S_FLAGS = set("gpiI0123456789")


class SedParseError(ValueError):
    """Raised when a script is outside the allowed subset."""


def _read_delimited(script: str, i: int, delim: str) -> int:
    """Return the index just past the closing ``delim`` starting at ``i``."""
    n = len(script)
    while i < n:
        c = script[i]
        if c == "\\":
            if i + 1 >= n:
                break
            i += 2
            continue
        if c == "\n":
            raise SedParseError("newline inside regex")
        if c == delim:
            return i + 1
        i += 1
    raise SedParseError("unterminated delimiter")


def _skip_ws(script: str, i: int) -> int:
    while i < len(script) and script[i] in " \t":
        i += 1
    return i


def _read_address(script: str, i: int) -> int:
    n = len(script)
    if i >= n:
        return i
    c = script[i]
    if c.isdigit():
        while i < n and script[i].isdigit():
            i += 1
        if i < n and script[i] == "~":
            i += 1
            if i >= n or not script[i].isdigit():
                raise SedParseError("bad step address")
            while i < n and script[i].isdigit():
                i += 1
        return i
    if c == "$":
        return i + 1
    if c == "/":
        i = _read_delimited(script, i + 1, "/")
    elif c == "\\":
        if i + 1 >= n or script[i + 1] in "\n\\":
            raise SedParseError("bad custom delimiter")
        i = _read_delimited(script, i + 2, script[i + 1])
    else:
        return i
    while i < n and script[i] in "IM":
        i += 1
    return i


def parse(script: str) -> list[str]:
    """Parse ``script`` and return the command letters, or raise SedParseError."""
    commands: list[str] = []
    depth = 0
    i = 0
    n = len(script)
    while True:
        while i < n and script[i] in " \t\n;":
            i += 1
        if i >= n:
            break
        start = i
        i = _read_address(script, i)
        if i > start:
            i = _skip_ws(script, i)
            if i < n and script[i] == ",":
                i = _skip_ws(script, i + 1)
                if i < n and script[i] in "+~":
                    i += 1
                    if i >= n or not script[i].isdigit():
                        raise SedParseError("bad address offset")
                    while i < n and script[i].isdigit():
                        i += 1
                else:
                    before = i
                    i = _read_address(script, i)
                    if i == before:
                        raise SedParseError("missing second address")
            i = _skip_ws(script, i)
        if i < n and script[i] == "!":
            i = _skip_ws(script, i + 1)
        if i >= n:
            raise SedParseError("address without command")
        cmd = script[i]
        i += 1
        if cmd == "{":
            depth += 1
            commands.append(cmd)
            continue
        if cmd == "}":
            depth -= 1
            if depth < 0:
                raise SedParseError("unbalanced }")
            commands.append(cmd)
        elif cmd == "s":
            if i >= n or script[i] in "\n\\":
                raise SedParseError("bad s delimiter")
            delim = script[i]
            i = _read_delimited(script, i + 1, delim)
            i = _read_delimited(script, i, delim)
            while i < n and script[i] not in " \t\n;}":
                if script[i] not in ALLOWED_S_FLAGS:
                    raise SedParseError(f"s flag {script[i]!r} not allowed")
                i += 1
            commands.append(cmd)
        elif cmd == "y":
            if i >= n or script[i] in "\n\\":
                raise SedParseError("bad y delimiter")
            delim = script[i]
            i = _read_delimited(script, i + 1, delim)
            i = _read_delimited(script, i, delim)
            commands.append(cmd)
        elif cmd in "qQ":
            i = _skip_ws(script, i)
            while i < n and script[i].isdigit():
                i += 1
            commands.append(cmd)
        elif cmd in ALLOWED_SIMPLE:
            commands.append(cmd)
        else:
            raise SedParseError(f"sed command {cmd!r} not allowed")
        i = _skip_ws(script, i)
        if i < n and script[i] not in "\n;}":
            raise SedParseError(f"trailing text after {cmd!r}")
    if depth:
        raise SedParseError("unbalanced {")
    return commands
