"""Small POSIX shell lexer used by the policy engine.

It is not a shell. It splits source into words, operators, redirections and
here-document bodies so that policy checks can look at what a command would
actually receive instead of matching regexes against raw text. Anything it
cannot lex raises ``ShellLexError`` and the caller fails closed.
"""

from dataclasses import dataclass, field

OPERATORS = ("&&", "||", ";;", "|&", "|", ";", "&", "(", ")", "\n")
REDIRECTS = ("<<<", "<<-", "<<", "<>", "<&", ">&", ">>", ">|", "&>>", "&>", "<", ">")
OUTPUT_REDIRECTS = {">", ">>", ">|", "<>", "&>", "&>>"}


class ShellLexError(ValueError):
    """Raised when the source cannot be lexed safely."""


@dataclass
class Redirect:
    op: str
    target: str
    heredoc_body: str | None = None
    heredoc_quoted: bool = False


@dataclass
class Command:
    words: list[str] = field(default_factory=list)
    redirects: list[Redirect] = field(default_factory=list)


@dataclass
class Lexed:
    commands: list[Command]
    # Source with single-quoted text, quoted here-doc bodies and comments removed.
    # This is the text the shell would still expand.
    active: str


def lex(source: str) -> Lexed:
    """Lex shell source into simple commands."""
    commands: list[Command] = []
    active: list[str] = []
    cur = Command()
    word: list[str] | None = None
    pending_redirect: str | None = None
    pending_heredocs: list[Redirect] = []
    i = 0
    n = len(source)

    def finish_word() -> None:
        nonlocal word, pending_redirect
        if word is None:
            return
        text = "".join(word)
        word = None
        if pending_redirect is not None:
            redir = Redirect(op=pending_redirect, target=text)
            if pending_redirect in ("<<", "<<-"):
                redir.heredoc_quoted = heredoc_quote_seen[0]
                pending_heredocs.append(redir)
            cur.redirects.append(redir)
            pending_redirect = None
        else:
            cur.words.append(text)

    def finish_command() -> None:
        nonlocal cur
        if pending_redirect is not None:
            raise ShellLexError("redirection without target")
        if cur.words or cur.redirects:
            commands.append(cur)
        cur = Command()

    heredoc_quote_seen = [False]

    while i < n:
        c = source[i]

        if c == "\\":
            if i + 1 < n and source[i + 1] == "\n":
                i += 2
                continue
            if i + 1 >= n:
                raise ShellLexError("trailing backslash")
            word = word if word is not None else []
            word.append(source[i + 1])
            active.append(source[i : i + 2])
            i += 2
            continue

        if c == "'":
            end = source.find("'", i + 1)
            if end < 0:
                raise ShellLexError("unterminated single quote")
            word = word if word is not None else []
            word.append(source[i + 1 : end])
            if pending_redirect in ("<<", "<<-"):
                heredoc_quote_seen[0] = True
            active.append("''")
            i = end + 1
            continue

        if c == '"':
            j = i + 1
            buf: list[str] = []
            while True:
                if j >= n:
                    raise ShellLexError("unterminated double quote")
                d = source[j]
                if d == '"':
                    break
                if d == "\\" and j + 1 < n and source[j + 1] in '$`"\\\n':
                    buf.append(source[j + 1])
                    j += 2
                    continue
                buf.append(d)
                j += 1
            word = word if word is not None else []
            word.append("".join(buf))
            if pending_redirect in ("<<", "<<-"):
                heredoc_quote_seen[0] = True
            active.append(source[i : j + 1])
            i = j + 1
            continue

        if c == "#" and word is None:
            end = source.find("\n", i)
            i = n if end < 0 else end
            continue

        if c in " \t":
            finish_word()
            active.append(c)
            i += 1
            continue

        redir = next((r for r in REDIRECTS if source.startswith(r, i)), None)
        if redir is not None:
            # A word made only of digits right before a redirection is an fd number.
            if word is not None and "".join(word).isdigit() and source[i - 1].isdigit():
                word = None
            finish_word()
            if pending_redirect is not None:
                raise ShellLexError("redirection without target")
            pending_redirect = redir
            heredoc_quote_seen[0] = False
            active.append(redir)
            i += len(redir)
            continue

        op = next((o for o in OPERATORS if source.startswith(o, i)), None)
        if op is not None:
            finish_word()
            finish_command()
            active.append(op)
            i += len(op)
            if op == "\n" and pending_heredocs:
                i = _read_heredocs(source, i, pending_heredocs, active)
                pending_heredocs.clear()
            continue

        word = word if word is not None else []
        word.append(c)
        active.append(c)
        i += 1

    finish_word()
    finish_command()
    if pending_heredocs:
        raise ShellLexError("unterminated here-document")
    return Lexed(commands=commands, active="".join(active))


def _read_heredocs(source: str, i: int, pending: list[Redirect], active: list[str]) -> int:
    for redir in pending:
        strip_tabs = redir.op == "<<-"
        body: list[str] = []
        while True:
            if i >= len(source):
                raise ShellLexError("unterminated here-document")
            end = source.find("\n", i)
            line = source[i:] if end < 0 else source[i:end]
            i = len(source) if end < 0 else end + 1
            check = line.lstrip("\t") if strip_tabs else line
            if check == redir.target:
                break
            body.append(line)
        redir.heredoc_body = "\n".join(body)
        if not redir.heredoc_quoted:
            # Unquoted here-docs still expand $(...), `...` and $VAR.
            active.append(redir.heredoc_body + "\n")
    return i
