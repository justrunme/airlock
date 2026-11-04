"""Static allow-list checks for shell jobs.

Commands are lexed (see shell_lexer), then every simple command must name an
allow-listed binary, use only options this module knows, and pass only file
arguments that stay inside /work. sed scripts must parse in the subset
accepted by sed_parser; awk and jq programs are checked for file, process
and environment access. Anything not understood is denied.
"""

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from airlock import sed_parser, shell_lexer

FORBIDDEN_BINARIES = {
    "docker",
    "nsenter",
    "mount",
    "umount",
    "unshare",
    "chroot",
    "sudo",
    "su",
    "nc",
    "netcat",
    "ncat",
    "curl",
    "wget",
    "ssh",
    "scp",
    "rsync",
    "find",
    "xargs",
    "env",
    "nohup",
    "timeout",
    "chmod",
    "chown",
    "rm",
    "dd",
    "kill",
    "ln",
    "cp",
    "mv",
    "socat",
    "telnet",
    "ftp",
    "tar",
    "unzip",
}
SHELL_INTERPRETERS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "mksh", "busybox", "toybox"}
OTHER_INTERPRETERS = {"perl", "ruby", "lua", "luajit", "php", "node", "nodejs", "tclsh", "expect"}
EXEC_BUILTINS = {".", "source", "exec", "eval", "command", "builtin", "trap", "alias", "enable"}
ALLOWED_RESERVED = {"{", "}", "!", "if", "then", "else", "elif", "fi"}
DENIED_RESERVED = {"while", "until", "for", "case", "esac", "select", "function", "do", "done"}
AWK_BINARIES = {"awk", "gawk", "mawk", "nawk"}
GREP_BINARIES = {"grep", "egrep", "fgrep", "zgrep"}
SAFE_REDIRECT_TARGETS = {"/dev/null", "/dev/stdout", "/dev/stderr"}
READABLE_DEVICES = {"/dev/null", "/dev/stdin", "/dev/zero", "/dev/urandom", "/dev/random"}
DANGEROUS_DEVICES = {"/dev/zero", "/dev/urandom", "/dev/random"}
SCRIPT_SUFFIXES = {".sh", ".bash", ".py", ".pl", ".rb", ".lua", ".so", ".exe", ".bin", ".elf"}

DANGEROUS_PATTERNS = [
    r"\$\(",  # Command substitution
    r"`",  # Backticks
    r"\|(?:sh|bash)",  # Piping to shell
    r"(?:eval|source)\s",  # eval or source
    r"base64\s+-d.*(?:\||;|&&)",  # base64 decode piped
    r"\$\{[^}]*\}",  # Variable expansion
    r"\$[A-Za-z_]",  # Variable in command position
    r"\$IFS",  # IFS variable tricks
    r"(?:^|[;&|(\n{]\s*)[A-Za-z_][A-Za-z0-9_]*=",  # Assignment in command position
    r"\$'",  # ANSI-C quoting hides command names
    r"--no-preserve-root",  # Dangerous rm flag
]
FORK_BOMB_PATTERNS = [
    r":\(\)\s*\{[^}]*:[^}]*\}",
    r"while\s+true.*fork",
    r"while\s+:.*fork",
    r"bomb.*\|.*bomb",
]


@dataclass
class Spec:
    """Options a binary accepts. Letters/names not listed are denied."""

    flags: str = ""
    values: str = ""  # short options that take a value we do not interpret
    files: str = ""  # short options that take an input path
    outputs: str = ""  # short options that take an output path
    programs: str = ""  # short options that carry the program/pattern
    long_flags: set[str] = field(default_factory=set)
    long_values: set[str] = field(default_factory=set)
    long_files: set[str] = field(default_factory=set)
    long_outputs: set[str] = field(default_factory=set)
    long_programs: set[str] = field(default_factory=set)
    digits: bool = False  # -5 style numeric options
    program_first: bool = False  # first positional is a program/pattern
    positional_files: bool = True


GREP = Spec(
    flags="EFGPivwxyclLoqsbHhnTZzrRUaI",
    values="mABCdD",
    files="f",
    programs="e",
    long_flags={
        "--count",
        "--ignore-case",
        "--invert-match",
        "--word-regexp",
        "--line-regexp",
        "--only-matching",
        "--quiet",
        "--silent",
        "--no-filename",
        "--with-filename",
        "--line-number",
        "--recursive",
        "--extended-regexp",
        "--fixed-strings",
        "--perl-regexp",
        "--files-with-matches",
        "--files-without-match",
        "--null",
        "--text",
        "--no-messages",
    },
    long_values={
        "--max-count",
        "--context",
        "--after-context",
        "--before-context",
        "--label",
        "--color",
        "--colour",
        "--include",
        "--exclude",
        "--exclude-dir",
        "--binary-files",
    },
    long_files={"--file", "--exclude-from"},
    long_programs={"--regexp"},
    digits=True,
    program_first=True,
)
GZIP = Spec(
    flags="cdfklnNqtvL123456789",
    long_flags={"--stdout", "--decompress", "--keep", "--test", "--list", "--quiet", "--verbose"},
)
SPECS: dict[str, Spec] = {
    "cat": Spec(
        flags="AbeEnstTuv",
        long_flags={"--number", "--show-all", "--squeeze-blank", "--number-nonblank"},
    ),
    **dict.fromkeys(GREP_BINARIES, GREP),
    **dict.fromkeys(AWK_BINARIES, Spec(values="Fv", program_first=True)),
    "sed": Spec(
        flags="nErzus",
        values="l",
        programs="e",
        long_flags={
            "--quiet",
            "--silent",
            "--regexp-extended",
            "--null-data",
            "--separate",
            "--unbuffered",
            "--posix",
            "--sandbox",
            "--debug",
        },
        long_values={"--line-length"},
        long_programs={"--expression"},
        program_first=True,
    ),
    "sort": Spec(
        flags="bdfgiMhnRrVcCumsz",
        values="kSt",
        files="T",
        outputs="o",
        long_flags={
            "--numeric-sort",
            "--reverse",
            "--unique",
            "--human-numeric-sort",
            "--general-numeric-sort",
            "--ignore-case",
            "--stable",
            "--version-sort",
            "--month-sort",
            "--check",
            "--merge",
            "--zero-terminated",
            "--ignore-leading-blanks",
            "--dictionary-order",
        },
        long_values={"--key", "--field-separator", "--buffer-size", "--parallel"},
        long_files={"--temporary-directory"},
        long_outputs={"--output"},
    ),
    "uniq": Spec(
        flags="cdDiuz",
        values="fsw",
        long_flags={"--count", "--repeated", "--unique", "--ignore-case"},
        long_values={"--skip-fields", "--skip-chars", "--check-chars"},
    ),
    "wc": Spec(
        flags="lwcmL",
        long_flags={"--lines", "--words", "--bytes", "--chars", "--max-line-length"},
    ),
    "head": Spec(flags="qvz", values="nc", long_values={"--lines", "--bytes"}, digits=True),
    "tail": Spec(flags="qvzr", values="nc", long_values={"--lines", "--bytes"}, digits=True),
    "cut": Spec(
        flags="sz",
        values="bcdf",
        long_flags={"--only-delimited", "--complement"},
        long_values={
            "--delimiter",
            "--fields",
            "--characters",
            "--bytes",
            "--output-delimiter",
        },
    ),
    "ls": Spec(
        flags="1aAlhRrtSdFiknpsuUcG",
        long_flags={"--all", "--human-readable", "--almost-all", "--recursive", "--reverse"},
        long_values={"--color", "--sort", "--time-style"},
    ),
    "zcat": GZIP,
    "gzip": GZIP,
    "gunzip": GZIP,
    "jq": Spec(
        flags="rcnseSjaCMR",
        long_flags={
            "--raw-output",
            "--compact-output",
            "--null-input",
            "--slurp",
            "--exit-status",
            "--sort-keys",
            "--join-output",
            "--ascii-output",
            "--tab",
            "--raw-input",
            "--seq",
            "--stream",
        },
        long_values={"--indent"},
        program_first=True,
    ),
    "tee": Spec(flags="ai", long_flags={"--append", "--ignore-interrupts"}),
    "date": Spec(
        flags="uRI",
        values="d",
        files="fr",
        long_flags={"--utc", "--universal", "--rfc-email"},
        long_values={"--date", "--iso-8601", "--rfc-3339"},
        long_files={"--file", "--reference"},
        positional_files=False,
    ),
}
NO_FILE_BINARIES = {"echo", "printf", "tr", "true", "false", ":", "test", "["}
SAFE_BINARIES = set(SPECS) | NO_FILE_BINARIES


class ShellChecker:
    def __init__(self, code: str):
        self.code = code
        self.result: dict[str, Any] = {
            "forbidden": [],
            "suspicious": [],
            "safe": False,
            "rules": [],
            "warnings": [],
        }

    def flag(self, message: str, rule: str, level: str = "forbidden") -> None:
        self.result[level].append(message)
        if rule not in self.result["rules"]:
            self.result["rules"].append(rule)

    # ------------------------------------------------------------------ paths

    @staticmethod
    def under_out(path: str) -> bool:
        p = PurePosixPath(path)
        return (
            path.startswith("/work/out/")
            and ".." not in p.parts
            and p != PurePosixPath("/work/out")
        )

    @staticmethod
    def path_ok(path: str) -> bool:
        if path == "-":
            return True
        if not path or path.startswith("~"):
            return False
        p = PurePosixPath(path)
        if ".." in p.parts or any(re.match(r"\.[*?\[]", part) for part in p.parts):
            return False
        if not path.startswith("/"):
            return True  # relative to the job's cwd, /work
        if path in READABLE_DEVICES:
            return True
        return any(
            p == PurePosixPath(r) or p.is_relative_to(r) for r in ("/work/input", "/work/out")
        )

    def check_output(self, path: str, rule: str, what: str) -> None:
        if not self.under_out(path):
            self.flag(f"{what} outside /work/out: {path}", rule)
        elif PurePosixPath(path).suffix.lower() in SCRIPT_SUFFIXES:
            self.flag(f"{what} writes a script file {path}", "R-SHELL-SCRIPT-WRITE")

    def check_input(self, path: str) -> None:
        if not self.path_ok(path):
            self.flag(f"file argument outside /work: {path}", "R-SHELL-PATH")

    # ---------------------------------------------------------------- options

    def scan(self, binary: str, args: list[str], spec: Spec) -> dict[str, list[str]] | None:
        out: dict[str, list[str]] = {
            "positional": [],
            "files": [],
            "outputs": [],
            "programs": [],
            "flags": [],
        }
        i = 0
        end = False
        while i < len(args):
            a = args[i]
            i += 1
            if end or a == "-" or not a.startswith("-"):
                out["positional"].append(a)
                continue
            if a == "--":
                end = True
                continue
            if a.startswith("--"):
                name, eq, val = a.partition("=")
                kinds = {
                    "files": spec.long_files,
                    "outputs": spec.long_outputs,
                    "programs": spec.long_programs,
                    "values": spec.long_values,
                }
                kind = next((k for k, names in kinds.items() if name in names), None)
                if kind is None:
                    if name in spec.long_flags and not eq:
                        out["flags"].append(name)
                        continue
                    self.flag(f"{binary} option {name} is not allowed", "R-SHELL-OPTION")
                    return None
                if not eq:
                    if i >= len(args):
                        self.flag(f"{binary} {name} without value", "R-SHELL-OPTION")
                        return None
                    val = args[i]
                    i += 1
                if kind != "values":
                    out[kind].append(val)
                continue
            if spec.digits and a[1:].isdigit():
                continue
            j = 1
            while j < len(a):
                ch = a[j]
                kind = None
                for k, letters in (
                    ("files", spec.files),
                    ("outputs", spec.outputs),
                    ("programs", spec.programs),
                    ("values", spec.values),
                ):
                    if ch in letters:
                        kind = k
                if kind is not None:
                    val = a[j + 1 :]
                    if not val:
                        if i >= len(args):
                            self.flag(f"{binary} -{ch} without value", "R-SHELL-OPTION")
                            return None
                        val = args[i]
                        i += 1
                    if kind != "values":
                        out[kind].append(val)
                    break
                if ch == "I" and binary == "date":
                    break  # -I[FMT]
                if ch not in spec.flags:
                    self.flag(f"{binary} option -{ch} is not allowed", "R-SHELL-OPTION")
                    return None
                out["flags"].append(ch)
                j += 1
        return out

    # ------------------------------------------------------------ languages

    @staticmethod
    def _strip_awk_literals(program: str) -> str:
        program = re.sub(r'"(?:\\.|[^"\\])*"', '""', program)
        res: list[str] = []
        i = 0
        prev = ""
        while i < len(program):
            c = program[i]
            if c == "/" and (prev == "" or prev in "(,!~{};&|\n"):
                j = i + 1
                while j < len(program) and program[j] != "/":
                    j += 2 if program[j] == "\\" else 1
                res.append("//")
                i = j + 1
                prev = "/"
                continue
            res.append(c)
            if not c.isspace():
                prev = c
            i += 1
        return "".join(res)

    def check_awk(self, program: str) -> None:
        stripped = self._strip_awk_literals(program)
        if re.search(r"\bsystem\s*\(", stripped):
            self.flag("awk system()", "R-AWK-SYSTEM")
        if re.search(r"(?<!\|)\|(?!\|)", stripped) or "|&" in stripped:
            self.flag("awk command pipe", "R-AWK-GETLINE")
        if re.search(r"\bgetline\b", stripped):
            self.flag("awk getline", "R-AWK-GETLINE")
        if re.search(r"\b(?:ENVIRON|PROCINFO)\b", stripped) or "@" in stripped:
            self.flag("awk environment or extension access", "R-AWK-ENV")
        for m in re.finditer(r"\b(?:print|printf)\b", stripped):
            depth = 0
            for c in stripped[m.end() :]:
                if c in "([":
                    depth += 1
                elif c in ")]":
                    depth -= 1
                    if depth < 0:
                        break
                elif c in ";}\n" and depth == 0:
                    break
                elif c == ">" and depth == 0:
                    self.flag("awk output redirection", "R-AWK-REDIRECT")
                    break

    def check_jq(self, program: str) -> None:
        if re.search(r"\benv\b|\$ENV|input_filename|\$__loc__|\bimport\b|\binclude\b", program):
            self.flag("jq environment or module access", "R-JQ-ENV")

    # ------------------------------------------------------------- commands

    def check_command(self, cmd: shell_lexer.Command) -> bool:
        """Return True when the command is fully understood and allowed."""
        for redir in cmd.redirects:
            if redir.op in shell_lexer.OUTPUT_REDIRECTS:
                if redir.target not in SAFE_REDIRECT_TARGETS:
                    self.check_output(redir.target, "R-SHELL-REDIRECT", "redirect")
            elif redir.op in (">&", "<&"):
                if not re.fullmatch(r"\d+-?|-", redir.target):
                    self.flag(f"Redirect to {redir.target}", "R-SHELL-REDIRECT")
            elif redir.op == "<":
                self.check_input(redir.target)

        words = list(cmd.words)
        while words and words[0] in ALLOWED_RESERVED:
            words.pop(0)
        if not words:
            return True
        first = words[0]
        if first in DENIED_RESERVED or first.endswith("()"):
            self.flag(f"shell control construct {first}", "R-SHELL-CONTROL")
            return False
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", first):
            self.flag("Variable assignment", "R-SHELL-ASSIGN")
            return False
        if re.search(r"[*?\[\]]", first):
            self.flag(f"globbed command name {first}", "R-SHELL-GLOB-CMD")
            return False
        binary = first.rsplit("/", 1)[-1]
        if "/" in first and first.rsplit("/", 1)[0] not in ("/bin", "/usr/bin"):
            self.flag(f"command run from a path: {first}", "R-SHELL-EXEC-FILE")
            return False
        args = words[1:]

        if binary in EXEC_BUILTINS:
            self.flag(f"{binary} runs other code", "R-SHELL-EXEC-FILE")
            return False
        if binary in SHELL_INTERPRETERS:
            self.flag(f"Shell interpreter {binary}", "R-SHELL-EXEC-FILE")
            return False
        if re.fullmatch(r"python[0-9.]*", binary):
            if "-c" in args or any(a.startswith("-") for a in args[:1]):
                self.flag("Python -c in shell", "R-SHELL-PYTHON-C")
            else:
                self.flag("Python interpreter in shell", "R-SHELL-EXEC-FILE")
            return False
        if binary in OTHER_INTERPRETERS:
            self.flag(f"interpreter {binary}", "R-SHELL-INTERP")
            return False
        if binary in FORBIDDEN_BINARIES:
            self.flag(f"Forbidden binary {binary}", f"R-BIN-{binary.upper()}")
            return False
        if binary not in SAFE_BINARIES:
            self.flag(f"binary {binary} is not allow-listed", "R-SHELL-BIN-UNKNOWN")
            return False
        if binary in NO_FILE_BINARIES:
            return True

        spec = SPECS[binary]
        if binary == "jq":
            args = self._jq_args(args)
            if args is None:
                return False
        if binary == "sort" and any(a.startswith("--compress-program") for a in args):
            self.flag("sort --compress-program", "R-SORT-COMPRESS")
            return False
        if binary == "sed" and any(
            a.startswith("-i") or a.startswith("--in-place") or a in ("-f", "--file") for a in args
        ):
            self.flag("sed in-place edit or script file", "R-SED-FLAG")
            return False
        if binary in AWK_BINARIES and any(
            a in ("-f", "--file", "-E", "--exec") or a.startswith("-f") for a in args
        ):
            self.flag("awk program from file", "R-AWK-FILE")
            return False

        scanned = self.scan(binary, args, spec)
        if scanned is None:
            return False
        positional = scanned["positional"]
        programs = scanned["programs"]
        if spec.program_first and not programs:
            if not positional:
                self.flag(f"{binary} without program", "R-SHELL-OPTION")
                return False
            programs = [positional.pop(0)]

        if binary in AWK_BINARIES:
            positional = [p for p in positional if not re.match(r"^[A-Za-z_]\w*=", p)]
            for p in programs:
                self.check_awk(p)
        elif binary == "sed":
            try:
                sed_parser.parse("\n".join(programs))
            except sed_parser.SedParseError as exc:
                self.flag(f"sed script not allowed: {exc}", "R-SED-FLAG")
        elif binary == "jq":
            for p in programs:
                self.check_jq(p)
        elif binary in ("gzip", "gunzip"):
            to_stdout = {"c", "t", "l", "--stdout", "--test", "--list"} & set(scanned["flags"])
            if positional and not to_stdout:
                self.flag(f"{binary} would replace its input file", "R-GZIP-INPLACE")
        elif binary == "tee":
            for p in positional:
                self.check_output(p, "R-TEE-PATH", "tee")
            positional = []
        elif binary == "uniq" and len(positional) > 1:
            for p in positional[1:]:
                self.check_output(p, "R-SHELL-PATH", "uniq output")
            positional = positional[:1]

        for out in scanned["outputs"]:
            self.check_output(out, "R-SORT-OUTPUT", f"{binary} output")
        for path in scanned["files"] + (positional if spec.positional_files else []):
            self.check_input(path)
        return True

    def _jq_args(self, args: list[str]) -> list[str] | None:
        """Drop --arg/--argjson pairs and refuse file-reading options."""
        kept: list[str] = []
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("--arg", "--argjson"):
                i += 3
                continue
            if a.split("=", 1)[0] in (
                "--rawfile",
                "--slurpfile",
                "--from-file",
                "--library-path",
                "--args",
                "--jsonargs",
            ) or re.match(r"^-[A-Za-z]*[fL]", a):
                self.flag(f"jq option {a} reads files or modules", "R-JQ-FILE")
                return None
            kept.append(a)
            i += 1
        return kept

    def run(self) -> dict[str, Any]:
        code = self.code
        for pattern in FORK_BOMB_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                self.flag("Fork bomb pattern", "R-FORK-001")
        if re.search(r"/dev/(?:tcp|udp)/", code):
            self.flag("/dev/tcp or /dev/udp socket", "R-SHELL-DEVTCP")
        try:
            lexed = shell_lexer.lex(code)
        except shell_lexer.ShellLexError as exc:
            lexed = None
            if re.search(r"[<>]\(", code):
                self.flag("process substitution", "R-SHELL-PROCSUB")
            self.flag(f"Could not parse shell: {exc}", "R-SHELL-PARSE")

        active = lexed.active if lexed else code
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, active):
                self.flag("Dangerous shell pattern", "R-SHELL-PATTERN")
        if lexed is not None and re.search(r"[<>]\(", active):
            self.flag("process substitution", "R-SHELL-PROCSUB")
        if re.search(r'\b(?:python3?)\s+(?:-c|["\']|<)', code):
            self.flag("Python in shell needs analysis", "R-SHELL-PYTHON")

        for device in sorted(DANGEROUS_DEVICES):
            if device in code:
                match = re.search(r"head\s+-c\s+(\d+)([KMG]?)", code)
                if match:
                    size = (
                        int(match.group(1))
                        * {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3}[match.group(2)]
                    )
                    if size > 16 * 1024 * 1024:
                        self.flag(f"{device} excessive size", "R-SHELL-DEVICE-SIZE")
                else:
                    self.flag(f"Unbounded {device}", "R-SHELL-DEVICE")

        for pattern in (
            r"rm\s+.*-rf?\s+/(?:\s|$)",
            r"/etc/shadow",
            r"/var/run/docker\.sock",
            r"/proc/",
            r"\.\./\.\./",
        ):
            if re.search(pattern, code):
                self.flag("Dangerous path", "R-PATH-DANGER")

        if lexed is None:
            return self.result
        has_bins = False
        all_ok = True
        for cmd in lexed.commands:
            if any(w not in ALLOWED_RESERVED for w in cmd.words):
                has_bins = True
            all_ok = self.check_command(cmd) and all_ok
        if has_bins and all_ok and not self.result["forbidden"] and not self.result["suspicious"]:
            self.result["safe"] = True
        return self.result


def analyze(code: str) -> dict[str, Any]:
    return ShellChecker(code).run()
