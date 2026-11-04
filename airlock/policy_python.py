"""Static allow-list checks for Python jobs.

The checker walks the AST. It allows a small set of modules, refuses any
attribute name that leads to processes, imports, the interpreter or private
state no matter which object it is read from, and only lets file access
through when the path is a literal (or a loop variable over a literal glob)
inside /work/input for reads or /work/out for writes. Anything it cannot
prove is denied; the sandbox is the second line of defence.
"""

import ast
import fnmatch
import string
from pathlib import PurePosixPath
from typing import Any

DANGEROUS_MODULES = {
    "subprocess",
    "socket",
    "ctypes",
    "shutil",
    "multiprocessing",
    "threading",
    "pty",
    "ptyprocess",
    "builtins",
    "importlib",
    "posix",
    "_posixsubprocess",
    "runpy",
    "pickle",
    "marshal",
    "code",
    "codeop",
    "gc",
    "inspect",
    "signal",
    "resource",
    "sysconfig",
    "site",
    "tempfile",
    "glob",
    "fileinput",
    "shelve",
    "dbm",
    "sqlite3",
    "http",
    "ftplib",
    "smtplib",
    "telnetlib",
    "ssl",
    "asyncio",
    "concurrent",
    "select",
    "selectors",
    "mmap",
    "fcntl",
    "termios",
    "pwd",
    "grp",
}

SAFE_MODULES = {
    "re",
    "json",
    "sys",
    "os",
    "collections",
    "datetime",
    "itertools",
    "statistics",
    "csv",
    "math",
    "argparse",
    "pathlib",
    "time",
    "typing",
    "dataclasses",
    "functools",
    "operator",
    "heapq",
    "bisect",
    "array",
    "enum",
    "gzip",
    "bz2",
    "lzma",
    "zlib",
    "decimal",
    "fractions",
    "pprint",
    "copy",
    "uuid",
    "ipaddress",
    "urllib",
    "zipfile",
    "textwrap",
    "string",
    "hashlib",
    "base64",
    "io",
    "random",
    "calendar",
    "difflib",
    "unicodedata",
    "struct",
    "binascii",
    "html",
    "email",
    "numbers",
    "abc",
}

# Attribute names refused on any object. Every name starting with "_" is
# refused as well, which covers dunders, _os, _sys and _getframe.
DENIED_ATTRS = {
    "os",
    "sys",
    "subprocess",
    "modules",
    "system",
    "popen",
    "popen2",
    "popen3",
    "eval",
    "exec",
    "compile",
    "open_code",
    "builtins",
    "importlib",
    "import_module",
    "load_module",
    "exec_module",
    "environ",
    "environb",
    "getenv",
    "putenv",
    "unsetenv",
    "kill",
    "killpg",
    "fork",
    "forkpty",
    "posix_spawn",
    "posix_spawnp",
    "startfile",
    "setrecursionlimit",
    "settrace",
    "setprofile",
    "attrgetter",
    "methodcaller",
    "itemgetter",
    "urlopen",
    "urlretrieve",
    "build_opener",
    "install_opener",
    "OpenerDirector",
    "URLopener",
    "vformat",
    "format_map",
    "Formatter",
    "f_globals",
    "f_locals",
    "f_builtins",
    "f_back",
    "f_code",
    "gi_frame",
    "gi_code",
    "cr_frame",
    "ag_frame",
    "tb_frame",
    "tb_next",
    "ctypes",
    "cdll",
    "dlopen",
    "CDLL",
    "socket",
    "shutil",
    "pickle",
    "marshal",
    "unlink",
    "rmdir",
    "removedirs",
    "rename",
    "symlink",
    "symlink_to",
    "hardlink_to",
    "link",
    "chmod",
    "lchmod",
    "chown",
    "mkfifo",
    "mknod",
    "setuid",
    "setgid",
    "chdir",
    "chroot",
    "ptrace",
    "breakpointhook",
    "displayhook",
    "excepthook",
}
FS_MUTATORS = {"unlink", "rmdir", "rename", "symlink_to", "hardlink_to", "chmod", "lchmod", "chown"}
DENIED_ATTR_PREFIXES = ("_", "exec", "spawn")

DENIED_CALLS = {"eval", "exec", "compile", "__import__", "breakpoint"}
INTROSPECTION_CALLS = {"vars", "globals", "locals", "dir", "help"}
ALLOWED_DUNDER_NAMES = {"__name__", "__doc__"}

SYS_ALLOWED = {"stdout", "stderr", "stdin", "exit", "version", "version_info", "maxsize", "argv"}
OS_ALLOWED = {"os.path", "os.listdir", "os.sep", "os.linesep"}
OS_PATH_PURE = {"basename", "dirname", "join", "splitext", "split", "normpath", "sep"}
OS_PATH_FS = {"exists", "getsize", "isfile", "isdir"}
# Sub-modules that ``from X import Y`` binds as module objects.
SUBMODULES = {"os.path", "urllib.parse", "urllib.request", "email.utils", "html.parser"}

OPEN_MODULE_FUNCS = {
    "io.open": "r",
    "io.FileIO": "r",
    "gzip.open": "rb",
    "gzip.GzipFile": "rb",
    "bz2.open": "rb",
    "bz2.BZ2File": "rb",
    "lzma.open": "rb",
    "lzma.LZMAFile": "rb",
    "zipfile.ZipFile": "r",
}
PATH_CTORS = {"Path", "PurePath", "PosixPath", "PurePosixPath"}
PATHLIB_READ = {
    "read_text",
    "read_bytes",
    "glob",
    "rglob",
    "iterdir",
    "exists",
    "is_file",
    "is_dir",
    "walk",
    "stat",
    "lstat",
    "is_symlink",
    "readlink",
    "samefile",
    "is_mount",
}
PATHLIB_WRITE = {"write_text", "write_bytes", "touch", "mkdir"}
PATH_ITERATORS = {"glob", "rglob", "iterdir", "walk"}
GLOB_ITERATORS = {"glob", "rglob"}
# A path method may only be called in place; a bound reference (r = p.read_text)
# would be called later where check_call cannot see its receiver.
PATH_METHODS = PATHLIB_READ | PATHLIB_WRITE | {"open"}
ALLOC_CALLS = {"bytearray", "bytes", "range", "zeros"}
MAX_ALLOC = 64 * 1024 * 1024
MAX_NUMBER = 1 << 64


def path_violation(path: str, write: bool) -> tuple[str, str] | None:
    """Return (rule, message) when a literal path is not allowed."""
    if ".." in PurePosixPath(path).parts:
        return "R-PY-OPEN-TRAVERSAL", "open() path traversal"
    full = PurePosixPath("/work") / path  # relative paths resolve against cwd /work
    for root in ("/proc", "/etc", "/dev", "/sys", "/var/run", "/run"):
        if full == PurePosixPath(root) or full.is_relative_to(root):
            return "R-PY-OPEN-PATH", f"open() dangerous path {path}"
    if write:
        if not full.is_relative_to("/work/out") or full == PurePosixPath("/work/out"):
            return "R-PY-OPEN-WRITE", f"write outside /work/out/: {path}"
    elif not full.is_relative_to("/work/input") and not full.is_relative_to("/work/out"):
        return "R-PY-OPEN-READ", f"read outside /work/input/: {path}"
    return None


def glob_violation(base: str, pattern: str) -> tuple[str, str] | None:
    """Return (rule, message) when a glob pattern can leave its base directory.

    A pattern is refused when it is absolute, has a ``..`` segment, has a
    bracket segment that matches ``..``, or when base/pattern normalised by
    path_violation is outside the read roots.
    """
    if not pattern or pattern.startswith("/") or "\\" in pattern:
        return "R-PY-GLOB-TRAVERSAL", f"glob pattern {pattern!r} is not a relative literal"
    for seg in pattern.split("/"):
        if ".." in seg or ("[" in seg and fnmatch.fnmatchcase("..", seg)):
            return "R-PY-GLOB-TRAVERSAL", f"glob pattern {pattern!r} climbs out of its base"
    violation = path_violation(str(PurePosixPath(base) / pattern), False)
    if violation:
        return "R-PY-GLOB-TRAVERSAL", f"glob {base}/{pattern} is outside the read roots"
    return None


def _const_int(node: ast.AST, depth: int = 0) -> int | None:
    """Fold a constant integer expression, saturating instead of computing huge powers."""
    if depth > 10:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        v = _const_int(node.operand, depth + 1)
        return None if v is None else -v
    if isinstance(node, ast.BinOp):
        a = _const_int(node.left, depth + 1)
        b = _const_int(node.right, depth + 1)
        if a is None or b is None:
            return None
        if isinstance(node.op, ast.Pow):
            if b < 0:
                return 0
            if abs(a) > 1 and b > 64:
                return MAX_NUMBER
            return min(a**b, MAX_NUMBER)
        if isinstance(node.op, ast.Mult):
            return min(a * b, MAX_NUMBER)
        if isinstance(node.op, ast.Add):
            return min(a + b, MAX_NUMBER)
        if isinstance(node.op, ast.LShift):
            return MAX_NUMBER if b > 64 else min(a << b, MAX_NUMBER)
    return None


class PythonChecker:
    """One-shot checker for a single Python source."""

    def __init__(self, code: str):
        self.code = code
        self.result: dict[str, Any] = {
            "forbidden": [],
            "suspicious": [],
            "safe": False,
            "rules": [],
            "warnings": [],
        }
        self.aliases: dict[str, str] = {}  # local name -> qualified name
        self.module_names: set[str] = set()  # local names bound to module objects
        self.consts: dict[str, ast.expr] = {}
        self.derived: dict[str, str] = {}  # loop var -> directory it iterates
        self.parents: dict[int, ast.AST] = {}

    def flag(self, message: str, rule: str, level: str = "forbidden") -> None:
        self.result[level].append(message)
        if rule not in self.result["rules"]:
            self.result["rules"].append(rule)

    # ---------------------------------------------------------------- binding

    def _collect(self, tree: ast.AST) -> None:
        bind_count: dict[str, int] = {}
        values: dict[str, ast.expr] = {}

        def bump(name: str, by: int = 1) -> None:
            bind_count[name] = bind_count.get(name, 0) + by

        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self.parents[id(child)] = node
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                bump(node.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bump(node.name)
            elif isinstance(node, ast.arg):
                bump(node.arg)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                for name in node.names:
                    bump(name, 2)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        local, qual = alias.asname, alias.name
                    else:
                        local = qual = alias.name.split(".")[0]
                    bump(local)
                    self.aliases[local] = qual
                    self.module_names.add(local)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for alias in node.names:
                    local = alias.asname or alias.name
                    qual = f"{node.module}.{alias.name}"
                    bump(local)
                    self.aliases[local] = qual
                    if qual in SUBMODULES:
                        self.module_names.add(local)
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                values[node.targets[0].id] = node.value
        self.consts = {k: v for k, v in values.items() if bind_count.get(k) == 1}
        # Rebinding an imported name makes its meaning unknowable.
        for name in list(self.aliases):
            if bind_count.get(name, 0) != 1:
                self.flag(f"import name {name} is rebound", "R-PY-MODULE-ALIAS")

        # Loop variables over a literal directory listing count as paths inside it.
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.comprehension)):
                target, it = node.target, node.iter
                if not isinstance(target, ast.Name) or bind_count.get(target.id) != 1:
                    continue
                while (
                    isinstance(it, ast.Call)
                    and isinstance(it.func, ast.Name)
                    and it.func.id in {"sorted", "list", "reversed"}
                    and it.args
                ):
                    it = it.args[0]
                if not (
                    isinstance(it, ast.Call)
                    and isinstance(it.func, ast.Attribute)
                    and it.func.attr in PATH_ITERATORS
                ):
                    continue
                base = self.resolve_path(it.func.value)
                if base is None or path_violation(base, False):
                    continue
                if it.func.attr in GLOB_ITERATORS:
                    pattern = self.glob_pattern(it)
                    if pattern is None or glob_violation(base, pattern):
                        continue
                self.derived[target.id] = base

    def qual(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.qual(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    # ------------------------------------------------------------------ paths

    def is_path_ctor(self, func: ast.AST) -> bool:
        q = self.qual(func)
        return q is not None and q.startswith("pathlib.") and q.split(".")[-1] in PATH_CTORS

    def resolve_path(self, node: ast.AST, depth: int = 0) -> str | None:
        """Resolve a path built only from string literals, or None."""
        if depth > 20:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in self.derived:
                return str(PurePosixPath(self.derived[node.id]) / "entry")
            if node.id in self.consts:
                return self.resolve_path(self.consts[node.id], depth + 1)
            return None
        if isinstance(node, ast.Call) and self.is_path_ctor(node.func) and not node.keywords:
            parts = [self.resolve_path(a, depth + 1) for a in node.args]
            if not parts or any(p is None for p in parts):
                return None
            return str(PurePosixPath(*parts))
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
            left = self.resolve_path(node.left, depth + 1)
            right = self.resolve_path(node.right, depth + 1)
            if left is None or right is None:
                return None
            if isinstance(node.op, ast.Add):
                return left + right
            return str(PurePosixPath(left) / right)
        return None

    def glob_pattern(self, call: ast.Call) -> str | None:
        """The literal pattern of a glob()/rglob() call, or None."""
        node = self.arg(call, 0, "pattern")
        if isinstance(node, ast.Name) and node.id in self.consts:
            node = self.consts[node.id]
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def zip_handle(self, node: ast.AST) -> bool:
        """True when node is a name bound once to zipfile.ZipFile(...) (member open)."""
        if isinstance(node, ast.Name) and node.id in self.consts:
            node = self.consts[node.id]
        return isinstance(node, ast.Call) and self.qual(node.func) == "zipfile.ZipFile"

    def check_access(
        self,
        path_node: ast.AST | None,
        mode_node: ast.AST | None,
        default_mode: str,
        write_rule: str = "R-PY-OPEN-WRITE",
        read_rule: str = "R-PY-OPEN-READ",
    ) -> None:
        if path_node is None:
            self.flag("file open without path", "R-PY-OPEN-NONLITERAL")
            return
        if isinstance(path_node, ast.Constant) and isinstance(path_node.value, int):
            self.flag("open() on a file descriptor", "R-PY-OPEN-FD")
            return
        if mode_node is None:
            mode = default_mode
        elif isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
            mode = mode_node.value
        else:
            self.flag("open() with non-literal mode", "R-PY-OPEN-NONLITERAL")
            return
        write = bool(set(mode) & set("wax+"))
        path = self.resolve_path(path_node)
        if path is None:
            self.flag("file access with a non-literal path", "R-PY-OPEN-NONLITERAL")
            return
        violation = path_violation(path, write)
        if violation:
            rule, message = violation
            if rule == "R-PY-OPEN-WRITE":
                rule = write_rule
            elif rule == "R-PY-OPEN-READ":
                rule = read_rule
            self.flag(message, rule)

    @staticmethod
    def arg(node: ast.Call, pos: int, *names: str) -> ast.expr | None:
        if len(node.args) > pos:
            return node.args[pos]
        for kw in node.keywords:
            if kw.arg in names:
                return kw.value
        return None

    # ------------------------------------------------------------------ rules

    def denied_attr(self, name: str) -> bool:
        return name in DENIED_ATTRS or name.startswith(DENIED_ATTR_PREFIXES)

    def check_import(self, node: ast.Import | ast.ImportFrom) -> None:
        if isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                self.flag("relative import", "R-PY-MOD-UNKNOWN")
                return
            modules = [node.module]
            for alias in node.names:
                if alias.name == "*":
                    self.flag("star import", "R-PY-MOD-STAR")
                    continue
                qual = f"{node.module}.{alias.name}"
                self.check_qual(qual)
                if self.denied_attr(alias.name):
                    rule = "R-PY-SYS-MODULES" if qual == "sys.modules" else "R-PY-ATTR-DENIED"
                    self.flag(f"import of {qual}", rule)
        else:
            modules = [a.name for a in node.names]
        for full in modules:
            top = full.split(".")[0]
            if top in DANGEROUS_MODULES:
                self.flag(f"Dangerous module {top}", f"R-PY-MOD-{top.upper()}")
            elif top not in SAFE_MODULES:
                self.flag(f"Module {top} is not allow-listed", "R-PY-MOD-UNKNOWN")
            if full != top and isinstance(node, ast.Import):
                for part in full.split(".")[1:]:
                    if self.denied_attr(part):
                        self.flag(f"import of {full}", "R-PY-ATTR-DENIED")

    def check_qual(self, qual: str) -> None:
        """Module-specific allow-lists for os and sys."""
        parts = qual.split(".")
        if parts[0] == "os" and len(parts) > 1:
            head = ".".join(parts[:2])
            bad_path_fn = (
                head == "os.path" and len(parts) > 2 and parts[2] not in OS_PATH_PURE | OS_PATH_FS
            )
            if head not in OS_ALLOWED or bad_path_fn:
                self.flag(f"{qual} is not allowed", "R-PY-MOD-OS")
        if parts[0] == "sys" and len(parts) > 1 and parts[1] not in SYS_ALLOWED:
            rule = "R-PY-SYS-MODULES" if parts[1] == "modules" else "R-PY-SYS-ATTR"
            self.flag(f"{qual} is not allowed", rule)
        if parts[0] == "operator" and len(parts) > 1 and parts[1] in DENIED_ATTRS:
            self.flag(f"{qual} is not allowed", "R-PY-ATTR-DENIED")

    def check_attribute(self, node: ast.Attribute) -> None:
        q = self.qual(node)
        if q is not None:
            parent = self.parents.get(id(node))
            # Only check the longest chain so os.path.join is judged once.
            if not (isinstance(parent, ast.Attribute) and self.qual(parent)):
                self.check_qual(q)
        if node.attr == "compile" and self.qual(node.value) == "re":
            return
        if node.attr in PATH_METHODS:
            parent = self.parents.get(id(node))
            if not (isinstance(parent, ast.Call) and parent.func is node):
                self.flag(f"reference to path method .{node.attr}", "R-PY-PATH-METHOD-REF")
        if self.denied_attr(node.attr):
            if node.attr == "modules":
                rule = "R-PY-SYS-MODULES"
            elif node.attr.startswith("__") or node.attr.startswith(("f_", "gi_", "tb_", "_get")):
                rule = "R-PY-ATTR-DANGER"
            elif node.attr in FS_MUTATORS:
                rule = "R-PY-PATHLIB-WRITE"
            else:
                rule = "R-PY-ATTR-DENIED"
            self.flag(f"Denied attribute {node.attr}", rule)

    def check_name(self, node: ast.Name, call_funcs: set[int]) -> None:
        if node.id.startswith("__") and node.id not in ALLOWED_DUNDER_NAMES:
            self.flag(f"Access to {node.id}", "R-PY-BUILTINS")
            return
        if not isinstance(node.ctx, ast.Load):
            return
        parent = self.parents.get(id(node))
        if node.id in self.module_names and not (
            isinstance(parent, ast.Attribute) and parent.value is node
        ):
            self.flag(f"module {node.id} used as a value", "R-PY-MODULE-ALIAS")
        if id(node) in call_funcs:
            return
        if node.id in DENIED_CALLS | INTROSPECTION_CALLS | {"getattr", "setattr", "delattr"}:
            self.flag(f"Reference to {node.id}", "R-PY-INTROSPECT")
        elif node.id == "open" or self.aliases.get(node.id) in OPEN_MODULE_FUNCS:
            self.flag("open referenced indirectly", "R-PY-OPEN-ALIAS")

    def check_format(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "format"):
            return
        receiver: ast.AST | None = func.value
        if isinstance(receiver, ast.Name) and receiver.id == "str":
            receiver = node.args[0] if node.args else None
        if isinstance(receiver, ast.Name) and receiver.id in self.consts:
            receiver = self.consts[receiver.id]
        if not (isinstance(receiver, ast.Constant) and isinstance(receiver.value, str)):
            self.flag("str.format() on a non-literal template", "R-PY-FORMAT-ATTR")
            return
        try:
            fields = [f for _, f, spec, _ in string.Formatter().parse(receiver.value) if f]
            specs = [s for _, _, s, _ in string.Formatter().parse(receiver.value) if s]
        except ValueError:
            self.flag("malformed format string", "R-PY-FORMAT-ATTR")
            return
        if any("." in f or "[" in f for f in fields) or any("{" in s for s in specs):
            self.flag("format string walks attributes or items", "R-PY-FORMAT-ATTR")

    def check_alloc(self, node: ast.AST) -> None:
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else None
            if isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name in ALLOC_CALLS:
                for a in node.args:
                    v = _const_int(a)
                    if v is not None and v > MAX_ALLOC:
                        self.flag(f"{name}() of {v} items", "R-PY-HUGE-ALLOC")
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Pow, ast.LShift)):
            v = _const_int(node)
            seq = any(
                isinstance(side, (ast.List, ast.Tuple))
                or (isinstance(side, ast.Constant) and isinstance(side.value, (str, bytes)))
                for side in (node.left, node.right)
            )
            other = _const_int(node.right) if seq else None
            if other is None and seq:
                other = _const_int(node.left)
            if (seq and other is not None and other > MAX_ALLOC) or (
                v is not None and v >= MAX_NUMBER
            ):
                self.flag("huge constant allocation", "R-PY-HUGE-ALLOC")

    def check_loop(self, node: ast.While) -> None:
        test = node.test
        truthy = isinstance(test, ast.Constant) and bool(test.value)
        if not truthy:
            return
        for child in ast.walk(node):
            if child is not node and isinstance(child, (ast.FunctionDef, ast.Lambda)):
                continue
            if isinstance(child, (ast.Break, ast.Return, ast.Raise)) or (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "exit"
            ):
                return
        self.flag("while True without break", "R-PY-INFINITE-LOOP")

    def check_call(self, node: ast.Call) -> None:
        func = node.func
        fname = func.id if isinstance(func, ast.Name) else None
        q = self.qual(func)
        if fname in DENIED_CALLS:
            self.flag(f"Dangerous call {fname}", f"R-PY-{fname.upper()}")
        if fname in INTROSPECTION_CALLS:
            self.flag(f"{fname}() introspection", "R-PY-INTROSPECT")
        if fname == "type" or (isinstance(func, ast.Attribute) and func.attr == "type"):
            self.flag("type() manipulation", "R-PY-TYPE")
        if fname in {"getattr", "setattr", "delattr", "hasattr"}:
            name_arg = node.args[1] if len(node.args) >= 2 else None
            if not (isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str)):
                self.flag(f"{fname} non-literal", "R-PY-GETATTR")
            elif self.denied_attr(name_arg.value) or name_arg.value in DENIED_CALLS:
                self.flag(f"{fname} dangerous attr {name_arg.value}", "R-PY-GETATTR-DANGER")
            elif fname == "getattr" and name_arg.value in PATH_METHODS:
                self.flag(f"getattr of path method {name_arg.value}", "R-PY-PATH-METHOD-REF")
            elif fname == "setattr" or fname == "delattr":
                self.flag(f"{fname} mutates objects", "R-PY-GETATTR")
        self.check_format(node)

        # File access
        if fname == "open" and "open" not in self.aliases:
            self.check_access(self.arg(node, 0, "file"), self.arg(node, 1, "mode"), "r")
        elif q in OPEN_MODULE_FUNCS:
            mode = self.arg(node, 1, "mode")
            self.check_access(self.arg(node, 0, "file", "filename"), mode, OPEN_MODULE_FUNCS[q])
            if (
                q == "zipfile.ZipFile"
                and mode is not None
                and not (isinstance(mode, ast.Constant) and mode.value == "r")
            ):
                self.flag("zipfile opened for writing", "R-PY-ZIP-WRITE")
        elif q in {"os.listdir"} or (q and q.startswith("os.path.") and q[8:] in OS_PATH_FS):
            target = self.arg(node, 0, "path")
            path = self.resolve_path(target) if target is not None else None
            if path is None:
                self.flag(f"{q}() on a non-literal path", "R-PY-OPEN-NONLITERAL")
            elif path_violation(path, False):
                rule, message = path_violation(path, False)
                self.flag(message, rule)
        elif isinstance(func, ast.Attribute) and func.attr in PATHLIB_READ | PATHLIB_WRITE | {
            "open"
        }:
            receiver = self.resolve_path(func.value)
            if func.attr == "open" and receiver is None:
                # Only a zipfile handle may open a non-path member name; any other
                # unresolvable receiver could be a Path that walked out of /work.
                if not self.zip_handle(func.value):
                    self.flag("open() on a non-literal path", "R-PY-OPEN-NONLITERAL")
            elif func.attr == "open":
                self.check_access(
                    func.value,
                    self.arg(node, 0, "mode"),
                    "r",
                    write_rule="R-PY-PATHLIB-WRITE",
                    read_rule="R-PY-PATHLIB-READ",
                )
            elif receiver is None:
                self.flag(f"{func.attr}() on a non-literal path", "R-PY-OPEN-NONLITERAL")
            else:
                write = func.attr in PATHLIB_WRITE
                self.check_access(
                    func.value,
                    ast.Constant("w" if write else "r"),
                    "r",
                    write_rule="R-PY-PATHLIB-WRITE",
                    read_rule="R-PY-PATHLIB-READ",
                )
                if func.attr in GLOB_ITERATORS:
                    pattern = self.glob_pattern(node)
                    if pattern is None:
                        self.flag(
                            f"{func.attr}() with a non-literal pattern", "R-PY-GLOB-TRAVERSAL"
                        )
                    else:
                        violation = glob_violation(receiver, pattern)
                        if violation:
                            self.flag(violation[1], violation[0])

    def run(self) -> dict[str, Any]:
        try:
            tree = ast.parse(self.code)
        except SyntaxError:
            self.flag("Invalid Python syntax", "R-PY-SYNTAX")
            return self.result
        self._collect(tree)
        call_funcs = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        forbidden_strings = DENIED_CALLS | {
            "__builtins__",
            "__import__",
            "__loader__",
            "__spec__",
            "__subclasses__",
            "__globals__",
            "__dict__",
            "__class__",
            "__bases__",
            "__mro__",
            "__code__",
        }
        has_operations = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                self.check_name(node, call_funcs)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value in forbidden_strings:
                    self.flag(f"String names {node.value}", "R-PY-DUNDER-STR")
                if "file:" in node.value.lower():
                    self.flag("file: URL", "R-PY-URL-FILE")
            elif isinstance(node, ast.Attribute):
                has_operations = True
                self.check_attribute(node)
            elif isinstance(node, ast.Call):
                has_operations = True
                self.check_call(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                has_operations = True
                self.check_import(node)
            elif isinstance(node, ast.While):
                self.check_loop(node)
            self.check_alloc(node)
        if has_operations and not self.result["forbidden"] and not self.result["suspicious"]:
            self.result["safe"] = True
        return self.result


def analyze(code: str) -> dict[str, Any]:
    return PythonChecker(code).run()
