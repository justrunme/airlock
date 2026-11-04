"""In-container bootstrap program.

This file is not imported by the host at run time. Its source text is passed
verbatim as ``python3 -c <source>`` when the sandbox container is created, so
the program that runs inside the container is fixed and owned by this
repository, never by the job author.

Protocol (stdin):
- line 1: a per-run nonce (32 lowercase hex chars) chosen by the host;
- then an uncompressed tar archive with ``job.py`` or ``job.sh`` and optional
  regular files under ``input/``. Absolute paths, ``..``, symlinks, hardlinks,
  devices and FIFOs are rejected.

Privilege split:
- The container starts as uid 0 with every capability dropped except SETUID
  and SETGID, and with no-new-privileges. This program marks itself
  non-dumpable, unpacks the archive (root-owned, read-only for the job), then
  runs the job as uid/gid 65534 with no supplementary groups, stdin closed,
  and RLIMIT_NPROC set from argv[1]. The job cannot open /proc/1/fd/*, read
  /proc/1/mem, ptrace or signal this process, because it runs as another uid.
- After the job exits, a short-lived child switches to uid 65534, kills every
  remaining process of that uid, then collects /work/out and hands the result
  back over a private pipe.

Protocol (stdout): exactly one JSON document carrying the nonce.
"""

import base64
import ctypes
import io
import json
import os
import posixpath
import re
import resource
import signal
import stat
import subprocess
import sys
import tarfile
import threading

WORK = "/work"
OUT = "/work/out"
JOB_UID = 65534
JOB_GID = 65534
MAX_TAR_BYTES = 48 * 1024 * 1024
MAX_STREAM_BYTES = 1024 * 1024
MAX_ARTIFACTS = 64
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
PR_SET_DUMPABLE = 4
NPROC_HINT = re.compile(
    rb"Resource temporarily unavailable|\[Errno 11\]|[Cc]an(?:'|no)t fork|fork: retry"
)

NONCE = ""


def _emit(doc):
    doc = {"v": 2, "nonce": NONCE, **doc}
    sys.stdout.write(json.dumps(doc, separators=(",", ":")))
    sys.stdout.flush()


def _no_dump():
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except OSError:
        pass


def _drop_privileges():
    os.setgroups([])
    os.setresgid(JOB_GID, JOB_GID, JOB_GID)
    os.setresuid(JOB_UID, JOB_UID, JOB_UID)
    if os.getuid() != JOB_UID or os.geteuid() != JOB_UID:
        raise OSError("privilege drop failed")


def _safe_name(name):
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        return None
    norm = posixpath.normpath(name)
    if norm in (".", "") or norm.startswith("/"):
        return None
    if any(part in ("..", "") for part in norm.split("/")):
        return None
    return norm


def _unpack(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        for member in tar.getmembers():
            name = _safe_name(member.name)
            if name is None:
                raise ValueError(f"unsafe path in archive: {member.name!r}")
            if name == "out" or name.startswith("out/"):
                raise ValueError(f"archive may not write to out/: {member.name!r}")
            dest = posixpath.join(WORK, name)
            if member.isdir():
                os.makedirs(dest, mode=0o755, exist_ok=True)
                continue
            if not member.isreg():
                raise ValueError(f"unsupported archive member: {member.name!r}")
            parent = posixpath.dirname(dest)
            os.makedirs(parent, mode=0o755, exist_ok=True)
            src = tar.extractfile(member)
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "wb") as fh:
                fh.write(src.read())


def _reader(stream, sink):
    total = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        total += len(chunk)
        room = MAX_STREAM_BYTES - len(sink["data"])
        if room > 0:
            sink["data"] += chunk[:room]
        if total > MAX_STREAM_BYTES:
            sink["truncated"] = True
    sink["total"] = total


def _collect_artifacts():
    """Runs as the job uid after every job process is gone."""
    artifacts = []
    dropped = []
    total = 0
    if not os.path.isdir(OUT) or os.path.islink(OUT):
        return artifacts, dropped
    for root, dirs, files in os.walk(OUT, followlinks=False):
        dirs.sort()
        for dname in list(dirs):
            if os.path.islink(os.path.join(root, dname)):
                dropped.append(
                    {
                        "path": os.path.relpath(os.path.join(root, dname), OUT),
                        "size": 0,
                        "reason": "not_regular_file",
                    }
                )
        for fname in sorted(files):
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, OUT)
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):
                dropped.append({"path": rel, "size": 0, "reason": "not_regular_file"})
                continue
            if len(artifacts) >= MAX_ARTIFACTS:
                dropped.append({"path": rel, "size": st.st_size, "reason": "too_many_files"})
                continue
            if total + st.st_size > MAX_ARTIFACT_BYTES:
                dropped.append({"path": rel, "size": st.st_size, "reason": "over_size_cap"})
                continue
            try:
                fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as fh:
                    content = fh.read(MAX_ARTIFACT_BYTES - total + 1)
            except OSError:
                dropped.append({"path": rel, "size": st.st_size, "reason": "unreadable"})
                continue
            if total + len(content) > MAX_ARTIFACT_BYTES:
                dropped.append({"path": rel, "size": len(content), "reason": "over_size_cap"})
                continue
            total += len(content)
            artifacts.append(
                {"path": rel, "size": len(content), "b64": base64.b64encode(content).decode()}
            )
    return artifacts, dropped


def _reap_and_collect():
    """Fork a child that becomes the job uid, kills all its processes, collects out/."""
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(rfd)
            _drop_privileges()
            for _ in range(50):
                try:
                    os.kill(-1, signal.SIGKILL)
                except ProcessLookupError:
                    break
            artifacts, dropped = _collect_artifacts()
            payload = json.dumps({"artifacts": artifacts, "dropped": dropped}).encode()
            with os.fdopen(wfd, "wb") as fh:
                fh.write(payload)
            os._exit(0)
        except BaseException:
            os._exit(3)
    os.close(wfd)
    chunks = []
    while True:
        chunk = os.read(rfd, 1 << 20)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(rfd)
    _, status = os.waitpid(pid, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise OSError("artifact collector failed")
    return json.loads(b"".join(chunks))


def main():
    global NONCE
    _no_dump()
    line = sys.stdin.buffer.readline(64).strip()
    if not re.fullmatch(rb"[0-9a-f]{32}", line):
        _emit({"error": "missing nonce"})
        return 2
    NONCE = line.decode()

    data = sys.stdin.buffer.read(MAX_TAR_BYTES + 1)
    if len(data) > MAX_TAR_BYTES:
        _emit({"error": "input archive too large"})
        return 2
    try:
        _unpack(data)
        os.makedirs(OUT, mode=0o755, exist_ok=True)
        os.chmod(OUT, 0o1777)  # job (another uid) may create files, not replace out/
        os.chmod(WORK, 0o755)
    except (ValueError, OSError, tarfile.TarError) as exc:
        _emit({"error": f"bad input archive: {exc}"})
        return 2

    if os.path.isfile(os.path.join(WORK, "job.py")):
        argv = ["python3", os.path.join(WORK, "job.py")]
    elif os.path.isfile(os.path.join(WORK, "job.sh")):
        argv = ["sh", os.path.join(WORK, "job.sh")]
    else:
        _emit({"error": "no job in archive"})
        return 2

    # Docker's --pids-limit is the primary control, but gVisor does not enforce
    # it, so cap the job uid's processes here as well.
    try:
        max_procs = max(int(sys.argv[1]), 8) if len(sys.argv) > 1 else 64
    except ValueError:
        max_procs = 64

    def _prepare_job():
        _drop_privileges()
        resource.setrlimit(resource.RLIMIT_NPROC, (max_procs, max_procs))
        os.umask(0o022)

    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/tmp",
    }
    try:
        proc = subprocess.Popen(
            argv,
            preexec_fn=_prepare_job,
            cwd=WORK,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _emit({"error": f"could not start job: {exc}"})
        return 2
    out = {"data": b"", "truncated": False, "total": 0}
    err = {"data": b"", "truncated": False, "total": 0}
    threads = [
        threading.Thread(target=_reader, args=(proc.stdout, out), daemon=True),
        threading.Thread(target=_reader, args=(proc.stderr, err), daemon=True),
    ]
    for t in threads:
        t.start()
    rc = proc.wait()
    exit_code = 128 - rc if rc < 0 else rc

    try:
        collected = _reap_and_collect()
    except (OSError, ValueError) as exc:
        _emit({"error": f"collect failed: {exc}"})
        return 2
    for t in threads:
        t.join(5)

    notes = [f"nproc_limit={max_procs}"]
    if NPROC_HINT.search(err["data"]) or NPROC_HINT.search(out["data"]):
        notes.append("nproc_limit_reached")
    _emit(
        {
            "exit_code": exit_code,
            "signal": -rc if rc < 0 else None,
            "stdout_b64": base64.b64encode(out["data"]).decode("ascii"),
            "stderr_b64": base64.b64encode(err["data"]).decode("ascii"),
            "stdout_truncated": out["truncated"],
            "stderr_truncated": err["truncated"],
            "stdout_bytes": out["total"],
            "stderr_bytes": err["total"],
            "artifacts": collected["artifacts"],
            "artifacts_dropped": collected["dropped"],
            "notes": notes,
        }
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
