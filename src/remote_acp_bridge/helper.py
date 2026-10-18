"""``remote-acp-helper`` — the privileged mount helper (T5 §4/§5).

A resident **root** systemd service (``remote-acp-helper.service``): it builds its own Unix
socket (path from its own config file) and serves one short transaction per connection —
read one JSON request, validate it against the whitelist in:mod:`.mounting`, run
``/bin/mount`` or ``/bin/umount`` by ``execve`` on a fixed argv list (never a shell), write
one JSON reply, close. Everything else is refused.

The allowed mount roots come **only** from the instance configs next to the helper's own
config — never from the request, which would let the unprivileged ``agent``
account point the helper at any directory.

The credential file is this process's own and lives only for the one mount: the request
carries ``credentials`` (a username/password/domain triple that arrived over the socket, not
argv), which we write to a ``0600`` temp file, hand mount the path, and delete immediately.
The caller can never name a ``credentials=`` option;:func:`mounting.validate_options`
rejects one outright.

Entry point::func:`main`, run by systemd through ``src/remote_acp_helper.py``. Validation is
pure and the mount itself goes through an injectable ``spawn``; the socket loop takes an
injectable ``server_factory``, so the decision path and the accept loop are unit-tested
without root, a real filesystem, or AF_UNIX.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import tomllib
from dataclasses import dataclass
from pathlib import PurePosixPath

from . import mounting
from .mounting import MountInputError

# There is no default config path — the helper reads everything from its command line
# (``--config`` is required), so nothing is hardcoded to one deployment root any more. The
# socket default stays: it is a socket's conventional path, overridable in helper.toml.
DEFAULT_HELPER_SOCKET = "/run/remote-acp-helper.sock"


@dataclass(frozen=True)
class MountSettings:
    """The helper's own ``[mount]`` budget.

    ``timeout`` is the per-attempt limit handed to ``subprocess.run``, ``retry`` the number
    of extra attempts after the first (so a mount is tried ``1 + retry`` times), and
    ``concurrency`` how many requests may be in flight at once. The defaults match the
    delivered ``configs/helper.toml``, so a file with no ``[mount]`` section keeps working.
    """

    timeout: int = 5
    retry: int = 3
    concurrency: int = 20


#: Per-key floor, so a mount budget can never be zero or negative.
_MOUNT_FLOORS = {"timeout": 1, "retry": 0, "concurrency": 1}


def _load_config_data(path: str) -> dict:
    """The parsed helper config as a dict; ``{}`` when the file does not exist.

    Raises:class:`HelperError` (English, one line) when the file exists but cannot be read
    or parsed. Both readers below share this so a file is parsed once and the ``[socket]``
    behaviour stays exactly as it was.
    """
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise HelperError(f"helper config {path} cannot be read: {type(exc).__name__}") from exc


def load_mount_settings(path: str) -> MountSettings:
    """The helper's ``[mount]`` budget (``timeout``/``retry``/``concurrency``).

    A missing file, or a file with no ``[mount]`` table, is the default budget — an operator
    who never wrote one still gets retries. A value that is not an integer, or below its
    floor (``timeout >= 1``, ``retry >= 0``, ``concurrency >= 1``), is a startup error: the
    service refuses to start rather than mounting with a budget it did not understand.
    """
    data = _load_config_data(path)
    section = data.get("mount")
    if section is None:
        return MountSettings()
    if not isinstance(section, dict):
        raise HelperError(f"helper config {path}: 'mount' must be a table")
    values: dict[str, int] = {}
    for key, floor in _MOUNT_FLOORS.items():
        raw = section.get(key, getattr(MountSettings(), key))
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < floor:
            raise HelperError(
                f"helper config {path}: 'mount.{key}' must be an integer >= {floor}")
        values[key] = raw
    return MountSettings(**values)


class HelperError(Exception):
    """A validation failure that maps to a refusal response, or a startup config error."""


def discover_roots(instances_dir: str) -> list[str]:
    """The allowed mount roots, read from ``<instances_dir>/*/server.toml``.

    ``instances_dir`` is the ``configs/`` directory (the parent of the per-instance folders and
    of the helper's own ``helper.toml``). One root per instance's ``[workspace].root``. Files
    that are missing, unreadable, not valid TOML, or without a non-empty string
    ``[workspace].root`` are skipped; no usable root yields an empty list, which the caller
    refuses on. Never raises.
    """
    roots: list[str] = []
    try:
        entries = sorted(os.listdir(instances_dir))
    except OSError:
        return roots
    for name in entries:
        config = os.path.join(instances_dir, name, "server.toml")
        if not os.path.isfile(config):
            continue
        try:
            with open(config, "rb") as handle:
                data = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
            continue
        workspace = data.get("workspace")
        if not isinstance(workspace, dict):
            continue
        root = workspace.get("root")
        if isinstance(root, str) and root.strip():
            roots.append(root.strip())
    return roots


def validate_request(req: dict, roots: list[str]) -> dict:
    """Validate a raw request and return the fields needed to act on it, or raise.

    Returns a dict with ``op`` and, per op, the already-whitelisted material. The caller
    supplies ``mount_point``; the helper does **not** re-derive it, it only insists — after
    ``realpath`` — that it lies strictly under **one of the configured ``roots``** (not equal
    to a root, no ``..``). That is the whole confinement: whoever may reach the socket may
    mount anything *under a configured root*, and nothing anywhere else. The roots themselves
    come from the config files, never from the request. The bridge derives the mount point
    as ``root/<hostname>`` on its side.

    Defence in depth: the **last segment** is put through ``sanitize_hostname``
    here as well, so the ASCII/length rule that keeps every refusal reason and log line on
    the wire plain English does not depend on the caller having applied it. A bridge that
    was rebuilt without that boundary check, or a hand-made request, still cannot get a
    non-ASCII or over-long segment onto ``/bin/mount``'s argv. ``roots`` are operator input
    and stay exempt — only the client-derived segment is a hostname.
    """
    if not isinstance(req, dict):
        raise HelperError("request is not an object")
    if not roots:
        raise HelperError("no workspace root is configured")
    op = req.get("op")
    if op not in (mounting.OP_MOUNT, mounting.OP_UMOUNT):
        raise HelperError("only mount and umount are accepted")
    mount_point = str(req.get("mount_point", ""))
    if not mount_point:
        raise HelperError("mount_point is required")
    try:
        mounting.sanitize_hostname(PurePosixPath(mount_point.rstrip("/")).name)
    except MountInputError as exc:
        raise HelperError(f"mount_point's last segment is not a workspace hostname: {exc}")
    try:
        mounting.validate_mount_point_under_any_root(roots, mount_point)
    except MountInputError as exc:
        raise HelperError(str(exc))
    if op == mounting.OP_UMOUNT:
        return {"op": op, "mount_point": mount_point}

    fs_type = str(req.get("fs_type", ""))
    device = str(req.get("device", ""))
    options = req.get("options", [])
    try:
        mounting.validate_device(fs_type, device)
        clean_options = mounting.validate_options(options)
    except MountInputError as exc:
        raise HelperError(str(exc))
    creds = req.get("credentials")
    if fs_type == "cifs":
        if not isinstance(creds, dict) or not creds.get("username") or not creds.get("password"):
            raise HelperError("cifs mount needs username and password credentials")
    # The share owner comes from the server config, passed by the bridge as dedicated
    # fields — never from the caller's mount options (validate_options drops uid=/gid= there).
    try:
        uid = mounting.validate_owner_token("uid", str(req.get("uid", "") or ""))
        gid = mounting.validate_owner_token("gid", str(req.get("gid", "") or ""))
    except MountInputError as exc:
        raise HelperError(str(exc))
    return {
        "op": op,
        "mount_point": mount_point,
        "fs_type": fs_type,
        "device": device,
        "options": clean_options,
        "credentials": creds if isinstance(creds, dict) else {},
        "uid": uid,
        "gid": gid,
    }


class CredentialFile:
    """A ``0600`` temp file holding the cifs credentials block, removed on exit."""

    def __init__(self, username: str, password: str, domain: str):
        self._path: str | None = None
        self._body = "".join([
            f"username={username}\n",
            f"password={password}\n",
            f"domain={domain}\n" if domain else "",
        ])

    def __enter__(self) -> str:
        fd, path = tempfile.mkstemp(prefix="rab-cred-", dir="/run", text=True)
        self._path = path
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0600
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(self._body)
        except OSError:
            self._discard()
            raise
        return path

    def __exit__(self, *exc) -> None:
        self._discard()

    def _discard(self) -> None:
        if self._path is not None:
            try:
                os.unlink(self._path)
            except OSError:
                pass
            self._path = None



def _journal(note: str) -> None:
    """Write an operator note to **stderr**, never stdout.

    The unit sends stdout to the socket (that is the reply channel) but stderr to the
    journal, so anything printed here reaches the operator and cannot corrupt the JSON
    reply the bridge parses.
    """
    print(f"remote-acp-helper: {note}", file=sys.stderr, flush=True)


def default_spawn(argv, *, check, timeout=None):
    """Run mount(8)/umount(8) with its output **captured** and a hard per-attempt timeout.

    measured: once the unit wires stdio to the socket, an un-captured ``/bin/mount``
    prints its own line onto the socket first, and the bridge reads *that* as the reply
    ("workspace helper response unparsable"). Capturing keeps the wire clean; the text is
    still surfaced to the journal for the operator.

    ``timeout`` is the helper's own ``[mount].timeout``. Without it a mount that hangs on an
    unreachable server is waited on forever, and the bridge (which has its own budget) has
    long since moved on.
    """
    return subprocess.run(argv, check=check, timeout=timeout, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")


def _command_output(exc: subprocess.CalledProcessError) -> str:
    text = " ".join(((exc.stderr or "") + " " + (exc.stdout or "")).split())
    return text[:200]


def _run_with_retry(action, *, attempts: int, op: str) -> None:
    """Run ``action`` up to ``attempts`` times and re-raise the last failure.

    ``attempts`` is ``1 + retry`` — the first try plus the configured retries. A retry is
    noted in the journal so an operator sees a flapping share, and only the final failure
    reaches the caller (whose wire reason stays ours and generic).
    """
    for attempt in range(1, attempts + 1):
        try:
            action()
            return
        except (OSError, subprocess.CalledProcessError) as exc:
            if attempt >= attempts:
                raise
            _journal(f"{op} attempt {attempt}/{attempts} failed "
                     f"({type(exc).__name__}), retrying")


def _mount_once(fields: dict, *, spawn, timeout: int) -> None:
    """One ``/bin/mount`` attempt; the credential file lives only for this call."""
    mount_point = fields["mount_point"]
    creds = fields["credentials"]
    if fields["fs_type"] == "cifs":
        with CredentialFile(creds["username"], creds["password"], creds.get("domain", "")) as cred_path:
            options = mounting.build_composed_options(
                fields["fs_type"], fields["options"], cred_path,
                uid=fields.get("uid", ""), gid=fields.get("gid", ""))
            spawn(mounting.build_mount_argv(
                fields["fs_type"], fields["device"], mount_point, options),
                check=True, timeout=timeout)
    else:
        options = mounting.build_composed_options(fields["fs_type"], fields["options"], "")
        spawn(mounting.build_mount_argv(
            fields["fs_type"], fields["device"], mount_point, options),
            check=True, timeout=timeout)


def run_mount(fields: dict, *, spawn=default_spawn, settings: MountSettings | None = None) -> None:
    """Create the mount dir, mount under it (``1 + retry`` attempts), roll back on failure.

    The credential file exists only inside one attempt, so mount sees it by path and it is
    gone before this returns either way. A mount that never succeeded leaves neither a mount
    nor a directory behind.
    """
    budget = settings or MountSettings()
    mount_point = fields["mount_point"]
    os.makedirs(mount_point, mode=0o555, exist_ok=True)
    try:
        _run_with_retry(lambda: _mount_once(fields, spawn=spawn, timeout=budget.timeout),
                        attempts=1 + budget.retry, op="mount")
    except (OSError, subprocess.CalledProcessError):
        # A failed mount must leave neither a mount nor a directory behind: the bridge's
        # gate rolls back its own mount, but this directory is ours (T54 note 5).
        with contextlib.suppress(OSError):
            os.rmdir(mount_point)
        raise


def run_umount(fields: dict, *, spawn=default_spawn, settings: MountSettings | None = None) -> None:
    """Unmount with the same ``1 + retry`` budget as a mount (a busy share can be brief)."""
    budget = settings or MountSettings()
    mount_point = fields["mount_point"]
    _run_with_retry(
        lambda: spawn(mounting.build_umount_argv(mount_point), check=True,
                      timeout=budget.timeout),
        attempts=1 + budget.retry, op="umount")


_mount_locks: dict[str, threading.Lock] = {}
_mount_locks_guard = threading.Lock()


def _mount_lock(key: str) -> threading.Lock:
    """The lock for one already-resolved mount point, created on first use.

    A per-key dict rather than one global lock: two requests for the same share must not
    overlap (mount/umount are not reentrant on one point), while different shares stay
    independent. A request takes exactly one lock, so there is no lock ordering to deadlock.
    """
    with _mount_locks_guard:
        lock = _mount_locks.get(key)
        if lock is None:
            lock = _mount_locks[key] = threading.Lock()
        return lock


def handle(req: dict, *, roots: list[str] | None = None, spawn=default_spawn,
           settings: MountSettings | None = None) -> dict:
    """Pure decision path: validate + act, always returning a ``{ok, reason}`` dict.

    ``roots`` are the allowed mount roots, and the caller must supply them: no roots (or
    ``None``) is a refusal (fail closed). T97 removed the old fallback that read them from a
    hardcoded deployment directory — the helper never guesses where its confinement comes
    from, and ``main`` always passes the directory of the ``--config`` it was given.

    The lock is taken **after** validation and keyed on the resolved mount point, so the
    whole transaction (mount or umount, including the failure rollback) is serialised per
    share — the key is never the caller's raw string.
    """
    budget = settings or MountSettings()
    allowed = list(roots or [])
    if not allowed:
        return {"ok": False, "reason": "no workspace root is configured"}
    try:
        fields = validate_request(req, allowed)
    except HelperError as exc:
        # These reasons are ours (whitelist verdicts), already English and secret-free.
        return {"ok": False, "reason": str(exc)}
    try:
        with _mount_lock(os.path.realpath(fields["mount_point"])):
            if fields["op"] == mounting.OP_MOUNT:
                run_mount(fields, spawn=spawn, settings=budget)
            else:
                run_umount(fields, spawn=spawn, settings=budget)
    except subprocess.CalledProcessError as exc:
        # mount's own words go to the journal, not to the wire: they can name the temporary
        # credential path, and the reason on the control frame has to be ours.
        _journal(f"{fields['op']} failed (rc={exc.returncode}): {_command_output(exc)}")
        return {"ok": False, "reason": "mount command failed"}
    except (OSError, subprocess.TimeoutExpired) as exc:
        # A timeout is a failed attempt like any other; never str(OSError), because strerror
        # is locale-dependent (M4 — a Chinese Windows renders WinError 5 in local words) and
        # this string reaches the client's control frame and the log, which have to be English
        # on every host.
        reason = "mount command timed out" if isinstance(exc, subprocess.TimeoutExpired) \
            else mounting.english_reason(exc)
        _journal(f"{fields['op']} failed: {reason}")
        return {"ok": False, "reason": reason}
    except MountInputError as exc:
        reason = mounting.english_reason(exc)
        _journal(f"{fields['op']} failed: {reason}")
        return {"ok": False, "reason": reason}
    return {"ok": True}


def load_helper_config(path: str) -> str:
    """The helper's socket path, from its own config file.

    The path lives under a ``[socket]`` heading — ``[socket]`` then ``path = "…"`` (2026-10-13
    口径 §6). Missing file ⇒ the default socket (an operator who never created one gets the
    conventional path). A file that cannot be parsed, or whose ``[socket].path`` is not a
    non-empty string, is a startup error with an English message: the service refuses to start
    rather than binding somewhere unexpected. The old top-level ``socket = "…"`` shape is not
    recognised (no compatibility branch).
    """
    if not os.path.isfile(path):
        return DEFAULT_HELPER_SOCKET
    data = _load_config_data(path)
    section = data.get("socket")
    if not isinstance(section, dict):
        # The convention is a ``[socket]`` table. Anything else — the section absent, or the
        # old top-level ``socket = "…"`` string — is not recognised and falls back to the
        # default; there is no compatibility branch for the old shape.
        return DEFAULT_HELPER_SOCKET
    socket_path = section.get("path")
    if not isinstance(socket_path, str) or not socket_path.strip():
        raise HelperError(f"helper config {path}: 'socket.path' must be a non-empty string")
    return socket_path.strip()


def _agent_gid() -> int:
    """The gid of the ``agent`` group the socket is owned by."""
    import grp
    return grp.getgrnam("agent").gr_gid


def _own_socket(path: str, gid: int) -> None:
    """Set the socket to root:agent ``0660``. ``os.chown`` is POSIX-only."""
    os.chmod(path, 0o660)
    chown = getattr(os, "chown", None)
    if chown is not None:
        chown(path, 0, gid)


def bind_socket(path: str, *, socket_factory=socket.socket, own=_own_socket) -> socket.socket:
    """Create the helper's listening AF_UNIX socket at ``path``.

    A stale socket file from a previous run is unlinked first, then ``bind`` + ``listen``, then
    the socket is set to root:agent ``0660`` — the bridge (account ``agent``) connects by
    group, which is the whole access control. Raises (English) if the socket cannot be created
    or the ``agent`` group cannot be resolved. ``socket_factory``/``own`` are injectable so the
    path is unit-tested without AF_UNIX or root.
    """
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    server = socket_factory(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(path)
        server.listen(8)
    except OSError:
        server.close()
        raise
    try:
        gid = _agent_gid()
    except (ImportError, KeyError) as exc:
        server.close()
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise HelperError(
            f"cannot resolve the 'agent' group to own the helper socket: {type(exc).__name__}"
        ) from exc
    own(path, gid)
    return server


def _read_request_line(connection, limit: int = 1 << 20) -> str:
    """One newline-terminated request line from the connection ("" at EOF)."""
    buffer = bytearray()
    while b"\n" not in buffer:
        chunk = connection.recv(4096)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > limit:
            break
    line, _, _ = bytes(buffer).partition(b"\n")
    return line.decode("utf-8", "replace")


def _reply(connection, reply: dict) -> None:
    """Send the one reply; a peer that already left is dropped, never the process.

    ``sendall`` raises ``BrokenPipeError`` when the bridge closed its end first (it gave up
    on its own budget and moved on). That is the connection's problem: unhandled it would
    exit the helper and have systemd restart it, and every connection in that restart window
    would be refused. The same treatment as the ``close()`` beside it.
    """
    with contextlib.suppress(OSError):
        connection.sendall((json.dumps(reply) + "\n").encode("utf-8"))


def _serve_one(connection, roots: list[str], *, spawn=default_spawn,
               settings: MountSettings | None = None) -> None:
    """Handle one connection: one JSON request in, one JSON reply out."""
    raw = _read_request_line(connection)
    if not raw.strip():
        _reply(connection, {"ok": False, "reason": "empty request"})
        return
    try:
        req = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        _reply(connection, {"ok": False, "reason": "request was not valid JSON"})
        return
    _reply(connection, handle(req, roots=roots, spawn=spawn, settings=settings))


def _serve_worker(connection, roots: list[str], spawn, settings: MountSettings,
                  slots: threading.Semaphore) -> None:
    """One accepted connection on its own thread: always closes it, always frees the slot.

    Nothing raised in here may take the service down (the thread's exception would be
    printed and lost); the connection is closed on every path, so none is leaked.
    """
    try:
        _serve_one(connection, roots, spawn=spawn, settings=settings)
    except Exception as exc:                      # noqa: BLE001 — a worker must not kill the service
        _journal(f"connection failed: {type(exc).__name__}")
    finally:
        with contextlib.suppress(OSError):
            connection.close()
        slots.release()


def serve(socket_path: str, roots: list[str], *, server_factory=bind_socket,
          spawn=default_spawn, settings: MountSettings | None = None) -> None:
    """Bind the helper socket and serve requests until killed.

    One connection is one short transaction (read a request, act, reply, close). Each is
    handed to its own thread, so a mount that uses its whole retry budget (20 s at the
    defaults) no longer blocks the next caller; at most ``concurrency`` run at once — the
    accept loop waits on the semaphore, so the listener's backlog holds the rest.
    ``server_factory`` is injectable so the accept loop is unit-tested without AF_UNIX;
    ``spawn`` and ``settings`` are threaded to:func:`handle`.
    """
    budget = settings or MountSettings()
    server = server_factory(socket_path)
    slots = threading.Semaphore(budget.concurrency)
    workers: set[threading.Thread] = set()
    try:
        while True:
            try:
                connection, _ = server.accept()
            except KeyboardInterrupt:
                return
            except OSError:
                continue
            slots.acquire()
            worker = threading.Thread(
                target=_serve_worker, args=(connection, roots, spawn, budget, slots),
                name="rab-helper-mount", daemon=True)
            workers.add(worker)
            worker.start()
            workers = {w for w in workers if w.is_alive()}
    finally:
        server.close()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="remote-acp-helper",
        description="Privileged mount helper for the Remote ACP Bridge.",
    )
    parser.add_argument("--config", required=True,
                        help="path to the helper's own config (its socket path); "
                             "there is no default (T97)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        socket_path = load_helper_config(args.config)
        settings = load_mount_settings(args.config)
        roots = discover_roots(os.path.dirname(os.path.abspath(args.config)))
        serve(socket_path, roots, settings=settings)
    except (HelperError, OSError) as exc:
        print(f"remote-acp-helper: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
