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
import tomllib
from pathlib import PurePosixPath

from . import mounting
from .mounting import MountInputError

# There is no default config path — the helper reads everything from its command line
# (``--config`` is required), so nothing is hardcoded to one deployment root any more. The
# socket default stays: it is a socket's conventional path, overridable in helper.toml.
DEFAULT_HELPER_SOCKET = "/run/remote-acp-helper.sock"


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


def default_spawn(argv, *, check):
    """Run mount(8)/umount(8) with its output **captured**.

    measured: once the unit wires stdio to the socket, an un-captured ``/bin/mount``
    prints its own line onto the socket first, and the bridge reads *that* as the reply
    ("workspace helper response unparsable"). Capturing keeps the wire clean; the text is
    still surfaced to the journal for the operator.
    """
    return subprocess.run(argv, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding="utf-8", errors="replace")


def _command_output(exc: subprocess.CalledProcessError) -> str:
    text = " ".join(((exc.stderr or "") + " " + (exc.stdout or "")).split())
    return text[:200]


def run_mount(fields: dict, *, spawn=default_spawn) -> None:
    """Create the mount dir, mount under it, and roll the dir back if the mount failed.

    The credential file exists only inside the ``with`` block, so mount sees it by path and
    it is gone before this returns either way.
    """
    mount_point = fields["mount_point"]
    os.makedirs(mount_point, mode=0o555, exist_ok=True)
    creds = fields["credentials"]
    try:
        if fields["fs_type"] == "cifs":
            with CredentialFile(creds["username"], creds["password"], creds.get("domain", "")) as cred_path:
                options = mounting.build_composed_options(
                    fields["fs_type"], fields["options"], cred_path,
                    uid=fields.get("uid", ""), gid=fields.get("gid", ""))
                spawn(mounting.build_mount_argv(
                    fields["fs_type"], fields["device"], mount_point, options), check=True)
        else:
            options = mounting.build_composed_options(fields["fs_type"], fields["options"], "")
            spawn(mounting.build_mount_argv(
                fields["fs_type"], fields["device"], mount_point, options), check=True)
    except (OSError, subprocess.CalledProcessError):
        # A failed mount must leave neither a mount nor a directory behind: the bridge's
        # gate rolls back its own mount, but this directory is ours (T54 note 5).
        with contextlib.suppress(OSError):
            os.rmdir(mount_point)
        raise


def run_umount(fields: dict, *, spawn=default_spawn) -> None:
    spawn(mounting.build_umount_argv(fields["mount_point"]), check=True)


def handle(req: dict, *, roots: list[str] | None = None, spawn=default_spawn) -> dict:
    """Pure decision path: validate + act, always returning a ``{ok, reason}`` dict.

    ``roots`` are the allowed mount roots, and the caller must supply them: no roots (or
    ``None``) is a refusal (fail closed). T97 removed the old fallback that read them from a
    hardcoded deployment directory — the helper never guesses where its confinement comes
    from, and ``main`` always passes the directory of the ``--config`` it was given.
    """
    allowed = list(roots or [])
    if not allowed:
        return {"ok": False, "reason": "no workspace root is configured"}
    try:
        fields = validate_request(req, allowed)
    except HelperError as exc:
        # These reasons are ours (whitelist verdicts), already English and secret-free.
        return {"ok": False, "reason": str(exc)}
    try:
        if fields["op"] == mounting.OP_MOUNT:
            run_mount(fields, spawn=spawn)
        else:
            run_umount(fields, spawn=spawn)
    except subprocess.CalledProcessError as exc:
        # mount's own words go to the journal, not to the wire: they can name the temporary
        # credential path, and the reason on the control frame has to be ours.
        _journal(f"{fields['op']} failed (rc={exc.returncode}): {_command_output(exc)}")
        return {"ok": False, "reason": "mount command failed"}
    except (OSError, MountInputError) as exc:
        # Never str(OSError): strerror is locale-dependent (M4 — a Chinese Windows
        # renders WinError 5 in local words) and this string reaches the client's control
        # frame and the log, which have to be English on every host.
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
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise HelperError(f"helper config {path} cannot be read: {type(exc).__name__}") from exc
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
    connection.sendall((json.dumps(reply) + "\n").encode("utf-8"))


def _serve_one(connection, roots: list[str], *, spawn=default_spawn) -> None:
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
    _reply(connection, handle(req, roots=roots, spawn=spawn))


def serve(socket_path: str, roots: list[str], *, server_factory=bind_socket,
          spawn=default_spawn) -> None:
    """Bind the helper socket and serve requests until killed.

    One connection is one short transaction (read a request, act, reply, close), handled
    serially — a per-mount helper needs no concurrency. ``server_factory`` is injectable so the
    accept loop is unit-tested without AF_UNIX; ``spawn`` is threaded to:func:`handle`.
    """
    server = server_factory(socket_path)
    try:
        while True:
            try:
                connection, _ = server.accept()
            except KeyboardInterrupt:
                return
            except OSError:
                continue
            try:
                _serve_one(connection, roots, spawn=spawn)
            finally:
                with contextlib.suppress(OSError):
                    connection.close()
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
        roots = discover_roots(os.path.dirname(os.path.abspath(args.config)))
        serve(socket_path, roots)
    except (HelperError, OSError) as exc:
        print(f"remote-acp-helper: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
