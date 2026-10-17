"""remote-acp-client: local stdio <-> WebSocket bridge for ACP hosts.

The client is itself an ACP agent as far as the host is concerned: it speaks
ndjson on stdin/stdout and relays every message to a remote agent over an
authenticated WebSocket. stdout stays pure ACP; everything else goes to stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import collections
import hashlib
import hmac
import json
import logging
import os
import ssl
import subprocess
import sys
import threading
import uuid as uuid_module
from contextlib import suppress

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from . import __version__
from .auth import SESSION_HEADER, auth_headers
from .config import ClientConfig, ClientWorkspaceConfig, ConfigError, ServerTarget
from .frames import (
    CLOSE_SESSION_END,
    CWD_ERROR_CODE,
    CWD_ERROR_PREFIX,
    CWD_REASON_NOT_DIRECTORY,
    CWD_REASON_NOT_FOUND,
    CWD_REASON_NOT_MOUNTED,
    CWD_REASON_NOT_READABLE,
    MAX_FRAME_BYTES,
    SENTINEL_NAME,
)
from .mounting import english_reason

PENDING_OUT_MAX = 1000
RETRY_BASE_SECONDS = 0.5
RETRY_MAX_SECONDS = 10
# CLOSE_SESSION_END (1000) means the session itself is over, so reconnecting is
# pointless; CLOSE_RESUMABLE (1001, same home) means only this connection was dropped
# and the session is still there to resume. R9: the client used to treat the two as one.
# The uuid you are dialling is gone and no reconnect will bring it back: the server
# declared the session ended (1000), or a handshake for it was refused (404/410).
EXIT_SESSION_GONE = 3
# The uuid is announced once an ACP session id is known, because that is the
# only form a host can render. If the agent never yields one, fall back to the
# bridge session id after this grace period.
INJECT_FALLBACK_SECONDS = 5.0

FATAL_STATUSES = {401: 4, 403: 5, 404: EXIT_SESSION_GONE, 410: EXIT_SESSION_GONE}
EXIT_TLS_REJECTED = 6
# The server refused the handshake because our workspace could not be mounted or gated
#: a 412 for the mount/gate and a 400 for a malformed Config header. The descriptor,
# credentials, device or share is wrong, and a reconnect would only ask it to mount the same
# thing again. Fatal, with the reason, never silent.
EXIT_WORKSPACE_REFUSED = 7
WORKSPACE_REFUSAL_STATUSES = {400: EXIT_WORKSPACE_REFUSED, 412: EXIT_WORKSPACE_REFUSED}
# R6 (unified across both binaries): 1 = the configuration is wrong, 2 = the command
# line is wrong. Usage errors leave via argparse, which already exits 2, so only the
# config path needed a code of its own.
EXIT_CONFIG_ERROR = 1


def log(msg: str) -> None:
    print(f"[remote-acp-client] {msg}", file=sys.stderr, flush=True)


# Severity numbers matching ``LoggingConfig.LEVELS``: the client's own lines are INFO,
# its problem lines ERROR, and the frame trace DEBUG.
LOG_DEBUG = 10
LOG_INFO = 20
LOG_ERROR = 40


def client_ssl(target: ServerTarget, insecure: bool) -> ssl.SSLContext | None:
    if not target.tls.enabled:
        return None
    if insecure or target.tls.insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if target.tls.ca_file:
        return ssl.create_default_context(cafile=target.tls.ca_file)
    return ssl.create_default_context()


# -- Certificate pinning ------------------------------------------------------------
#
# ``[servers.tls].fingerprint`` is a pin: verify the peer's certificate DER against
# ``base64(SHA-256(DER))`` **before the WebSocket upgrade leaves the machine** — that request
# carries the bridge key, so checking afterwards would already have handed it to an impostor.
# websockets cannot reuse a socket we TLS-wrapped ourselves (``ssl=None`` is rejected for a
# ``wss://`` URI since 15.0), but it exposes the documented ``create_connection`` hook: the
# connection's ``connection_made`` fires right after the TLS handshake, before the Sans-I/O
# layer's first write. That is the one supported point that is both after the certificate is
# known and before any of our bytes are out.


class FingerprintRejected(Exception):
    """The peer certificate did not match ``[servers.tls].fingerprint``."""


def fingerprint_of_der(der: bytes) -> str:
    """``base64(SHA-256(der))`` — the form the pin is written in."""
    return base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")


def fingerprint_matches(expected: str, der: bytes) -> bool:
    """Compare the pin to a peer certificate's DER, constant-time."""
    return hmac.compare_digest(fingerprint_of_der(der), expected)


def pinned_connection_class(expected: str, failures: list) -> type:
    """A ``ClientConnection`` that checks the pin before anything is written.

    On a mismatch (or a certificate we cannot read at all — never a silent pass) it records
    the English reason and aborts the transport, so ``connect()`` fails without the upgrade
    request ever having been sent. ``failures`` is the caller's list; whichever reason lands
    there is what the reconnect loop reports.
    """

    class PinnedConnection(ClientConnection):
        def connection_made(self, transport) -> None:
            ssl_object = transport.get_extra_info("ssl_object") if transport else None
            der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
            if not der:
                failures.append("tls peer certificate is unavailable for the fingerprint check")
                transport.abort()
                return
            if not fingerprint_matches(expected, der):
                failures.append("tls certificate fingerprint mismatch")
                transport.abort()
                return
            super().connection_made(transport)

    return PinnedConnection


def session_notice(acp_session_id: str, bridge_session_id: str) -> str:
    """ACP session/update notification carrying the bridge session uuid."""
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": acp_session_id,
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": bridge_session_id},
                },
            },
        },
        separators=(",", ":"),
    )


def observed_acp_session_id(frame: str) -> str | None:
    """Pull a session id out of a frame without interpreting ACP semantics."""
    try:
        message = json.loads(frame)
    except (ValueError, TypeError):
        return None
    if not isinstance(message, dict):
        return None
    for field in ("params", "result"):
        value = message.get(field)
        if isinstance(value, dict) and isinstance(value.get("sessionId"), str):
            return value["sessionId"]
    return None


def frame_trace_enabled() -> bool:
    """``RAB_TRACE=1`` mirrors every frame through the client onto stderr."""
    return os.environ.get("RAB_TRACE", "") == "1"


# ACP methods whose params carry the *local* working directory the host wants the agent
# to work in, and the host's own MCP servers. On a remote bridge both are the host's
# local facts, which the remote agent cannot use (T27: opencode answers a Windows cwd
# with -32603 "OpenCode service failure" on the first prompt).
CWD_METHODS = frozenset({"session/new", "session/load", "session/resume"})


def normalize_uplink(frame: str, *, pass_mcp: collections.abc.Sequence[str] = ("*",)
                     ) -> tuple[str, str]:
    """Rewrite one uplink frame's ``mcpServers`` the way the operator opted into.

    Returns ``(frame, note)``. Deliberately narrow, so the bridge keeps its "never interpret
    ACP" stance: ``pass_mcp`` containing ``*`` (the default) returns the frame **byte for
    byte**, only the three session-opening methods' ``mcpServers`` is ever touched, and
    anything that cannot be parsed as a JSON-RPC request goes out exactly as it came in.
    ``note`` (what changed, for stderr) is empty whenever nothing did, and never names a value.

    A list without ``*`` keeps only the entries whose ``name`` is listed — an entry with no
    ``name``, or a non-string one, cannot be named and is therefore dropped. ``pass_mcp = []``
    drops every entry, which is what the removed ``drop_local_mcp = true`` used to do.
    """
    if "*" in pass_mcp:
        return frame, ""
    try:
        message = json.loads(frame)
    except (ValueError, TypeError):
        return frame, ""
    if not isinstance(message, dict) or message.get("method") not in CWD_METHODS:
        return frame, ""
    params = message.get("params")
    if not isinstance(params, dict):
        return frame, ""
    servers = params.get("mcpServers")
    if not isinstance(servers, list) or not servers:
        return frame, ""
    kept = [
        entry
        for entry in servers
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
        and entry["name"] in pass_mcp
    ]
    if len(kept) == len(servers):
        return frame, ""          # every entry is allowed through: not one byte changes
    params["mcpServers"] = kept
    return (
        json.dumps(message, separators=(",", ":"), ensure_ascii=False),
        f"mcpServers: passed {len(kept)} entr(ies), dropped {len(servers) - len(kept)}",
    )


class ShareLinkError(Exception):
    """The host's session cwd could not be linked into this client's share."""


def share_link_name(cwd: str) -> str:
    """The link name for a host cwd inside the share: the cwd's own last segment.

    The AionUi project folder name is the natural stable name, and the whole share is one
    namespace, so two cwds whose last segment is the same are the same project and must map to
    the same link — no hash, no suffix. Falls back to ``workspace`` for a cwd with no
    last segment (e.g. a filesystem root).
    """
    return os.path.basename(os.path.normpath(cwd)) or "workspace"


def _make_dir_link(target: str, link: str) -> None:
    """A junction on Windows (``mklink /J``); a directory symlink anywhere else.

    A junction needs no privilege, unlike a directory symlink, which needs
    ``SeCreateSymbolicLinkPrivilege`` (Developer Mode or an elevated shell).
    """
    if os.name == "nt":
        result = subprocess.run(["cmd", "/c", "mklink", "/J", link, target],
                                capture_output=True, text=True)
        if result.returncode != 0 or not os.path.lexists(link):
            detail = (result.stderr or result.stdout or "").strip() or f"exit {result.returncode}"
            raise ShareLinkError(f"cannot create junction {link!r} -> {target!r}: {detail}")
        return
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        raise ShareLinkError(f"cannot link {link!r} -> {target!r}: {exc}") from exc


def ensure_share_link(share_dir: str, cwd: str) -> str:
    """Link ``cwd`` into ``share_dir`` idempotently; return the link **name**.

    The name is the cwd's last segment. An entry of that name already present in the share is
    reused as-is — same name means the same project — so a reconnect or a second session for
    the same folder never adds a suffix or a second link. Nothing is moved or copied.
    """
    target = os.path.abspath(cwd)
    if not os.path.isdir(target):
        raise ShareLinkError(f"session cwd {cwd!r} is not an existing directory")
    name = share_link_name(cwd)
    link = os.path.join(share_dir, name)
    if os.path.lexists(link):
        return name
    try:
        os.makedirs(share_dir, exist_ok=True)
    except OSError as exc:
        raise ShareLinkError(f"cannot create share dir {share_dir!r}: {exc}") from exc
    _make_dir_link(target, link)
    return name


def seed_workspace_sentinel(workspace: ClientWorkspaceConfig | None) -> None:
    """Seed ``<share_dir>/<SENTINEL_NAME>`` with the token before the first handshake.

    The server's gate reads that fixed file from *its* mount of the same share, so the client
    writes it once, and only when this server carries a ``[servers.workspace]`` (branch A). An
    existing file is left byte-for-byte untouched (idempotent). A failure to write is **not
    fatal** — the server's gate is the definitive refusal — and is reported in English pure
    ASCII so the run continues with the same exit codes.
    """
    if workspace is None or not workspace.share_dir or not workspace.sentinel_token:
        return
    path = os.path.join(workspace.share_dir, SENTINEL_NAME)
    if os.path.exists(path):
        return
    try:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(workspace.sentinel_token)
    except (OSError, ValueError) as exc:
        log(f"cannot write workspace sentinel file {SENTINEL_NAME}: {english_reason(exc)}")


def map_cwd_into_share(frame: str, *, share_dir: str) -> tuple[str, str]:
    """Branch A uplink rewrite: link the host cwd into the share, send only the link name.

    Only the three session-opening methods are touched, only their ``cwd``, and only when it
    is a non-empty string; anything else goes out byte-for-byte. Returns ``(frame, note)``,
    with an empty note when nothing changed.
    """
    if not share_dir:
        return frame, ""
    try:
        message = json.loads(frame)
    except (ValueError, TypeError):
        return frame, ""
    if not isinstance(message, dict) or message.get("method") not in CWD_METHODS:
        return frame, ""
    params = message.get("params")
    if not isinstance(params, dict):
        return frame, ""
    cwd = params.get("cwd")
    if not isinstance(cwd, str) or not cwd.strip():
        return frame, ""
    name = ensure_share_link(share_dir, cwd)
    params["cwd"] = name
    return (
        json.dumps(message, separators=(",", ":"), ensure_ascii=False),
        f"cwd {cwd!r} -> share link {name!r}",
    )


TRACE_LIMIT = 4000


def _trace_line(frame: str) -> str:
    """One frame for the trace, cut at a readable length so a big payload cannot flood."""
    if len(frame) <= TRACE_LIMIT:
        return frame
    return f"{frame[:TRACE_LIMIT]}... (+{len(frame) - TRACE_LIMIT} bytes)"


def _without_terminator(line: bytes) -> bytes:
    if line.endswith(b"\r\n"):
        return line[:-2]
    if line.endswith(b"\n"):
        return line[:-1]
    return line


def _read_line(stream, limit: int) -> tuple[bytes, int]:
    """Read one newline-terminated stdin line of at most ``limit`` payload bytes.

    Returns ``(line, oversize_bytes)``: ``line`` is the raw line (possibly without
    a terminator at EOF), ``oversize_bytes`` is the **frame length** of a rejected
    line — the terminator is excluded, so an over-long line is reported with the
    same number the send gate would have used. ``line`` is then empty.
    An over-long line is drained up to its terminator so the stream stays in sync
    instead of desynchronising the host's framing.
    """
    parts: list[bytes] = []
    total = 0
    while True:
        chunk = stream.readline(limit + 2)
        if not chunk:
            return b"".join(parts), 0
        parts.append(chunk)
        total += len(chunk)
        if chunk.endswith(b"\n"):
            return b"".join(parts), 0
        if total > limit:
            while True:
                extra = stream.readline(limit + 2)
                if not extra:
                    break
                parts.append(extra)
                if extra.endswith(b"\n"):
                    break
            return b"", len(_without_terminator(b"".join(parts)))


class BridgeClient:
    def __init__(
        self,
        target: ServerTarget,
        agent: str,
        key: str,
        *,
        session_id: str = "",
        insecure: bool = False,
        quiet: bool = False,
        workspace: dict | None = None,
        share_dir: str = "",
        workspace_account: str = "",
    ):
        self.target = target
        self.agent = agent
        self.key = key
        self.session_id = session_id
        self.insecure = insecure
        self.quiet = quiet
        self.share_dir = share_dir
        # The share account (client workspace `username`) and the host's own cwd per request:
        # the client uses both to translate the server's cwd error into the final host-facing
        # text.
        self.workspace_account = workspace_account
        self._host_cwd_by_id: dict = {}
        self._last_host_cwd = ""
        self.path = f"/agents/{agent}"
        self.url = target.url(self.path)
        # The workspace descriptor travels in the handshake Config header, sent fresh
        # on every connect so a reconnect re-proves its mount. None when no [workspace] section
        # is configured. The password is inside it and is never logged (headers are not traced).
        self._workspace = workspace
        self._out_queue: asyncio.Queue[str | None] = asyncio.Queue()
        self._pending_out: collections.deque[str] = collections.deque()
        self._dropped_out = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._eof = False
        self._injected = False
        self._acp_session_id: str | None = None
        self._frames_up = 0
        self._frames_down = 0
        self._frames_rejected = 0
        self.inject_fallback_seconds = INJECT_FALLBACK_SECONDS
        self.pass_mcp = target.pass_mcp
        # This server's log sink: `[servers.logging]`. No file ⇒ stderr only, exactly
        # as before. A named file gets a level-filtered mirror of the client's lines and, at
        # ``debug``, the frame trace too — with one global, cross-direction sequence number.
        self._log_file = target.logging.file
        self._log_enabled = target.logging.enabled
        self._log_level = target.logging.severity
        self._log_handle = None
        if self._log_enabled and self._log_file:
            try:
                self._log_handle = open(self._log_file, "a", encoding="utf-8")
            except OSError as exc:
                log(f"cannot open client log file {ascii(self._log_file)}, writing to stderr: "
                    f"{english_reason(exc)}")
        self._trace_seq = 0
        self._trace_to_file = (target.logging.level == "debug" and self._log_enabled
                               and bool(self._log_file))
        self._trace_to_stderr = frame_trace_enabled()
        self.trace = self._trace_to_file or self._trace_to_stderr

    def _say(self, msg: str) -> None:
        if not self.quiet:
            log(msg)
            self._mirror_line(LOG_INFO, msg)

    def _problem(self, msg: str) -> None:
        log(msg)
        self._mirror_line(LOG_ERROR, msg)

    def _mirror_line(self, severity: int, msg: str) -> None:
        """Mirror one client line into this server's log file. stderr already carries
        it, so a broken sink does not duplicate it onto stderr here — only traces fall back."""
        if not self._log_enabled or not self._log_file or severity < self._log_level:
            return
        self._write_file(msg)

    def _write_file(self, msg: str) -> bool:
        if self._log_handle is None:
            return False
        try:
            self._log_handle.write(f"[remote-acp-client] {msg}\n")
            self._log_handle.flush()
            return True
        except OSError as exc:
            self._log_handle = None
            log(f"cannot write client log file {ascii(self._log_file)}, writing to stderr: "
                f"{english_reason(exc)}")
            return False

    def _emit_trace(self, arrow: str, frame: str) -> None:
        self._trace_seq += 1
        text = f"{arrow}#{self._trace_seq} {_trace_line(frame)}"
        if self._trace_to_file and not self._write_file(text):
            print(f"[remote-acp-client] {text}", file=sys.stderr, flush=True)   # sink broke
        if self._trace_to_stderr:
            log(text)

    # -- stdio plumbing ----------------------------------------------------

    def _read_stdin_thread(self) -> None:
        stream = sys.stdin.buffer
        while True:
            try:
                line, oversize = _read_line(stream, MAX_FRAME_BYTES)
            except (ValueError, OSError) as exc:
                self._loop.call_soon_threadsafe(self._problem, f"stdin read failed: {exc!r}")
                break
            if oversize:
                self._loop.call_soon_threadsafe(self._note_oversize, oversize)
            if line:
                text = line.decode("utf-8", errors="replace").rstrip("\r\n")
                if text and not oversize:
                    self._loop.call_soon_threadsafe(self._out_queue.put_nowait, text)
            if not line and not oversize:
                break
        self._loop.call_soon_threadsafe(self._out_queue.put_nowait, None)

    def _write_stdout(self, frame: str) -> None:
        sys.stdout.buffer.write((frame + "\n").encode("utf-8"))
        sys.stdout.buffer.flush()

    # -- connection --------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return auth_headers(self.key, session=self.session_id, workspace=self._workspace)

    async def _open(self):
        # With a pin configured, the check rides on the documented create_connection
        # hook (see the module's pinning note). Without one this is byte-for-byte the old
        # call, so a config that never set ``fingerprint`` behaves exactly as before.
        kwargs: dict = {}
        failures: list[str] = []
        if self.target.tls.fingerprint:
            kwargs["create_connection"] = pinned_connection_class(
                self.target.tls.fingerprint, failures)
        try:
            return await connect(
                self.url,
                additional_headers=self._headers(),
                max_size=MAX_FRAME_BYTES,
                ssl=client_ssl(self.target, self.insecure),
                **kwargs,
            )
        except Exception as exc:
            if failures:
                raise FingerprintRejected(failures[0]) from exc
            raise

    def _buffer_out(self, frame: str) -> None:
        if len(self._pending_out) >= PENDING_OUT_MAX:
            self._pending_out.popleft()
            self._dropped_out += 1
        self._pending_out.append(frame)

    async def _pump(self, connection) -> str:
        """Relay until one direction ends; return "host-ended", "server-ended" or "retry".

        R9: a clean remote close does **not** raise out of ``async for`` — it ends the
        read the same way for 1000 and 1001 — so the decision has to come from the close
        code, not from whether an exception appeared.
        """
        sender = asyncio.create_task(self._send_loop(connection))
        receiver = asyncio.create_task(self._recv_loop(connection))
        timer = asyncio.create_task(self._inject_timer())
        host_ended = False
        server_ended = False
        try:
            done, _ = await asyncio.wait(
                {sender, receiver}, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                exc = task.exception()
                if exc is None:
                    code = connection.close_code
                elif isinstance(exc, ConnectionClosed):
                    # Prefer the frame the server actually sent over what the connection
                    # settled on: a close we started ourselves leaves both at 1000.
                    code = exc.rcvd.code if exc.rcvd is not None else connection.close_code
                else:
                    self._say(f"pump failed: {exc!r}")
                    code = None
                if self._eof:
                    # The host closed stdin, so this goodbye is ours: a normal end.
                    host_ended = True
                elif code == CLOSE_SESSION_END:
                    # The server says the session itself is over: dialling it again can
                    # only answer 404, so this is not a retryable drop.
                    server_ended = True
        finally:
            for task in (sender, receiver, timer):
                task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await task
            with suppress(Exception):
                await connection.close()
        if host_ended:
            return "host-ended"
        return "server-ended" if server_ended else "retry"

    def _uplink(self, frame: str) -> str:
        """The one place a host frame is touched on its way up."""
        if self.share_dir:
            self._remember_host_cwd(frame)
        prepared, changed = normalize_uplink(frame, pass_mcp=self.pass_mcp)
        if changed:
            self._say(f"normalised uplink: {changed}")
        if self.share_dir:
            try:
                prepared, note = map_cwd_into_share(prepared, share_dir=self.share_dir)
            except ShareLinkError as exc:
                # Leave the frame as the host wrote it: the server (branch A) will refuse a
                # cwd it cannot join onto the share, so the failure is loud, never silent.
                self._problem(f"workspace share link failed: {exc}")
            else:
                if note:
                    self._say(f"workspace uplink: {note}")
        if self.trace:
            self._emit_trace("UP   ", prepared)
        return prepared

    async def _send_loop(self, connection) -> None:
        while True:
            while self._pending_out:
                frame = self._uplink(self._pending_out[0])
                if self._check_size(frame):
                    try:
                        await connection.send(frame)
                    except ConnectionClosed as exc:
                        self._problem(f"buffered frame still undelivered ({exc}): keeping it for the next connect")
                        raise
                    self._pending_out.popleft()
                    self._frames_up += 1
                else:
                    self._pending_out.popleft()
            frame = await self._out_queue.get()
            if frame is None:
                self._eof = True
                await connection.close(code=CLOSE_SESSION_END, reason="session-end")
                return
            frame = self._uplink(frame)
            if not self._check_size(frame):
                continue
            try:
                await connection.send(frame)
            except ConnectionClosed:
                self._buffer_out(frame)
                raise
            self._frames_up += 1

    def _check_size(self, frame: str) -> bool:
        """Frames over the wire limit are refused out loud, never silently dropped."""
        size = len(frame.encode("utf-8"))
        if size <= MAX_FRAME_BYTES:
            return True
        self._note_oversize(size)
        return False

    def _note_oversize(self, size: int) -> None:
        self._frames_rejected += 1
        self._problem(
            f"REFUSED frame of {size} bytes: over the {MAX_FRAME_BYTES} byte limit. "
            f"It was not sent, so its request will get no answer "
            f"(rejected={self._frames_rejected}). Increase the host message size or split the payload."
        )

    def _buffer_out(self, frame: str) -> None:
        if len(self._pending_out) >= PENDING_OUT_MAX:
            dropped = self._pending_out.popleft()
            self._dropped_out += 1
            self._problem(
                f"reconnect buffer full ({PENDING_OUT_MAX} frames): dropped oldest "
                f"frame of {len(dropped)} bytes (dropped={self._dropped_out})"
            )
        self._pending_out.append(frame)

    def _remember_host_cwd(self, frame: str) -> None:
        """Record the host's own cwd per request id.

        The client knows the folder AionUi chose (a local path); the server only knows the
        mounted share path. Remembering it lets the client name the folder accurately when it
        translates a server cwd error back to the host.
        """
        try:
            message = json.loads(frame)
        except (ValueError, TypeError):
            return
        if not isinstance(message, dict) or message.get("method") not in CWD_METHODS:
            return
        params = message.get("params")
        if not isinstance(params, dict):
            return
        cwd = params.get("cwd")
        if not isinstance(cwd, str) or not cwd.strip():
            return
        self._last_host_cwd = cwd
        if "id" in message:
            try:
                self._host_cwd_by_id[message["id"]] = cwd
            except TypeError:
                # A JSON id can be a list/dict (unhashable); it simply cannot be remembered.
                pass

    def _cwd_error_text(self, server_message: str, host_cwd: str) -> str:
        """The final host-facing text for a server cwd error.

        The server names the reason; the client supplies the folder (its own local path) and,
        for a permission failure, the share account to grant access to. Verbatim permission
        template (leader, 2026-10-13):
        ``session working directory is not accessible in the mounted share: Permission denied;
        grant the share account '<account>' read access to '<folder>' on the client.``
        """
        folder = host_cwd or self._last_host_cwd or "the selected folder"
        if CWD_REASON_NOT_READABLE in server_message:
            return (f"{CWD_ERROR_PREFIX}: Permission denied; grant the share account "
                    f"'{self.workspace_account}' read access to '{folder}' on the client.")
        for reason in (CWD_REASON_NOT_MOUNTED, CWD_REASON_NOT_FOUND, CWD_REASON_NOT_DIRECTORY):
            if reason in server_message:
                return f"{CWD_ERROR_PREFIX}: {reason}; path '{folder}' on the client."
        return server_message

    def _translate_cwd_error(self, frame: str) -> str:
        """Rewrite a server cwd error's message for the host; else return it as-is.

        Gated on the **request id**: only an error whose id matches a session-opening request
        this client recorded is ours to rewrite. Anything else — a different id, a foreign
        source, or an unhashable JSON id — goes out byte-for-byte, so a downstream agent that
        happens to use the same code/message is never touched.
        """
        if not self.share_dir:
            return frame
        try:
            message = json.loads(frame)
        except (ValueError, TypeError):
            return frame
        if not isinstance(message, dict):
            return frame
        error = message.get("error")
        if not isinstance(error, dict) or error.get("code") != CWD_ERROR_CODE:
            return frame
        request_id = message.get("id")
        try:
            host_cwd = self._host_cwd_by_id.get(request_id)
        except TypeError:
            return frame          # unhashable id: not one of ours
        if host_cwd is None:
            return frame          # not a session-opening request we recorded
        error["message"] = self._cwd_error_text(str(error.get("message", "")), host_cwd)
        # One cwd error answers one request: forget the mapping (S1: the map must not only grow).
        self._host_cwd_by_id.pop(request_id, None)
        return json.dumps(message, separators=(",", ":"), ensure_ascii=False)

    async def _recv_loop(self, connection) -> None:
        async for frame in connection:
            if isinstance(frame, bytes):
                frame = frame.decode("utf-8", errors="replace")
            self._frames_down += 1
            if self.trace:
                self._emit_trace("DOWN ", frame)
            frame = self._translate_cwd_error(frame)
            if self._acp_session_id is None:
                self._acp_session_id = observed_acp_session_id(frame)
            self._write_stdout(frame)
            await self._inject()

    async def _inject_timer(self) -> None:
        await asyncio.sleep(self.inject_fallback_seconds)
        await self._inject(force=True)

    async def _inject(self, force: bool = False) -> None:
        if self._injected or not self.session_id:
            return
        if self._acp_session_id is None and not force:
            return
        self._injected = True
        self._write_stdout(session_notice(self._acp_session_id or self.session_id, self.session_id))
        self._say("announced session uuid on stdout")

    # -- main loop ---------------------------------------------------------

    async def run(self) -> int:
        self._loop = asyncio.get_running_loop()
        threading.Thread(target=self._read_stdin_thread, name="acp-stdin", daemon=True).start()
        if (self.insecure or self.target.tls.insecure) and self.target.tls.enabled:
            self._problem("TLS certificate verification is disabled (insecure)")
        attempts = 0
        while True:
            try:
                connection = await self._open()
            except InvalidStatus as exc:
                status = exc.response.status_code
                reason = exc.response.reason_phrase
                detail = refusal_reason(exc)
                if status in FATAL_STATUSES:
                    self._problem(f"handshake rejected: HTTP {status} {reason}" + (f": {detail}" if detail else ""))
                    return FATAL_STATUSES[status]
                if status in WORKSPACE_REFUSAL_STATUSES:
                    # The server refused the handshake because our [workspace] could not be
                    # mounted or gated (bad credentials, wrong or unreachable share), or the
                    # Config header was malformed. Reconnecting only asks it to mount the same
                    # thing again, so this is fatal. The reason is the server's, not a secret.
                    self._problem(f"workspace refused by server: HTTP {status} {reason}"
                                  + (f": {detail}" if detail else "") + f", not reconnecting ({self.stats()})")
                    return EXIT_WORKSPACE_REFUSED
                if status >= 500:
                    # A 5xx carries the server's own reason (a refused session cwd, an
                    # agent that will not start). Going quiet about it turns a permanent
                    # shape problem into an endless silent reconnect, so this
                    # goes through ``_problem`` and survives --quiet.
                    self._problem(f"handshake refused: HTTP {status} {reason}"
                                  + (f": {detail}" if detail else "") + ", retrying")
                else:
                    self._say(f"handshake failed: HTTP {status} {reason}, retrying")
            except FingerprintRejected as exc:
                # A pin is a hard stop. The upgrade was never sent, so the server is
                # simply not the one this config trusts — no retry, no reconnect.
                self._problem(f"{exc}. Check [servers.tls].fingerprint against the real server.")
                return EXIT_TLS_REJECTED
            except ssl.SSLCertVerificationError as exc:
                # verify_message is set by CPython's ssl layer, not by every code path
                # that can raise this class, so the handler must not depend on it.
                detail = getattr(exc, "verify_message", None) or exc
                self._problem(f"TLS certificate rejected: {detail}. Trust it via [servers.tls].ca_file or pass --insecure.")
                return EXIT_TLS_REJECTED
            except ssl.SSLError as exc:
                # Local TLS material that stopped being usable mid-session. Never
                # transient: retrying an unparseable PEM is what R5 was.
                self._problem(f"TLS setup failed: {exc}. Check [servers.tls].ca_file.")
                return EXIT_TLS_REJECTED
            except (OSError, asyncio.TimeoutError) as exc:
                self._say(f"connect failed: {exc!r}")
            else:
                attempts = 0
                returned = connection.response.headers.get(SESSION_HEADER) or ""
                resumed = bool(self.session_id) and returned == self.session_id
                self.session_id = returned or self.session_id
                self._say(f"connected {self.url} session={self.session_id} ({'resume' if resumed else 'new'})")
                action = await self._pump(connection)
                if action == "host-ended":
                    self._say(f"session ended ({self.stats()})")
                    return 0
                if action == "server-ended":
                    # Loud even under --quiet: the host asked for a session the remote
                    # side just retired, and silence here would look like a clean exit.
                    self._problem(f"server ended the session ({CLOSE_SESSION_END}): not reconnecting ({self.stats()})")
                    return EXIT_SESSION_GONE
            attempts += 1
            delay = min(RETRY_MAX_SECONDS, RETRY_BASE_SECONDS * 2 ** (attempts - 1))
            self._say(f"reconnecting in {delay:.1f}s (attempt {attempts})")
            await asyncio.sleep(delay)

    def stats(self) -> str:
        return (
            f"up={self._frames_up} down={self._frames_down} "
            f"buffered={len(self._pending_out)} dropped={self._dropped_out} "
            f"rejected={self._frames_rejected}"
        )


def resolve_target(cfg: ClientConfig, name: str, agent: str) -> ServerTarget:
    target = cfg.servers.get(name)
    if target is None:
        known = ", ".join(sorted(cfg.servers)) or "none"
        raise ConfigError(f"unknown server {name!r} (configured: {known})")
    if target.agents and agent not in target.agents:
        raise ConfigError(
            f"agent {agent!r} is not enabled on server {name!r} "
            f"(configured: {', '.join(target.agents)})"
        )
    return target


def refusal_reason(exc: InvalidStatus) -> str:
    """The server's own one-line reason for a refused handshake, from the response body.

    ``Bridge._reject`` puts the real cause in the body ("cannot create session cwd
    …"), and without it a refusal that never becomes fatal shows up as a bare
    ``HTTP 500 …, retrying`` forever.

    ``websockets`` hands the body over as a ``bytearray``, not ``bytes``, so both have to
    be decoded — otherwise the line the operator is supposed to read becomes
    ``bytearray(b'…')`` with escaped bytes for anything non-ASCII.
    """
    body = getattr(exc.response, "body", b"") or b""
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8", "replace")
    for line in str(body).splitlines():
        if line.strip():
            return line.strip()
    return ""


def resolve_client_key(cfg: ClientConfig, target: ServerTarget) -> str:
    """The key for the server we are connecting to.

    Each [[servers]] entry carries its own inline key; the client-wide ``keys_file`` is
    abolished. ``load`` already guarantees every server has a key, so this never has to
    guess.
    """
    if target.key:
        return target.key
    raise ConfigError(f"[servers] {target.name}: key = \"...\" is required (T53: per-server key)")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="remote-acp-client",
        description="Bridge a local ACP host's stdio to a remote ACP agent.",
    )
    parser.add_argument("--config", required=True, help="path to the client config (required; nothing is read by default)")
    parser.add_argument("--server", required=True, help="[[servers]] name to connect to")
    parser.add_argument("--agent", required=True, help="remote agent name (URL /agents/<name>)")
    parser.add_argument("--session", help="bridge session uuid to resume")
    parser.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help=(
            "suppress routine stderr messages; problems are still reported "
            "(bad config, refused frames, dropped frames, handshake rejections, TLS warnings)"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    if args.session:
        try:
            args.session = str(uuid_module.UUID(args.session))
        except ValueError:
            parser.error(f"--session must be a uuid, got {args.session!r}")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    # The handshake Config header carries the share password, and websockets' DEBUG
    # trace logs request headers. Pin the library loggers regardless of how the launching host
    # has configured root logging.
    for name in ("websockets", "websockets.client"):
        logging.getLogger(name).setLevel(logging.INFO)
    try:
        cfg = ClientConfig.load(args.config)
        target = resolve_target(cfg, args.server, args.agent)
        key = resolve_client_key(cfg, target)
    except (ConfigError, OSError) as exc:
        log(str(exc))
        return EXIT_CONFIG_ERROR
    # Before any handshake (the server gates the sentinel at handshake time, T20): make sure
    # the share the server will mount carries the sentinel file it will read.
    seed_workspace_sentinel(target.workspace)
    client = BridgeClient(
        target,
        args.agent,
        key,
        session_id=args.session or "",
        insecure=args.insecure,
        quiet=args.quiet,
        workspace=target.workspace.as_descriptor() if target.workspace else None,
        share_dir=target.workspace.share_dir if target.workspace else "",
        workspace_account=target.workspace.username if target.workspace else "",
    )
    try:
        return asyncio.run(client.run())
    except KeyboardInterrupt:
        log("interrupted")
        return 130


def cli_entry(argv: list[str] | None = None) -> int:
    """The one finalize every entry point shares (shim, ``-m``, console).

    The stdin reader is a daemon thread blocked in ``readline()``. Letting CPython
    finalize with it alive aborts the process on Windows with an access violation
    (0xC0000005, "Fatal Python error: _enter_buffered_busy... possibly due to
    daemon threads"), which swallows our exit code. Everything is flushed above,
    so leave via ``os._exit``.
    """
    code = main(argv)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


if __name__ == "__main__":
    cli_entry()
