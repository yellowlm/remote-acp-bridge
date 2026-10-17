"""remote-acp-server: authenticated WebSocket front for ACP agent subprocesses.

The bridge never parses ACP. It authenticates the opening handshake with a plaintext
key header (mounted over TLS), keeps one agent subprocess per session, and shuttles
ndjson lines between the agent's stdio and WebSocket text frames.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import functools
import json
import logging
import os
import signal
import socket
import ssl
import stat
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import AsyncExitStack
from dataclasses import dataclass
from urllib.parse import unquote

from websockets.asyncio.server import ServerConnection, serve
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Response

from . import __version__
from .auth import (
    SESSION_HEADER,
    WORKSPACE_KEY,
    ConfigHeaderError,
    KeyVerifier,
    decode_config,
    load_keys,
)
from .config import AGENT_PATH_PREFIX, ConfigError, ServerConfig, default_config_path
from .frames import (
    CLIENT_ENV,
    CLOSE_RESUMABLE,
    CLOSE_SESSION_END,
    CWD_ERROR_CODE,
    CWD_ERROR_PREFIX,
    CWD_REASON_NOT_DIRECTORY,
    CWD_REASON_NOT_FOUND,
    CWD_REASON_NOT_MOUNTED,
    CWD_REASON_NOT_READABLE,
    IPVERSION_ENV,
    MAX_FRAME_BYTES,
    SENTINEL_NAME,
    SESSION_ID_ENV,
)
from .mounting import (
    MountInputError,
    english_reason,
    join_share_path,
    mount_point_for,
    probe_target,
    sanitize_hostname,
    validate_device,
    validate_options,
)
from .session import Session
from .workspace import (
    MountError,
    MountMonitor,
    ascii_text,
    helper_mount,
    helper_umount,
    resolve_unc_share,
    sentinel_gate,
    unc_link_ok,
    unc_share_target,
    unc_sentinel_gate,
)

# The idle watchdog polls at this step so a connection is dropped within
# idle + IDLE_POLL_SECONDS rather than up to twice the idle window.
IDLE_POLL_SECONDS = 1.0

# Threads the handshake workspace-gate may occupy at once. Small and separate
# from the default executor the monitor uses, so hung-share gates queue here rather than
# starving the monitor; the wait_for timeout still fails each one closed.
WORKSPACE_GATE_WORKERS = 4

# Before unmounting a share whose last session just left, wait up to this long for that
# session's agent process to exit (its cwd may be inside the mount), and retry a busy umount a
# few times. A single failure used to leave the share mounted with no registry entry, so the
# next connect mounted onto a busy path (EBUSY) and was refused 412 forever.
UMOUNT_WAIT_SECONDS = 5.0
UMOUNT_ATTEMPTS = 3
UMOUNT_RETRY_DELAY_SECONDS = 0.5

# Only the empty ``host`` means "bind every stack we can open". An explicit ``"0.0.0.0"``
# binds IPv4 only and ``"::"`` binds IPv6 only — they are addresses, not wildcards
# (口径 §8, 2026-10-13).
DUAL_STACK_HOST = ""
LISTEN_BACKLOG = socket.SOMAXCONN


def build_logger(cfg: ServerConfig) -> logging.Logger:
    logger = logging.getLogger("remote-acp-server")
    logger.handlers.clear()
    logger.propagate = False
    if not cfg.logging.enabled:
        # ``level = "off"`` (the default) silences everything and must not open the
        # ``file`` either. A NullHandler keeps the logger usable without emitting anything.
        logger.setLevel(logging.CRITICAL + 1)
        logger.addHandler(logging.NullHandler())
        return logger
    logger.setLevel(cfg.logging.severity)
    handler: logging.Handler
    handler = logging.FileHandler(cfg.logging.file, encoding="utf-8") if cfg.logging.file else logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    # Never let the library's wire trace run, even at [logging] level = debug: its
    # DEBUG trace logs request headers, and the handshake ``Config`` header carries the
    # client's share password. The bridge's own log level is the operator's business;
    # the plaintext of a client's credential on disk is not. websockets.client /
    # websockets.server are the two logger names this version traces on (websockets>=13 asyncio).
    for name in ("websockets", "websockets.client", "websockets.server"):
        logging.getLogger(name).setLevel(logging.INFO)
    return logger


def server_context(cfg: ServerConfig) -> ssl.SSLContext | None:
    if not cfg.tls.enabled:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cfg.tls.cert_file, cfg.tls.key_file)
    return context


def stack_targets(host: str) -> list[str]:
    """The addresses to bind: the empty host means both stacks, anything else is itself.

    ``"0.0.0.0"`` binds IPv4 only and ``"::"`` binds IPv6 only (``IPV6_V6ONLY=1``) — an
    explicit address, not a wildcard (口径 §8, 2026-10-13).
    """
    cleaned = host.strip()
    return ["0.0.0.0", "::"] if cleaned == DUAL_STACK_HOST else [cleaned]


def describe_socket(sock: socket.socket) -> str:
    """``[::]:7801 (ipv6)`` / ``0.0.0.0:7801 (ipv4)`` — what actually got bound."""
    address = sock.getsockname()
    host, port = address[0], address[1]
    shown = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return f"{shown} ({'ipv6' if sock.family == socket.AF_INET6 else 'ipv4'})"


# -- Platform seams ----------------------------------------------------------------
#
# Windows stage 1 keeps one code base: every difference is a platform branch behind a small
# seam, and the POSIX branches keep executing exactly what they did before. Deleting the
# marked functions and the branches that call them restores the pure-Linux behaviour.


def _on_windows() -> bool:
    """True when the bridge runs on Windows. One seam, so tests can pick a side."""
    return os.name == "nt"


# winsock's ``SO_EXCLUSIVEADDRUSE`` is ``~SO_REUSEADDR``; the constant only exists on
# Windows, so a non-Windows host (and the tests) falls back to its value.
_SO_EXCLUSIVEADDRUSE = getattr(socket, "SO_EXCLUSIVEADDRUSE", 0xFFFFFFFB)


def _socket_options(*, windows: bool | None = None) -> list[tuple[int, int, int]]:
    """The ``setsockopt`` list a new listening socket gets.

    POSIX keeps ``SO_REUSEADDR`` — unchanged. Windows uses ``SO_EXCLUSIVEADDRUSE`` instead:
    there ``SO_REUSEADDR`` lets a second process **steal** the bound port, the opposite of
    "this service owns this port".
    """
    if _on_windows() if windows is None else windows:
        return [(socket.SOL_SOCKET, _SO_EXCLUSIVEADDRUSE, 1)]
    return [(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)]


def _mount_ok(mount_point: str) -> bool:
    """Is the session's share really in place at ``mount_point``?

    POSIX asks the kernel (``os.path.ismount`` — unchanged). Windows asks the structure: a
    reparse point at a UNC path, because ``ismount``'s Windows behaviour is not something
    this project has verified.
    """
    if _on_windows():
        return unc_link_ok(mount_point)
    return os.path.ismount(mount_point)


def _listening_socket(family: int, host: str, port: int, *,
                      socket_factory=socket.socket,
                      windows: bool | None = None) -> socket.socket:
    sock = socket_factory(family, socket.SOCK_STREAM)
    try:
        for level, option, value in _socket_options(windows=windows):
            sock.setsockopt(level, option, value)
        if family == socket.AF_INET6:
            # Explicit, and it has to be: Linux defaults V6ONLY to 0, so an IPv6
            # wildcard listener would also claim IPv4 and the IPv4 bind on the same
            # port would then fail with EADDRINUSE.
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port, 0, 0) if family == socket.AF_INET6 else (host, port))
        sock.listen(LISTEN_BACKLOG)
    except OSError:
        sock.close()
        raise
    return sock


def listen_sockets(cfg: ServerConfig, log: logging.Logger | None = None) -> list[socket.socket]:
    """Pre-bind one listening socket per stack, ready for ``serve_on``.

    ``serve(host=...)`` cannot express dual stack: websockets forwards ``sock`` to the
    event loop but only accepts a *single* socket (a list dies on ``sock.type``), on
    both 15.x and 17.x — so each stack gets its own ``serve()``.

    A second stack that cannot be opened (a box with no IPv6) is a warning, not a
    failure, as long as something is listening: dual stack (``host = ""``) must not break
    on an IPv4-only box. A single explicit address — including ``"0.0.0.0"`` and ``"::"`` —
    has no fallback, so the error propagates and the caller exits 1.
    """
    socks: list[socket.socket] = []
    port = cfg.port
    for target in stack_targets(cfg.host):
        try:
            infos = socket.getaddrinfo(target, port or None, type=socket.SOCK_STREAM)
        except OSError as exc:
            if socks:
                _skipped(log, target, f"cannot resolve: {english_reason(exc)}")
                continue
            raise OSError(f"cannot resolve host {target!r}: {english_reason(exc)}") from exc
        for family, host in _unique_families(infos):
            try:
                sock = _listening_socket(family, host, port)
            except OSError as exc:
                if socks:
                    _skipped(log, host, f"cannot bind: {english_reason(exc)}")
                    continue
                raise
            if not port:
                # First bind picked an ephemeral port; every other stack must share it,
                # or "one port, two stacks" would silently become two ports. A config
                # file cannot reach this — ServerConfig.load refuses port 0 — so it is
                # the embedding path (the test fixtures bind this way) and is pinned by
                # DualStackTest.test_wildcard_opens_both_families_on_the_same_port.
                port = sock.getsockname()[1]
            socks.append(sock)
    if not socks:
        raise OSError(f"cannot listen on {cfg.host!r}:{cfg.port}: no address family available")
    return socks


def _unique_families(infos) -> list[tuple[int, str]]:
    seen: set[tuple[int, str]] = set()
    ordered: list[tuple[int, str]] = []
    for family, _, _, _, sockaddr in infos:
        key = (family, sockaddr[0])
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered


def _skipped(log: logging.Logger | None, host: str, why: str) -> None:
    message = f"IPv4/IPv6 listener on {host!r} skipped: {why}"
    if log:
        log.warning(message)
    else:  # before the logger exists, e.g. while resolving the config
        print(f"remote-acp-server: {message}", file=sys.stderr)


def serve_on(bridge: Bridge, sock: socket.socket):
    """``serve()`` for one pre-created listening socket (an async context manager)."""
    return serve(
        bridge.handler,
        sock=sock,
        process_request=bridge.process_request,
        process_response=bridge.process_response,
        ssl=server_context(bridge.cfg),
        max_size=MAX_FRAME_BYTES,
        logger=bridge.log,
    )


SESSION_OPEN_METHODS = frozenset({"session/new", "session/load", "session/resume"})


# The handshake HTTP status the server answers a client whose workspace could not be
# mounted or gated with: a distinct 4xx the client maps to exit code 7 and does not
# retry (a reconnect would ask it to mount the same wrong share again).
WORKSPACE_REFUSED_STATUS = 412

# The JSON-RPC error code the bridge answers a host request with while a session's share is
# marked down. It is the bridge's own code, deliberately NOT the provider rate-limit
# code; AionUi renders any error response to a host request in its error box, so this reaches
# the same render path without impersonating a provider error.
WORKSPACE_UNAVAILABLE_CODE = -32000

# A session cwd that cannot be used is answered with CWD_ERROR_CODE and a message of the
# form "<CWD_ERROR_PREFIX>: <reason>"; the client turns that into the final host-facing text
# (see frames.py).


class CwdRefused(Exception):
    """The directory a ``session/new`` asks to work in could not be made.

    Raised after the handshake, when there is no HTTP response left to refuse with, so
    the handler ends the session instead of letting the error escape: an uncaught error
    here kills the connection with 1011 and leaves the agent this session had already
    spawned running with nobody attached to it.
    """


class _Abandon:
    """A one-way flag the caller raises when it gives up on an off-loop mount.

    ``wait_for`` can cancel a queued executor job but never a running one, so a mount that
    is already under way keeps going after the handshake refused and would register
    a ``refs=0`` entry nobody owns — a real mount with no monitor and no session, left until
    the process exits. The worker checks this before it registers, and the caller gets a
    done-callback backstop for the narrow window where the mount finished first.

    ``handed_off`` records that the worker itself noticed the abandonment and already gave
    the mount to the loop; the backstop then stays quiet so a mount is never reclaimed twice
    over (N2: the reclaim must be a single, lock-held decision).
    """

    __slots__ = ("abandoned", "handed_off")

    def __init__(self):
        self.abandoned = False
        self.handed_off = False


@dataclass
class _HostLock:
    """One hostname's mount lock plus how many callers hold a claim on it.

    ``users`` counts everyone inside or waiting on the lock, which is what makes the lock
    recyclable: a plain dict of locks grows by one entry per client hostname forever,
    and it is only safe to drop a lock when nobody is queued on it *and* it has no mount.
    """

    lock: asyncio.Lock
    users: int = 0


@dataclass
class _MountEntry:
    """One client hostname's mount: where it lives, who is bound, and its own monitor.

    ``refs`` counts the live sessions sharing it — the first connect mounts, the last
    session to close unmounts. ``available`` is that mount's liveness verdict, flipped off
    by its monitor after ``monitor_fail_threshold`` consecutive probe failures (which cuts
    only the sessions bound to *this* entry). The monitor's stop event and task are kept so
    unmounting can shut them down.
    """

    mount_point: str
    sentinel_token: str
    probe_host: str
    probe_port: int
    refs: int = 0
    available: bool = True
    monitor: MountMonitor | None = None
    monitor_task: asyncio.Task | None = None
    stop: asyncio.Event | None = None


def _parse_cwd_frame(frame: str) -> tuple[dict, dict] | None:
    """One parse shared by the cwd rewriter and the cwd probe.

    Returns ``(message, params)`` for a session-opening method whose params really is a
    table, otherwise ``None`` — every caller then treats the frame as pass-through.
    """
    try:
        message = json.loads(frame)
    except (ValueError, TypeError):
        return None
    if not isinstance(message, dict) or message.get("method") not in SESSION_OPEN_METHODS:
        return None
    params = message.get("params")
    if not isinstance(params, dict):
        return None
    return message, params


def _cwd_of(params: dict) -> str:
    """The ``cwd`` in an already-parsed session params table, or "" for none."""
    cwd = params.get("cwd")
    return cwd if isinstance(cwd, str) and cwd.strip() else ""


def session_cwd(frame: str) -> str:
    """The ``cwd`` a session-opening frame asks the agent to work in, or "" for none.

    Read-only on purpose: the value is only used to decide which directory to create
; the frame itself goes out untouched.
    """
    parsed = _parse_cwd_frame(frame)
    return _cwd_of(parsed[1]) if parsed else ""


# How many mcpServers names one log line lists before it is cut short.
MCP_NAME_LIMIT = 20


def _mcp_name(entry) -> str:
    """The name one ``mcpServers`` entry shows in the log, and nothing else.

    Only ``name`` is ever read: an entry's ``env``/``args``/``url``/``command`` can carry
    tokens (T65 found ``TEAM_MCP_TOKEN`` in an AionUi-injected server) and never reach a log.
    A missing or non-string name is ``<unnamed>``, and every character that would break the
    line — control bytes, the ``,``/``(``/``)`` separators, or anything non-ASCII, since the
    line is plain English on the wire — becomes ``-``.
    """
    name = entry.get("name") if isinstance(entry, dict) else None
    if not isinstance(name, str) or not name:
        return "<unnamed>"
    return "".join(ch if ch.isascii() and ch.isprintable() and ch not in ",()" else "-"
                   for ch in name)


def _mcp_names_line(servers: list) -> tuple[int, str]:
    """``(count, rendered names)`` for one session-opening frame's ``mcpServers``."""
    names = [_mcp_name(entry) for entry in servers]
    shown = ", ".join(names[:MCP_NAME_LIMIT])
    if len(names) > MCP_NAME_LIMIT:
        shown += f", (+{len(names) - MCP_NAME_LIMIT} more)"
    return len(names), shown


# A branch-B session's directory name is the **host's own** cwd's last segment, sanitised
# to one safe path segment, so the same host folder always resolves to the same directory across
# bridge sessions. The bridge used to key it by its own session UUID, which changed on every new
# connection — and the agent keys a session to the cwd it was created in, so a resumed session
# was rejected with "does not belong to cwd".
_BRANCH_B_KEEP = frozenset("._-")

# The two reasons a branch-B session is refused rather than guessed a directory for. The
# message is ASCII and self-contained: branch B has no mounted share, so the client's T8 rewrite
# (which is gated on having one) passes it to the host verbatim.
BRANCH_B_NO_CWD = "session cwd refused: the host sent no folder for this session"
BRANCH_B_NO_NAME = "session cwd refused: the host folder name has no usable characters"


def branch_b_dirname(host_cwd: str) -> str:
    """The branch-B directory name for a host cwd, or refuse the session.

    The name is the cwd's **last** segment (``/`` and ``\\`` both separate, so a Windows path
    works), with every character outside ASCII alphanumerics and ``._-`` replaced by ``-``. The
    result is always one path segment and never ``.``/``..``, so it cannot escape
    ``<root>/localhost``.

    A cwd the host did not really send (missing, not a string, blank), a segment with nothing
    usable left, or ``.``/``..`` raises:class:`CwdRefused`. Guessing a directory here would
    hand the agent a working directory the host never named — the old per-connection UUID
    directory is exactly what made the agent reject a resumed session.

    ASCII-only on purpose: the name reaches the log line and the refusal text, and those stay
    plain English on the wire (the rule ``sanitize_hostname`` already follows, N5). A
    non-ASCII folder therefore collapses to ``-`` rather than through.
    """
    raw = host_cwd.strip()
    if not raw:
        raise CwdRefused(BRANCH_B_NO_CWD)
    trimmed = raw.replace("\\", "/").rstrip("/")     # a trailing separator still names the folder
    segment = trimmed.rsplit("/", 1)[-1].strip()
    if not segment:
        raise CwdRefused(BRANCH_B_NO_CWD)
    name = "".join(ch if (ch.isascii() and ch.isalnum()) or ch in _BRANCH_B_KEEP else "-"
                   for ch in segment)
    if not name or name in (".", ".."):
        raise CwdRefused(BRANCH_B_NO_NAME)
    return name


def _ip_version(connection) -> str | None:
    """The IP family this connection's own transport uses: ``"4"``/``"6"``, else ``None``.

    The criterion is the **transport's socket family** (``AF_INET``/``AF_INET6``), never the
    address text: an IPv4-mapped address on an ``AF_INET6`` socket is a v6 connection, and a
    "does the address contain a colon" test would call it v4. A connection with no transport (a
    hand-made one), no socket, or another family has no answer, and the caller injects nothing
    rather than guessing.
    """
    transport = getattr(connection, "transport", None)
    extra = getattr(transport, "get_extra_info", None)
    if extra is None:
        return None
    try:
        family = getattr(extra("socket"), "family", None)
    except Exception:  # pragma: no cover - defensive: a transport that raises must not
        return None     # kill the handshake, and there is nothing to report anyway
    if family == socket.AF_INET:
        return "4"
    if family == socket.AF_INET6:
        return "6"
    return None


class Bridge:
    def __init__(self, cfg: ServerConfig, log: logging.Logger | None = None):
        self.cfg = cfg
        self.log = log or logging.getLogger("remote-acp-server")
        self.verifier = KeyVerifier(
            load_keys(cfg.auth.keys_file),
            cfg.auth.clock_skew_seconds,
            cfg.auth.nonce_cache_seconds,
        )
        self.sessions: dict[str, Session] = {}
        # Sessions whose admission is mid-flight (slot taken, agent not yet started).
        # They count against max_sessions but are not eviction candidates (R7/R8).
        self._admitting: set[str] = set()
        # Per-client workspace mounts. One entry per client hostname, keyed and
        # reference-counted across the sessions bound to it: the first connection of a
        # hostname mounts under root/<hostname> and starts that mount's gate/monitor; the
        # last session bound to it unmounts. The mount/umount and the sentinel read all
        # touch the filesystem or the helper socket, so they run **off the event loop** in
        # one bounded pool — a hung share queues here and fails closed on the
        # monitor_timeout, never freezing a handshake or starving another client.
        self._mounts: dict[str, _MountEntry] = {}
        # Serialises mount+gate+unmount per hostname: two concurrent first-connections for
        # the same client must not both see "no entry" and mount twice, and a departing
        # client's umount must not run underneath a newcomer that is mid-mount.
        self._host_locks: dict[str, _HostLock] = {}
        # In-flight last-session unmounts, kept referenced so the loop does not GC them out
        # from under asyncio, and drained on shutdown (run() → shutdown_workspaces).
        self._release_tasks: set[asyncio.Task] = set()
        # The running loop, captured the first time a connection reaches the handler: the
        # mount worker needs it to hand an abandoned mount back for a **lock-held** reclaim
        # instead of unmounting from its own thread.
        self._loop: asyncio.AbstractEventLoop | None = None
        # The workspace feature is always on: the pool that runs a mount/gate (a hung
        # share or a slow helper must never touch the event loop) always exists.
        self._ws_pool: ThreadPoolExecutor | None = ThreadPoolExecutor(
            max_workers=WORKSPACE_GATE_WORKERS, thread_name_prefix="rab-ws"
        )

    # -- handshake ---------------------------------------------------------

    def agent_for_path(self, path: str) -> str | None:
        if not path.startswith(AGENT_PATH_PREFIX):
            return None
        name = unquote(path[len(AGENT_PATH_PREFIX) :]).strip("/")
        return name if name in self.cfg.agents else None

    async def process_request(
        self, connection: ServerConnection, request
    ) -> Response | None:
        path = request.path.split("?", 1)[0]
        agent_name = self.agent_for_path(path)
        if agent_name is None:
            return self._reject(404, "unknown agent", path=path, connection=connection)

        decision = self.verifier.authenticate(request.headers)
        if not decision.ok:
            return self._reject(decision.status, decision.reason, path=path, connection=connection)

        # The client's workspace descriptor travels in the Config header (T1 §2/§3); a client
        # without a workspace sends ``{}``. Parsing it here means a malformed one is refused
        # before any session is registered.
        try:
            config = decode_config(request.headers)
        except ConfigHeaderError as exc:
            return self._reject(400, str(exc), path=path, connection=connection)
        descriptor = config.get(WORKSPACE_KEY)
        if descriptor is not None and not isinstance(descriptor, dict):
            return self._reject(400, "config workspace must be a table", path=path, connection=connection)

        resume_id = request.headers.get(SESSION_HEADER) or ""
        victim = None
        retained = 0
        if resume_id:
            session = self.sessions.get(resume_id)
            if session is None:
                return self._reject(404, "unknown or expired session", path=path, connection=connection)
            if session.agent.name != agent_name:
                return self._reject(403, "session belongs to another agent", path=path, connection=connection)
            if session.closing:
                return self._reject(410, "session is closing", path=path, connection=connection)
        else:
            retained = len(self.sessions)
            if self.cfg.max_sessions and retained >= self.cfg.max_sessions:
                victim = self._eviction_candidate()
                if victim is None:
                    return self._reject(
                        503, self._capacity_refusal(), path=path, connection=connection
                    )
            # Register the newcomer BEFORE the victim is dropped and before anything is
            # awaited (R7): popping the victim freed a slot that a second concurrent
            # handshake could sit in while this one was still inside
            # ``await victim.close()``. One synchronous block per admission means the
            # registry is never readable mid-flight, so ``max_sessions`` holds under
            # concurrency, not just serially.
            session = self._register_session(agent_name)
            if victim is not None:
                self._retire(victim)
            self._admitting.add(session.session_id)

        # The mount is proven **before** the 101: a client whose share cannot be
        # mounted or gated is answered with a distinct status and gets no session. The agent
        # is not spawned here — the handler does that once the upgrade is written, by which
        # time the mount is in place, so ``[[agents]].cwd`` may live under ``root/<hostname>``.
        if descriptor is not None:
            reason = await self._admit_workspace(descriptor, session)
            if reason is not None:
                self._rollback_admission(session, victim)
                return self._reject(WORKSPACE_REFUSED_STATUS, reason, path=path, connection=connection)

        # The mount (if any) is in place, so the agent can be spawned now — ``[[agents]].cwd``
        # may live under ``root/<hostname>``. A spawn failure is still a handshake 500:
        # the 101 has not been written yet. ``_ensure_agent`` is a no-op on a resume whose agent
        # is already up.
        try:
            start_reason = await self._ensure_agent(session, _ip_version(connection))
        except BaseException:
            # A non-OSError failure, or a cancellation mid-spawn, reaches no client: give the
            # slot (and any mount) back synchronously so the registry cannot keep a session with
            # no agent, then let the error out.
            self._rollback_admission(session, victim)
            raise
        finally:
            self._admitting.discard(session.session_id)
        if start_reason is not None:
            self._rollback_admission(session, victim)
            return self._reject(500, start_reason, path=path, connection=connection)

        if victim is not None:
            self._announce_eviction(victim, retained)
            await victim.close("evicted")

        connection.acp_session = session
        self.log.info(
            "handshake ok agent=%s session=%s resume=%s workspace=%s from %s",
            agent_name,
            session.session_id,
            bool(resume_id),
            getattr(session, "_rab_hostname", None) or "-",
            connection.remote_address,
        )
        return None

    def process_response(
        self, connection: ServerConnection, request, response: Response
    ) -> Response | None:
        session = getattr(connection, "acp_session", None)
        if session is not None and response.status_code == 101:
            response.headers[SESSION_HEADER] = session.session_id
        return None

    def _reject(self, status: int, reason: str, *, path: str, connection) -> Response:
        self.log.warning(
            "%d %s: path=%s from %s", status, reason, path, connection.remote_address
        )
        return connection.respond(status, f"{reason}\n")

    def _capacity_refusal(self) -> str:
        """Why a newcomer was turned away, stated in terms an operator can act on.

        The body used to end in "no disconnected session to evict", which has been
        wrong since R7: a registry holding only in-flight handshakes has no connected
        session either, and telling an operator to go disconnect one sends them chasing
        nothing. So name the actual composition of the registry.
        """
        retained = len(self.sessions)
        connected = sum(1 for session in self.sessions.values() if session.connection is not None)
        handshaking = sum(1 for session in self.sessions.values() if session.session_id in self._admitting)
        reclaiming = retained - connected - handshaking
        return (
            f"max sessions reached: {retained} retained "
            f"(connected={connected} handshaking={handshaking} reclaiming={reclaiming}) "
            f">= {self.cfg.max_sessions}; no session is eligible to evict"
        )

    def _register_session(self, agent_name: str) -> Session:
        """Create a session and take its slot; the caller starts the agent.

        Reservation is deliberately separate from ``start()`` so it happens in the
        same synchronous block as the capacity check (R7).
        """
        session = Session(
            str(uuid.uuid4()),
            self.cfg.agents[agent_name],
            grace_seconds=self.cfg.session_grace_seconds,
            log=self.log,
            on_closed=self._session_closed,
            global_env=self.cfg.env,
        )
        self.sessions[session.session_id] = session
        return session

    def _session_closed(self, session: Session) -> None:
        self.sessions.pop(session.session_id, None)
        self._admitting.discard(session.session_id)
        if getattr(session, "_rab_hostname", None):
            # Last session on a hostname unmounts it. Scheduled as a task: the
            # umount is a helper round-trip and must not block the teardown that is
            # already on the loop. run() drains any that are still pending on shutdown.
            self._release_tasks.add(asyncio.create_task(self._release_mount(session)))

    def _eviction_candidate(self) -> Session | None:
        """Which retained session a new one may take over: the longest-disconnected.

        A session with a live connection is never a candidate — an in-progress
        conversation is not cut off (the rule the user set on 2026-10-10). Ordering
        falls back to ``created_at`` so a session that never got attached (its client
        died between the 101 and the handler) cannot sit in the registry forever with
        ``grace = 0``; with one uniform grace window the earliest key is also
        the first to expire.

        Sessions whose admission is still in flight are skipped: they have taken a slot
        but not run an agent yet, and letting a newcomer evict the *other* newcomer
        would be a coin toss rather than a policy.
        """
        waiting = [
            session
            for session in self.sessions.values()
            if session.connection is None
            and not session.closing
            and session.session_id not in self._admitting
        ]
        if not waiting:
            return None
        return min(waiting, key=lambda session: session.disconnected_at or session.created_at)

    def _retire(self, session: Session) -> None:
        """Unregister it *before* awaiting the teardown.

        No await sits between the capacity check and this pop, so the slot is freed
        only after the replacement already holds one. It also makes the uuid answer
        404 on resume from this instant, which is the promised semantics — until the
        admission is rolled back, if the newcomer's agent never comes up.

        Nothing is logged here: the announcement lives in ``_announce_eviction``, made
        once the newcomer is actually admitted. Announcing at the pop left an
        ``evicted session …`` line with no matching ``closed (evicted)`` behind it every
        time ``start()`` failed, telling an operator the session was reaped while it was
        still live and resumable.
        """
        self.sessions.pop(session.session_id, None)
        self._admitting.discard(session.session_id)

    def _announce_eviction(self, session: Session, retained: int) -> None:
        """The log half of a retirement that really happened."""
        age = time.time() - (session.disconnected_at or session.created_at)
        # A session that never had a connection is aged from its creation, and the line
        # has to say so: "disconnected 0.4s ago" about a handshake that never attached
        # describes an event that did not happen.
        state = (
            f"disconnected {age:.1f}s ago"
            if session.disconnected_at is not None
            else f"created {age:.1f}s ago, never attached"
        )
        self.log.info(
            "evicted session %s (agent %s, %s) to admit a new session: %d retained >= max_sessions=%d",
            session.session_id,
            session.agent.name,
            state,
            retained,
            self.cfg.max_sessions,
        )

    def _rollback_admission(self, session: Session, victim: Session | None) -> None:
        """Undo an admission that never completed: give up the slot and the victim.

        Called when a workspace mount/gate refuses the handshake or the agent cannot start
. It is deliberately synchronous — a cancellation mid-spawn must still be able
        to give the slot back — so a mount the session had already bound is released by a
        scheduled task, exactly as ``_session_closed`` does. The victim is put back unless
        something already started closing it, so a failed admission never costs a healthy grace
        session; the eviction is never announced.
        """
        self.sessions.pop(session.session_id, None)
        self._admitting.discard(session.session_id)
        if getattr(session, "_rab_hostname", None):
            # Let _release_mount read (and clear) the binding itself; clearing it here would
            # make the scheduled release a no-op and leak the mount.
            self._release_tasks.add(asyncio.create_task(self._release_mount(session)))
        if victim is not None and not victim.closing:
            self.sessions[victim.session_id] = victim

    # -- traffic -----------------------------------------------------------

    async def handler(self, connection: ServerConnection) -> None:
        session = getattr(connection, "acp_session", None)
        if session is None:  # pragma: no cover - handshake was rejected
            return
        if session.closing:
            # R8: the handshake check in process_request and this attach are separated
            # by the await that writes the 101 response, and an eviction can land in
            # that gap. Attaching then would bind a live connection to a session whose
            # agent is already reaped - it would never receive a frame or a close.
            # Eviction wins (README §1.2): end the connection with 1000, which the
            # client reads as "session over, do not reconnect".
            self.log.warning(
                "session %s was reclaimed during the handshake (evicted or closed); ending the connection",
                session.session_id,
            )
            with contextlib.suppress(Exception):
                await connection.close(code=CLOSE_SESSION_END, reason="session-reclaimed")
            return
        session.attach(connection)
        watchdog = asyncio.create_task(self._idle_watchdog(session, connection))
        end = False
        try:
            while True:
                try:
                    message = await connection.recv()
                except ConnectionClosed as exc:
                    end = _is_session_end(exc)
                    break
                offline = self._offline_mount_point(session)
                if offline is not None:
                    # The session's share is marked down. Do not forward to the agent;
                    # answer a host request with a JSON-RPC error (the shape AionUi renders as
                    # its error box). The connection stays, and once the monitor sees the share
                    # again forwarding resumes.
                    reply = self._offline_error_reply(message, offline)
                    if reply is not None:
                        session._deliver(reply)
                    continue
                try:
                    prepared = self._for_agent(message, session)
                except CwdRefused as exc:
                    # Answer the request with a JSON-RPC error instead of opening the
                    # session and then closing it with 1000 — that made the client exit and
                    # AionUi show only "Incoming transport closed". The session stays; a later
                    # valid request can still go through. The full reason goes to the log too.
                    self.log.error("session %s cwd refused: %s", session.session_id, exc)
                    reply = self._jsonrpc_error_reply(message, str(exc), CWD_ERROR_CODE)
                    if reply is not None:
                        session._deliver(reply)
                    continue
                await session.send_to_agent(prepared)
        finally:
            watchdog.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watchdog
            session.detach(connection, end=end)

    def _for_agent(self, frame: str, session: Session) -> str:
        """The one place a session-opening frame's ``cwd`` is settled and created (T1 §4/§7).

        The workspace is always on, so every session-opening frame's ``cwd`` is decided here:

        * this session has a mounted share (branch A) — the client sent only the **link name**
          it made inside the share; join it with the session's mount point so the agent gets
          the same absolute directory the client meant.
        * no share on this session (branch B) — the host cwd's **last segment** names
          ``<root>/localhost/<that segment>/``, so one host folder is one directory across
          reconnects; a folder the host did not name refuses the session.

        Branch A's path is the client's **own** entry inside the mounted share: the server only
        **checks it exists and is readable** and refuses the session otherwise — it never
        ``mkdir``-s into the operator's share. Branch B's path is server-local, so
        ``mkdir -p`` is applied there. A cwd that cannot be used raises:class:`CwdRefused`;
        the handler answers that request with a JSON-RPC error and keeps the session.
        """
        parsed = _parse_cwd_frame(frame)
        if parsed is None:
            return frame
        message, params = parsed
        # One line per session-opening frame, saying which MCP servers the host is
        # handing the agent — names only, and always, so "none" is visible as ``0 ()``.
        servers = params.get("mcpServers")
        count, names = _mcp_names_line(servers if isinstance(servers, list) else [])
        self.log.info("[session %s] injected mcp servers: %d (%s)",
                      session.session_id, count, names)
        host_cwd = _cwd_of(params)
        prepared = frame
        has_share = bool(getattr(session, "_rab_hostname", None))
        if has_share:
            wanted = self._share_cwd(session, host_cwd)
        else:
            # With no workspace descriptor the session works under a literal
            # ``localhost`` segment named after the host's own folder, so the same folder is
            # the same directory across bridge sessions. No folder, no session.
            wanted = os.path.join(self.cfg.workspace.root, "localhost",
                                  branch_b_dirname(host_cwd))
        if wanted and params.get("cwd") != wanted:
            params["cwd"] = wanted
            prepared = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
            self.log.info("workspace cwd -> %s (agent %s, session %s)",
                          wanted, session.agent.name, session.session_id)
        if not wanted:
            return prepared
        if has_share:
            # The mount's path is the client's own, already-created entry: check, never create.
            self._check_share_cwd(session, wanted)
        else:
            try:
                created = session.ensure_cwd(wanted, session.agent.cwd)
            except OSError as exc:
                raise CwdRefused(str(exc)) from exc
            if created:
                self.log.info("created session cwd %s (session %s)", created, session.session_id)
        return prepared

    def _share_cwd(self, session: Session, host_cwd: str) -> str:
        """Branch A: the mount point joined with the client's share-relative link name."""
        if not host_cwd:
            return ""
        entry = getattr(session, "_rab_entry", None)
        if entry is None:
            return ""
        try:
            return join_share_path(entry.mount_point, host_cwd)
        except MountInputError as exc:
            raise CwdRefused(
                f"session cwd {host_cwd!r} is not share-relative: {exc}"
            ) from exc

    def _check_share_cwd(self, session: Session, wanted: str) -> None:
        """Branch A: the client's share entry must exist and be readable.

        Three separate verdicts, so the operator learns which one failed — the old single
        ``os.path.isdir`` folded every ``OSError`` into "does not exist", which is exactly what
        hid a permission problem behind a misleading message:

        1. the mount point is really a mount;
        2. the entry exists (``ENOENT``);
        3. it is readable (``EACCES``/``EPERM``) and is a directory.

        A failure raises:class:`CwdRefused` with ``"<prefix>: <reason>"``; the handler answers
        that request with a JSON-RPC error, and the **client** turns the reason into the final
        host-facing text (its own local path and the share account, T8 §3C).
        """
        entry = getattr(session, "_rab_entry", None)
        mount_point = entry.mount_point if entry is not None else ""
        if mount_point and not _mount_ok(mount_point):     # POSIX still ismount
            raise CwdRefused(f"{CWD_ERROR_PREFIX}: {CWD_REASON_NOT_MOUNTED}")
        try:
            info = os.stat(wanted)
        except FileNotFoundError as exc:
            raise CwdRefused(f"{CWD_ERROR_PREFIX}: {CWD_REASON_NOT_FOUND}") from exc
        except OSError as exc:
            # The errno table keeps this ASCII on any locale; it is for the log, the
            # client rewrites the host-facing message.
            self.log.warning("session cwd %s not readable: %s", wanted, english_reason(exc))
            raise CwdRefused(f"{CWD_ERROR_PREFIX}: {CWD_REASON_NOT_READABLE}") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise CwdRefused(f"{CWD_ERROR_PREFIX}: {CWD_REASON_NOT_DIRECTORY}")

    def _offline_mount_point(self, session: Session) -> str | None:
        """This session's mount point when its share is marked down, else ``None``.

        A session with no share, or one whose share is available, forwards normally.
        """
        hostname = getattr(session, "_rab_hostname", None)
        if not hostname:
            return None
        entry = self._mounts.get(hostname)
        if entry is None or entry.available:
            return None
        return entry.mount_point

    def _jsonrpc_error_reply(self, frame: str, message_text: str, code: int) -> str | None:
        """A JSON-RPC error response to the host request ``frame``, or ``None``.

        Standard JSON-RPC shape (``{"jsonrpc","id","error":{"code","message"}}``) — what
        AionCore maps and AionUi renders as its error box. The code is the bridge's own and the
        message is fixed English, ASCII. A frame with no ``id`` is a notification, not a
        request, so there is nothing to answer.
        """
        try:
            parsed = json.loads(frame)
        except (ValueError, TypeError):
            return None
        if not isinstance(parsed, dict) or "id" not in parsed:
            return None
        return json.dumps({
            "jsonrpc": "2.0",
            "id": parsed.get("id"),
            "error": {"code": code, "message": message_text},
        }, separators=(",", ":"))

    def _offline_error_reply(self, frame: str, mount_point: str) -> str | None:
        """The T6 error for a host request while the session's share is marked down."""
        return self._jsonrpc_error_reply(
            frame, f"workspace storage unavailable at {mount_point}", WORKSPACE_UNAVAILABLE_CODE)

    async def _idle_watchdog(self, session: Session, connection: ServerConnection) -> None:
        idle = self.cfg.connection_idle_seconds
        if idle <= 0:
            return
        step = min(idle, IDLE_POLL_SECONDS)
        while True:
            await asyncio.sleep(step)
            if session.connection is not connection:
                return
            if session.idle_seconds() >= idle:
                self.log.info("session %s idle %ss, dropping connection", session.session_id, idle)
                await connection.close(code=CLOSE_RESUMABLE, reason="idle timeout")
                return

    # -- lifecycle ---------------------------------------------------------

    def session_count(self) -> int:
        return len(self.sessions)

    async def close_all(self) -> None:
        for session in list(self.sessions.values()):
            await session.close("server-shutdown")
        self.sessions.clear()

    # -- per-client workspace (T53 §3 / T1 §3) -----------------------------

    def _mount_refusal(self, hostname: str, descriptor: dict, abandon: _Abandon) -> tuple[str, _MountEntry | None]:
        """Off-loop half of a workspace admission: mount if this hostname has no entry yet,
        then gate the fresh-or-existing mount point. Returns ``(refusal_reason_or_empty, entry)``.

        Runs in the workspace pool (a hung share or a slow helper must never touch the event
        loop; the caller bounds it with a fail-closed ``wait_for``, R19). A gate failure
        on a mount this very call created is rolled back with an umount so a wrong-but-mounted
        share does not linger; a failure on a pre-existing shared mount leaves the other
        sessions that already hold it untouched.

        ``abandon`` is checked at every point where this function could still decide to hand
        an entry back: the caller may already have refused the client and gone, and a mount
        registered then would be owned by nobody.
        """
        cfg = self.cfg.workspace
        try:
            mount_point = mount_point_for(cfg.root, hostname)
            fs_type = str(descriptor.get("fs_type", "cifs"))
            device = str(descriptor.get("device", ""))
            options = [str(o) for o in (descriptor.get("mount_options") or [])]
            validate_device(fs_type, device)
            clean_options = validate_options(options)
            probe_host, probe_port = probe_target(fs_type, device)
        except MountInputError as exc:
            return f"workspace descriptor rejected: {exc}", None

        entry = self._mounts.get(hostname)
        created = False
        # An entry the monitor marked unreachable no longer refuses a newcomer. The share
        # may still be mounted (the gate below re-checks it), and a session admitted on it is
        # answered with a JSON-RPC error per request until the monitor sees it again.
        if entry is None:
            if os.path.ismount(mount_point):
                # A mount left behind by an earlier failed unmount. Try to clear it; if it
                # will not clear, **adopt** it rather than mounting onto a busy path (which would
                # raise EBUSY on every connect, i.e. a permanent 412). The sentinel gate below
                # still proves it is the right share.
                self.log.warning("workspace mount point %s is already mounted; reusing it", mount_point)
                with contextlib.suppress(MountError):
                    helper_umount(mount_point, timeout=cfg.monitor_timeout_seconds,
                                  sock_path=cfg.helper_socket)
            if not os.path.ismount(mount_point):
                credentials = {
                    "username": str(descriptor.get("username", "")),
                    "password": str(descriptor.get("password", "")),   # travels only into the socket
                    "domain": str(descriptor.get("domain", "")),
                }
                try:
                    helper_mount({
                        "fs_type": fs_type,
                        "device": device,
                        "mount_point": mount_point,
                        "options": clean_options,
                        "credentials": credentials,
                        # The share owner is the server's choice, never the client's options.
                        "uid": cfg.mount_uid,
                        "gid": cfg.mount_gid,
                    }, timeout=cfg.monitor_timeout_seconds, sock_path=cfg.helper_socket)
                except MountError as exc:
                    return str(exc), None
            if abandon.abandoned:
                # The caller gave up while mount(8) was running. Do **not** unmount here:
                # that caller released _host_lock(hostname) when it timed out, so a newer
                # client may already have mounted this very path and been admitted on it, and
                # umounting from the pool thread would take the share out from under a live
                # session. Hand it to the loop, which reclaims under the lock.
                self._hand_off_abandoned(hostname, mount_point, abandon)
                return "abandoned", None
            entry = _MountEntry(
                mount_point=mount_point,
                sentinel_token=str(descriptor.get("sentinel_token", "")),
                probe_host=probe_host,
                probe_port=probe_port,
            )
            self._mounts[hostname] = entry
            created = True

        reason = sentinel_gate(entry.mount_point, SENTINEL_NAME, entry.sentinel_token)
        if reason is not None:
            if created:
                # A gate failure on a mount this call just made: give it straight back. The
                # caller still holds the lock here (it has not timed out — it is waiting on
                # this very result), so releasing the registry claim and unmounting is safe.
                self._mounts.pop(hostname, None)
                with contextlib.suppress(MountError):
                    helper_umount(entry.mount_point, timeout=cfg.monitor_timeout_seconds,
                                  sock_path=cfg.helper_socket)
            return reason, None
        if abandon.abandoned:
            # Same hazard as above, for an entry this call did or did not create: everything
            # abandoned goes to the loop and is decided under the lock.
            self._hand_off_abandoned(hostname, entry.mount_point, abandon, created=created)
            return "abandoned", None
        return "", entry

    def _hand_off_abandoned(self, hostname: str, mount_point: str, abandon: _Abandon,
                            *, created: bool = True) -> None:
        """Pool-thread side of an abandoned mount: claim it and hand it to the loop.

        ``abandon.handed_off`` makes the reclaim happen exactly once: the worker that noticed
        the abandonment owns the decision, so the future's done-callback backstop stays quiet.
        ``created`` is only a hint for the log — the loop-side reclaim decides by looking at
        the registry, because between here and there a newer client may have taken the path.
        """
        abandon.handed_off = True
        loop = self._loop
        if loop is None:      # pragma: no cover - no connection ever reached the handler
            return
        loop.call_soon_threadsafe(self._schedule_reclaim, hostname, mount_point, created)

    def _schedule_reclaim(self, hostname: str, mount_point: str, created: bool) -> None:
        """Loop-side: start the lock-held reclaim, kept referenced until it finishes."""
        task = asyncio.ensure_future(self._reclaim_abandoned_mount(hostname, mount_point, created))
        self._release_tasks.add(task)

    async def _reclaim_abandoned_mount(self, hostname: str, mount_point: str, created: bool) -> None:
        """Give back a mount whose client abandoned, **under that hostname's lock**.

        By the time this runs, the lock has been contended with: a newer client may have
        mounted the same path and been admitted. The safe direction is to leave a stacked
        mount in place (shutdown sweeps it) rather than to pull a share out from under a
        session that is running on it now.
        """
        async with self._host_lock(hostname):
            entry = self._mounts.get(hostname)
            if entry is None:
                # Nobody owns the path: this is ours to give back.
                await self._umount_point(mount_point, reason="abandoned mount reclaimed")
                return
            if entry is not None and entry.mount_point == mount_point and entry.refs == 0:
                # Registered by the abandoned call itself and never claimed: drop and unmount.
                if await self._discard_mount(hostname, entry):
                    self._mounts.pop(hostname, None)
                return
            self.log.warning(
                "abandoned workspace mount at %s left in place: %s now owns it%s",
                mount_point, hostname, " (stacked mount, swept on shutdown)" if created else "",
            )

    async def _umount_point(self, mount_point: str, *, reason: str) -> None:
        """One unmount with no registry entry behind it, off the loop (retried, T14)."""
        loop = asyncio.get_running_loop()
        if await loop.run_in_executor(self._ws_pool, self._umount_sync, mount_point):
            self.log.info("workspace unmounted %s (%s)", mount_point, reason)

    async def _admit_workspace(self, descriptor: dict, session: Session) -> str | None:
        """Mount + gate this connection's share before the 101; return reason or None.

        Runs off the event loop in the bounded workspace pool (a hung share or a slow helper
        must never touch the loop) and fails closed on the gate timeout. On success the session
        gets a **per-session** reference to the mount entry and that mount's monitor is
        started. On failure nothing is bound and the reason is English and ASCII.
        """
        if _on_windows():
            # Windows has no mount(8) and no helper — the share is linked in instead.
            return await self._admit_workspace_unc(descriptor, session)
        cfg = self.cfg.workspace
        try:
            hostname = sanitize_hostname(str(descriptor.get("hostname", "")))
        except MountInputError as exc:
            return f"workspace descriptor rejected: {exc}"
        # Enforce the token on **this** side too. Requiring it in the client config is
        # only half the promise: an old or hand-rolled client can still send an empty one, and
        # the gate then degrades to "is anything mounted at this path" — silently dropping the
        # wrong-share/empty-share check that is the sentinel's entire purpose. A share that
        # cannot prove itself is refused, not admitted on trust.
        if not str(descriptor.get("sentinel_token", "")):
            return ("workspace descriptor rejected: sentinel_token is required to prove the "
                    "mounted share is yours")
        previous = getattr(session, "_rab_hostname", None)
        if previous is not None and previous != hostname:
            # A session's workspace is **fixed at session start and can never move**.
            # Releasing the old share here — which N1 needs to keep the count honest —
            # would umount ``root/<previous>`` right under an agent that is still running,
            # because ``[[agents]].cwd`` may live *inside* that share and a resume does not
            # restart the agent. Refusing is the only safe answer: start a new session instead.
            return (f"this session belongs to workspace {previous!r}; it cannot switch to "
                    f"{hostname!r}, start a new session instead")
        loop = asyncio.get_running_loop()
        self._loop = loop
        abandon = _Abandon()
        async with self._host_lock(hostname):
            future = loop.run_in_executor(
                self._ws_pool, self._mount_refusal, hostname, descriptor, abandon
            )
            # Backstop for the race where mount(8) finishes just as the timeout fires: the
            # callback sees the registered entry and reclaims it instead of orphaning it.
            future.add_done_callback(functools.partial(self._reclaim_abandoned, hostname, abandon))
            try:
                reason, entry = await asyncio.wait_for(
                    asyncio.shield(future),
                    timeout=cfg.monitor_timeout_seconds * 2,   # the mount and the gate after it
                )
            except asyncio.TimeoutError:
                abandon.abandoned = True
                return "workspace storage unavailable (gate timed out)"
            if reason:
                return reason
            # Mounted and gated. References are counted **per session, per entry**: a
            # reconnect re-runs this for the same session, so an unconditional increment would
            # let refs outrun sessions — refs stuck at 1/2/3… while one session holds one
            # release, meaning the share for any client that ever dropped a connection can
            # never reach zero and is never unmounted. Comparing the entry object, not just the
            # hostname, also keeps this correct when our entry was reclaimed and a fresh one
            # mounted in its place.
            held = getattr(session, "_rab_entry", None)
            if held is not entry:
                entry.refs += 1
                session._rab_hostname = hostname
                session._rab_entry = entry
            self._ensure_monitor(hostname, entry)
        self.log.info(
            "workspace ready agent=%s session=%s mount=%s",
            session.agent.name, session.session_id, entry.mount_point,
        )
        return None

    async def _admit_workspace_unc(self, descriptor: dict, session: Session) -> str | None:
        """Windows: link the client's share into ``<root>/<hostname>``, then gate it.

        Windows has no ``mount(8)``, no bind mount and no privileged helper, so the share is
        reached at its own UNC path and made visible to the session as a **directory symlink**
        at the very same ``<root>/<hostname>`` the POSIX branch mounts to — the hostname layer
        is unchanged, and so is everything downstream (``_share_cwd`` joins the link name onto
        this mount point exactly as before).

        Nothing is unmounted and no monitor is started in this stage, so **no registry entry is
        taken**: ``_mounts`` stays empty, which is what makes the existing release path
        (``_release_mount`` → nothing to find → return) already correct here. The session gets a
        standalone entry so the branch-A cwd still knows its mount point.
        """
        cfg = self.cfg.workspace
        try:
            hostname = sanitize_hostname(str(descriptor.get("hostname", "")))
        except MountInputError as exc:
            return f"workspace descriptor rejected: {exc}"
        token = str(descriptor.get("sentinel_token", ""))
        if not token:
            return ("workspace descriptor rejected: sentinel_token is required to prove the "
                    "mounted share is yours")
        previous = getattr(session, "_rab_hostname", None)
        if previous is not None and previous != hostname:
            return (f"this session belongs to workspace {previous!r}; it cannot switch to "
                    f"{hostname!r}, start a new session instead")
        fs_type = str(descriptor.get("fs_type", "cifs"))
        device = str(descriptor.get("device", ""))
        try:
            validate_device(fs_type, device)
            unc = unc_share_target(fs_type, device)
        except MountInputError as exc:
            return f"workspace descriptor rejected: {exc}"
        link = os.path.normpath(mount_point_for(cfg.root, hostname))
        try:
            resolve_unc_share(unc, link)
        except MountError as exc:
            # A MountError already carries an English sentence — ``english_reason`` maps a
            # non-OSError to its class name, which is what used to reach the wire ("workspace
            # link failed: MountError"). Log the original for the operator and put an
            # ASCII-safe copy of its own sentence on the wire, exactly as POSIX does.
            self.log.warning("workspace link failed session=%s hostname=%s: %s",
                             session.session_id, hostname, exc)
            return f"workspace link failed: {ascii_text(str(exc))}"
        except OSError as exc:
            return f"workspace link failed: {english_reason(exc)}"
        reason = unc_sentinel_gate(link, SENTINEL_NAME, token)
        if reason is not None:
            return reason
        session._rab_hostname = hostname
        session._rab_entry = _MountEntry(mount_point=link, sentinel_token=token,
                                         probe_host="", probe_port=0)
        self.log.info("workspace linked agent=%s session=%s link=%s -> %s",
                      session.agent.name, session.session_id, link, unc)
        return None

    def _reclaim_abandoned(self, hostname: str, abandon: _Abandon, future: asyncio.Future) -> None:
        """Backstop for the race where mount(8) finished just as the caller's timeout fired.

        Quiet when the worker noticed the abandonment itself (``handed_off``) — that path
        already scheduled the reclaim, and two claims on one mount is exactly what this must
        not do. Otherwise hand the entry to the **same lock-held reclaim** the worker uses:
        deciding and unmounting from this callback directly would repeat N2 in a different
        shape, because a newer client may have taken the path in the meantime.
        """
        if not abandon.abandoned or abandon.handed_off:
            return
        try:
            _reason, entry = future.result()
        except (Exception, asyncio.CancelledError):
            return
        if entry is None:
            return
        self._schedule_reclaim(hostname, entry.mount_point, True)

    def _umount_sync(self, mount_point: str) -> bool:
        """Unmount with a few retries; runs off the loop. True when it is gone.

        ``umount`` fails with "target is busy" while a process still has its cwd inside the
        mount — the session's agent was just reaped, but its children can lag a moment — so a
        couple of short retries are the difference between a clean teardown and a stale mount
        that makes every later connect 412.
        """
        cfg = self.cfg.workspace
        last = ""
        for attempt in range(UMOUNT_ATTEMPTS):
            try:
                helper_umount(mount_point, timeout=cfg.monitor_timeout_seconds,
                              sock_path=cfg.helper_socket)
                return True
            except MountError as exc:
                last = str(exc)
                if attempt + 1 < UMOUNT_ATTEMPTS:
                    time.sleep(UMOUNT_RETRY_DELAY_SECONDS)
        self.log.error("workspace unmount failed at %s after %d attempts: %s",
                       mount_point, UMOUNT_ATTEMPTS, last)
        return False

    async def _discard_mount(self, hostname: str, entry: _MountEntry) -> bool:
        """Unmount a mount and, only if it really went away, stop its monitor.

        Returns ``True`` when the mount is gone. On failure the monitor is left running and the
        **caller keeps the entry**, so the next admission reuses the still-mounted share instead
        of mounting onto a busy path.

        Callers hold ``_host_lock(hostname)`` — the last session for a hostname leaving and
        the lock-held reclaim of an abandoned mount both decide inside the lock, so no umount
        can land on top of a newcomer that was just admitted. ``shutdown_workspaces``
        takes the lock too rather than relying on "no traffic left" being true at that instant.
        """
        loop = asyncio.get_running_loop()
        if not await loop.run_in_executor(self._ws_pool, self._umount_sync, entry.mount_point):
            return False
        if entry.stop is not None:
            entry.stop.set()
        if entry.monitor_task is not None:
            entry.monitor_task.cancel()
        self.log.info("workspace unmounted %s (no session left for %s)", entry.mount_point, hostname)
        return True

    async def _ensure_agent(self, session: Session, ipversion: str | None = None) -> str | None:
        """Spawn the session's agent, once, during admission.

        Returns ``None`` when the agent is up (or was already up on a resume), or an English
        reason when it could not be started.

        The predicate is the session's own state — no process yet — so a resume that already
        has an agent is a no-op. The caller releases the admission slot once this is decided.

        ``ipversion`` is the connection's IP family (``"4"``/``"6"``, or ``None`` when it cannot
        be told). It joins the client hostname in the agent's environment; both are
        injected **only here**, at the one moment the agent starts, so a reconnect that reuses a
        running agent keeps the values its first connection fixed.
        """
        if session.proc is not None:
            return None
        if session.closing:
            # Distinct from "already running": returning None here would let the
            # handler go on to ``send_to_agent``, and that **silently drops** a frame whenever
            # there is no process (session.py). A session on its way out gets an explicit
            # refusal instead of a frame that vanishes without a trace.
            return f"session {session.session_id} is closing; its agent was not started"
        extra_env: dict[str, str] = {}
        hostname = getattr(session, "_rab_hostname", None)
        if hostname:
            # Branch A only: the hostname exactly as the descriptor carried it (sanitize_hostname
            # validates but returns it unchanged). Branch B has none, and an empty value would be
            # worse than no variable at all.
            extra_env[CLIENT_ENV] = hostname
        if ipversion:
            extra_env[IPVERSION_ENV] = ipversion
        # The session's own bridge id, unconditional — the same value the handshake
        # response header and every ``[session …]`` log line carry.
        extra_env[SESSION_ID_ENV] = session.session_id
        try:
            await session.start(extra_env)
        except OSError as exc:
            # There is no HTTP response left to send after the 101, so the reason goes back to
            # the caller, which puts it on the close frame. Only OSError is answered
            # with a reason: an unexpected error keeps propagating instead of being dressed up
            # as something the client could act on.
            return f"cannot start agent {session.agent.name}: {english_reason(exc)}"
        return None

    def _ensure_monitor(self, hostname: str, entry: _MountEntry) -> None:
        """One monitor per mount point, started once. It cuts only the sessions bound to
        this hostname when the share goes unreachable."""
        if entry.monitor is not None:
            return
        cfg = self.cfg.workspace
        entry.stop = asyncio.Event()
        entry.monitor = MountMonitor(
            mount_point=entry.mount_point,
            probe_host=entry.probe_host,
            probe_port=entry.probe_port,
            timeout=cfg.monitor_timeout_seconds,
            interval=cfg.monitor_interval_seconds,
            fail_threshold=cfg.monitor_fail_threshold,
            log=self.log,
            on_change=functools.partial(self._on_mount_change, hostname),
        )
        entry.monitor_task = asyncio.create_task(entry.monitor.run(entry.stop))

    def _on_mount_change(self, hostname: str, available: bool) -> None:
        """Monitor verdict for one mount.

        Going down only flips the entry's flag: live sessions are **not** closed. Their host
        requests are answered with a JSON-RPC error (see the handler) and the connection stays,
        so when the monitor sees the share again, forwarding resumes on the same session.
        """
        entry = self._mounts.get(hostname)
        if entry is not None:
            entry.available = available

    @contextlib.asynccontextmanager
    async def _host_lock(self, hostname: str):
        """Serialize everything that changes one hostname's mount, and recycle the lock.

        A claim is registered before waiting so the lock cannot be dropped out from under a
        waiter (S4: the old dict of locks only ever grew).
        """
        entry = self._host_locks.get(hostname)
        if entry is None:
            entry = self._host_locks[hostname] = _HostLock(asyncio.Lock())
        entry.users += 1
        try:
            async with entry.lock:
                yield
        finally:
            entry.users -= 1
            if entry.users == 0 and hostname not in self._mounts:
                self._host_locks.pop(hostname, None)

    async def _release_mount(self, session: Session) -> None:
        """Drop a session's reference; unmount the last one on that hostname.

        Runs under the same per-hostname lock the mount takes: without it, a
        departing client's umount can land *after* a newcomer finished mounting and was
        admitted — yanking the working share out from under a live session, or failing the
        umount as busy and leaving the registry and the kernel disagreeing.

        What is released is the reference this session was actually given (``_rab_entry``,
        N1). If the registry now holds a **different** entry under that hostname, ours was
        already reclaimed together with its mount, and decrementing the newcomer's count would
        steal a reference from a session that never took one.
        """
        hostname = getattr(session, "_rab_hostname", None)
        if not hostname:
            return
        held = getattr(session, "_rab_entry", None)
        # The agent's cwd may live inside the mount; let it exit (bounded) before the
        # umount, or ``umount`` reports "target is busy" and the share is left mounted.
        await session.wait_exit(UMOUNT_WAIT_SECONDS)
        session._rab_hostname = None       # idempotent — a session releases at most once
        session._rab_entry = None
        async with self._host_lock(hostname):
            entry = self._mounts.get(hostname)
            if entry is None or (held is not None and entry is not held):
                return
            entry.refs = max(0, entry.refs - 1)
            if entry.refs > 0:
                return                   # still in use by another session: leave it mounted
            if not await self._discard_mount(hostname, entry):
                # Keep it registered (its monitor still running) so the next admission
                # reuses the still-mounted share instead of mounting onto a busy path.
                self.log.warning("workspace %s left mounted for reuse after a failed unmount",
                                 entry.mount_point)
                return
            self._mounts.pop(hostname, None)

    async def shutdown_workspaces(self) -> None:
        """Stop every monitor, drain pending unmounts, and unmount anything still held.

        Called from ``run()`` after the listeners are gone. A session that was still up when
        the service stopped never fires its last-release, so the mounts left in the registry
        are torn down here; the helper is asked to unmount each so a share does not linger
        mounted on the box after the bridge exits.
        """
        # Let the in-flight releases and abandoned-mount reclaims **finish** rather than
        # cancelling them: a cancelled task can die between "popped the entry" and "umounted",
        # and the sweep below would then unmount a path the half-finished task already took
        # down. Each mount must be given back exactly once (N2's whole point). Bounded by
        # the helper timeout on each round-trip; run() is already past the listeners.
        if self._release_tasks:
            await asyncio.gather(*list(self._release_tasks), return_exceptions=True)
        self._release_tasks.clear()
        for hostname, entry in list(self._mounts.items()):
            async with self._host_lock(hostname):
                if await self._discard_mount(hostname, entry):
                    self._mounts.pop(hostname, None)
        self._host_locks.clear()
        if self._ws_pool is not None:
            # wait=False: a gate/umount worker parked on an uninterruptible mount syscall
            # must not hang the shutdown this await is part of. The wait_for in the request
            # path already failed that call closed; this only bounds how long exit waits.
            self._ws_pool.shutdown(wait=False)
            self._ws_pool = None


def _is_session_end(exc: ConnectionClosed) -> bool:
    return exc.rcvd is not None and exc.rcvd.code == CLOSE_SESSION_END


async def run(cfg: ServerConfig, log: logging.Logger) -> None:
    bridge = Bridge(cfg, log)
    # §3: the workspace is mounted per client at handshake time, not at startup, so
    # the service comes up whether or not any share is reachable — "if it cannot mount, do not
    # start" is retired along with the single global mount. A client whose share is not ready
    # is refused in its handshake, before the 101, not here.
    socks = listen_sockets(cfg, log)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)
    scheme = "wss" if cfg.tls.enabled else "ws"
    try:
        async with AsyncExitStack() as stack:
            servers = [await stack.enter_async_context(serve_on(bridge, sock)) for sock in socks]
            # One line per stack, with the address that actually got bound: an operator
            # reading a log has to be able to tell v4 from v6 without guessing.
            for sock in socks:
                log.info(
                    "listening on %s://%s agents=%s tls=%s max_sessions=%s grace=%ss",
                    scheme,
                    describe_socket(sock),
                    ",".join(sorted(cfg.agents)),
                    cfg.tls.enabled,
                    cfg.max_sessions or "unlimited",
                    cfg.session_grace_seconds,
                )
            try:
                await stop.wait()
            except (KeyboardInterrupt, asyncio.CancelledError):
                pass
            finally:
                for server in servers:
                    server.close()
                with contextlib.suppress(asyncio.CancelledError):
                    await bridge.close_all()
                await bridge.shutdown_workspaces()
                log.info("stopped")
    finally:
        for sock in socks:
            sock.close()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="remote-acp-server",
        description="Serve ACP agents over an authenticated WebSocket bridge.",
    )
    parser.add_argument("--config", help="path to the instance's server.toml (alternative to --instances-dir)")
    parser.add_argument("--instances-dir", help="the configs/ directory holding <instance>/server.toml")
    parser.add_argument("--instance", help="instance name; the config is <instances-dir>/<instance>/server.toml")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


class UsageError(ValueError):
    """Command line is missing a required selection; exit code 2 like argparse."""


def resolve_config_path(args: argparse.Namespace) -> str:
    if args.config:
        return args.config
    if not args.instances_dir:
        raise UsageError("--config, or --instances-dir together with --instance, is required")
    if not args.instance:
        raise UsageError("--instances-dir requires --instance")
    return str(default_config_path(args.instances_dir, args.instance))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        config_path = resolve_config_path(args)
    except UsageError as exc:
        print(f"remote-acp-server: {exc}", file=sys.stderr)
        return 2
    try:
        cfg = ServerConfig.load(config_path)
    except (ConfigError, OSError) as exc:
        print(f"remote-acp-server: {exc}", file=sys.stderr)
        return 1
    log = build_logger(cfg)
    if args.instance:
        log.info("instance %s config %s", args.instance, config_path)
    try:
        asyncio.run(run(cfg, log))
    except KeyboardInterrupt:
        log.info("interrupted, shutting down")
    except ConfigError as exc:
        # The keys file is read when the Bridge is built, one step after the config
        # load, so an undecodable keys file lands here. It is still a configuration
        # error: one line and exit 1, never a traceback (R6).
        print(f"remote-acp-server: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        log.error("cannot listen on %s:%d: %s", cfg.host, cfg.port, exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
