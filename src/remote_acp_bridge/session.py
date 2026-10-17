"""One bridge session: an agent subprocess plus its frame buffers."""

from __future__ import annotations

import asyncio
import collections
import contextlib
import json
import os
import time
from dataclasses import dataclass, field

from .config import AgentConfig
from .frames import (
    CLOSE_RESUMABLE,
    CLOSE_SESSION_END,
    MAX_FRAME_BYTES,
    LineDecoder,
    encode_frame,
)
from .mounting import english_reason
from .plugins import PLUGINS
from .plugins.base import DROP

PENDING_MAX = 1000
# A plugin hook that runs longer than this is abandoned and its frame passed through
# (fail-open, T24); the per-command ask timeout is what actually bounds the built-in plugin.
PLUGIN_TIMEOUT = 60.0
PLUGIN_ASK_TIMEOUT = 10.0


@dataclass
class _Ask:
    """One in-flight ``ctx.ask_agent``: its private request id, session, future and captured
    frames."""

    request_id: str
    session_id: str
    future: asyncio.Future
    frames: list[str] = field(default_factory=list)


# The two ``session/update`` chunk types that carry a command's *text* answer. Everything
# else an ask's window sees is none of the ask's business and must reach the host (T26/S1).
_ASK_CHUNK_TYPES = frozenset({"agent_message_chunk", "agent_thought_chunk"})


def _frame_id(frame: str):
    try:
        message = json.loads(frame)
    except (ValueError, TypeError):
        return None
    return message.get("id") if isinstance(message, dict) else None


def _frame_result(frame: str):
    try:
        message = json.loads(frame)
    except (ValueError, TypeError):
        return None
    result = message.get("result") if isinstance(message, dict) else None
    return result if isinstance(result, dict) else None


def _is_our_chunk(frame: str, ask: _Ask) -> bool:
    """Is this the text answer to ``ask``'s own command and nothing else?

    Only ``agent_message_chunk`` / ``agent_thought_chunk`` updates for the ask's session
    qualify. **Honest boundary**: the protocol cannot tell whose text block this is, so a
    same-typed text block produced by the host's own traffic during the window is taken as
    ours and swallowed too — the price of never leaking ``/model status``.
    """
    try:
        message = json.loads(frame)
    except (ValueError, TypeError):
        return False
    if not isinstance(message, dict) or message.get("method") != "session/update":
        return False
    params = message.get("params")
    if not isinstance(params, dict):
        return False
    if ask.session_id and params.get("sessionId") != ask.session_id:
        return False
    update = params.get("update")
    return isinstance(update, dict) and update.get("sessionUpdate") in _ASK_CHUNK_TYPES


class PluginContext:
    """The four capabilities a plugin hook is handed (T24): send to agent/host, ask, log.

    Frames the plugin itself pushes still pass the *other* plugins, but never re-enter this
    one (anti-self).
    """

    def __init__(self, session: "Session", plugin, config: dict | None = None):
        self._session = session
        self._plugin = plugin
        # T27: this entry's [[agents.plugins]].config, handed over as-is.
        self.config = config if isinstance(config, dict) else {}

    async def send_to_agent(self, frame: str) -> None:
        await self._session.send_to_agent(frame, origin=self._plugin)

    async def send_to_host(self, frame: str) -> None:
        await self._session.from_agent(frame, origin=self._plugin)

    async def ask_agent(self, method: str, params: dict, timeout: float = PLUGIN_ASK_TIMEOUT):
        return await self._session.ask_agent(method, params, timeout, origin=self._plugin)

    def log(self, msg: str) -> None:
        self._session._plugin_log(f"{_plugin_name(self._plugin)}: {msg}")


def _plugin_name(plugin) -> str:
    return getattr(plugin, "name", type(plugin).__name__)


class Session:
    """Lifetime unit of an agent subprocess.

    The agent is started when the session is created and terminated when the
    session ends (client says goodbye, grace period expires, or the agent dies).
    """

    def __init__(
        self,
        session_id: str,
        agent: AgentConfig,
        *,
        grace_seconds: float = 0,
        pending_max: int = PENDING_MAX,
        log=None,
        on_closed=None,
        global_env: dict[str, str] | None = None,
    ):
        self.session_id = session_id
        self.agent = agent
        self.grace_seconds = grace_seconds
        self.pending_max = pending_max
        self.log = log
        self.on_closed = on_closed
        # T77: the instance-wide ``[env]``, one layer below the agent's own ``env``.
        self.global_env = dict(global_env or {})
        self.connection = None
        self.proc: asyncio.subprocess.Process | None = None
        self.created_at = time.time()
        self.last_activity = self.created_at
        # When the connection went away and the session entered retention. Eviction
        # orders by this, not by last_activity: an idle session that dropped has an
        # earlier last_activity than disconnected_at.
        self.disconnected_at: float | None = None
        self.frames_in = 0
        self.frames_out = 0
        self.pending_dropped = 0
        self.closing = False
        self._pending: collections.deque[str] = collections.deque()
        self._decoder = LineDecoder()
        self._outbox: asyncio.Queue[str] = asyncio.Queue()
        self._pump: asyncio.Task | None = None
        self._sender: asyncio.Task | None = None
        self._stderr: asyncio.Task | None = None
        self._grace: asyncio.TimerHandle | None = None
        # -- plugins (T24) --------------------------------------------------
        self._plugins: list = []
        self._contexts: dict[int, PluginContext] = {}
        for spec in (getattr(agent, "plugins", None) or []):
            plugin_name = getattr(spec, "name", spec)
            factory = PLUGINS.get(plugin_name)
            if factory is None:
                self._warn(f"unknown plugin {plugin_name!r}; ignoring it")
                continue
            plugin = factory()
            self._plugins.append(plugin)
            self._contexts[id(plugin)] = PluginContext(self, plugin, getattr(spec, "config", None))
        # Agent output is read by ``_pump_agent`` and processed (through the plugin chain)
        # by ``_process_from_agent``: two tasks, so a plugin awaiting an ask never blocks the
        # reader that must deliver the ask's answer.
        self._from_queue: asyncio.Queue[str] = asyncio.Queue()
        self._processor: asyncio.Task | None = None
        self._ask: _Ask | None = None
        self._ask_seq = 0
        self._swallow_ids: set[str] = set()

    def _plugin_log(self, message: str) -> None:
        if self.log:
            self.log.warning("[session %s] plugin %s", self.session_id, message)

    def _warn(self, message: str) -> None:
        if self.log:
            self.log.warning("[session %s] %s", self.session_id, message)

    # -- agent lifecycle ---------------------------------------------------

    def ensure_cwd(self, cwd: str, base: str = "") -> str:
        """Create the directory the session is going to work in (T34).

        The host sits on another machine and cannot mkdir here, and a missing directory
        only shows up later as the agent failing to start (opencode answers a bogus cwd
        on the first ``session/prompt``). An empty cwd means "use the process default"
        and is skipped; an existing directory is left exactly as it is. A relative cwd is
        resolved against ``base`` — the directory the agent itself will start in — so the
        one that gets created is the one that gets used (T35-S2).

        Returns an empty string when nothing was created, otherwise the path created, so
        the caller can put one line in the log. Raises ``OSError`` when the directory
        cannot be made: that becomes the refusal the client is told with — a handshake 500
        while the workspace feature is off, or the reason on the bridge error frame / the
        close frame once the agent start is deferred behind the connection's first frame
        (T56-D) — never a session that quietly works somewhere else. ``os.makedirs`` reports
        a path containing a NUL byte as ``ValueError``, which is not an ``OSError``, so both
        are folded into the same refusal (T35-R15) — otherwise the error escapes the
        handler, the connection dies with 1011 and the agent already spawned by that
        session is left running with nobody attached to it.
        """
        if not cwd:
            return ""
        if base and not os.path.isabs(cwd):
            cwd = os.path.join(base, cwd)
        if os.path.isdir(cwd):
            return ""
        try:
            os.makedirs(cwd, exist_ok=True)
        except (OSError, ValueError) as exc:
            # Our own English sentence, never strerror: this text is what the client is
            # refused with, and a Chinese Windows renders WinError 5 in local words
            # (T55-M4 applies to this path too, not just the workspace one).
            raise OSError(f"cannot create session cwd {cwd!r}: {english_reason(exc)}") from exc
        return cwd

    async def start(self, extra_env: dict[str, str] | None = None) -> None:
        """Launch the agent subprocess.

        ``extra_env`` is the bridge's own session-level environment (T64): the client's
        hostname and the connection's IP family. Our values win over a same-named
        ``[[agents]].env`` entry and that override is logged once — these are runtime facts
        about the session, not settings the config file may shadow.

        The full ladder, low to high (T77): the inherited ``os.environ``, then the instance's
        ``[env]``, then the agent's own ``[[agents]].env``, then ``extra_env``.
        """
        command = [self.agent.command, *self.agent.args]
        created = self.ensure_cwd(self.agent.cwd)
        overrides = {**self.global_env, **self.agent.env, **(extra_env or {})}
        replaced = sorted(name for name in (extra_env or {}) if name in self.agent.env)
        self.proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.agent.cwd or None,
            env={**os.environ, **overrides} if overrides else None,
            limit=MAX_FRAME_BYTES,
        )
        self._pump = asyncio.create_task(self._pump_agent())
        self._sender = asyncio.create_task(self._pump_outbox())
        self._stderr = asyncio.create_task(self._drain_stderr())
        if self._plugins:
            self._processor = asyncio.create_task(self._process_from_agent())
            await self._open_plugins()
        if self.log:
            if created:
                self.log.info("[session %s] created agent cwd %s", self.session_id, created)
            if replaced:
                self.log.info("[session %s] bridge env overrides [[agents]].env for %s",
                              self.session_id, ", ".join(replaced))
            self.log.info(
                "[session %s] started agent %s pid=%s", self.session_id, self.agent.name, self.proc.pid
            )

    async def _pump_agent(self) -> None:
        stdout = self.proc.stdout
        try:
            while True:
                chunk = await stdout.read(65536)
                if not chunk:
                    break
                for frame in self._decoder.feed(chunk):
                    self._route_from_agent(frame)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            self._warn(f"agent stdout read failed: {exc!r}")
        finally:
            for frame in self._decoder.flush():
                self._route_from_agent(frame)
            if not self.closing:
                self._warn(f"agent exited (rc={self.proc.returncode}), ending session")
                asyncio.create_task(self.close("agent-exited"))

    async def _drain_stderr(self) -> None:
        stderr = self.proc.stderr
        try:
            while True:
                chunk = await stderr.read(65536)
                if not chunk:
                    break
                if self.log:
                    for line in chunk.decode("utf-8", errors="replace").splitlines():
                        if line:
                            self.log.debug("[session %s] agent stderr: %s", self.session_id, line)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    # -- ws side -----------------------------------------------------------

    def attach(self, connection) -> None:
        if self._grace is not None:
            self._grace.cancel()
            self._grace = None
        previous = self.connection
        self.connection = connection
        self.disconnected_at = None
        self.last_activity = time.time()
        if previous is not None and previous is not connection:
            asyncio.create_task(previous.close(code=CLOSE_RESUMABLE, reason="superseded"))
        pending, self._pending = list(self._pending), collections.deque()
        for frame in pending:
            self._outbox.put_nowait(frame)

    def detach(self, connection=None, *, end: bool = False) -> None:
        if connection is not None and self.connection is not connection:
            return
        self.connection = None
        if end or self.closing:
            asyncio.create_task(self.close("client-end"))
            return
        self.disconnected_at = time.time()
        if self.grace_seconds > 0:
            loop = asyncio.get_running_loop()
            self._grace = loop.call_later(self.grace_seconds, self._grace_expired)
        elif self.log:
            self._warn("disconnected; session kept indefinitely (grace = 0)")

    def _grace_expired(self) -> None:
        self._grace = None
        if self.connection is None:
            asyncio.create_task(self.close("grace-expired"))

    def touch(self) -> None:
        self.last_activity = time.time()

    def idle_seconds(self) -> float:
        return time.time() - self.last_activity

    async def wait_exit(self, timeout: float) -> None:
        """Wait (bounded) for the agent process to exit before its cwd is unmounted (T14).

        The agent's cwd may live inside the mounted share, so unmounting before it exits gives
        ``target is busy``. ``close()`` already reaps the process; this is the explicit,
        bounded wait for callers that unmount the share the process was working in.
        """
        if self.proc is None or self.proc.returncode is not None:
            return
        try:
            await asyncio.wait_for(self.proc.wait(), timeout)
        except asyncio.TimeoutError:
            pass

    async def send_to_agent(self, frame: str | bytes, *, origin=None) -> None:
        """Host → agent. Every frame runs the plugin chain first (T24)."""
        out = await self._run_hooks("on_to_agent", frame, origin=origin)
        if out is None:
            return
        await self._write_agent(out)

    async def _write_agent(self, frame: str | bytes) -> None:
        data = encode_frame(frame)
        if not data or self.proc is None or self.proc.stdin is None:
            return
        self.frames_in += 1
        self.touch()
        try:
            self.proc.stdin.write(data)
            await self.proc.stdin.drain()
        except (ConnectionResetError, BrokenPipeError, ValueError) as exc:
            self._warn(f"agent stdin closed: {exc!r}")

    def _buffer(self, frame: str) -> None:
        if len(self._pending) >= self.pending_max:
            self._pending.popleft()
            self.pending_dropped += 1
        self._pending.append(frame)

    def _deliver(self, frame: str) -> None:
        self.frames_out += 1
        self._outbox.put_nowait(frame)

    async def _pump_outbox(self) -> None:
        """Single consumer, so frames reach the client in agent output order."""
        while True:
            frame = await self._outbox.get()
            connection = self.connection
            if connection is None:
                self._buffer(frame)
                continue
            try:
                await connection.send(frame)
                self.touch()
            except Exception as exc:
                self._warn(f"ws send failed: {exc!r}")
                self._buffer(frame)

    # -- plugin chain (T24) -------------------------------------------------

    def _context(self, plugin) -> PluginContext:
        context = self._contexts.get(id(plugin))
        if context is None:
            context = PluginContext(self, plugin, {})
            self._contexts[id(plugin)] = context
        return context

    async def _open_plugins(self) -> None:
        for plugin in self._plugins:
            hook = getattr(plugin, "on_open", None)
            if hook is None:
                continue
            try:
                await asyncio.wait_for(hook(self, self._context(plugin)), PLUGIN_TIMEOUT)
            except asyncio.TimeoutError:
                self._plugin_log(f"{_plugin_name(plugin)}.on_open timed out")
            except Exception as exc:
                self._plugin_log(f"{_plugin_name(plugin)}.on_open failed ({english_reason(exc)})")

    async def _run_hooks(self, hook: str, frame, *, origin):
        """Run one direction's chain in order; ``None`` return means "swallowed"."""
        for plugin in self._plugins:
            if plugin is origin:
                continue
            method = getattr(plugin, hook, None)
            if method is None:
                continue
            try:
                out = await asyncio.wait_for(method(frame, self._context(plugin)), PLUGIN_TIMEOUT)
            except asyncio.TimeoutError:
                self._plugin_log(f"{_plugin_name(plugin)}.{hook} timed out; passing the frame through")
                continue
            except Exception as exc:
                self._plugin_log(f"{_plugin_name(plugin)}.{hook} failed ({english_reason(exc)}); passing the frame through")
                continue
            if out is DROP:
                return None
            if isinstance(out, str):
                frame = out
            elif out is not None:
                self._plugin_log(f"{_plugin_name(plugin)}.{hook} returned {type(out).__name__}; passing the frame through")
        return frame

    async def from_agent(self, frame: str, *, origin=None) -> None:
        """Agent → host. Every frame runs the plugin chain first (T24)."""
        out = await self._run_hooks("on_from_agent", frame, origin=origin)
        if out is not None:
            self._deliver(out)

    def _route_from_agent(self, frame: str) -> None:
        """Reader side: hand an ask its own frames, everything else to the processor.

        Only what provably belongs to the in-flight ask is swallowed (T26/S1): the reply to
        its private id, and a text chunk for its session while that id is in flight. Any
        other frame — ``available_commands_update``, ``session_info_update``, ``usage_update``,
        ``tool_call*``, a reply to some other id — is passed on to the host untouched.
        """
        ask = self._ask
        frame_id = _frame_id(frame)
        if ask is not None:
            if frame_id == ask.request_id:
                self._ask = None
                ask.frames.append(frame)
                if not ask.future.done():
                    ask.future.set_result((_frame_result(frame), ask.frames))
                return
            if frame_id is None and _is_our_chunk(frame, ask):
                ask.frames.append(frame)
                return
        if frame_id is not None and frame_id in self._swallow_ids:
            return
        if self._processor is None:
            self._deliver(frame)          # no plugin chain: keep the old direct path
        else:
            self._from_queue.put_nowait(frame)

    async def _process_from_agent(self) -> None:
        while True:
            frame = await self._from_queue.get()
            await self.from_agent(frame)

    async def ask_agent(self, method, params, timeout=PLUGIN_ASK_TIMEOUT, *, origin=None):
        """Ask the agent one request with a private id; the reply to that id, and its text
        answer while the id is in flight, are captured and never reach the host (T24/T26)."""
        self._ask_seq += 1
        request_id = f"rab-plugin-{self._ask_seq}"
        request = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            separators=(",", ":"), ensure_ascii=False,
        )
        session_id = params.get("sessionId") if isinstance(params, dict) else ""
        ask = _Ask(request_id, session_id if isinstance(session_id, str) else "",
                   asyncio.get_running_loop().create_future(), [])
        self._ask = ask
        try:
            await self.send_to_agent(request, origin=origin)
            return await asyncio.wait_for(ask.future, timeout)
        finally:
            if self._ask is ask:
                self._ask = None
            self._swallow_ids.add(request_id)

    # -- teardown ----------------------------------------------------------

    async def close(self, reason: str) -> None:
        if self.closing:
            return
        self.closing = True
        if self._grace is not None:
            self._grace.cancel()
            self._grace = None
        for task in (self._pump, self._sender, self._stderr, self._processor):
            if task is None:
                continue
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:  # pragma: no cover - defensive
                self._warn(f"task ended during teardown: {exc!r}")
        if self.connection is not None:
            try:
                await self.connection.close(code=CLOSE_SESSION_END, reason=reason)
            except Exception:
                pass
            self.connection = None
        if self.proc is not None and self.proc.returncode is None:
            try:
                self.proc.terminate()
                await asyncio.wait_for(self.proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        if self.proc is not None:
            # T17-S3: close the subprocess transport while the loop still lives.
            # ``asyncio.subprocess.Process`` has no ``close()`` on any version we
            # support (verified on 3.12.12 and 3.14.7), so the call that used to sit
            # here was a silent no-op inside the suppress(): the transport survived
            # until GC, and if the interpreter got to it after the loop was closed,
            # CPython printed "Exception ignored in: BaseSubprocessTransport.__del__
            # ... Event loop is closed". There is no public API for this, hence the
            # private attribute; if it ever disappears we fall back to today's
            # behaviour rather than crashing a session teardown.
            transport = getattr(self.proc, "_transport", None)
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()
        self._pending.clear()
        if self.on_closed is not None:
            self.on_closed(self)
        if self.log:
            self.log.info(
                "[session %s] closed (%s) in=%d out=%d dropped=%d",
                self.session_id,
                reason,
                self.frames_in,
                self.frames_out,
                self.pending_dropped,
            )
