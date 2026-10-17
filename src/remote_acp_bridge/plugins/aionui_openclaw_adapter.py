"""First server plugin: give AionUi the model list ACP will not advertise (T24).

openclaw's ACP gateway hardcodes its ``configOptions`` whitelist and advertises no
``category: "model"`` entry, so AionUi's model dropdown is empty. This plugin fills it in
on the ``session/new`` / ``session/load`` reply and translates the host's selection back
into openclaw's own ``/model`` commands.

The four command texts are openclaw's, so they are fixed here on purpose::

    /model list                 the providers
    /models <provider>          one provider's models
    /model status               the model in use
    /model <provider>/<model>   switch

Everything runs synchronously on the ``session/new`` / ``session/load`` reply and when the
host picks a model. The plugin's own commands and every frame they produce — notifications
and results alike — are swallowed, never leaked to the host (``/model status`` carries key
prefixes, two endpoints and ``~/.openclaw/...`` paths). Any parse failure is fail-open: the
frame is passed through unchanged and one English line is logged.
"""

from __future__ import annotations

import asyncio
import json
import re
from contextlib import suppress
from pathlib import Path

from .base import DROP, rewrite_texts

MODEL_COMMAND = "/model"
LIST_COMMAND = "/model list"
STATUS_COMMAND = "/model status"

# The three session-opening methods whose frame carries the (already mapped) session cwd (T31).
SESSION_METHODS = frozenset({"session/new", "session/load", "session/resume"})
# The banner's placeholder token: ``__PATH__`` / ``__WORKING_DIRECTORY__`` / …
NAME_PLACEHOLDER = re.compile(r"__[A-Z][A-Z0-9_]*__")

# Session permission modes (T38B): AionUi only renders the `mode` / `model` / `thought_level`
# categories, so the five modes ride a real `category:"mode"` configOption. ``default`` means
# "clear the session override" (permissionMode: null).
MODE_ID = "mode"
PERMISSION_OPTIONS = (
    ("default", "Default"),
    ("read-only", "Read-only"),
    ("guarded", "Guarded"),
    ("workspace", "Workspace"),
    ("full", "Full"),
)
PERMISSION_VALUES = frozenset(value for value, _ in PERMISSION_OPTIONS)
PERMISSION_TIMEOUT = 10.0

# The banner is read from this file at runtime (T29): editing the wording is editing the file,
# never this module. It ships with the package (``resources/`` under ``src``).
PROMPT_RESOURCE = Path(__file__).resolve().parent.parent / "resources" / "prompt_aionui_openclaw_adapter.txt"
RULES_MARKER = "[Assistant Rules]"

# ``provider/model`` and a bare token (a provider, or a model typed without its provider).
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-]*/[A-Za-z0-9][A-Za-z0-9_.\-]*")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*$")
_SKIP_WORDS = {"providers", "provider", "models", "model", "list", "status", "current"}


def _load(frame: str):
    try:
        message = json.loads(frame)
    except (ValueError, TypeError):
        return None
    return message if isinstance(message, dict) else None


def _text_of(frames) -> str:
    """Every human-readable string the agent emitted for one command."""
    chunks: list[str] = []
    for frame in frames:
        message = _load(frame)
        if message is None:
            continue
        params = message.get("params")
        update = params.get("update") if isinstance(params, dict) else None
        if isinstance(update, dict):
            content = update.get("content")
            if isinstance(content, dict) and isinstance(content.get("text"), str):
                chunks.append(content["text"])
            for key in ("text", "content"):
                if isinstance(update.get(key), str):
                    chunks.append(update[key])
        result = message.get("result")
        if isinstance(result, dict):
            for key in ("text", "output", "message"):
                if isinstance(result.get(key), str):
                    chunks.append(result[key])
    return "\n".join(chunks)


def _strip_bullet(line: str) -> str:
    for bullet in ("-", "*", "\u2022"):
        if line.startswith(bullet):
            return line[len(bullet):].strip()
    return line.strip()


def _providers(text: str) -> list[str]:
    """The provider on each line: the first whitespace-separated word after the bullet.

    openclaw prints ``- provider-name (1)`` (a trailing count), so a
    whole-line-must-be-a-bare-token rule sees nothing (T27). Hint lines (``Use: /models
    <provider>``, ``Switch: /model <provider>/<model>``) are skipped by their colon.
    """
    found: list[str] = []
    for raw in text.splitlines():
        line = _strip_bullet(raw)
        if not line or ":" in line:
            continue
        word = line.split()[0]
        if _TOKEN_RE.match(word) and word.lower() not in _SKIP_WORDS and word not in found:
            found.append(word)
    return found


def _models(text: str, provider: str) -> list[str]:
    """Model lines only: a ``- `` bullet whose body starts with the ``<provider>/`` asked for.

    openclaw's model page also carries a header (``… — showing 1-1 of 1 (page 1/1)``) and
    hint/footer lines (``Switch: /model <provider/model>``, ``All: …``); a "any X/Y on the
    line is a model" rule turned the ``<provider/model>`` placeholder and ``1/1`` into fake
    dropdown entries (T29), so only real bulleted rows count.
    """
    found: list[str] = []
    prefix = f"{provider}/"
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("- "):
            continue
        body = line[2:].strip()
        if not body.startswith(prefix):
            continue
        name = body.split()[0]
        if name not in found:
            found.append(name)
    return found


def _current_model(text: str) -> str:
    """The model on the ``Current:`` line, or the first ``provider/model`` if there is none."""
    for raw in text.splitlines():
        line = _strip_bullet(raw)
        if line.lower().startswith("current:"):
            match = _MODEL_RE.search(line)
            if match:
                return match.group(0)
    match = _MODEL_RE.search(text)
    return match.group(0) if match else ""


def _prompt_block() -> str:
    """The banner text, read fresh from the resource file each time (T29). '' if unreadable."""
    try:
        return PROMPT_RESOURCE.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _fill_placeholder(block: str, cwd: str) -> str | None:
    """Replace the banner's placeholder token(s) with the session's directory (T31).

    The placeholder is the ``__NAME__`` token the file carries (the task book called it
    ``__PATH__``; the shipped file uses ``__WORKING_DIRECTORY__``). The surrounding text —
    including any quotes the file puts around it — is left byte-for-byte. ``None`` when a
    placeholder cannot be filled: no directory yet, or one would survive the substitution
    (never emit a literal placeholder to the agent).
    """
    if not NAME_PLACEHOLDER.search(block):
        return block
    if not cwd:
        return None
    filled = NAME_PLACEHOLDER.sub(lambda _match: cwd, block)
    return None if NAME_PLACEHOLDER.search(filled) else filled


def _mode_option(value: str) -> dict:
    """The ``category:"mode"`` configOption (T38B): friendly names shown, internal values sent."""
    return {
        "type": "select",
        "id": MODE_ID,
        "name": "Mode",
        "category": "mode",
        "currentValue": value,
        "options": [{"value": item, "name": label} for item, label in PERMISSION_OPTIONS],
    }


def _mode_update(session_id: str, mode_id: str) -> str:
    """The ``current_mode_update`` notification AionUi reads after a mode change (T45)."""
    return json.dumps(
        {"jsonrpc": "2.0", "method": "session/update",
         "params": {"sessionId": session_id,
                    "update": {"sessionUpdate": "current_mode_update", "currentModeId": mode_id}}},
        separators=(",", ":"), ensure_ascii=False)


def _modes_slot(value: str) -> dict:
    """The ACP ``modes`` slot carrying our five permission modes (T48)."""
    return {
        "currentModeId": value,
        "availableModes": [{"id": item, "name": label} for item, label in PERMISSION_OPTIONS],
    }


_SECRET_RE = re.compile(r"sk-[A-Za-z0-9_\-]{6,}")
_KEYED_QUOTED_RE = re.compile(r'("?(?:token|password|apiKey)"?\s*[:=]\s*)"[^"]*"', re.IGNORECASE)
_KEYED_BARE_RE = re.compile(r'("?(?:token|password|apiKey)"?\s*[:=]\s*)([^\s,}"]+)', re.IGNORECASE)


def _sanitize(text: str) -> str:
    """Blank out secrets before a line reaches the log (T50): ``sk-…`` and keyed values."""
    text = _SECRET_RE.sub("sk-***", text)
    text = _KEYED_QUOTED_RE.sub(r'\1"***"', text)
    return _KEYED_BARE_RE.sub(r"\1***", text)


def _first_line(text: str) -> str:
    """First line of a CLI stream, whitespace collapsed, cut to 200 chars ('-' when empty)."""
    lines = text.splitlines() if text else []
    collapsed = " ".join(lines[0].split()) if lines else ""
    return collapsed[:200] if collapsed else "-"


def _try_json(text: str):
    """The CLI's JSON reply, or ``None`` when the output is not JSON (T50)."""
    try:
        return json.loads(text)
    except (ValueError, UnicodeDecodeError):
        return None


def _error_type(payload) -> str:
    """``error.type`` from a CLI JSON reply, for a one-glance diagnosis (T50)."""
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict) and isinstance(error.get("type"), str):
            return error["type"]
    return ""


def _permission_ok(payload) -> bool:
    """Did ``sessions.patch`` land? ``entry.permissionMode`` present, or ``ok`` truthy."""
    if not isinstance(payload, dict):
        return False
    entry = payload.get("entry")
    if isinstance(entry, dict) and "permissionMode" in entry:
        return True
    return bool(payload.get("ok"))


def _close_transport(proc) -> None:
    """Close a finished subprocess's transport (T35; the same shape as ``session.py`` T17-S3).

    ``asyncio.subprocess.Process`` has no public ``close()``; leaving the transport for GC
    makes the interpreter print a ResourceWarning traceback ("I/O operation on closed pipe")
    at exit. Suppressed so a close that cannot happen never breaks fail-open.
    """
    transport = getattr(proc, "_transport", None)
    if transport is not None:
        with suppress(Exception):
            transport.close()


class AionuiOpenclawAdapter:
    name = "aionui_openclaw_adapter"

    def __init__(self):
        self._session_id = ""
        self._current = ""
        self._option: dict | None = None
        self._injected = False     # T29: the banner goes in at most once per session
        # T31: the session's absolute working directory on the server, remembered from the
        # ``session/new|load|resume`` frame the bridge already mapped (``_for_agent``).
        self._cwd = ""
        # T33: the openclaw session key and the permission-mode state.
        self._session_key = ""
        self._permission = "default"       # last value openclaw confirmed
        self._pending_permission: str | None = None
        self._previous_permission: str | None = None   # T40: revert target if the patch fails
        self._config_options: list | None = None       # T40: last session reply's options
        self._permission_retry = False
        self._inflight: set = set()        # host prompt ids sent but not yet answered

    # -- session opening: fill in the model dropdown -----------------------

    async def on_from_agent(self, frame, ctx):
        message = _load(frame)
        if message is None:
            return None
        self._learn_session_id(message, ctx)
        if message.get("method") == "session/update":
            return await self._take_over_update(message, ctx)
        await self._on_prompt_result(message, ctx)
        result = message.get("result")
        if not isinstance(result, dict):
            return None
        reply_sid = result.get("sessionId")
        if isinstance(reply_sid, str) and reply_sid:
            # Only a session/new reply carries its own id: remember it (T55/M1 also resets the
            # key here). A session/load reply has none, so it keeps the id learned from a frame.
            await self._remember_session_key(message, result, ctx)
        if not self._session_id:
            return None
        if self._pending_permission is not None:
            # T52: this reply brought (or let us resolve) the session key — send the patch
            # that was waiting.
            await self._flush_permission(ctx)
        changed = False
        try:
            changed = await self._fill_models(result, ctx)
        except Exception as exc:      # fail-open: leave the reply byte-for-byte as it was
            ctx.log(f"model list failed ({type(exc).__name__}); leaving the reply unchanged")
        try:
            changed = self._add_mode_option(result, ctx) or changed
        except Exception as exc:
            ctx.log(f"mode option failed ({type(exc).__name__}); leaving the reply unchanged")
        options = result.get("configOptions")
        if isinstance(options, list):
            # T40: keep this reply's option list so a failed patch can notify the host with it.
            self._config_options = json.loads(json.dumps(options))
        if not changed:
            return None
        return json.dumps(message, separators=(",", ":"), ensure_ascii=False)

    def _learn_session_id(self, message: dict, ctx) -> None:
        """Remember the ACP session id from any frame that carries one (T59).

        A ``session/load`` reply has no ``sessionId`` (only ``session/new`` does), so on a
        reconnect the id has to come from a frame's ``params.sessionId``. Only fills an empty
        slot: an id we already have is never overwritten.
        """
        if self._session_id:
            return
        params = message.get("params")
        sid = params.get("sessionId") if isinstance(params, dict) else None
        if isinstance(sid, str) and sid:
            self._session_id = sid
            ctx.log(f"session id learned: {sid} (via frame)")

    async def _remember_session_key(self, message: dict, result: dict, ctx) -> None:
        """The gateway session key the CLI patch needs (T33/T52).

        ``_meta.sessionKey`` is authoritative. Without it the key is resolved through the
        CLI's own ``sessions list`` (the entry whose ``sessionId`` is ours); the bare ACP
        sessionId is **never** used as a key — ``sessions.patch`` would happily create a
        phantom session for it and report ok.
        """
        self._session_id = result["sessionId"]
        self._session_key = ""     # T55/M1: re-resolve the key for every session reply
        for holder in (result, message):
            meta = holder.get("_meta")
            if isinstance(meta, dict) and isinstance(meta.get("sessionKey"), str) and meta["sessionKey"]:
                self._session_key = meta["sessionKey"]
                ctx.log(f"session key resolved: {self._session_key} (via meta)")
                return
        key = await self._resolve_key_via_list(ctx)
        if key:
            self._session_key = key
            ctx.log(f"session key missing in the session reply; resolved via sessions list: {key}")
        else:
            ctx.log("session key missing in the session reply; sessions list could not resolve it")

    async def _resolve_key_via_list(self, ctx) -> str:
        """Ask ``sessions list`` for the key whose ``sessionId`` is ours (T52); "" on failure."""
        command = self._config(ctx).get("openclaw_command")
        if not isinstance(command, str) or not command.strip():
            return ""
        argv = [command, "sessions", "list", "--json"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except (OSError, ValueError):
            return ""
        try:
            out, _err = await asyncio.wait_for(proc.communicate(), PERMISSION_TIMEOUT)
        except asyncio.TimeoutError:
            with suppress(Exception):
                proc.kill()
            with suppress(Exception):
                await asyncio.wait_for(proc.wait(), 5)
            _close_transport(proc)
            return ""
        _close_transport(proc)
        payload = _try_json((out or b"").decode("utf-8", errors="replace"))
        if isinstance(payload, list):
            sessions = payload
        elif isinstance(payload, dict):
            sessions = payload.get("sessions")
        else:
            return ""
        if not isinstance(sessions, list):
            return ""
        for entry in sessions:
            if isinstance(entry, dict):
                key = entry.get("key")
                # T57: pair by the key's tail (``…:acp-bridge:<sessionId>``); the entry's own
                # ``sessionId`` field is a different uuid and never matches.
                if isinstance(key, str) and key.endswith(":" + self._session_id):
                    return key
        return ""

    def _add_mode_option(self, result: dict, ctx) -> bool:
        """Take over both places AionUi may read the mode from (T38B/T48).

        AionUi renders only the ``mode``/``model``/``thought_level`` categories, and it also
        re-derives that control from the ACP ``modes`` slot; both are replaced with our five
        so the control can never fall back to openclaw's thought levels.
        """
        if not self._permission_enabled(ctx):
            return False
        options = result.get("configOptions")
        if isinstance(options, list):
            item = _mode_option(self._permission)
            for index, existing in enumerate(options):
                if isinstance(existing, dict) and existing.get("id") == MODE_ID:
                    options[index] = item
                    break
            else:
                options.append(item)
        result["modes"] = _modes_slot(self._permission)
        return True

    async def _take_over_update(self, message: dict, ctx) -> object:
        """Rewrite the agent's own mode updates so the host keeps seeing our five (T48).

        Also learns the gateway session key from ``session_info_update`` (T57) — openclaw
        sends it right after ``session/new`` *and* after ``session/load`` (reconnect).
        """
        if not self._permission_enabled(ctx):
            return None
        params = message.get("params")
        update = params.get("update") if isinstance(params, dict) else None
        if not isinstance(update, dict):
            return None
        kind = update.get("sessionUpdate")
        if kind == "session_info_update":
            await self._learn_key_from_update(update, ctx)
            return None
        if kind == "config_option_update":
            options = update.get("configOptions")
            if not isinstance(options, list):
                return None
            item = _mode_option(self._permission)
            for index, existing in enumerate(options):
                if isinstance(existing, dict) and existing.get("id") == MODE_ID:
                    options[index] = item
                    break
            else:
                options.append(item)
            return json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        if kind == "current_mode_update":
            # openclaw is announcing a thought level: the host must see our mode instead.
            return _mode_update(self._session_id, self._permission)
        return None

    async def _learn_key_from_update(self, update: dict, ctx) -> None:
        """Take the gateway key out of a ``session_info_update`` (T57).

        Only the ``kind:"direct"`` value (``agent:<agentId>:acp-bridge:<sessionId>``) is the
        patch key; the earlier ``kind:"unknown"`` ``acp-bridge:<uuid>`` half-value is ignored.
        """
        if self._session_key:
            return
        meta = update.get("_meta")
        if not isinstance(meta, dict):
            return
        key = meta.get("sessionKey")
        if not isinstance(key, str) or not key:
            return
        kind = meta.get("kind") or update.get("kind")
        if ":acp-bridge:" not in key and kind != "direct":
            return
        self._session_key = key
        ctx.log(f"session key resolved: {key} (via session_info_update)")
        if self._pending_permission is not None:
            await self._flush_permission(ctx)

    async def _on_prompt_result(self, message: dict, ctx) -> None:
        """A host prompt's result: its turn converged, so a stored permission patch may go."""
        result = message.get("result")
        if not isinstance(result, dict) or "stopReason" not in result:
            return
        if message.get("id") not in self._inflight:
            return
        self._inflight.discard(message.get("id"))
        if self._pending_permission is not None:
            await self._flush_permission(ctx)

    async def _fill_models(self, result: dict, ctx) -> bool:
        self._session_id = result["sessionId"]
        providers = _providers(await self._ask(ctx, LIST_COMMAND))
        if not providers:
            ctx.log("/model list parsed 0 providers; leaving the reply unchanged")
            return False
        models: list[str] = []
        for provider in providers:
            models.extend(_models(await self._ask(ctx, f"/models {provider}"), provider))
        if not models:
            ctx.log("/models parsed 0 models; leaving the reply unchanged")
            return False
        current = _current_model(await self._ask(ctx, STATUS_COMMAND)) or self._current
        if current not in models:
            current = current or models[0]
        self._current = current
        self._option = {
            "type": "select",
            "id": "model",
            "name": "Model",
            "category": "model",
            "currentValue": current,
            "options": [{"value": model, "name": model} for model in models],
        }
        options = result.get("configOptions")
        if not isinstance(options, list):
            return False
        for index, item in enumerate(options):
            if isinstance(item, dict) and item.get("id") == "model":
                options[index] = self._option
                break
        else:
            options.append(self._option)
        return True

    # -- first message: inject the banner once per session -----------------

    def _inject_banner(self, frame: str, message: dict) -> str | None:
        if self._injected:
            return None
        params = message.get("params")
        prompt = params.get("prompt") if isinstance(params, dict) else None
        if not isinstance(prompt, list):
            return None
        block = _prompt_block()
        if not block:
            return None
        block = _fill_placeholder(block, self._cwd)
        if block is None:
            # T31: without a session directory we cannot fill the placeholder; never emit
            # the literal token, so skip the banner entirely.
            return None
        for part in prompt:
            if not isinstance(part, dict) or part.get("type") != "text":
                continue
            text = part.get("text")
            if not isinstance(text, str) or RULES_MARKER not in text:
                continue
            rewritten = rewrite_texts(
                frame, [(text, text.replace(RULES_MARKER, block + RULES_MARKER, 1))])
            if rewritten is not None:
                self._injected = True
            return rewritten
        return None

    # -- host selection: drive openclaw's own /model command ---------------

    async def on_to_agent(self, frame, ctx):
        message = _load(frame)
        if message is None:
            return None
        self._learn_session_id(message, ctx)
        method = message.get("method")
        if method == "session/prompt":
            self._inflight.add(message.get("id"))
            return self._inject_banner(frame, message)
        if method in SESSION_METHODS:
            params = message.get("params")
            cwd = params.get("cwd") if isinstance(params, dict) else None
            if isinstance(cwd, str) and cwd:
                self._cwd = cwd            # already mapped to the agent's absolute directory
            return None
        if method == "session/set_mode":
            return await self._handle_set_mode(frame, message, ctx)
        if method != "session/set_config_option":
            return None
        params = message.get("params")
        if not isinstance(params, dict):
            return None
        if params.get("configId") == MODE_ID:
            return await self._handle_mode(frame, message, ctx)
        if params.get("configId") != "model":
            return None
        value = params.get("value")
        if not isinstance(value, str) or not value:
            return None
        # Swallow the host's set_config_option (openclaw answers it -32603) and switch the
        # model with openclaw's own command; its output is captured and swallowed by the ask.
        try:
            await self._ask(ctx, f"{MODEL_COMMAND} {value}")
        except Exception as exc:
            ctx.log(f"model switch failed ({type(exc).__name__}); leaving the answer to the host")
        self._current = value
        if self._option is not None:
            self._option = {**self._option, "currentValue": value}
        payload = {"configOptions": [self._option]} if self._option else {}
        await ctx.send_to_host(json.dumps(
            {"jsonrpc": "2.0", "id": message.get("id"), "result": payload},
            separators=(",", ":"), ensure_ascii=False))
        return DROP

    # -- session mode (T33/T38): bypass the ACP surface via openclaw's CLI --------------

    @staticmethod
    def _config(ctx) -> dict:
        config = getattr(ctx, "config", None)
        return config if isinstance(config, dict) else {}

    def _permission_enabled(self, ctx) -> bool:
        """The CLI path comes from config (T33); no default path, and no URL switch (T46)."""
        command = self._config(ctx).get("openclaw_command")
        return isinstance(command, str) and bool(command.strip())

    async def _handle_mode(self, frame: str, message: dict, ctx) -> object:
        params = message.get("params") or {}
        value = params.get("value")
        if value not in PERMISSION_VALUES or not self._permission_enabled(ctx):
            return None                    # not ours / feature off: pass the frame through
        # T40/T43: ``previous`` is the last **confirmed** value; ``_permission`` only ever moves
        # on a confirmed patch, so a second in-flight request must not see the first request's
        # wish as its revert target.
        self._previous_permission = self._permission
        self._pending_permission = value   # last request wins
        ctx.log(_sanitize(f"permission mode requested: {value} via set_config_option "
                          f"(session {self._session_id})"))
        # Answer the host optimistically and swallow the frame (openclaw's ACP surface would
        # answer it -32603). The patch is sent now, or when the turn ends.
        await ctx.send_to_host(json.dumps(
            {"jsonrpc": "2.0", "id": message.get("id"),
             "result": {"configOptions": [_mode_option(value)]}},
            separators=(",", ":"), ensure_ascii=False))
        if not self._inflight:
            await self._flush_permission(ctx)
        return DROP

    async def _handle_set_mode(self, frame: str, message: dict, ctx) -> object:
        """``session/set_mode``: AionUi's other way to pick a permission mode (T45).

        Only our five values are ours; a thought level (``off``/``medium``/…) passes straight
        through. ACP's set_mode is a request, so it is answered (an empty result) and swallowed
        — openclaw must never read it as a thought level — and the host also gets the mode
        update. The patch uses the same store/defer/revert path as the configOption route.
        """
        params = message.get("params") or {}
        mode_id = params.get("modeId")
        if mode_id not in PERMISSION_VALUES or not self._permission_enabled(ctx):
            return None                    # not ours / feature off: pass the frame through
        await ctx.send_to_host(json.dumps(
            {"jsonrpc": "2.0", "id": message.get("id"), "result": {}},
            separators=(",", ":"), ensure_ascii=False))
        await ctx.send_to_host(_mode_update(self._session_id, mode_id))
        self._previous_permission = self._permission
        self._pending_permission = mode_id
        ctx.log(_sanitize(f"permission mode requested: {mode_id} via set_mode "
                          f"(session {self._session_id})"))
        if not self._inflight:
            await self._flush_permission(ctx)
        return DROP

    async def _flush_permission(self, ctx) -> None:
        value = self._pending_permission
        if value is None:
            return
        outcome = await self._dispatch_permission(ctx, value)
        if outcome == "ok":
            self._permission = value       # only a confirmed patch moves the known value
            self._pending_permission = None
            self._permission_retry = False
            ctx.log(_sanitize(f"permission mode applied: {value}"))
        elif outcome == "defer-key":
            pass                           # T55/S1: keep the request; no retry budget spent
        elif outcome == "defer" and not self._permission_retry:
            # openclaw said a run is still active (our "in flight" view missed one): keep the
            # request and retry once, when the next turn's result lands.
            self._permission_retry = True
        else:
            # Final failure (or a second defer): fall back to the value we had before the
            # request and tell the host, so its control shows the old mode again (T40).
            self._pending_permission = None
            self._permission_retry = False
            if self._previous_permission is not None:
                self._permission = self._previous_permission
            notice = self._revert_notification(self._permission)
            if notice is not None:
                await ctx.send_to_host(notice)

    def _revert_notification(self, value: str) -> str | None:
        """The ``config_option_update`` telling the host a failed patch left the mode alone."""
        if not isinstance(self._config_options, list):
            return None
        options = json.loads(json.dumps(self._config_options))
        for index, item in enumerate(options):
            if isinstance(item, dict) and item.get("id") == MODE_ID:
                options[index] = {**item, "currentValue": value}
                break
        return json.dumps(
            {"jsonrpc": "2.0", "method": "session/update",
             "params": {"sessionId": self._session_id,
                        "update": {"sessionUpdate": "config_option_update",
                                   "configOptions": options}}},
            separators=(",", ":"), ensure_ascii=False)

    async def _dispatch_permission(self, ctx, value: str) -> str:
        """Run ``openclaw gateway call sessions.patch`` once. "ok" | "defer" | "fail"."""
        if not self._session_key:
            # T52: without a resolved session key the patch would go out with an empty key and
            # the CLI would fail (or, worse, create a phantom session). Keep it stored until
            # the session reply resolves the key. "defer-key" (T55/S1) is its own outcome so it
            # never spends the one retry the "active run" path owns.
            ctx.log("permission mode deferred: session key not resolved yet")
            return "defer-key"
        command = self._config(ctx).get("openclaw_command")
        if not isinstance(command, str) or not command.strip():
            ctx.log("permission mode not applied: openclaw_command is not configured")
            return "fail"
        mode = None if value == "default" else value
        params = json.dumps({"key": self._session_key, "permissionMode": mode},
                            separators=(",", ":"))
        # No URL switch at all (T46): the CLI may only drive the local gateway it is
        # configured with.
        argv = [command, "gateway", "call", "sessions.patch", "--json", "--params", params]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except (OSError, ValueError) as exc:
            self._log_failure(ctx, "exited", -1, argv, "", f"cannot run: {type(exc).__name__}")
            return "fail"
        try:
            out, err = await asyncio.wait_for(proc.communicate(), PERMISSION_TIMEOUT)
        except asyncio.TimeoutError:
            with suppress(Exception):
                proc.kill()
            with suppress(Exception):
                await asyncio.wait_for(proc.wait(), 5)
            _close_transport(proc)
            self._log_failure(ctx, "timeout", -1, argv, "", "")
            return "fail"
        _close_transport(proc)
        out_text = (out or b"").decode("utf-8", errors="replace")
        err_text = (err or b"").decode("utf-8", errors="replace")
        payload = _try_json(out_text)
        if proc.returncode != 0:
            if "active run" in err_text.lower() or "active run" in out_text.lower():
                if not self._permission_retry:
                    ctx.log("permission mode deferred: openclaw reported an active run")
                    return "defer"
            self._log_failure(ctx, "exited", proc.returncode, argv, out_text, err_text, payload)
            return "fail"
        if payload is None:
            self._log_failure(ctx, "no-json", proc.returncode, argv, out_text, err_text)
            return "fail"
        if not _permission_ok(payload):
            self._log_failure(ctx, "not-confirmed", proc.returncode, argv, out_text, err_text, payload)
            return "fail"
        return "ok"

    def _log_failure(self, ctx, reason: str, rc: int, argv: list, out: str, err: str,
                     payload=None) -> None:
        """One English ASCII line: why the patch failed, with argv and the CLI's first lines."""
        line = (f"permission mode not applied: {reason} rc={rc} argv={' '.join(argv)} "
                f"out={_first_line(out)} err={_first_line(err)}")
        etype = _error_type(payload)
        if etype:
            line += f" type={etype}"
        ctx.log(_sanitize(line))

    # -- one command -------------------------------------------------------

    async def _ask(self, ctx, command: str) -> str:
        _result, frames = await ctx.ask_agent(
            "session/prompt",
            {"sessionId": self._session_id,
             "prompt": [{"type": "text", "text": command}]},
        )
        return _text_of(frames)
