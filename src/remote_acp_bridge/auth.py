"""Handshake authentication for the authenticated WebSocket bridge.

The handshake is a single ``GET`` upgrade. Authentication and the client's workspace
descriptor both travel in request headers, all named ``X-Remote-ACP-Bridge-*``:

    X-Remote-ACP-Bridge-AuthKey the bridge key, plaintext (the transport is TLS)
    X-Remote-ACP-Bridge-Timestamp unix seconds
    X-Remote-ACP-Bridge-Nonce a random string, single use
    X-Remote-ACP-Bridge-Session-Id the uuid being resumed; absent for a new session
    X-Remote-ACP-Bridge-Config base64(json), always present; ``{}`` without workspace

The server compares the key against every line of ``keys_file`` in constant time, checks
the timestamp against the clock-skew window, and refuses a nonce it has already seen.
There is no HMAC signature any more: the key is sent in the clear under TLS, so a
signature would add nothing.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Callable

from .config import ConfigError

AUTH_KEY_HEADER = "X-Remote-ACP-Bridge-AuthKey"
TIMESTAMP_HEADER = "X-Remote-ACP-Bridge-Timestamp"
NONCE_HEADER = "X-Remote-ACP-Bridge-Nonce"
SESSION_HEADER = "X-Remote-ACP-Bridge-Session-Id"
CONFIG_HEADER = "X-Remote-ACP-Bridge-Config"

# The workspace key inside the Config payload. Everything else in the payload is ignored
# by this version, so later additions can ride along without touching the handshake.
WORKSPACE_KEY = "workspace"


def make_nonce() -> str:
    return secrets.token_urlsafe(16)


def encode_config(workspace: dict | None) -> str:
    """The ``Config`` header value: ``{"workspace": <descriptor>}``, or ``{}``."""
    payload: dict = {WORKSPACE_KEY: workspace} if workspace else {}
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def auth_headers(
    key: str,
    session: str = "",
    workspace: dict | None = None,
    now: float | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """The client's handshake headers. ``Session-Id`` is only added when resuming."""
    headers = {
        AUTH_KEY_HEADER: key,
        TIMESTAMP_HEADER: str(int(now if now is not None else time.time())),
        NONCE_HEADER: nonce or make_nonce(),
        CONFIG_HEADER: encode_config(workspace),
    }
    if session:
        headers[SESSION_HEADER] = session
    return headers


class ConfigHeaderError(ValueError):
    """The ``Config`` header is missing or is not a base64-encoded JSON object."""


def parse_keys_file_text(text: str) -> list[str]:
    """One key per line; ``#`` starts a comment (whole line or trailing)."""
    keys = []
    for raw in text.splitlines():
        candidate = raw.split("#", 1)[0].strip()
        if candidate:
            keys.append(candidate)
    return keys


def load_keys(path: str) -> list[str]:
    """Read the keys file.

    A file that is not valid UTF-8 is a configuration problem, not a transient one,
    so it surfaces as ConfigError: both entry points then report it on one line and
    exit 1 instead of printing a bare ``UnicodeDecodeError`` traceback (R6).
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return parse_keys_file_text(handle.read())
    except UnicodeDecodeError as exc:
        raise ConfigError(f"keys file is not valid UTF-8: {path}") from exc


class NonceCache:
    """Remembers used nonces until they fall outside the replay window."""

    def __init__(self, cache_seconds: float, clock: Callable[[], float] = time.time):
        self.cache_seconds = cache_seconds
        self._clock = clock
        self._used: dict[str, float] = {}

    def _prune(self, now: float) -> None:
        expired = [n for n, seen in self._used.items() if now - seen > self.cache_seconds]
        for n in expired:
            del self._used[n]

    def seen(self, nonce: str) -> bool:
        now = self._clock()
        self._prune(now)
        return nonce in self._used

    def remember(self, nonce: str) -> None:
        self._used[nonce] = self._clock()

    def __len__(self) -> int:
        self._prune(self._clock())
        return len(self._used)


@dataclass
class Decision:
    ok: bool
    status: int
    reason: str

    @staticmethod
    def reject(status: int, reason: str) -> "Decision":
        return Decision(False, status, reason)


def _header(headers, name: str) -> str:
    try:
        value = headers[name]
    except (KeyError, TypeError):
        return ""
    return value.strip() if isinstance(value, str) else ""


def decode_config(headers) -> dict:
    """Parse the ``Config`` header into its JSON object; raise ConfigHeaderError otherwise.

    A missing, non-base64, non-UTF-8 or non-object value is refused with an English reason,
    never a traceback: the header is client-supplied and reaches the server before any ACP
    traffic.
    """
    raw = _header(headers, CONFIG_HEADER)
    if not raw:
        raise ConfigHeaderError("missing config header")
    try:
        decoded = base64.b64decode(raw, validate=True).decode("utf-8")
        data = json.loads(decoded)
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise ConfigHeaderError(f"config header is not base64-encoded JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigHeaderError("config header must be a JSON object")
    return data


class KeyVerifier:
    """Authenticates a handshake against every key in ``keys_file``."""

    def __init__(
        self,
        keys: list[str],
        clock_skew_seconds: float = 300,
        nonce_cache_seconds: float = 600,
        nonces: NonceCache | None = None,
        clock: Callable[[], float] = time.time,
    ):
        if not keys:
            raise ValueError("no keys configured")
        self.keys = keys
        self.clock_skew_seconds = clock_skew_seconds
        self.clock = clock
        self.nonces = nonces or NonceCache(nonce_cache_seconds, clock=clock)

    @classmethod
    def from_file(cls, keys_file: str, clock_skew_seconds: float, nonce_cache_seconds: float) -> "KeyVerifier":
        return cls(load_keys(keys_file), clock_skew_seconds, nonce_cache_seconds)

    def authenticate(self, headers) -> Decision:
        """Check the AuthKey, the timestamp window and the nonce, in that order."""
        auth_key = _header(headers, AUTH_KEY_HEADER)
        timestamp = _header(headers, TIMESTAMP_HEADER)
        nonce = _header(headers, NONCE_HEADER)
        if not auth_key or not timestamp or not nonce:
            return Decision.reject(401, "missing authentication headers")

        try:
            issued_at = int(timestamp)
        except ValueError:
            return Decision.reject(401, "malformed timestamp")

        if abs(self.clock() - issued_at) > self.clock_skew_seconds:
            return Decision.reject(401, "timestamp outside clock skew window")

        provided = auth_key.encode("utf-8")
        matched = False
        for key in self.keys:
            # Every key is compared even after a match, so the work does not depend on which
            # line matched.
            if hmac.compare_digest(key.encode("utf-8"), provided):
                matched = True
        if not matched:
            return Decision.reject(401, "auth key mismatch")

        if self.nonces.seen(nonce):
            return Decision.reject(401, "replayed nonce")
        self.nonces.remember(nonce)
        return Decision(True, 101, "ok")
