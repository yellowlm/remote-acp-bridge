"""ndjson <-> WebSocket text frame codec.

One ACP message is one WebSocket text frame, so the newline that ACP uses as a
message delimiter is added on the way into the agent and stripped on the way
out. Nothing here interprets the payload.
"""

from __future__ import annotations

MAX_FRAME_BYTES = 16 * 1024 * 1024

# The two WebSocket close codes, named once for the whole package (README §1.3). They
# are the protocol contract the three modules share: the server sends them, the session
# tears down with them, and the client decides "reconnect or not" on them — so the
# numbers must not be spelled out in three places (T23-S3).
CLOSE_SESSION_END = 1000    # the session itself is over; a client must not reconnect
CLOSE_RESUMABLE = 1001      # only this connection dropped; the session can be resumed

# T8: a session cwd the bridge cannot use. The server answers the host request with a JSON-RPC
# error carrying CWD_ERROR_CODE and a message "<CWD_ERROR_PREFIX>: <one reason>"; the client
# rewrites that message into the final host-facing text (its own local path + the share
# account). The exact strings live here so the two binaries cannot drift apart.
CWD_ERROR_CODE = -32001
CWD_ERROR_PREFIX = "session working directory is not accessible in the mounted share"
CWD_REASON_NOT_MOUNTED = "the workspace share is not mounted"
CWD_REASON_NOT_FOUND = "the folder does not exist in the mounted share"
CWD_REASON_NOT_READABLE = "the folder is not readable in the mounted share"
CWD_REASON_NOT_DIRECTORY = "the path is not a directory in the mounted share"

# T20/T21: the sentinel file name is a fixed convention shared by both binaries — the server's
# gate reads it and the client seeds it. It lives here, a module **both** the client and the
# server import, so the client's import closure never pulls in a server-only module just to
# learn the name.
SENTINEL_NAME = ".rab-workspace-token"

# T64/T79: the variables the bridge puts into each agent subprocess's environment. They are
# session-level runtime facts — who the client is, which IP family its connection used, and
# which bridge session this is — fixed when the session's agent starts, not configuration.
# The names live here so the server and the tests cannot drift apart.
CLIENT_ENV = "REMOTE_ACP_BRIDGE_CLIENT"
IPVERSION_ENV = "REMOTE_ACP_BRIDGE_IPVERSION"
SESSION_ID_ENV = "REMOTE_ACP_BRIDGE_SID"


def encode_frame(frame: str | bytes) -> bytes:
    """Agent stdin bytes for one WebSocket text frame."""
    if isinstance(frame, bytes):
        frame = frame.decode("utf-8", errors="replace")
    text = frame.rstrip("\r\n")
    if not text:
        return b""
    return (text + "\n").encode("utf-8")


class LineDecoder:
    """Turns agent stdout bytes into frames, buffering a partial tail."""

    def __init__(self, max_bytes: int = MAX_FRAME_BYTES):
        self.max_bytes = max_bytes
        self.dropped_long_lines = 0
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> list[str]:
        self._buffer.extend(chunk)
        frames: list[str] = []
        while True:
            index = self._buffer.find(b"\n")
            if index < 0:
                break
            line = bytes(self._buffer[:index])
            del self._buffer[: index + 1]
            frames.extend(self._to_frame(line))
        if len(self._buffer) > self.max_bytes:
            self.dropped_long_lines += 1
            self._buffer.clear()
        return frames

    def flush(self) -> list[str]:
        """Emit a trailing line the agent wrote without a final newline."""
        line, self._buffer = bytes(self._buffer), bytearray()
        return self._to_frame(line) if line else []

    def _to_frame(self, line: bytes) -> list[str]:
        if not line:
            return []
        if len(line) > self.max_bytes:
            self.dropped_long_lines += 1
            return []
        text = line.decode("utf-8", errors="replace").rstrip("\r")
        return [text] if text else []
