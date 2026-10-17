"""Per-client workspace mount, gate and liveness monitor.

The bridge runs as the unprivileged ``agent`` account and therefore **cannot mount** a
share. §3 moves mounting to *handshake time*, per client: when a client's handshake carries a
workspace descriptor, the bridge asks a small privileged helper over a Unix socket to mount
that client's device under ``root/<hostname>``, then runs its own gate and monitor against the
fresh mount point. The bridge never touches a mount syscall — it only opens a socket.

Layers, all English and locale-independent (a refusal never echoes ``strerror``):

*:func:`helper_mount` /:func:`helper_umount` — the client side of the
  ``remote-acp-helper`` Unix socket. A password travels only inside this request; it is
  never logged, never put in argv.
*:func:`sentinel_gate` — before any session is admitted, the mount is really there
  (``ismount``) **and** really the expected share (a sentinel file whose content equals
  the client's own token). A wrong-but-mounted or empty share fails the second check.
*:class:`MountMonitor` — a background loop probing the storage server's TCP port and the
  local mount, **never touching files under the mount** (a hung share must not wedge the
  probe). After N consecutive failures it declares that one mount point down, which cuts
  only the sessions hanging off it.

Nothing is hardcoded and nothing comes from the environment: the helper socket path is a
field of the server config (``[workspace].helper_socket``, T5) and is passed in per call, and
every device/option/hostname is validated in:mod:`.mounting`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import subprocess
import shutil
from typing import Callable

from .mounting import MountInputError
from .mounting import english_reason as _reason_from


class MountError(Exception):
    """The helper refused or failed a mount/umount. English, never echoes secrets."""


def sentinel_gate(mount_point: str, sentinel_name: str, sentinel_token: str) -> str | None:
    """None when the mount point is usable, otherwise an English reason. **Never raises.**

    Two checks, both mandatory: the mount (``ismount``), then the sentinel — a file whose
    content equals ``sentinel_token``. **An empty token is a refusal, not a relaxation**
: the boundary already rejects it (client config, and the server on the control
    frame), so a "no token means any mount will do" branch here would be a silent internal
    degradation path just waiting for the next caller to find it. The content comparison is
    the whole point of the sentinel — it is what catches a wrong or empty share sitting on the
    same path.

    Wrapped because non-``OSError`` paths escape and reach the client as a bare
    500 with no reason: a sentinel that is not valid UTF-8 raises ``UnicodeDecodeError`` (a
    ``ValueError``), and a path containing NUL raises ``ValueError`` from ``ismount``/``open``
    outright. Both fold into one English refusal.
    """
    if not mount_point:
        return "workspace mount point is empty"
    if not sentinel_token:
        return "workspace sentinel token is not configured"
    try:
        if not os.path.ismount(mount_point):
            return f"workspace storage is not mounted at {mount_point}"
        tp = os.path.join(mount_point, sentinel_name)
        try:
            with open(tp, "r", encoding="utf-8") as handle:
                value = handle.read().strip()
        except FileNotFoundError:
            return f"workspace sentinel not found at {tp}"
    except (OSError, ValueError) as exc:
        return f"workspace check failed at {mount_point}: {_reason_from(exc)}"
    if value != sentinel_token:
        return "workspace sentinel token mismatch (wrong or empty share mounted)"
    return None


def tcp_probe(host: str, port: int, timeout: float) -> bool:
    """Can we open a TCP connection to the storage server? Never blocks longer than
    ``timeout`` and never raises — a failure just reads as ``False``."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def mount_probe(mount_point: str, timeout: float) -> bool:
    """`mountpoint -q <mp>` exits 0 when it is a mount point. Falls back to
    ``os.path.ismount`` when the util-linux binary is not on PATH."""
    if _on_windows():                      # No mount(8); the share is a UNC link
        return unc_link_ok(mount_point)
    binary = shutil.which("mountpoint")
    if not binary:
        return os.path.ismount(mount_point)
    try:
        return subprocess.run(
            [binary, "-q", mount_point], timeout=timeout,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def storage_reachable(mount_point: str, probe_host: str, probe_port: int, timeout: float) -> bool:
    """Server answers on its port **and** the local mount is present. Deliberately does
    NOT stat anything under the mount, so an unresponsive share cannot hang this."""
    return tcp_probe(probe_host, probe_port, timeout) and mount_probe(mount_point, timeout)


class MountMonitor:
    """Poll one mount point's:func:`storage_reachable` and flip availability on a run of
    failures. The actual probing runs in a worker thread so a slow socket/connect never
    stalls the event loop; tests pass a synchronous ``probe`` fake instead.

    Deliberately on the **default** executor, not the bridge's bounded workspace pool
: that pool is sized for handshakes (4), and its whole purpose is to be small
    enough that a hung share cannot starve the rest of the bridge. A monitor is a different
    shape of load — one long-lived poller per mounted client, ``tcp_probe`` already bounded by
    ``timeout`` — so parking those behind 4 slots would let N slow shares delay the (N+1)-th
    client's *handshake*, which is the thing the small pool exists to protect. Cost of the
    choice: many hung shares can occupy default-pool threads at once, and each is capped at
    ``timeout`` seconds per probe.
    """

    def __init__(
        self,
        *,
        mount_point: str,
        probe_host: str,
        probe_port: int,
        timeout: float,
        interval: float,
        fail_threshold: int,
        log,
        on_change: Callable[[bool], None],
        probe: Callable[..., bool] = storage_reachable,
    ):
        self.mount_point = mount_point
        self.probe_host = probe_host
        self.probe_port = probe_port
        self.timeout = timeout
        self.interval = interval
        self.fail_threshold = fail_threshold
        self.log = log
        self.on_change = on_change
        self._probe = probe
        self.fails = 0
        self.available = True

    def _probe_bound(self) -> bool:
        return self._probe(self.mount_point, self.probe_host, self.probe_port, self.timeout)

    async def check_once(self) -> None:
        """One probe + state update. Exposed for deterministic tests and reused by run()."""
        try:
            ok = await asyncio.get_running_loop().run_in_executor(None, self._probe_bound)
        except Exception as exc:  # a probe that blows up counts as a failure, not a crash
            ok = False
            self.log.warning("workspace probe raised %r", exc)
        if ok:
            self.fails = 0
            if not self.available:
                self.available = True
                self.log.info("workspace storage available again at %s", self.mount_point)
                self.on_change(True)
        else:
            self.fails += 1
            if self.available and self.fails >= self.fail_threshold:
                self.available = False
                self.log.error(
                    "workspace storage unavailable at %s (%d consecutive probe failures)",
                    self.mount_point, self.fails,
                )
                self.on_change(False)

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await self.check_once()
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                pass


# -- helper socket client (runs in a worker thread; never on the event loop) ------------

def _default_connector(path: str, timeout: float) -> socket.socket:
    """Open an AF_UNIX stream connection to the helper. Separated so the framing logic is
    testable on a host without AF_UNIX (some Windows builds) by injecting a fake socket."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(path)
    except OSError:
        sock.close()
        raise
    return sock


def _round_trip(request: dict, timeout: float, *, sock_path: str,
                connector=_default_connector) -> dict:
    """Send one JSON line to the helper and read one JSON line back. Raises MountError.

    ``sock_path`` is the helper's Unix socket, from the server config
    (``[workspace].helper_socket``). The password lives only in ``request`` and only inside
    this socket write; it is never logged and never appears in argv. The helper is a resident
    service and each connection is one short transaction, so a credential outlives only its own
    mount. ``connector`` is injectable so the wire framing can be exercised where AF_UNIX is
    absent.
    """
    path = sock_path
    try:
        sock = connector(path, timeout)
    except OSError as exc:
        raise MountError(f"workspace helper call failed: {_reason_from(exc)}") from exc
    try:
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        # Read up to the first **non-blank** line. Leading blank lines are tolerated
        # because anything the helper's own interpreter or a stray child writes before the
        # reply would otherwise turn a clean socket into "response unparsable" and bury the
        # real mount failure. The helper itself captures mount(8)'s output, so this is a
        # second line of defence, not the only one.
        buf = b""
        line = b""
        while not line:
            cut = buf.find(b"\n")
            if cut != -1:
                candidate, buf = buf[:cut], buf[cut + 1:]
                if candidate.strip():
                    line = candidate
                    break
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        if not line and buf.strip():
            line = buf.strip()           # a final reply with no trailing newline
    except OSError as exc:
        raise MountError(f"workspace helper call failed: {_reason_from(exc)}") from exc
    finally:
        with contextlib.suppress(Exception):
            sock.close()
    if not line:
        raise MountError("workspace helper returned no response")
    try:
        reply = json.loads(line.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise MountError(f"workspace helper response unparsable: {_reason_from(exc)}") from exc
    if not isinstance(reply, dict):
        raise MountError("workspace helper response was not an object")
    return reply


def helper_mount(request: dict, timeout: float, *, sock_path: str,
                 connector=_default_connector) -> None:
    """Ask the helper to mount; raise MountError with an English reason on refusal."""
    reply = _round_trip({"op": "mount", **request}, timeout, sock_path=sock_path, connector=connector)
    if not reply.get("ok"):
        raise MountError(str(reply.get("reason") or "workspace helper refused the mount"))


def helper_umount(mount_point: str, timeout: float, *, sock_path: str,
                  connector=_default_connector) -> None:
    """Ask the helper to unmount; raise MountError on a refusal."""
    reply = _round_trip({"op": "umount", "mount_point": mount_point}, timeout,
                        sock_path=sock_path, connector=connector)
    if not reply.get("ok"):
        raise MountError(str(reply.get("reason") or "workspace helper refused the unmount"))


# -- The Windows share model ---------------------------------------------------------
#
# Windows has no mount(8), no bind mount and no privileged helper: a client's share is not
# *mounted* onto ``<root>/<hostname>``, it is **linked** there with ``mklink /D`` — a
# directory symlink, which is the only reparse point that may target a UNC path (a junction
# cannot). "Is the share really there" is therefore answered structurally — *a symbolic link
# whose target is a UNC path* — and never by ``os.path.ismount``, whose Windows behaviour this
# project has not verified. Everything here is injectable so it is unit-tested on any host
# without creating a link, mounting anything, or reaching a share.


def _on_windows() -> bool:
    """True when the bridge runs on Windows. One seam, so tests can pick a side."""
    return os.name == "nt"


def unc_share_target(fs_type: str, device: str) -> str:
    """The UNC path a client's cifs device names, in ``\\\\host\\share`` form.

    The device (``//host/share``) is already validated by:func:`mounting.validate_device`
    before this runs. nfs4 is refused: there is no NFS client here, and the Windows branch
    links SMB shares only.
    """
    if fs_type != "cifs":
        raise MountInputError(f"the Windows server links cifs shares only, not {fs_type!r}")
    if not device.startswith("//"):
        raise MountInputError("cifs device must look like //host/share")
    return "\\\\" + device[2:].replace("/", "\\")


def _run_mklink(argv: list[str]) -> None:
    """Run the ``mklink`` argv; raise (English) when the link is not there afterwards."""
    result = subprocess.run(argv, capture_output=True, text=True)
    link = argv[-2]                     # mklink /D <link> <target>
    if result.returncode != 0 or not os.path.lexists(link):
        detail = (result.stderr or result.stdout or "").strip() or f"exit {result.returncode}"
        raise MountError(f"cannot create the share link: {detail}")


def _make_dir_link_to_unc(unc: str, link: str, *, spawn=None) -> None:
    """Create ``link`` as a directory symlink to ``unc``.

    The argv **is** the contract — ``["cmd", "/c", "mklink", "/D", link, unc]`` (``mklink``
    is a cmd builtin, so it goes through ``cmd /c``). Creating a directory symlink needs
    Developer Mode or an elevated shell; that is a deployment prerequisite documented in the
    README, not something the bridge can grant itself. ``spawn`` (default:func:`_run_mklink`)
    is injectable, so the argv is asserted without running anything.
    """
    argv = ["cmd", "/c", "mklink", "/D", link, unc]
    (spawn or _run_mklink)(argv)


# Windows hands back an NT-namespace prefix from ``os.readlink`` — a directory symlink to
# a share reads ``\\?\UNC\host\share``, and an extended *local* path reads ``\\?\C:\…``. Both
# are stripped before a value is classified or compared, or a link that is exactly right looks
# like a different one (and a local path looks like a UNC).
_NT_PREFIXES = ("\\\\?\\UNC\\", "\\??\\UNC\\", "\\\\?\\", "\\??\\")


def _strip_nt_prefix(value: str) -> str:
    """Drop a Windows NT path prefix, case-insensitively.

    ``\\\\?\\UNC\\host\\share`` names the share ``\\\\host\\share``, so that prefix maps back
    to ``\\\\``; the plain ``\\\\?\\``/``\\??\\`` forms (extended local paths) just come off.
    Anything else is returned untouched, so POSIX paths are unaffected.
    """
    lowered = value.lower()
    for prefix in _NT_PREFIXES:
        if lowered.startswith(prefix.lower()):
            tail = value[len(prefix):]
            return "\\\\" + tail if prefix.lower().endswith("unc\\") else tail
    return value


def unc_link_ok(link: str, *, islink=os.path.islink, readlink=os.readlink) -> bool:
    """Is ``link`` a **directory symbolic link** whose target is a UNC share?

    The Windows stand-in for "the share is mounted here": structural, not ``ismount``. The
    criterion is ``os.path.islink`` plus ``os.readlink`` — a **directory symbolic link**,
    which is what ``mklink /D`` creates. A junction does not count: the bridge never makes
    one, and a junction cannot target a UNC path anyway. ``islink``/``readlink`` are
    injectable so this is tested without creating a link.

    The target is classified **after** its NT prefix is stripped: ``\\\\?\\C:\\local`` is
    a local path, not a share, and must not pass just because it starts with two backslashes.
    """
    try:
        if not islink(link):
            return False
        return _strip_nt_prefix(readlink(link)).startswith("\\\\")
    except OSError:
        return False


def _same_unc(left: str, right: str) -> bool:
    """Do two paths name the same UNC share? (Windows is case-insensitive; separators vary.)"""
    def norm(value: str) -> str:
        return _strip_nt_prefix(value).replace("/", "\\").rstrip("\\").lower()
    return norm(left) == norm(right)


def resolve_unc_share(unc: str, link: str, *, spawn=None, islink=os.path.islink,
                      readlink=os.readlink, exists=os.path.lexists) -> None:
    """Point ``link`` at ``unc``, idempotently; refuse a wrong existing entry.

    * nothing there ⇒ create it with ``mklink /D``;
    * a reparse point already at the same UNC ⇒ **reuse it**, creating nothing;
    * anything else ⇒ refuse: an entry the operator put there is not ours to replace, and
      ``mklink`` would fail on it anyway.
    """
    if exists(link):
        if unc_link_ok(link, islink=islink, readlink=readlink) and _same_unc(readlink(link), unc):
            return
        raise MountError(f"workspace link {link!r} already exists and does not point at {unc!r}")
    _make_dir_link_to_unc(unc, link, spawn=spawn)


def _ascii_path(path: str) -> str:
    """A path safe for a wire reason: ASCII printable, anything else becomes '?'.

    ``root`` is operator input, so on Windows it may hold non-ASCII characters; every refusal
    reason this module puts on the wire has to stay plain ASCII.
    """
    return "".join(c if c.isascii() and c.isprintable() else "?" for c in path)


# The same filter, under a name another module may import — it is not only about paths
# (the Windows admission reuses it for a ``MountError``'s own sentence).
ascii_text = _ascii_path


def unc_sentinel_gate(link: str, sentinel_name: str, sentinel_token: str, *,
                      link_ok=unc_link_ok) -> str | None:
    """The Windows gate: a UNC symbolic link at ``link`` plus the sentinel content.

    Same shape and the same verdicts as:func:`sentinel_gate`; the only difference is the
    first check —:func:`unc_link_ok` instead of ``os.path.ismount``. Never raises. The paths
    that reach a reason go through:func:`_ascii_path`.
    """
    if not link:
        return "workspace mount point is empty"
    if not sentinel_token:
        return "workspace sentinel token is not configured"
    try:
        if not link_ok(link):
            return f"workspace storage is not linked at {_ascii_path(link)}"
        tp = os.path.join(link, sentinel_name)
        try:
            with open(tp, "r", encoding="utf-8") as handle:
                value = handle.read().strip()
        except FileNotFoundError:
            return f"workspace sentinel not found at {_ascii_path(tp)}"
    except (OSError, ValueError) as exc:
        return f"workspace check failed at {_ascii_path(link)}: {_reason_from(exc)}"
    if value != sentinel_token:
        return "workspace sentinel token mismatch (wrong or empty share mounted)"
    return None
