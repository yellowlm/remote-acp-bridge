"""Pure, side-effect-free primitives for the per-client workspace mount (T53 §3).

Everything the *bridge* (an unprivileged ``agent`` process) needs in order to ask the
privileged ``remote-acp-helper`` to mount a client's share, and everything the helper
needs to *validate* that request, lives here as plain functions over strings and lists.
No filesystem access, no subprocess, no socket: that keeps this module unit-testable on
any host, including the Windows dev box, where a real ``mount`` cannot be exercised.

The security line the helper must never cross (and which these validators encode):

* the mount point is always ``<root>/<sanitised hostname>`` — never anywhere else;
* ``device`` and every ``option`` are matched against a form/character whitelist so a
  malicious client cannot smuggle a second mount target or an option that reinterprets
  the command;
* ``credentials=`` is **the helper's own** — a request may never supply it, because the
  helper writes the credential file itself and passes it by path, so a password never
  appears in argv, a log, or a caller-controlled location;
* the mount is run with ``execve`` on a fixed argv list, never through a shell.
"""

from __future__ import annotations

import errno
import ipaddress
import re

OP_MOUNT = "mount"
OP_UMOUNT = "umount"

FS_TYPES = ("cifs", "nfs4")
DEFAULT_PROBE_PORT = {"cifs": 445, "nfs4": 2049}

# Upper bound for a client hostname (T63-N5): the total length a DNS name may carry. Every
# hostname-derived text on the wire (refusal reason, log line, mount path, helper argv) is
# bounded by the cap in sanitize_hostname, so this is the one number that bounds them all.
MAX_HOSTNAME_LENGTH = 253

# An option token is ONE mount flag: ``soft`` or ``uid=agent``. Since mount is execve'd
# (no shell), the residual risk is mount(8)/the fs driver reinterpreting the string, so the
# alphabet is tight and a **comma is forbidden** (T55-M1): a comma is mount(8)'s own option
# separator, so an item carrying one smuggles extra options past any per-item name check
# (``soft,credentials=/etc/shadow``). Items are flattened to one flag each before they are
# checked, so the returned list is exactly the set of options mount will see.
_OPTION_RE = re.compile(r"^[A-Za-z0-9._:/+=-]+$")
# Credentials are helper-owned; a caller must never try to pass them in options — under any
# name, in any position of the list.
_BANNED_OPTION_NAMES = ("credentials", "password", "username", "domain")
# The mounted share's owner is the *server's* choice (T8): the client may not name uid=/gid=,
# and any it sends is dropped here rather than refused (an old client.toml keeps working).
_OWNER_OPTION_NAMES = ("uid", "gid")
# A uid/gid the server puts in ``-o uid=…``: a plain user/group name or numeric id (T8).
_OWNER_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def validate_owner_token(label: str, value: str) -> str:
    """Check a ``mount_uid``/``mount_gid`` value is a plain owner token; return it (T8)."""
    if value and not _OWNER_RE.match(value):
        raise MountInputError(f"{label} must be a plain user/group name or id")
    return value


class MountInputError(ValueError):
    """A mount request field failed validation. English, never echoes secrets."""


# A refusal has to be English on every host, so the OS `strerror` is never echoed —
# `str(OSError)` renders it in the machine's locale (a Chinese Windows answers WinError 5
# with the localized words for "access denied", T48/T55-M4-measured), and that string
# travels on the handshake refusal and into the log. Map the errno we know to fixed English,
# fall back to the ASCII errno NAME, and only then the exception class (also ASCII). Lives
# here rather than in workspace.py because both the bridge and the root helper need one table.
_ERRNO_EN = {
    errno.EACCES: "permission denied",
    errno.EPERM: "operation not permitted",
    errno.ENOENT: "no such file or directory",
    errno.ENOTDIR: "not a directory",
    errno.EISDIR: "is a directory",
    errno.ENAMETOOLONG: "file name too long",
    errno.EROFS: "read-only file system",
    errno.ENXIO: "no such device or address",
    errno.ESTALE: "stale file handle",
    errno.EIO: "I/O error",
    errno.ETIMEDOUT: "connection timed out",
    errno.EHOSTDOWN: "host is down",
    errno.EHOSTUNREACH: "host is unreachable",
    errno.ENETUNREACH: "network is unreachable",
    errno.EOPNOTSUPP: "operation not supported",
    errno.ENOTSUP: "operation not supported",
    # Listener setup (T59, after A6 routed these through the table): without these the
    # wording collapses from a sentence to the bare errno name and an operator loses the
    # meaning — e.g. an IPv6-less box degrading to a warning reads "cannot bind: address
    # family not supported by protocol", not "cannot bind: EAFNOSUPPORT (errno=97)".
    errno.EAFNOSUPPORT: "address family not supported by protocol",
    errno.EADDRINUSE: "address already in use",
    errno.EADDRNOTAVAIL: "address not available",
    errno.EINVAL: "invalid argument",
}
# errno.ELOOP is deliberately NOT here (T52 review): a symlink loop is a path problem, not
# an OS "capability" refusal, and folding it into the capability set mislabels the cause.


def english_reason(exc: BaseException) -> str:
    """An ASCII, locale-independent description of why a mount-side check failed.

    Order matters: the errno table first (that is what beats a localized ``strerror``),
    then the ASCII errno name, then — only when the message is already ASCII — the text of
    the exception itself, because the bridge raises ``OSError`` with its own English
    sentence attached (``cannot create session cwd ...``) and throwing that away would trade
    a leaked translation for a lost diagnosis. Anything non-ASCII with no errno degrades to
    the bare class name rather than putting local words on the wire.
    """
    if isinstance(exc, OSError):
        text = _ERRNO_EN.get(exc.errno) if exc.errno is not None else None
        name = errno.errorcode.get(exc.errno) if exc.errno is not None else None
        if text:
            return f"{text} (errno={exc.errno}{'' if not name else ' / ' + name})"
        if name:
            return f"{name} (errno={exc.errno})"
        message = str(exc).strip()
        if message.isascii():
            return message
    return type(exc).__name__        # ValueError (NUL / UnicodeDecodeError), or a localized message with no errno


def sanitize_hostname(hostname: str) -> str:
    """Map a client hostname to one safe path segment under ``root``.

    Rejects the empty string, ``.``/``..``, and any character that could escape the
    single-segment guarantee (``/``, ``\\``, NUL, other control bytes, or whitespace).
    A normal FQDN (dots, hyphens, alphanumerics, underscores) passes through unchanged.

    Also ASCII-only and bounded in length (T63-N5), because this is the *one* place every
    hostname-derived text passes through: the control-frame refusal reason, the log line,
    the mount path, and the helper's re-validation. The contract is that a refusal reason is
    plain English on the wire, and an interpolated client-supplied name would break it — a
    non-ASCII hostname used to reach the frame as ``... switch to '<the client's own name>'``
    with ``isascii()`` False. An unbounded name likewise has no length ceiling anywhere else
    (a 400-character hostname went through, and it lands in a path, a reason, and
    ``mount``'s argv), so the cap here is what makes every downstream text bounded. 253 is
    the total length a DNS name may have.
    """
    if not hostname:
        raise MountInputError("hostname is empty")
    if hostname in (".", ".."):
        raise MountInputError("hostname must not be . or ..")
    if not hostname.isascii():
        raise MountInputError("hostname must be ASCII")
    if len(hostname) > MAX_HOSTNAME_LENGTH:
        raise MountInputError(f"hostname must not be longer than {MAX_HOSTNAME_LENGTH} characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in hostname):
        raise MountInputError("hostname contains a control character")
    if "/" in hostname or "\\" in hostname:
        raise MountInputError("hostname contains a path separator")
    if ".." in hostname:
        raise MountInputError("hostname contains '..'")
    if hostname[0] in ("-", " "):
        raise MountInputError("hostname must not start with '-' or a space")
    if hostname[-1] == " ":
        raise MountInputError("hostname must not end with a space")
    return hostname


def validate_device(fs_type: str, device: str) -> str:
    """Check a device string matches the form its ``fs_type`` requires; return it.

    * ``cifs``  -> ``//host/share`` (optionally deeper: ``//host/share/sub``)
    * ``nfs4``  -> ``host:/export``
    """
    if fs_type not in FS_TYPES:
        raise MountInputError(f"unknown fs_type {fs_type!r}")
    if not device or any(ord(c) < 32 or ord(c) == 127 for c in device):
        raise MountInputError("device is empty or contains a control character")
    if device[0] == "-":
        raise MountInputError("device must not start with '-'")
    if fs_type == "cifs":
        if not device.startswith("//"):
            raise MountInputError("cifs device must look like //host/share")
        rest = device[2:]
        if "/" not in rest:
            raise MountInputError("cifs device must name a share: //host/share")
        host, _, share = rest.partition("/")
        if not host or not share:
            raise MountInputError("cifs device has an empty host or share")
        if ".." in device:
            raise MountInputError("cifs device must not contain '..'")
        return device
    # nfs4: host:/export
    if "/" not in device or ":" not in device:
        raise MountInputError("nfs4 device must look like host:/export")
    host, _, export = device.partition(":")
    if not host or not export.startswith("/"):
        raise MountInputError("nfs4 device needs a host and an absolute export path")
    if ".." in export:
        raise MountInputError("nfs4 export must not contain '..'")
    return device


def _is_valid_hostname_or_ip(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    return bool(re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?", host))


def probe_target(fs_type: str, device: str) -> tuple[str, int]:
    """The (host, port) the liveness monitor TCP-probes for this share.

    Derived from the device so the server config never names a storage host: cifs uses the
    ``//host`` component on 445, nfs4 the ``host:`` component on 2049.
    """
    if fs_type == "cifs":
        host = device[2:].split("/", 1)[0]
    elif fs_type == "nfs4":
        host = device.split(":", 1)[0]
    else:
        raise MountInputError(f"unknown fs_type {fs_type!r}")
    if not _is_valid_hostname_or_ip(host):
        raise MountInputError("device host is not a valid name or address")
    return host, DEFAULT_PROBE_PORT[fs_type]


def validate_options(options: list[str]) -> list[str]:
    """Return the safe set of mount flags, flattening and rejecting anything else.

    One item is ONE flag. A comma is mount(8)'s own option separator, so a caller who writes
    ``"soft,credentials=/etc/shadow"`` is asking for two flags in one list slot — and a name
    check that only reads up to the first ``=`` sees just the leading ``soft`` and lets the
    credential through (T55-M1). So: split every item on commas first, then check each part
    on its own — tight character class (no comma remains possible), no leading ``-`` (a
    smuggled flag), and no caller-supplied ``credentials``/``username``/``password``/``domain``
    under any name in any position. The returned list is exactly what mount will be given.
    """
    if not isinstance(options, list):
        raise MountInputError("mount_options must be a list")
    cleaned: list[str] = []
    for raw in options:
        for part in str(raw).split(","):
            opt = part.strip()
            if not opt:
                continue
            if not _OPTION_RE.match(opt):
                raise MountInputError("mount option contains a forbidden character")
            if opt[0] == "-":
                raise MountInputError("mount option must not start with '-'")
            name = opt.partition("=")[0]
            if name.lower() in _BANNED_OPTION_NAMES:
                raise MountInputError("credential options are set by the helper, not the caller")
            if name.lower() in _OWNER_OPTION_NAMES:
                continue          # owner comes from the server config (T8), never the caller
            cleaned.append(opt)
    return cleaned


def build_composed_options(fs_type: str, options: list[str], credentials_path: str,
                           *, uid: str = "", gid: str = "") -> list[str]:
    """Assemble the ``-o`` flags the helper runs.

    The caller's flags come first, already whitelisted and flattened (``uid=``/``gid=`` in them
    are dropped — the owner is not the caller's to set, T8). For cifs the helper appends its own
    ``credentials=`` file and the **server's** ``uid=``/``gid=`` (``mount_uid``/``mount_gid``);
    nfs4 needs no credentials — it authenticates at the server or via ``sec=`` in options.
    """
    merged = validate_options(options)
    if fs_type == "cifs" and credentials_path:
        merged.append(f"credentials={credentials_path}")
    if fs_type == "cifs":
        if uid:
            merged.append(f"uid={uid}")
        if gid:
            merged.append(f"gid={gid}")
    return merged


def validate_mount_point_under_root(root: str, mount_point: str, resolve=None) -> str:
    """Assert ``mount_point`` is strictly inside ``root`` after path normalisation.

    ``resolve`` defaults to :func:`os.path.realpath`; tests inject a fake to exercise the
    ``..``/symlink-escape cases on a host with no POSIX filesystem. Mount paths are POSIX,
    so resolved separators are normalised to ``/`` first — the logic is identical on the
    Linux deployment and on a Windows box whose ``realpath`` yields backslashes. Returns
    ``mount_point`` on success, raises :class:`MountInputError` otherwise.
    """
    if resolve is None:
        import os.path as _p
        resolve = _p.realpath
    real_root = resolve(root).replace("\\", "/")
    real_mp = resolve(mount_point).replace("\\", "/")
    if real_mp == real_root:
        raise MountInputError("mount_point must not equal root")
    prefix = real_root.rstrip("/") + "/"
    if not (real_mp + "/").startswith(prefix):
        raise MountInputError("mount_point is not under root")
    if ".." in mount_point:
        raise MountInputError("mount_point must not contain '..'")
    return mount_point


def mount_point_for(root: str, hostname: str) -> str:
    """The per-client mount point: ``root/<sanitised hostname>`` (POSIX join)."""
    safe = sanitize_hostname(hostname)
    base = root.rstrip("/")
    return f"{base}/{safe}"


def validate_mount_point_under_any_root(roots: list[str], mount_point: str, resolve=None) -> str:
    """Assert ``mount_point`` is strictly inside at least one of ``roots`` (T4).

    The helper's allowed roots come from the server config files (there may be several
    instances), so confinement is "under *some* configured root". The per-root checks are
    unchanged (:func:`validate_mount_point_under_root`: realpath, no ``..``, not equal to the
    root itself); a mount point that matches none — or a caller that picked a root itself — is
    refused. An empty ``roots`` is a refusal too (fail closed). Returns ``mount_point`` on
    success, raises :class:`MountInputError` otherwise.
    """
    for root in roots:
        try:
            return validate_mount_point_under_root(root, mount_point, resolve=resolve)
        except MountInputError:
            continue
    raise MountInputError("mount_point is not under any configured workspace root")


def validate_share_relative(value: str) -> str:
    """A client's session cwd expressed **relative to its mounted share** (T1 §6A).

    In branch A the client links the host's ``session/new`` cwd into its share and sends the
    server only the link name; the server joins it onto the session's mount point. Accept
    only a plain relative path — reject an absolute path, a Windows drive/UNC form (a colon
    means the client sent a host path it never mapped), and any ``..`` segment — so a
    misbehaving or old client can never make the session cwd escape the mount point.
    Returns the normalised POSIX relative path.
    """
    rel = value.replace("\\", "/").strip()
    if not rel:
        raise MountInputError("share-relative cwd is empty")
    if rel.startswith("/") or ":" in rel:
        raise MountInputError("share-relative cwd must be a plain relative path")
    parts = [part for part in rel.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise MountInputError("share-relative cwd must not contain '..'")
    return "/".join(parts)


def join_share_path(mount_point: str, relative: str) -> str:
    """``<mount_point>/<safe relative>`` (POSIX). Raises on an escaping value (T1 §6A)."""
    return mount_point.rstrip("/") + "/" + validate_share_relative(relative)



def build_mount_argv(fs_type: str, device: str, mount_point: str, options: list[str]) -> list[str]:
    """The fixed argv for ``mount``. Execve'd directly, never through a shell.

    ``options`` is the already-composed flag list (see :func:`build_composed_options`), so
    the helper's own ``credentials=<temp file>`` is already in there — this function adds
    nothing, which keeps the argv derivation in one place.
    """
    if fs_type not in FS_TYPES:
        raise MountInputError(f"unknown fs_type {fs_type!r}")
    argv = ["/bin/mount", "-t", fs_type]
    if options:
        argv += ["-o", ",".join(options)]
    argv += [device, mount_point]
    return argv


def build_umount_argv(mount_point: str) -> list[str]:
    return ["/bin/umount", mount_point]
