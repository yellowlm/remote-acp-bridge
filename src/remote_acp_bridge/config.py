"""TOML configuration for the server and the client.

Contracts follow T1 task book section 4.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import ssl
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

AGENT_PATH_PREFIX = "/agents/"

# A SHA-256 digest is 32 bytes; a `[servers.tls].fingerprint` decodes to exactly that.
SHA256_BYTES = 32


class ConfigError(ValueError):
    pass


def _get(section: dict, key: str, default):
    value = section.get(key, default)
    return default if value is None else value


def default_config_path(instances_dir: str | os.PathLike[str], instance: str) -> Path:
    """``<instances_dir>/<instance>/server.toml``.

    ``instances_dir`` is the ``configs/`` directory itself (the parent of the per-instance
    folders). The instance name **is** the directory name and the file is always
    ``server.toml``, so one instance owns one directory holding its config, its cert pair and
    its key file — the whole directory moves between hosts untouched.
    """
    return Path(instances_dir) / instance / "server.toml"


def _resolve(base: Path | None, value: str) -> str:
    """A relative path in a server config means "next to this config file".

    Everything one instance owns - its cert pair and its keys file - lives in
    ``configs/<instance>/``, so naming them plainly keeps the instance portable: the
    same directory moves to another host without editing absolute paths. The service's
    cwd belongs to systemd (``WorkingDirectory``), not to the instance, so resolving at
    load time is the only place where that intent survives.
    """
    if base is None or not value:
        return value
    path = Path(value)
    return value if path.is_absolute() else str(base / value)


def _load_toml(file: Path) -> dict:
    """Parse a config file, turning a broken one into a ConfigError.

    Two escapes to cover, because ``tomllib`` raises something different for each and
    neither is a ConfigError or an OSError, so both used to leave both entry points as
    a bare traceback (R6): ``TOMLDecodeError`` for a syntax error, and
    ``UnicodeDecodeError`` — a ValueError, so ``except OSError`` never catches it — for
    a file that is not valid UTF-8 at all.
    """
    try:
        with file.open("rb") as handle:
            return tomllib.load(handle)
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{file}: config file is not valid UTF-8: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{file}: not a valid TOML document: {exc}") from exc


@dataclass
class TlsConfig:
    enabled: bool = False
    cert_file: str = ""
    key_file: str = ""

    @classmethod
    def from_dict(cls, data: dict, base: Path | None = None) -> "TlsConfig":
        tls = cls(
            enabled=bool(_get(data, "enabled", False)),
            cert_file=str(_get(data, "cert_file", "")),
            key_file=str(_get(data, "key_file", "")),
        )
        # A cert pair that belongs to one instance lives next to that instance's config,
        # so it is named there as `server.crt` / `server.key`.
        tls.cert_file = _resolve(base, tls.cert_file)
        tls.key_file = _resolve(base, tls.key_file)
        if tls.enabled and not (tls.cert_file and tls.key_file):
            raise ConfigError("[server.tls] enabled requires cert_file and key_file")
        for path in (tls.cert_file, tls.key_file):
            if tls.enabled and path and not Path(path).is_file():
                raise ConfigError(f"TLS file not found: {path}")
        if tls.enabled:
            _verify_server_chain(tls.cert_file, tls.key_file)
        return tls


@dataclass
class PluginConfig:
    """One ``[[agents.plugins]]`` entry: a built-in plugin's name and its config.

    ``config`` is passed to the plugin untouched — the server does not interpret or validate
    its contents (the plugin reads it as ``ctx.config``).
    """

    name: str
    config: dict = field(default_factory=dict)


@dataclass
class AgentConfig:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    cwd: str = ""
    env: dict[str, str] = field(default_factory=dict)
    # The plugin chain in written order; each entry is a name plus the config dict.
    plugins: list[PluginConfig] = field(default_factory=list)

    @property
    def path(self) -> str:
        return AGENT_PATH_PREFIX + self.name


def _load_plugins(agent_name: str, raw, registry: dict) -> list[PluginConfig]:
    """The ``[[agents.plugins]]`` array for one agent.

    Each entry is a table with exactly ``name`` (a built-in plugin) and ``config`` (a table,
    required; handed to the plugin untouched). The written order is the chain order. The old
    ``plugins = [...]`` shape is a hard error — silently ignoring it would be "the plugin
    quietly stopped working".
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ConfigError(f"[agents] {agent_name}: plugins must be an array of tables ([[agents.plugins]])")
    plugins: list[PluginConfig] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ConfigError(
                f"[agents] {agent_name}: plugins = [...] was replaced (T27): use "
                f"[[agents.plugins]] with name and config instead"
            )
        extra = set(entry) - {"name", "config"}
        if extra:
            raise ConfigError(
                f"[agents] {agent_name}: [[agents.plugins]] has unknown key(s): {', '.join(sorted(extra))}"
            )
        plugin_name = str(entry.get("name") or "").strip()
        if not plugin_name:
            raise ConfigError(f"[agents] {agent_name}: [[agents.plugins]] needs a name")
        if plugin_name not in registry:
            known = ", ".join(sorted(registry)) or "none"
            raise ConfigError(
                f"[agents] {agent_name}: unknown plugin {plugin_name!r} (built-in plugins: {known})"
            )
        if "config" not in entry:
            raise ConfigError(
                f"[agents] {agent_name}: plugin {plugin_name!r} needs config (use config = {{}} when it takes none)"
            )
        config = entry["config"]
        if not isinstance(config, dict):
            raise ConfigError(f"[agents] {agent_name}: plugin {plugin_name!r} config must be a table")
        plugins.append(PluginConfig(name=plugin_name, config=dict(config)))
    return plugins


def _load_agents(raw: list) -> dict[str, AgentConfig]:
    # Imported here, not at module scope: the client imports this module, and the plugin
    # registry is server-only — a top-level import would pull it into the client's closure
    #. Agents are only ever loaded on the server.
    from .plugins import PLUGINS

    agents: dict[str, AgentConfig] = {}
    if not isinstance(raw, list) or not raw:
        raise ConfigError("at least one [[agents]] entry is required")
    for item in raw:
        if not isinstance(item, dict):
            raise ConfigError("[[agents]] entries must be tables")
        name = str(item.get("name") or "").strip()
        command = str(item.get("command") or "").strip()
        if not name or not command:
            raise ConfigError("[[agents]] entry needs both name and command")
        if name in agents:
            raise ConfigError(f"duplicate agent name: {name}")
        args = item.get("args") or []
        if not isinstance(args, list):
            raise ConfigError(f"[agents] {name}: args must be a list")
        env = item.get("env") or {}
        if not isinstance(env, dict):
            raise ConfigError(f"[agents] {name}: env must be a table")
        plugins_raw = item.get("plugins")
        plugins = _load_plugins(name, plugins_raw, PLUGINS)
        agents[name] = AgentConfig(
            name=name,
            command=command,
            args=[str(a) for a in args],
            cwd=str(item.get("cwd") or ""),
            env={str(k): str(v) for k, v in env.items()},
            plugins=plugins,
        )
    return agents


@dataclass
class AuthConfig:
    mode: str = "key"
    keys_file: str = ""
    clock_skew_seconds: float = 300
    nonce_cache_seconds: float = 600

    @classmethod
    def from_dict(cls, data: dict, base: Path | None = None) -> "AuthConfig":
        auth = cls(
            mode=str(_get(data, "mode", "key")),
            keys_file=str(_get(data, "keys_file", "")),
            clock_skew_seconds=float(_get(data, "clock_skew_seconds", 300)),
            nonce_cache_seconds=float(_get(data, "nonce_cache_seconds", 600)),
        )
        auth.keys_file = _resolve(base, auth.keys_file)
        if auth.mode != "key":
            raise ConfigError(f"unsupported auth mode: {auth.mode!r} (only 'key')")
        if not auth.keys_file:
            raise ConfigError("[auth] keys_file is required")
        if not Path(auth.keys_file).is_file():
            raise ConfigError(f"keys file not found: {auth.keys_file}")
        return auth


@dataclass
class LoggingConfig:
    level: str = "off"
    file: str = ""

    # ``off`` silences everything (and, in ``build_logger``, suppresses the file handler too).
    # It sits above CRITICAL so every ordinary record is filtered. The default is ``off``: a
    # fresh instance logs nothing until the operator asks for a level.
    LEVELS = {"off": 60, "debug": 10, "info": 20, "warn": 30, "warning": 30, "error": 40}

    @classmethod
    def from_dict(cls, data: dict) -> "LoggingConfig":
        level = str(_get(data, "level", "off")).lower()
        if level not in cls.LEVELS:
            raise ConfigError(f"[logging] level must be one of off|debug|info|warn|error, got {level!r}")
        return cls(level=level, file=str(_get(data, "file", "")))

    @property
    def severity(self) -> int:
        return self.LEVELS[self.level]

    @property
    def enabled(self) -> bool:
        return self.level != "off"


# Fields the pre-T53 server [workspace] section used to carry. In §3 they moved to the
# client (the share belongs to whoever connects) or became per-mountpoint; leaving one in
# server.toml is a hard error with a migration note, not a silent ignore.
_LEGACY_SERVER_WORKSPACE = {
    "mount_point": "derived per client from [workspace].root + the client's hostname",
    "fs_type": "now sent by the client in its [workspace] section",
    "device": "now sent by the client in its [workspace] section",
    "probe_host": "derived from the client's device at mount time",
    "probe_port": "derived from the client's device at mount time",
    "mount_options": "now sent by the client in its [workspace] section",
    "credentials_file": "the client sends credentials to the helper over its socket",
    "sentinel_token": "a property of each client's own share; now in the client [workspace]",
}


@dataclass
class WorkspaceConfig:
    """Server-side workspace root and liveness timing.

    Always on: the server manages every session's working directory (branch A under a
    client's mounted share, branch B under ``root`` by session uuid), so ``root`` is
    required and there is no ``enabled`` switch to turn the feature off. The share, its
    credentials and its sentinel *token* all travel with the client that connects (in the
    handshake ``Config`` header), so the server only says **where** client shares get mounted
    (``root``) and the monitor cadence. The **sentinel file name** is a fixed constant
    (``frames.SENTINEL_NAME`` = ``.rab-workspace-token``), not a config field; a
    ``sentinel_name`` left behind in a config file is ignored rather than rejected.
    """

    root: str = ""                       # fixed base dir, e.g. /home/agent/workspace
    # The bridge's side of the helper socket. The helper binds the same path, read from
    # its own configs/helper.toml `[socket].path`; the two must name the same path.
    helper_socket: str = "/run/remote-acp-helper.sock"
    # The owner the mounted share is given. Server config, not the client's mount_options:
    # the client can no longer name uid=/gid= (they are stripped), so these are the only source.
    mount_uid: str = "agent"
    mount_gid: str = "agent"
    monitor_interval_seconds: float = 5.0
    monitor_timeout_seconds: float = 2.0
    monitor_fail_threshold: int = 3
    # The budget for the handshake's "mount the share, then run the gate" step. It is its own
    # key because the helper's own worst case is ``[mount].timeout * (1 + retry)`` = 20 s at
    # the delivered defaults, and ``monitor_timeout_seconds`` (2 s) is only the monitor
    # probe's — the two must not be coupled, or the bridge gives up long before the helper
    # has finished trying.
    helper_timeout_seconds: float = 30.0

    @classmethod
    def from_dict(cls, data: dict, base: Path | None = None) -> "WorkspaceConfig":
        for legacy, where in _LEGACY_SERVER_WORKSPACE.items():
            if legacy in data:
                raise ConfigError(
                    f"[workspace] {legacy} was removed (T53): {where}"
                )
        helper_timeout = _get(data, "helper_timeout_seconds", 30.0)
        if isinstance(helper_timeout, bool) or not isinstance(helper_timeout, (int, float)):
            raise ConfigError("[workspace] helper_timeout_seconds must be a number")
        ws = cls(
            root=str(_get(data, "root", "")),
            helper_socket=str(_get(data, "helper_socket", "/run/remote-acp-helper.sock")),
            mount_uid=str(_get(data, "mount_uid", "agent")).strip(),
            mount_gid=str(_get(data, "mount_gid", "agent")).strip(),
            monitor_interval_seconds=float(_get(data, "monitor_interval_seconds", 5.0)),
            monitor_timeout_seconds=float(_get(data, "monitor_timeout_seconds", 2.0)),
            monitor_fail_threshold=int(_get(data, "monitor_fail_threshold", 3)),
            helper_timeout_seconds=float(helper_timeout),
        )
        # The workspace is always on: every server.toml must name its root.
        # The criterion is platform-aware. ``PurePosixPath('C:\\RAB\\ws')`` is never
        # absolute, which kept the Windows server from starting at all. The platform verdict
        # (``Path``) is the one that matters on the host the bridge runs on; a POSIX-style
        # root stays accepted as before (it is absolute for the Linux deployment, and this
        # suite's fixtures use one) — so this is a superset, never a regression on either host.
        if not ws.root or not (Path(ws.root).is_absolute()
                               or PurePosixPath(ws.root).is_absolute()):
            raise ConfigError("[workspace] root must be an absolute path")
        if not ws.helper_socket:
            raise ConfigError("[workspace] helper_socket must not be empty")
        if not ws.mount_uid:
            raise ConfigError("[workspace] mount_uid must not be empty")
        if not ws.mount_gid:
            raise ConfigError("[workspace] mount_gid must not be empty")
        if ws.monitor_fail_threshold < 1:
            raise ConfigError("[workspace] monitor_fail_threshold must be >= 1")
        if ws.monitor_interval_seconds <= 0:
            raise ConfigError("[workspace] monitor_interval_seconds must be > 0")
        if ws.monitor_timeout_seconds <= 0:
            # Only the monitor probe's budget now; a 0/negative value would either refuse
            # instantly or never time out.
            raise ConfigError("[workspace] monitor_timeout_seconds must be > 0")
        if ws.helper_timeout_seconds <= 0:
            # The handshake mount/gate budget: it must outlast the helper's own worst case
            # (timeout * (1 + retry)), or the bridge abandons a mount that is still trying.
            raise ConfigError("[workspace] helper_timeout_seconds must be > 0")
        return ws


@dataclass
class ClientWorkspaceConfig:
    """The client's own network share, sent to the server on connect.

    Everything about *what to mount* lives here, on the machine that owns the share. The
    server mounts ``device`` at ``root/<hostname>`` using these options and credentials,
    and checks the sentinel: ``read(root/<hostname>/.rab-workspace-token) == sentinel_token``.
    That token is **required**: without it the gate could only ask "is anything
    mounted here", which is exactly the wrong-share/empty-share case the sentinel exists to
    catch, and it would degrade silently.

    ``password`` is ``repr=False`` so it never reaches a log line, an exception string, or a
    printed config; its only storage is the operator's own 0600 ``client.toml``, from which it
    travels in the handshake ``Config`` header and then into the helper over its Unix socket.
    No value is ever baked into code.

    ``share_dir`` is this machine's own mount of the same share: the client links the
    host's ``session/new`` cwd into it and sends the server only the **link name**. It is a
    local path and lives in the config, never in the environment.
    """

    hostname: str = ""
    share_dir: str = ""
    fs_type: str = "cifs"
    device: str = ""
    mount_options: list[str] = field(default_factory=list)
    username: str = ""
    password: str = field(default="", repr=False)
    domain: str = ""
    sentinel_token: str = ""

    @classmethod
    def from_dict(cls, data: dict, base: Path | None = None) -> "ClientWorkspaceConfig":
        from .mounting import FS_TYPES, MountInputError, sanitize_hostname, validate_device
        try:
            host = sanitize_hostname(str(_get(data, "hostname", "")))
        except MountInputError as exc:
            raise ConfigError(f"[workspace] hostname invalid: {exc}")
        share_dir = _resolve(base, str(_get(data, "share_dir", "")))
        fs_type = str(_get(data, "fs_type", "cifs")).lower()
        if fs_type not in FS_TYPES:
            raise ConfigError(f"[workspace] fs_type must be one of cifs|nfs4, got {fs_type!r}")
        device = str(_get(data, "device", ""))
        try:
            validate_device(fs_type, device)
        except MountInputError as exc:
            raise ConfigError(f"[workspace] device invalid: {exc}")
        options = _get(data, "mount_options", []) or []
        if not isinstance(options, list):
            raise ConfigError("[workspace] mount_options must be a list")
        username = str(_get(data, "username", ""))
        password = str(_get(data, "password", ""))
        domain = str(_get(data, "domain", ""))
        sentinel_token = str(_get(data, "sentinel_token", ""))
        if fs_type == "cifs" and not username:
            raise ConfigError("[workspace] username is required for cifs")
        if fs_type == "cifs" and not password:
            raise ConfigError("[workspace] password is required for cifs")
        # Without a token the server-side gate degrades to "is _anything_ mounted here",
        # which is exactly the "wrong share / empty share mounted" case the sentinel exists
        # to catch — and it degrades silently. Make the client state it.
        if not sentinel_token:
            raise ConfigError(
                "[workspace] sentinel_token is required: it is what proves the mounted share "
                "is yours and not an empty or wrong one sitting on the same path"
            )
        # Without it branch A cannot map the host's session cwd into the share: the
        # client would send a Windows path the server cannot use.
        if not share_dir:
            raise ConfigError(
                "[workspace] share_dir is required: it is this machine's mount of the share, "
                "where the host's session cwd is linked so the server sees the same directory"
            )
        return cls(
            hostname=host,
            share_dir=share_dir,
            fs_type=fs_type,
            device=device,
            mount_options=[str(o) for o in options],
            username=username,
            password=password,
            domain=domain,
            sentinel_token=sentinel_token,
        )

    def as_descriptor(self) -> dict:
        """The workspace payload of the handshake ``Config`` header.

        Includes ``password``. Its only storage is the ``client.toml`` the operator wrote
        (keep it 0600); the client makes no further copy — this dict is built in memory,
        serialised into the header, and never returned by ``repr`` (see the field) and never
        logged on either side. ``share_dir`` is sent because the task book's payload
        names it, but the server only needs the mount fields.
        """
        return {
            "hostname": self.hostname,
            "share_dir": self.share_dir,
            "fs_type": self.fs_type,
            "device": self.device,
            "mount_options": list(self.mount_options),
            "username": self.username,
            "password": self.password,
            "domain": self.domain,
            "sentinel_token": self.sentinel_token,
        }


def _load_env(raw) -> dict[str, str]:
    """The top-level ``[env]`` table of an instance: key -> string.

    Optional — absent or empty is byte-for-byte today's behaviour. Anything else is a config
    error, checked the way every other field is (one English, ASCII line).
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError("[env] must be a table")
    env: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(value, str):
            raise ConfigError(f"[env] {key}: value must be a string")
        env[str(key)] = value
    return env


@dataclass
class ServerConfig:
    host: str = ""
    port: int = 7801
    max_sessions: int = 0
    connection_idle_seconds: float = 0
    session_grace_seconds: float = 0
    tls: TlsConfig = field(default_factory=TlsConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    workspace: WorkspaceConfig = field(default_factory=WorkspaceConfig)
    agents: dict[str, AgentConfig] = field(default_factory=dict)
    # A top-level ``[env]`` table injected into **every** agent of this instance, so a
    # shared variable is written once. It sits between the inherited environment and the
    # agent's own ``env``: an ``[[agents]].env`` entry overrides a same-named global one, and
    # the session facts the bridge injects override both.
    env: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "ServerConfig":
        file = Path(path)
        if not file.is_file():
            raise ConfigError(f"config file not found: {file}")
        raw = _load_toml(file)
        server = raw.get("server", {})
        if not isinstance(server, dict):
            raise ConfigError("[server] must be a table")
        port = int(_get(server, "port", 7801))
        if not 1 <= port <= 65535:
            # 0 is not a configuration option: an ephemeral port cannot be probed by
            # devrun, firewall-rule-protected, or written into a client's [[servers]]
            # entry. ``listen_sockets`` does support port 0 (that is how the test
            # fixtures bind), but that is the embedding API, not this file format.
            raise ConfigError(
                f"[server] port must be 1-65535, got {port} "
                f"(0 = let the OS pick only works inside listen_sockets(), not in a config)"
            )
        return cls(
            host=str(_get(server, "host", "")),
            port=port,
            max_sessions=int(_get(server, "max_sessions", 0)),
            connection_idle_seconds=float(_get(server, "connection_idle_seconds", 0)),
            session_grace_seconds=float(_get(server, "session_grace_seconds", 0)),
            tls=TlsConfig.from_dict(server.get("tls") or {}, base=file.parent),
            auth=AuthConfig.from_dict(raw.get("auth") or {}, base=file.parent),
            logging=LoggingConfig.from_dict(raw.get("logging") or {}),
            workspace=WorkspaceConfig.from_dict(raw.get("workspace") or {}, base=file.parent),
            agents=_load_agents(raw.get("agents", [])),
            env=_load_env(raw.get("env")),
        )


@dataclass
class ClientTlsConfig:
    enabled: bool = True
    insecure: bool = False
    ca_file: str = ""
    # An optional certificate pin — ``base64(SHA-256(peer DER))``. Orthogonal to
    # ``insecure``, which only decides CA/hostname checking: a configured pin is **always**
    # enforced (that combination is exactly the self-signed-certificate deployment).
    fingerprint: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "ClientTlsConfig":
        pin = str(_get(data, "fingerprint", "")).strip()
        if pin:
            try:
                raw = base64.b64decode(pin, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ConfigError(
                    "[servers.tls] fingerprint must be valid base64 of a SHA-256 digest"
                ) from exc
            if len(raw) != SHA256_BYTES:
                raise ConfigError(
                    f"[servers.tls] fingerprint must decode to {SHA256_BYTES} bytes, "
                    f"got {len(raw)}"
                )
        return cls(
            enabled=bool(_get(data, "enabled", True)),
            insecure=bool(_get(data, "insecure", False)),
            ca_file=str(_get(data, "ca_file", "")),
            fingerprint=pin,
        )


@dataclass
class ServerTarget:
    name: str
    host: str
    port: int
    agents: list[str] = field(default_factory=list)
    tls: ClientTlsConfig = field(default_factory=ClientTlsConfig)
    # The bridge key lives on the server it authenticates to: one inline key per
    # [[servers]] entry. Optional on the dataclass because from_dict runs before load()
    # enforces that every entry carries one, but a config that omits it is rejected.
    key: str = ""
    # ``pass_mcp`` names the mcpServers entries this client lets through on
    # session-opening frames. ``["*"]`` (the default) passes every entry untouched; a list
    # without ``*`` keeps only the entries whose ``name`` is listed (``[]`` drops them all).
    # It replaced the boolean ``drop_local_mcp``, which could only say "keep all" or "drop all".
    # ``remote_cwd`` was removed in T2 — the server owns the session cwd now (branches A/B),
    # so a client-side cwd rewrite only fought it.
    pass_mcp: list[str] = field(default_factory=lambda: ["*"])
    # This server's own workspace share: `[servers.workspace]`. Per server, not
    # top-level — the handshake carries the connecting server's descriptor, or `{}`.
    workspace: "ClientWorkspaceConfig | None" = None
    # This server's own log sink: `[servers.logging]`, same shape as the server's
    # `[logging]`. The default (`off`, no file) changes nothing — the client keeps writing
    # its lines to stderr; naming a file redirects the filtered lines (and, at `debug`, the
    # frame trace with sequence numbers) into that file instead.
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    @property
    def scheme(self) -> str:
        return "wss" if self.tls.enabled else "ws"

    @property
    def authority(self) -> str:
        """The host as it may appear in a URL — bracketed if it is an IPv6 literal.

        ``ws://::1:7801/`` is not a URL: IPv6 literals contain the delimiter the
        host/port split uses. A host the user already wrote in brackets is left alone,
        and a hostname or IPv4 address is returned untouched.
        """
        host = self.host.strip()
        if host.startswith("[") and host.endswith("]"):
            return host
        try:
            version = ipaddress.ip_address(host).version
        except ValueError:
            return host          # a hostname; nothing to bracket
        return f"[{host}]" if version == 6 else host

    def url(self, agent_path: str) -> str:
        return f"{self.scheme}://{self.authority}:{self.port}{agent_path}"

    @classmethod
    def from_dict(cls, data: dict, base: Path | None = None) -> "ServerTarget":
        name = str(data.get("name") or "").strip()
        host = str(data.get("host") or "").strip()
        if not name or not host:
            raise ConfigError("[[servers]] entry needs both name and host")
        port_value = data.get("port", 7801)
        try:
            port = int(port_value)
        except (TypeError, ValueError):
            raise ConfigError(f"[servers] {name}: port must be an integer, got {port_value!r}")
        if not 1 <= port <= 65535:
            raise ConfigError(f"[servers] {name}: port out of range: {port}")
        agents = data.get("agents") or []
        if not isinstance(agents, list):
            raise ConfigError(f"[servers] {name}: agents must be a list")
        key = str(_get(data, "key", "")).strip()
        if "#" in key:
            raise ConfigError(f"[servers] {name}: key must not contain '#'")
        if "drop_local_mcp" in data:
            # Refusing is the point. Treating the old name as "the default" would quietly
            # turn an operator's "drop them all" into "keep them all".
            raise ConfigError(
                f"[servers] {name}: drop_local_mcp was removed (T67): use pass_mcp = [] to drop "
                "every entry, or omit pass_mcp (or write pass_mcp = [\"*\"]) to keep them all"
            )
        pass_mcp = data.get("pass_mcp")
        if pass_mcp is None:
            pass_mcp = ["*"]
        elif not isinstance(pass_mcp, list) or any(not isinstance(v, str) for v in pass_mcp):
            raise ConfigError(f"[servers] {name}: pass_mcp must be a list of strings")
        workspace = data.get("workspace")
        if workspace is not None and not isinstance(workspace, dict):
            raise ConfigError(f"[servers] {name}: workspace must be a table")
        workspace_cfg = (
            ClientWorkspaceConfig.from_dict(workspace, base=base)
            if isinstance(workspace, dict) else None
        )
        logging_data = data.get("logging")
        if logging_data is not None and not isinstance(logging_data, dict):
            raise ConfigError(f"[servers] {name}: logging must be a table")
        logging_cfg = LoggingConfig.from_dict(logging_data or {})
        logging_cfg.file = _resolve(base, logging_cfg.file)
        return cls(
            name=name,
            host=host,
            port=port,
            agents=[str(a) for a in agents],
            tls=ClientTlsConfig.from_dict(data.get("tls") or {}),
            key=key,
            pass_mcp=pass_mcp,
            workspace=workspace_cfg,
            logging=logging_cfg,
        )


@dataclass
class ClientConfig:
    # The bridge key lives on each [[servers]].key and nowhere else. The client-wide
    # ``key`` and ``keys_file`` are both abolished (hard error, no compat) so ``[client]``
    # is genuinely empty and can be deleted; every server must carry its own key.
    # The workspace is per server (``[servers.workspace]``); a top-level ``[workspace]``
    # is no longer read.
    servers: dict[str, ServerTarget] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "ClientConfig":
        file = Path(path)
        if not file.is_file():
            raise ConfigError(f"config file not found: {file}")
        raw = _load_toml(file)
        client = raw.get("client", {})
        if str(_get(client, "key", "")).strip():
            raise ConfigError(
                "[client] key was removed (T53): put key = \"...\" on each [[servers]] entry instead"
            )
        if client.get("keys_file"):
            raise ConfigError(
                "[client] keys_file was removed (T53): put key = \"...\" on each [[servers]] entry instead"
            )
        raw_servers = raw.get("servers", [])
        if isinstance(raw_servers, dict):
            raw_servers = [raw_servers]
        if not isinstance(raw_servers, list) or not raw_servers:
            raise ConfigError("at least one [[servers]] entry is required")
        servers: dict[str, ServerTarget] = {}
        for item in raw_servers:
            target = ServerTarget.from_dict(item, base=file.parent)
            if target.name in servers:
                raise ConfigError(f"duplicate server name: {target.name}")
            if target.tls.ca_file and target.tls.enabled:
                # Only a TLS entry's trust anchor matters; a stale path on a
                # plaintext entry should not fail the whole file.
                label = f"[servers] {target.name}: ca_file"
                resolved = _resolve_existing(file.parent, target.tls.ca_file, label)
                if not target.tls.insecure:
                    resolved = _verify_trust_anchor(resolved, label)
                target.tls.ca_file = resolved
            servers[target.name] = target
        # Every server authenticates with its own inline key. Fail at load time, not deep
        # in the reconnect loop.
        for target in servers.values():
            if not target.key:
                raise ConfigError(
                    f"[servers] {target.name}: key = \"...\" is required (T53: per-server key)"
                )
        return ClientConfig(servers=servers)


def _resolve_existing(base: Path, value: str, label: str) -> str:
    """Relative paths resolve against the config file's own directory.

    The client's cwd belongs to whoever launched the host, not to the user, so a
    relative ``keys_file``/``ca_file`` that is validated only at connect time
    would surface as an OS error and spin in the reconnect loop instead of
    failing the load.
    """
    path = Path(value)
    candidate = path if path.is_absolute() else base / path
    if not candidate.is_file():
        raise ConfigError(f"{label} not found: {candidate}")
    return str(candidate)


def _verify_server_chain(cert_file: str, key_file: str) -> None:
    """Existence is not enough: an unparseable cert/key must fail the load.

    ``ssl.SSLError`` is an ``OSError`` subclass, so if it only shows up when the
    TLS context is built, callers that retry on ``OSError`` (the client reconnect
    loop, the server's listen path) treat a broken config as a transient fault
    and never report it.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(cert_file, key_file)
    except ssl.SSLError as exc:
        raise ConfigError(f"TLS cert/key cannot be loaded ({cert_file}): {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"TLS cert/key cannot be read ({cert_file}): {exc}") from exc


def _verify_trust_anchor(ca_file: str, label: str) -> str:
    """Same rule for the client's trust anchor, with the exact call `client_ssl` makes."""
    try:
        ssl.create_default_context(cafile=ca_file)
    except ssl.SSLError as exc:
        raise ConfigError(f"{label} cannot be loaded as a trust anchor: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"{label} cannot be read: {exc}") from exc
    return ca_file
