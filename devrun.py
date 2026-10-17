"""Background control for a locally running remote-acp-server.

Working spec appendix A: never start a long-lived process in the foreground of a
tool call. This script detaches the server, records its pid, redirects stdout and
stderr to log files, probes readiness, and stops it by pid again.

    python run.bat start  --config ..\\workspace\\run\\local.toml
    python run.bat status --config ..\\workspace\\run\\local.toml
    python run.bat stop

Pid files and logs live in the project's development workspace (never in the source tree).
"""

from __future__ import annotations

import argparse
import ctypes
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

# Never leave __pycache__ in the source tree (working spec rule 7): this process
# imports the package, and it also spawns the server, which would write .pyc there.
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
RUN_DIR = HERE.parent / "Dev" / "run"
SERVER = HERE / "src" / "remote_acp_server.py"

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259


def python() -> str:
    return sys.executable


def names(name: str) -> tuple[Path, Path, Path]:
    base = str(RUN_DIR / f"remote-acp-server.{name}")
    return Path(base + ".pid"), Path(base + ".out.log"), Path(base + ".err.log")


def pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_pid(pid_file: Path) -> int | None:
    if not pid_file.is_file():
        return None
    try:
        pid = int(pid_file.read_text(encoding="ascii").strip())
    except ValueError:
        return None
    return pid if pid_alive(pid) else None


def probe_addresses(host: str) -> list[str]:
    """Addresses worth dialling to prove readiness.

    Mirrors the server's binding rule (口径 §8): the empty host is dual stack, so the
    probe must accept an answer from either stack; ``"0.0.0.0"`` is IPv4 only and
    ``"::"`` is IPv6 only.
    """
    cleaned = (host or "").strip()
    if cleaned == "":
        return ["127.0.0.1", "::1"]
    if cleaned == "0.0.0.0":
        return ["127.0.0.1"]
    if cleaned == "::":
        return ["::1"]
    return [cleaned]


def display_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def port_open(host: str, port: int, timeout: float = 0.5) -> tuple[bool, str]:
    """(open, the address that answered) — "" when nothing answered."""
    for candidate in probe_addresses(host):
        try:
            with socket.create_connection((candidate, port), timeout=timeout):
                return True, candidate
        except OSError:
            continue
    return False, ""


def wait_for_port(host: str, port: int, deadline: float) -> tuple[bool, str]:
    stop = time.time() + deadline
    while time.time() < stop:
        open_now, answered = port_open(host, port)
        if open_now:
            return True, answered
        time.sleep(0.1)
    return False, ""


def tail(path: Path, lines: int = 20) -> str:
    if not path.is_file():
        return ""
    body = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(body[-lines:])


def listening_on(config: str) -> tuple[str, int]:
    sys.path.insert(0, str(HERE / "src"))
    from remote_acp_bridge.config import ServerConfig

    try:
        cfg = ServerConfig.load(config)
    except Exception as exc:  # ConfigError, OSError, TOMLDecodeError
        raise SystemExit(f"devrun: cannot read config {config}: {exc}") from exc
    return cfg.host, cfg.port


def cmd_start(args) -> int:
    pid_file, out_log, err_log = names(args.name)
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    running = read_pid(pid_file)
    if running:
        print(f"already running pid={running}")
        return 0
    host, port = listening_on(args.config)
    # The server is spawned with cwd=Code, so a relative --config has to be
    # resolved against the caller's directory before handing it over.
    config_path = str(Path(args.config).resolve())
    command = [python(), str(SERVER), "--config", config_path]
    with out_log.open("ab") as out, err_log.open("ab") as err:
        popen_kwargs: dict = {"cwd": str(HERE), "stdout": out, "stderr": err}
        if sys.platform == "win32":
            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            popen_kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        process = subprocess.Popen(command, **popen_kwargs)
    pid_file.write_text(str(process.pid), encoding="ascii")
    print(f"started pid={process.pid} config={config_path}")
    print(f"  out={out_log}\n  err={err_log}")
    ready, answered = wait_for_port(host, port, args.ready_timeout)
    if not ready:
        tried = ", ".join(display_host(item) for item in probe_addresses(host))
        print(f"FAILED: nothing listening on {tried}:{port} after {args.ready_timeout}s")
        print(tail(err_log) or tail(out_log))
        cmd_stop(args)
        return 1
    print(f"ready: {display_host(answered)}:{port} accepting connections")
    return 0


def cmd_stop(args) -> int:
    pid_file, _, _ = names(args.name)
    if not pid_file.is_file():
        print("not running (no pid file)")
        return 0
    try:
        pid = int(pid_file.read_text(encoding="ascii").strip())
    except ValueError:
        pid = None
    if pid and pid_alive(pid):
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=False, capture_output=True)
        else:
            for signal_number, wait_seconds in ((15, 5.0), (9, 2.0)):
                try:
                    os.kill(pid, signal_number)
                except ProcessLookupError:
                    break
                deadline = time.time() + wait_seconds
                while time.time() < deadline and pid_alive(pid):
                    time.sleep(0.1)
                if not pid_alive(pid):
                    break
        print(f"stopped pid={pid} ({'still running' if pid_alive(pid) else 'confirmed dead'})")
    else:
        print(f"pid file stale (pid={pid})")
    pid_file.unlink(missing_ok=True)
    return 0


def cmd_status(args) -> int:
    pid_file, out_log, err_log = names(args.name)
    pid = read_pid(pid_file)
    print(f"name={args.name} pid={pid or '-'} pidfile={pid_file if pid_file.is_file() else '-'}")
    if args.config:
        host, port = listening_on(args.config)
        open_now, answered = port_open(host, port)
        shown = f" ({answered})" if open_now and answered != host else ""
        print(f"listen={display_host(host)}:{port} probe={'OPEN' if open_now else 'CLOSED'}{shown}")
    for label, log in (("out", out_log), ("err", err_log)):
        size = log.stat().st_size if log.is_file() else 0
        print(f"{label}_log={log} bytes={size}")
    return 0 if pid else 3


def cmd_logs(args) -> int:
    _, out_log, err_log = names(args.name)
    for label, log in (("stdout", out_log), ("stderr", err_log)):
        print(f"----- {label} ({log}) -----")
        print(tail(log, args.lines))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run", description=__doc__)
    parser.add_argument("command", choices=["start", "stop", "status", "logs"])
    parser.add_argument("--config", default="", help="server instance toml (needed for start/status)")
    parser.add_argument("--name", default="local", help="label for the pid file and logs")
    parser.add_argument("--ready-timeout", type=float, default=15.0, help="seconds to wait for the port")
    parser.add_argument("--lines", type=int, default=20, help="log lines for `logs`")
    args = parser.parse_args(argv)
    if args.command == "start" and not args.config:
        parser.error("--config is required for start")
    handlers = {"start": cmd_start, "stop": cmd_stop, "status": cmd_status, "logs": cmd_logs}
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
