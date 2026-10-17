#!/usr/bin/env python3
"""Entry point for remote-acp-helper (systemd ExecStart of the resident service).

Runs as root as a long-lived service (``remote-acp-helper.service``): it builds its own Unix
socket (path from its own config) and serves one JSON mount/umount request per connection,
validating against the whitelist and execve'ing /bin/mount or /bin/umount. The package's
``main`` owns that; this shim only keeps the interpreter from writing __pycache__ into the
source tree (working spec rule 7).
"""

import sys

sys.dont_write_bytecode = True

from remote_acp_bridge.helper import main

if __name__ == "__main__":
    raise SystemExit(main())
