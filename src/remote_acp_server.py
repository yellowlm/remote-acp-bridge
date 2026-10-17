#!/usr/bin/env python3
"""Entry point for remote-acp-server (systemd ExecStart runs this script)."""

import sys

# Must precede the import below. This file runs as __main__, which CPython never
# caches, so it is the one place that can keep the package from writing
# __pycache__ into the source tree (working spec rule 7).
sys.dont_write_bytecode = True

from remote_acp_bridge.server import main

if __name__ == "__main__":
    raise SystemExit(main())
