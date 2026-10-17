#!/usr/bin/env python3
"""Entry point for remote-acp-client.

The package's ``cli_entry`` owns the finalize, so ``python -m
remote_acp_bridge.client`` behaves identically to this shim.
"""

import sys

# Must precede the import below. This file runs as __main__, which CPython never
# caches, so it is the one place that can keep the package from writing
# __pycache__ into the source tree (working spec rule 7).
sys.dont_write_bytecode = True

from remote_acp_bridge.client import cli_entry

if __name__ == "__main__":
    cli_entry()
