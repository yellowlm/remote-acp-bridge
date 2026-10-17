"""Remote ACP Bridge: WebSocket transport for ACP agent subprocesses."""

import contextlib
import importlib.util
import sys
from pathlib import Path

# CPython compiles and writes this module's own.pyc *before* running the body
# below, so a flag set here cannot protect this file - it only protects modules
# imported afterwards. Both halves are needed, because every entry point (the two
# shims, ``-m remote_acp_bridge.client``, devrun, the tests) has to leave the
# source tree clean without anyone setting PYTHONDONTWRITEBYTECODE
# (working spec rule 7).
sys.dont_write_bytecode = True

# Only ever touch the cache entry sitting next to this source file. With
# PYTHONPYCACHEPREFIX / sys.pycache_prefix set, cache_from_source resolves into
# that prefix - outside the project - and nothing there is ours to delete (no
# pollution happens in the source tree in that mode either).
_own_cache = Path(importlib.util.cache_from_source(__file__))
_expected_parent = Path(__file__).resolve().parent / "__pycache__"
if _own_cache.parent == _expected_parent and _own_cache.is_file():
    with contextlib.suppress(OSError):
        _own_cache.unlink()
        if not any(_expected_parent.iterdir()):
            _expected_parent.rmdir()

__version__ = "0.1.0"
