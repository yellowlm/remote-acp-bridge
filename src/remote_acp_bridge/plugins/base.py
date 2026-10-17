"""Server plugin framework primitives.

A plugin is a class with up to three hooks::

    on_to_agent(frame, ctx) every frame on its way to the agent
    on_from_agent(frame, ctx) every frame coming back from the agent
    on_open(session, ctx) the session's agent has just started

A hook returns ``None`` to pass the frame unchanged, a ``str`` to replace it, or ``DROP``
to swallow it. A hook may also inject frames through ``ctx`` (``send_to_agent`` /
``send_to_host`` / ``ask_agent`` / ``log``). Hooks may be sync or async; the session
awaits whatever it gets. A hook raising or timing out is **fail-open**: the frame is passed
through unchanged and one English line is logged.
"""

from __future__ import annotations

import json


class _Drop:
    """The singleton "swallow this frame" marker — a hook ``return DROP``."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "DROP"


DROP = _Drop()


def _encoded(text: str, ascii_only: bool) -> str:
    """The text as it appears inside a JSON string (no surrounding quotes)."""
    return json.dumps(text, ensure_ascii=ascii_only)[1:-1]


def rewrite_texts(frame: str, edits: list[tuple[str, str]]) -> str | None:
    """Swap each old text for its new text in the **raw frame**, leaving every other byte
    alone (no re-serialisation: the frame's other fields and prompt items stay byte-identical).

    Returns ``None`` when an old text cannot be located verbatim, so the caller passes the
    frame through unchanged rather than applying a partial rewrite.
    """
    out = frame
    for old, new in edits:
        for ascii_only in (False, True):
            needle = _encoded(old, ascii_only)
            if needle in out:
                out = out.replace(needle, _encoded(new, ascii_only))
                break
        else:
            return None
    return out
