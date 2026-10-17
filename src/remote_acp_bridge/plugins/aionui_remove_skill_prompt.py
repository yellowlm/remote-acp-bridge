"""Second server plugin: drop the ``## Available Skills`` section AionUi injects (T27-C).

AionUi prepends its own prompt to every ``session/prompt``, wrapped in
``[Assistant Rules]`` … ``[/Assistant Rules]``: an ``## Available Skills`` section that the
remote agent must not see. This plugin removes that one section from the prompt's text parts
and nothing else.

Hard rules (so the user's own text is never touched):

* Only the ``[Assistant Rules]`` / ``[/Assistant Rules]`` pair is recognised, and only what
  is **between** them is edited; both markers stay; outside them not one character changes.
* Inside the pair, the whole ``## Available Skills`` section is dropped — from that heading up
  to the next ``## `` heading (or the closing marker). Its trailing ``$AIONUI_HELPER_BIN``
  paragraphs go with it.
* Unpaired markers ⇒ the text is passed through untouched (no guessing to the end).
* Idempotent; only ``type == "text"`` parts are touched; no logging (the section may carry
  machine-specific text).
"""

from __future__ import annotations

import json

from .base import rewrite_texts

OPEN_MARKER = "[Assistant Rules]"
CLOSE_MARKER = "[/Assistant Rules]"
SECTION = "## Available Skills"


def _section_start(inner: str) -> int | None:
    """Index of the ``## Available Skills`` heading at the start of a line, or ``None``."""
    if inner.startswith(SECTION) and inner[len(SECTION):len(SECTION) + 1] in ("", "\n"):
        return 0
    index = inner.find("\n" + SECTION)
    while index >= 0:
        after = inner[index + 1 + len(SECTION):index + 2 + len(SECTION)]
        if after in ("", "\n"):
            return index + 1
        index = inner.find("\n" + SECTION, index + 1)
    return None


def _section_end(inner: str, start: int) -> int:
    """End of the section: the next ``## `` heading line, or the end of the inner text."""
    marker = inner.find("\n## ", start + len(SECTION))
    return len(inner) if marker < 0 else marker + 1


def _strip_section(inner: str) -> str:
    start = _section_start(inner)
    if start is None:
        return inner
    end = _section_end(inner, start)
    stripped = inner[:start] + inner[end:]
    # Tidy the join only: never leave a three-newline gap where the section was.
    while "\n\n\n" in stripped:
        stripped = stripped.replace("\n\n\n", "\n\n")
    return stripped


def strip_skills_section(text: str) -> str:
    """Remove the ``## Available Skills`` section from each ``[Assistant Rules]`` pair."""
    out = text
    cursor = 0
    while True:
        open_at = out.find(OPEN_MARKER, cursor)
        if open_at < 0:
            return out
        close_at = out.find(CLOSE_MARKER, open_at + len(OPEN_MARKER))
        if close_at < 0:
            return out                     # unpaired opener: leave everything as it is
        inner_start = open_at + len(OPEN_MARKER)
        inner = out[inner_start:close_at]
        stripped = _strip_section(inner)
        if stripped == inner:
            cursor = close_at + len(CLOSE_MARKER)
            continue
        out = out[:inner_start] + stripped + out[close_at:]
        cursor = inner_start + len(stripped) + len(CLOSE_MARKER)


class AionuiRemoveSkillPrompt:
    name = "aionui_remove_skill_prompt"

    def __init__(self):
        # T29: strip at most once per session; afterwards every frame passes straight through.
        self._stripped = False

    async def on_to_agent(self, frame, ctx):
        if self._stripped:
            return None
        try:
            message = json.loads(frame)
        except (ValueError, TypeError):
            return None
        if not isinstance(message, dict) or message.get("method") != "session/prompt":
            return None
        params = message.get("params")
        prompt = params.get("prompt") if isinstance(params, dict) else None
        if not isinstance(prompt, list):
            return None
        edits: list[tuple[str, str]] = []
        for part in prompt:
            if not isinstance(part, dict) or part.get("type") != "text":
                continue
            text = part.get("text")
            if not isinstance(text, str):
                continue
            stripped = strip_skills_section(text)
            if stripped != text:
                edits.append((text, stripped))
        if not edits:
            return None
        rewritten = rewrite_texts(frame, edits)
        if rewritten is not None:
            self._stripped = True
        return rewritten
