"""Built-in server plugins.

``[[agents]].plugins`` names entries in:data:`PLUGINS`; an unknown name is a configuration
error so a typo never silently disables a plugin. Plugin code ships with the package under
``plugins/*.py``.
"""

from __future__ import annotations

from .aionui_openclaw_adapter import AionuiOpenclawAdapter
from .aionui_remove_skill_prompt import AionuiRemoveSkillPrompt
from .base import DROP

PLUGINS: dict[str, type] = {
    "aionui_openclaw_adapter": AionuiOpenclawAdapter,
    "aionui_remove_skill_prompt": AionuiRemoveSkillPrompt,
}

__all__ = ["DROP", "PLUGINS", "AionuiOpenclawAdapter", "AionuiRemoveSkillPrompt"]
