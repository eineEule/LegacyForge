from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from ..context import Context


class FixError(Exception):
    pass


REGISTRY: dict[str, type["Fix"]] = {}


def register(cls: type["Fix"]) -> type["Fix"]:
    REGISTRY[cls.type] = cls
    return cls


class Fix:
    """One kind of fix. Subclasses set `type` and implement the hooks below.

    `params` is whatever the recipe gave under the fix's key; `recipe_exe`
    is the recipe's main executable, used as a default by several fixes.
    """

    type: ClassVar[str] = ""

    def __init__(self, params: Any, recipe_exe: str | None = None):
        self.params = params if params is not None else {}
        self.recipe_exe = recipe_exe
        self.validate()

    def validate(self) -> None:
        """Raise FixError if params are malformed. No filesystem access."""

    def writes(self, ctx: Context) -> list[Path]:
        """Files this fix will create or modify (used to detect conflicts)."""
        return []

    def describe(self, ctx: Context) -> str:
        raise NotImplementedError

    def apply(self, ctx: Context) -> str:
        """Do the work. Call ctx.track(path) before touching any file."""
        raise NotImplementedError

    # helpers
    def _exe(self, ctx: Context) -> Path:
        exe = self.params.get("exe") if isinstance(self.params, dict) else None
        exe = exe or self.recipe_exe
        if not exe:
            raise FixError(f"{self.type}: no exe given and recipe has no detect.exe")
        return ctx.resolve(exe)
