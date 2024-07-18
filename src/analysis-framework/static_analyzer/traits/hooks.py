from __future__ import annotations

from static_analyzer.code.instruction import Instruction
from static_analyzer.logger import Logger


class Hooks:
    def __init__(self) -> None:
        self.hooks: set[Instruction] | None = None
        self.params_per_hook: dict[int, set[int]] | None = None

    def add_hook(self, hook: Instruction, param: int) -> None:
        if self.hooks is None or self.params_per_hook is None:
            self.hooks = set()
            self.params_per_hook = {}

        self.hooks.add(hook)

        if not param in self.params_per_hook:
            self.params_per_hook[param] = set()
        self.params_per_hook[param].add(hook.ea)

        if Logger.is_debug():
            Logger.log().debug("New hook: {")
            Logger.log().debug(f"Arg#{param} hooked at {hook}")
            Logger.log().debug("}")

    def set_empty_hooks(self):
        self.hooks = set()
        self.params_per_hook = {}

