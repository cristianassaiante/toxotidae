from __future__ import annotations
from copy import deepcopy
from typing import List

from static_analyzer.arch.register import Register


class Param:
    def __init__(
        self, state: int, base: Register | None, size: int | None = None
    ) -> None:
        self.state = state
        self.base = base

        self.size = size
        self.is_used = False

    def update_stack(self, sp_reg: Register, sp: int) -> None:
        return None

    def is_memory(self) -> bool:
        return False

    def is_value(self) -> bool:
        return False

    def copy(self) -> Param:
        param = deepcopy(self)
        param.is_used = False
        return param

    def copy_at(self, reg: Register) -> Param:
        param = deepcopy(self)
        param.base = reg
        param.is_used = False
        return param

    def uses(self, reg: Register) -> bool:
        return self.base == reg

    def get_refs(self) -> List[Param]:
        return []

    @staticmethod
    def delete_from_reg(params: List[Param], reg: Register) -> None:
        to_rem = []
        for param in params:
            if param.uses(reg):
                to_rem.append(param)
        for param in to_rem:
            if param in params:
                params.remove(param)

    @staticmethod
    def get_from_base(params: List[Param], reg: Register) -> List[Param]:
        return [param for param in params if param.base == reg]

    @staticmethod
    def is_subset(params1: List[Param], params2: List[Param]) -> List[Param]:
        inn = 0
        for param in params1:
            if param in params2:
                inn += 1
        return inn == len(params1)

    def __str__(self) -> str:
        if self.size:
            return f"Arg#{self.state} [{int(self.is_used)},{self.size}]: {self.base.__str__()}"
        return f"Arg#{self.state} [{int(self.is_used)}]: {self.base.__str__()}"

    def __eq__(self, oth: Param) -> bool:
        eq = True
        eq = eq and self.state == oth.state
        eq = eq and self.base == oth.base
        return self.__class__ == oth.__class__ and eq

    def __hash__(self) -> int:
        return hash(self.state) ^ hash(self.base)
