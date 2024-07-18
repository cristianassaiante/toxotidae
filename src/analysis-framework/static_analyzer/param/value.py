from __future__ import annotations
from typing import List

from static_analyzer.arch.register import Register
from static_analyzer.param.param import Param


class Value(Param):
    def __init__(self, state: int, base: Register, size: int | None = None) -> None:
        super().__init__(state, base, size)

    def is_memory(self) -> bool:
        return False

    def is_value(self) -> bool:
        return True

    @staticmethod
    def get_from_reg(params: List[Value], reg: Register) -> Value | None:
        for param in params:
            if param.base == reg:
                return param

    @staticmethod
    def get_value_params(params: List[Param]) -> List[Value]:
        return [param for param in params if param.is_value()]  # type: ignore

    def __str__(self) -> str:
        out = super().__str__()
        return out

    def __eq__(self, oth: Value) -> bool:
        return super().__eq__(oth)

    def __hash__(self) -> int:
        return super().__hash__()
