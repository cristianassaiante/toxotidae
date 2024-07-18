from __future__ import annotations
from typing import List
from static_analyzer.arch.register import Register

from static_analyzer.param.param import Param


class CallingConvention:
    regs: List[Register] = []
    regs_fp: List[Register] = []

    @staticmethod
    def params(bits: int, n: int, types: List[str]) -> List[Param]:
        return []


class CallingConventionManager:
    def __init__(self, bits: int) -> None:
        self.bits = bits

    def get_params(self, n: int) -> List[Param] | None:
        return None

    def is_used(self, param: Param, sp: int, is_tail_jmp: bool) -> bool:
        return False
