from __future__ import annotations
from typing import List

from static_analyzer.arch.register import Register
from static_analyzer.code.basic_block import BasicBlock
from static_analyzer.code.function import Function
from static_analyzer.code.instruction import Instruction
from static_analyzer.param.param import Param


class ComputeUnit:
    @staticmethod
    def compute(func: Function, bb: BasicBlock) -> List[Param]:
        return []

    @staticmethod
    def get_used(
        func: Function, ins: Instruction, params: List[Param], sp: int
    ) -> List[Param]:
        return []

    @staticmethod
    def get_sp() -> Register | None:
        return None

    @staticmethod
    def is_hookable(func: Function, ins: Instruction) -> bool:
        return False
    
    @staticmethod
    def is_call_mem(func: Function, ins: Instruction) -> bool:
        return False

    @staticmethod
    def merge(all_par_in: List[List[Param]], bb: BasicBlock) -> List[Param]:
        return []
