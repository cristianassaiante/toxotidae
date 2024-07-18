from __future__ import annotations
from typing import List

from static_analyzer.code.instruction import Instruction
from static_analyzer.param.param import Param
from static_analyzer.traits.live import Live
from static_analyzer.traits.propagation import Propagation
from static_analyzer.traits.stats import Stats


class BasicBlock(Live, Propagation, Stats):
    def __init__(self, start_ea: int, end_ea: int) -> None:
        Live.__init__(self)
        Propagation.__init__(self)
        Stats.__init__(self)

        self.start_ea = start_ea
        self.end_ea = end_ea

        self.ins: List[Instruction] = []

    def add_instruction(self, ins: Instruction) -> None:
        self.ins.append(ins)

    def get_instructions(self) -> List[Instruction]:
        return self.ins

    def get_par_in(self) -> List[Param] | None:
        return self.ins[0].get_par_in()

    def get_par_out(self) -> List[Param] | None:
        return self.ins[-1].get_par_out()

    def set_par_in(self, par_in: List[Param]) -> None:
        self.ins[0].set_par_in(par_in)

    def set_par_out(self, par_out: List[Param]) -> None:
        self.ins[-1].set_par_out(par_out)

    def get_sp(self) -> int:
        return self.ins[0].sp

    def get_live_params_states(self) -> set[int] | None:
        return self.ins[0].get_live_params_states()
    
    def get_live_params(self) -> List[Param] | None:
        return self.ins[0].get_live_params()

    def __str__(self) -> str:
        out = f"BasicBlock@{hex(self.start_ea)} (end: {hex(self.end_ea)})"
        # for ins in self.ins:
        #     out += ins.__str__()
        return out
