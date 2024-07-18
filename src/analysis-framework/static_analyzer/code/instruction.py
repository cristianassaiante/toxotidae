from __future__ import annotations
from copy import deepcopy
from typing import List

from static_analyzer.logger import Logger
from static_analyzer.param.param import Param
from static_analyzer.traits.callable import Callable
from static_analyzer.traits.live import Live
from static_analyzer.traits.propagation import Propagation
from static_analyzer.traits.stats import Stats


class Instruction(Live, Propagation, Stats, Callable):
    def __init__(self, ins: bytes, ea: int, sp: int) -> None:
        Live.__init__(self)
        Propagation.__init__(self)
        Stats.__init__(self)
        Callable.__init__(self)

        self.ins_bytes = ins
        self.ea = ea
        self.sp = sp

    def get_par_in(self) -> List[Param] | None:
        if self.par_in is not None:
            return deepcopy(self.par_in)
        return None

    def get_par_out(self) -> List[Param] | None:
        if self.par_out is not None:
            return deepcopy(self.par_out)
        return None

    def set_par_in(self, par_in: List[Param]) -> None:
        if Logger.is_debug():
            Logger.log().debug("Parameters In: {")
            for par in par_in:
                Logger.log().debug(f"{par}")
            Logger.log().debug("}")

        self.par_in = deepcopy(par_in)

    def set_par_out(self, par_out: List[Param]) -> None:
        if Logger.is_debug():
            Logger.log().debug("Parameters Out: {")
            for par in par_out:
                Logger.log().debug(f"{par}")
            Logger.log().debug("}")

        self.par_out = deepcopy(par_out)

    def set_live(self, live: List[Param]) -> None:
        live = set(deepcopy(live))
        if Logger.is_debug():
            Logger.log().debug("Parameters Live: {")
            for par in live:
                Logger.log().debug(f"{par}")
            Logger.log().debug("}")

        self.live = live

    def get_live_params_states(self) -> set[int] | None:
        if self.live is not None:
            return set([live.state for live in self.live])
        return None

    def get_live_params(self) -> List[Param] | None:
        if self.live is not None:
            return [live for live in self.live]
        return None

    def __str__(self) -> str:
        out = f"Instruction@{hex(self.ea)} [sp = {self.sp}, "
        if self.depth is not None:
            out += f"depth = {self.depth}"
        return out + "]"

    def __hash__(self) -> int:
        return hash(self.ea) ^ hash(self.sp)
