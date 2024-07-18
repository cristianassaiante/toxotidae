from __future__ import annotations
from typing import List

from static_analyzer.param.param import Param


class Propagation:
    def __init__(self) -> None:
        self.par_in: List[Param] | None = None
        self.par_out: List[Param] | None = None

    def get_par_in(self) -> List[Param] | None:
        return None

    def get_par_out(self) -> List[Param] | None:
        return None

    def set_par_in(self, par_in: List[Param]) -> None:
        return None

    def set_par_out(self, par_out: List[Param]) -> None:
        return None
