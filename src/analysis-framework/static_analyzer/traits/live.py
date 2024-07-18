from __future__ import annotations
from typing import List

from static_analyzer.param.param import Param


class Live:
    def __init__(self) -> None:
        self.live: List[Param] | None = None

    def set_live(self, live: List[Param]) -> None:
        return None

    def get_live_params_states(self) -> set[int] | None:
        return None
    
    def get_live_params(self) -> List[Param] | None:
        return None
