from __future__ import annotations
from typing import List, Tuple

from static_analyzer.logger import Logger
from static_analyzer.param.param import Param


class Vulnerable:
    # NOTE: this threshold is the minimum time window depth that we consider vulnerable
    THRESHOLD = 0

    def __init__(self) -> None:
        self.vuln_spots: List[Param] | None = None

    def add_vuln_spot(self, vuln_spot: Tuple[int, int, int, int]) -> None:
        if self.vuln_spots is None:
            self.vuln_spots = []
        self.vuln_spots.append(vuln_spot)  # type: ignore

        if Logger.is_debug():
            param, offset, wnd_start, wnd_end = vuln_spot
            sign = ["+", ""][offset < 0]
            Logger.log().debug("New vulnerable spot: {")
            Logger.log().debug(
                f"Arg#{param} vulnerable at stack pointer {sign}{offset}\t [timewnd = {wnd_start, wnd_end}]"
            )
            Logger.log().debug("}")

    def set_empty_vuln_spots(self):
        self.vuln_spots = []

    def is_vulnerable(self) -> bool:
        return (
            self.vuln_spots is not None
            and len(self.vuln_spots) > 0
            and not all(map(lambda x: x[3] < self.THRESHOLD, self.vuln_spots))
        )
