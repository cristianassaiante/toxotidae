from __future__ import annotations


class Callable:
    def __init__(self) -> None:
        self.nargs = None

    def set_nargs(self, nargs: int) -> None:
        self.nargs = nargs
