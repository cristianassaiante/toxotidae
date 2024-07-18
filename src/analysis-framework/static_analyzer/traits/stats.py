from __future__ import annotations


class Stats:
    def __init__(self) -> None:
        self.depth: int | None = None

    def set_depth(self, depth: int) -> None:
        self.depth = depth
