from __future__ import annotations

from static_analyzer.code.function import Function


class Analysis:
    @staticmethod
    def analyzed(func: Function) -> bool:
        return False
