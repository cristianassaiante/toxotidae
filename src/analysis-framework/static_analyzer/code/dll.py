from __future__ import annotations
import pickle
from typing import List

from static_analyzer.traits.dumpable import Dumpable
from static_analyzer.code.function import Function


class DLL(Dumpable):
    def __init__(self, name: str, bits: int) -> None:
        self.bits = bits
        self.name = name

        self.apis: List[Function] = []

    def add_api(self, function: Function) -> None:
        self.apis.append(function)

    def __str__(self):
        out = f"{self.name} ({self.bits}bit)"
        # for api in self.apis:
        #     out += api.__str__()
        return out

    @staticmethod
    def load(fin: str) -> DLL:
        with open(fin, "rb") as f:
            return pickle.load(f)
