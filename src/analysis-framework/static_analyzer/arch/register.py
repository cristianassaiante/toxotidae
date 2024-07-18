from __future__ import annotations
from typing import List


class Register:
    def __str__(self) -> str:
        return ""

    @staticmethod
    def from_regname(reg_name: str) -> Register | None:
        return None

    @staticmethod
    def caller_saved() -> List[Register]:
        return []

    @staticmethod
    def call_params() -> List[Register]:
        return []

    @staticmethod
    def call_params_fp() -> List[Register]:
        return []
