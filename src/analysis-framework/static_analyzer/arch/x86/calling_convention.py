from __future__ import annotations
from typing import List

from static_analyzer.arch.calling_convention import (
    CallingConvention,
    CallingConventionManager,
)
from static_analyzer.arch.x86.register import X86Register
from static_analyzer.param.memory import Memory
from static_analyzer.param.param import Param
from static_analyzer.param.value import Value


# NOTE: here ideally, we should parse type from ida local type table
# this is temporary code that will be replaced with a better type class
def _is_arg_fp(ty: str) -> bool:
    if ty == "FLOAT" or ty == "DOUBLE" or ty == "DATE":
        return True
    return False


def _is_arg_large(ty: str) -> bool:
    if ty == "DOUBLE" or ty == "LONGLONG" or ty == "ULONGLONG":
        return True
    return False


class Stdcall(CallingConvention):
    regs = [
        X86Register.R_C,
        X86Register.R_D,
        X86Register.R_8,
        X86Register.R_9,
    ]

    regs_fp = [
        X86Register.R_XMM0,
        X86Register.R_XMM1,
        X86Register.R_XMM2,
        X86Register.R_XMM3,
    ]

    @staticmethod
    def params(bits: int, n: int, types: List[str]) -> List[Param]:
        params: List[Param] = []

        regs_fp = Stdcall.regs_fp[:]
        regs = Stdcall.regs[:]

        if bits == 32:
            offset = 0
            for arg in range(n):
                arg_type = types.pop(0)
                offset += 8 if _is_arg_large(arg_type) else 4

                params.append(Memory(arg, X86Register.R_SP, offset=offset, sp=0))
        else:
            for arg in range(n):
                arg_type = types.pop(0)

                if regs_fp and _is_arg_fp(arg_type):
                    params.append(Value(arg, regs_fp.pop(0)))
                    regs.pop(0)

                elif regs:
                    params.append(Value(arg, regs.pop(0)))
                    regs_fp.pop(0)

                else:
                    offset = 8 * (arg + 1)
                    params.append(Memory(arg, X86Register.R_SP, offset=offset, sp=0))
        return params


class Cdecl(CallingConvention):
    regs = [
        X86Register.R_DI,
        X86Register.R_SI,
        X86Register.R_D,
        X86Register.R_C,
        X86Register.R_8,
        X86Register.R_9,
    ]
    regs_fp = [
        X86Register.R_XMM0,
        X86Register.R_XMM1,
        X86Register.R_XMM2,
        X86Register.R_XMM3,
        X86Register.R_XMM4,
        X86Register.R_XMM5,
        X86Register.R_XMM6,
        X86Register.R_XMM7,
    ]

    @staticmethod
    def params(bits: int, n: int, types: List[str]) -> List[Param]:
        params: List[Param] = []

        regs_fp = Cdecl.regs_fp[:]
        regs = Cdecl.regs[:]

        if bits == 32:
            offset = 0
            for arg in range(n):
                arg_type = types.pop(0)
                offset += 8 if _is_arg_large(arg_type) else 4

                params.append(Memory(arg, X86Register.R_SP, offset=offset, sp=0))
        else:
            for arg in range(n):
                offset = 0
                arg_type = types.pop(0)

                if regs_fp and _is_arg_fp(arg_type):
                    params.append(Value(arg, regs_fp.pop(0)))
                    regs.pop(0)

                elif regs:
                    params.append(Value(arg, regs.pop(0)))
                    regs_fp.pop(0)

                else:
                    offset += 8
                    params.append(Memory(arg, X86Register.R_SP, offset=offset, sp=0))


class X86CallingConventionManager(CallingConventionManager):
    def __init__(self, bits: int, calling_convention: str) -> None:
        super().__init__(bits)
        self.cc = X86CallingConventionManager.__from_ccname(calling_convention)

    @staticmethod
    def __from_ccname(name: str) -> CallingConvention:
        __conventionmap = {
            "__stdcall": Stdcall,
            # "__cdecl": Cdecl,
        }
        if name in __conventionmap:
            return __conventionmap[name]
        return None

    def get_params(self, n: int, types: List[str]) -> List[Param] | None:
        if not self.cc:
            return None
        return self.cc.params(self.bits, n, types)

    def is_used(
        self, param: Param, sp: int, is_tail_jmp: bool, bits: int, nargs: int | None
    ) -> bool:
        # NOTE: this is the inaccurate version for when we dont know the number
        # of argument passed to the call
        if nargs is None:
            if param.base in self.cc.regs:
                return True
            if param.base in self.cc.regs_fp:
                return True
            if (
                param.is_memory()
                and param.offset is not None  # type: ignore
                and param.base == X86Register.R_SP
            ):
                if param.offset + sp < 0:  # type: ignore
                    return True
                if (is_tail_jmp or sp == 0) and param.offset + sp > 0:  # type: ignore
                    return True
            return False
        # NOTE: here we are able to perform a much more accurate analysis
        else:
            if bits == 64:
                # NOTE: here we check if according to calling convention params are used
                for locs in list(zip(self.cc.regs, self.cc.regs_fp))[:nargs]:
                    if param.base in set(locs):
                        return True

                scale = bits // 8
                for i in range(4, nargs):
                    offset = (i * scale) if not is_tail_jmp else ((i + 1) * scale)
                    if (
                        param.is_memory()
                        and param.base == X86Register.R_SP
                        and param.offset == offset
                    ):
                        return True
            else:
                scale = bits // 8
                for i in range(nargs):
                    offset = (i * scale) if not is_tail_jmp else ((i + 1) * scale)
                    if (
                        param.is_memory()
                        and param.base == X86Register.R_SP
                        and param.offset == offset
                    ):
                        return True
