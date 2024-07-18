from __future__ import annotations
from enum import Enum, unique
from typing import List

from static_analyzer.arch.register import Register


@unique
class X86Register(Register, Enum):
    R_A = "r-a"
    R_B = "r-b"
    R_C = "r-c"
    R_D = "r-d"
    R_SP = "r-sp"
    R_BP = "r-bp"
    R_SI = "r-si"
    R_DI = "r-di"
    R_8 = "r-8"
    R_9 = "r-9"
    R_10 = "r-10"
    R_11 = "r-11"
    R_12 = "r-12"
    R_13 = "r-13"
    R_14 = "r-14"
    R_15 = "r-15"
    R_XMM0 = "r-xmm0"
    R_XMM1 = "r-xmm1"
    R_XMM2 = "r-xmm2"
    R_XMM3 = "r-xmm3"
    R_XMM4 = "r-xmm4"
    R_XMM5 = "r-xmm5"
    R_XMM6 = "r-xmm6"
    R_XMM7 = "r-xmm7"
    R_XMM8 = "r-xmm8"
    R_XMM9 = "r-xmm9"
    R_XMM10 = "r-xmm10"
    R_XMM11 = "r-xmm11"
    R_XMM12 = "r-xmm12"
    R_XMM13 = "r-xmm13"
    R_XMM14 = "r-xmm14"
    R_XMM15 = "r-xmm15"
    R_IP = "r-ip"

    def __str__(self) -> str:
        return self._value_

    @staticmethod
    def from_regname(reg_name: str) -> Register | None:
        __registermap = {
            "ah": X86Register.R_A,
            "al": X86Register.R_A,
            "ax": X86Register.R_A,
            "eax": X86Register.R_A,
            "rax": X86Register.R_A,
            "ch": X86Register.R_C,
            "cl": X86Register.R_C,
            "cx": X86Register.R_C,
            "ecx": X86Register.R_C,
            "rcx": X86Register.R_C,
            "dh": X86Register.R_D,
            "dl": X86Register.R_D,
            "dx": X86Register.R_D,
            "edx": X86Register.R_D,
            "rdx": X86Register.R_D,
            "bh": X86Register.R_B,
            "bl": X86Register.R_B,
            "bx": X86Register.R_B,
            "ebx": X86Register.R_B,
            "rbx": X86Register.R_B,
            "sph": X86Register.R_SP,
            "spl": X86Register.R_SP,
            "sp": X86Register.R_SP,
            "esp": X86Register.R_SP,
            "rsp": X86Register.R_SP,
            "bph": X86Register.R_BP,
            "bpl": X86Register.R_BP,
            "bp": X86Register.R_BP,
            "ebp": X86Register.R_BP,
            "rbp": X86Register.R_BP,
            "sih": X86Register.R_SI,
            "sil": X86Register.R_SI,
            "si": X86Register.R_SI,
            "esi": X86Register.R_SI,
            "rsi": X86Register.R_SI,
            "dih": X86Register.R_DI,
            "dil": X86Register.R_DI,
            "di": X86Register.R_DI,
            "edi": X86Register.R_DI,
            "rdi": X86Register.R_DI,
            "r8": X86Register.R_8,
            "r8d": X86Register.R_8,
            "r8w": X86Register.R_8,
            "r8b": X86Register.R_8,
            "r9": X86Register.R_9,
            "r9d": X86Register.R_9,
            "r9w": X86Register.R_9,
            "r9b": X86Register.R_9,
            "r10": X86Register.R_10,
            "r10d": X86Register.R_10,
            "r10w": X86Register.R_10,
            "r10b": X86Register.R_10,
            "r11": X86Register.R_11,
            "r11d": X86Register.R_11,
            "r11w": X86Register.R_11,
            "r11b": X86Register.R_11,
            "r12": X86Register.R_12,
            "r12d": X86Register.R_12,
            "r12w": X86Register.R_12,
            "r12b": X86Register.R_12,
            "r13": X86Register.R_13,
            "r13d": X86Register.R_13,
            "r13w": X86Register.R_13,
            "r13b": X86Register.R_13,
            "r14": X86Register.R_14,
            "r14d": X86Register.R_14,
            "r14w": X86Register.R_14,
            "r14b": X86Register.R_14,
            "r15": X86Register.R_15,
            "r15d": X86Register.R_15,
            "r15w": X86Register.R_15,
            "r15b": X86Register.R_15,
            "xmm0": X86Register.R_XMM0,
            "xmm1": X86Register.R_XMM1,
            "xmm2": X86Register.R_XMM2,
            "xmm3": X86Register.R_XMM3,
            "xmm4": X86Register.R_XMM4,
            "xmm5": X86Register.R_XMM5,
            "xmm6": X86Register.R_XMM6,
            "xmm7": X86Register.R_XMM7,
            "xmm8": X86Register.R_XMM8,
            "xmm9": X86Register.R_XMM9,
            "xmm10": X86Register.R_XMM10,
            "xmm11": X86Register.R_XMM11,
            "xmm12": X86Register.R_XMM12,
            "xmm13": X86Register.R_XMM13,
            "xmm14": X86Register.R_XMM14,
            "xmm15": X86Register.R_XMM15,
            "rip": X86Register.R_IP,
            "eip": X86Register.R_IP,
        }
        if reg_name in __registermap:
            return __registermap[reg_name]
        return None

    @staticmethod
    def caller_saved() -> List[Register]:
        return [
            X86Register.R_A,
            X86Register.R_C,
            X86Register.R_D,
            X86Register.R_8,
            X86Register.R_9,
            X86Register.R_10,
            X86Register.R_11,
            X86Register.R_XMM0,
            X86Register.R_XMM1,
            X86Register.R_XMM2,
            X86Register.R_XMM3,
            X86Register.R_XMM4,
            X86Register.R_XMM5,
        ]
