from __future__ import annotations
from typing import Tuple
import capstone as cs

from static_analyzer.arch.register import Register
from static_analyzer.arch.x86.register import X86Register
from static_analyzer.code.basic_block import BasicBlock
from static_analyzer.code.function import Function


class X86Utils:
    mov_mnems = [
        "mov",
        "movsx",
        "movzx",
        "movsxd",
        "movntps",
        "movntq",
        "movnti",
        "movd",
        "movq",
        "movups",
        "movss",
        "movaps",
        "movlps",
        "movlhps",
        "movhps",
        "movhlps",
        "movntps",
        "movapd",
        "movhpd",
        "movlpd",
        "movntpd",
        "movupd",
        "movdq2q",
        "movdqa",
        "movdqu",
        "movq2dq",
        "movntdq",
        "movddup",
        "movsldup",
        "movshdup",
        "pmovsxbw",
        "pmovzxbw",
        "pmovsxbd",
        "pmovzxbd",
        "pmovsxbq",
        "pmovzxbq",
        "pmovsxwd",
        "pmovzxwd",
        "pmovsxwq",
        "pmovzxwq",
        "pmovsxdq",
        "pmovzxdq",
        "movntdqa",
    ]
    movs_mnems = ["movs", "movsb", "movsw", "movsd", "movsq"]
    cmovs_mnems = ["cmov"]
    lods_mnems = ["lods", "lodsb", "lodsw", "lodsd", "lodsq"]
    stos_mnems = ["stos", "stosb", "stosw", "stosd", "stosq"]
    str_cpy_mnems = lods_mnems + stos_mnems

    lea_mnems = ["lea"]
    xchg_mnems = ["xchg"]

    data_movement_mnems = mov_mnems + lea_mnems + xchg_mnems # + str_cpy_mnems

    pushpop_mnems = ["push", "pushad", "pusha", "pop", "popad", "popa"]
    logic_mnems = [
        "add",
        "sub",
        "inc",
        "dec",
        "imul",
        "idiv",
        "and",
        "or",
        "xor",
        "not",
        "neg",
        "sal",
        "sar",
        "shl",
        "shr",
    ]
    sub_mnems = ["sub"]
    call_mnems = ["call"]
    nop_mnems = ["nop"]
    unconditional_jmp = ["jmp"]

    @staticmethod
    def get_disassembler(bits: int) -> cs.Cs:
        if bits == 64:
            md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        else:
            md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        md.detail = True
        return md

    @staticmethod
    def disassemble_ins(md: cs.Cs, ins: bytes, ea: int) -> cs.CsInsn:
        return md.disasm(ins, ea).__next__()

    @staticmethod
    def get_memory_location(
        op, ins: cs.CsInsn
    ) -> Tuple[Register | None, Register | None, int | None, int]:
        base = X86Register.from_regname(ins.reg_name(op.mem.base))  # type: ignore
        index = X86Register.from_regname(ins.reg_name(op.mem.index))  # type: ignore
        offset = int(op.mem.disp)
        scale = int(op.mem.scale)

        return (base, index, offset, scale)

    @staticmethod
    def is_tail_jump(func: Function, bb: BasicBlock, ins: cs.CsInsn) -> bool:
        if ins.mnemonic not in X86Utils.unconditional_jmp:
            return False
        if len(func.get_successors(bb.start_ea)):
            return False
        return True
