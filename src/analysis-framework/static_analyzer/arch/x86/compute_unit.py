from __future__ import annotations
from typing import List
import capstone as cs

from static_analyzer.arch.compute_unit import ComputeUnit
from static_analyzer.arch.register import Register
from static_analyzer.arch.x86.register import X86Register
from static_analyzer.arch.x86.utils import X86Utils
from static_analyzer.code.basic_block import BasicBlock
from static_analyzer.code.function import Function
from static_analyzer.code.instruction import Instruction
from static_analyzer.logger import Logger
from static_analyzer.param.memory import Memory
from static_analyzer.param.param import Param
from static_analyzer.param.value import Value


class _X86ComputeUnitHelpers:
    @staticmethod
    def compute_mov(ins: cs.CsInsn, params: List[Param], sp: int) -> None:
        dst_op = ins.operands[0]
        src_op = ins.operands[1]

        # case 1: reg <- reg
        if src_op.type == cs.CS_OP_REG and dst_op.type == cs.CS_OP_REG:
            src_reg = X86Register.from_regname(ins.reg_name(src_op.reg))  # type: ignore
            dst_reg = X86Register.from_regname(ins.reg_name(dst_op.reg))  # type: ignore

            if not dst_reg:
                return
            if not src_reg:
                return

            if dst_reg in X86ComputeUnit.sp_aliases:
                X86ComputeUnit.sp_aliases.remove(dst_reg)
                X86ComputeUnit.sp_aliases_offsets.pop(dst_reg)

            # case 1.1 | 1.2
            if src_reg == dst_reg or dst_reg == X86Register.R_SP:
                return

            # case 1.3 | 1.4 | 1.5(base)
            src_params = Param.get_from_base(params, src_reg)
            Param.delete_from_reg(params, dst_reg)

            if src_reg == X86Register.R_SP:
                X86ComputeUnit.sp_aliases.add(dst_reg)
                X86ComputeUnit.sp_aliases_offsets[dst_reg] = sp

            # NOTE: here it means we are only accessing part of the argument
            # and not the full argument -> do not propagate partial values
            if len(src_params) == 1:
                src_param = src_params[0]
                if src_param.size is not None:
                    if src_param.size > src_op.size:
                        return

            if len(src_params):
                for param in src_params:
                    params.append(param.copy_at(dst_reg))
                return

            # case 1.5(index)
            src_params = Memory.get_from_index(
                Memory.get_memory_params(params), src_reg
            )
            for param in src_params:
                params.append(param.copy_at_index(dst_reg))
            return

        # case 2: reg <- imm
        if src_op.type == cs.CS_OP_IMM and dst_op.type == cs.CS_OP_REG:
            dst_reg = X86Register.from_regname(ins.reg_name(dst_op.reg))  # type: ignore
            if not dst_reg:
                return

            Param.delete_from_reg(params, dst_reg)
            if dst_reg in X86ComputeUnit.sp_aliases:
                X86ComputeUnit.sp_aliases.remove(dst_reg)
                X86ComputeUnit.sp_aliases_offsets.pop(dst_reg)
            return

        # case 3: reg <- mem
        if src_op.type == cs.CS_OP_MEM and dst_op.type == cs.CS_OP_REG:
            dst_reg = X86Register.from_regname(ins.reg_name(dst_op.reg))  # type: ignore
            if not dst_reg:
                return

            Param.delete_from_reg(params, dst_reg)
            if dst_reg in X86ComputeUnit.sp_aliases:
                X86ComputeUnit.sp_aliases.remove(dst_reg)
                X86ComputeUnit.sp_aliases_offsets.pop(dst_reg)

            mem_loc = X86Utils.get_memory_location(src_op, ins)

            src_param = Memory.get_from_memory(
                Memory.get_memory_params(params), mem_loc
            )
            if src_param:
                params.append(Value(src_param.state, dst_reg, src_param.size))
            return

        # case 4: mem <- reg
        if src_op.type == cs.CS_OP_REG and dst_op.type == cs.CS_OP_MEM:
            src_reg = X86Register.from_regname(ins.reg_name(src_op.reg))  # type: ignore
            if not src_reg:
                return

            mem_loc = X86Utils.get_memory_location(dst_op, ins)
            dst_param = Memory.get_from_memory(
                Memory.get_memory_params(params), mem_loc
            )

            # here we also want to propagate memory locations with offset 0 -> from lea
            # NOTE: here it may happen (in case of structs) that we have both an arg in register
            # which is a ptr and an arg at register+0, meaning that we are writing in the struct field
            # when this happens we ignore the memory parameter and we only keep the register
            src_params = [
                param
                for param in Param.get_from_base(params, src_reg)
                if not (param.is_memory() and param.offset)  # type: ignore
            ]

            # NOTE: here it means we are only accessing part of the argument
            # and not the full argument -> do not propagate partial values
            if len(src_params) == 1:
                src_param = src_params[0]
                if src_param.is_value() and src_param.size is not None:
                    if src_param.size > src_op.size:
                        return

            if len(src_params) > 1:
                for param in src_params:
                    if not param.is_memory():
                        src_params = [param]
                        break

            if src_params:
                src_param = src_params[0]

                if src_param.is_memory() and src_param.offset:  # type: ignore
                    return

                if dst_param and dst_param.is_none():
                    dst_param.state = src_param.state

                elif not (dst_param and dst_param.state == src_param.state):
                    if src_param.is_memory():
                        new_mem = Memory(
                            src_param.state, *mem_loc, sp, to_ref=src_param.ref_to
                        )
                    else:
                        new_mem = Memory(src_param.state, *mem_loc, sp)

                    # NOTE: here it means we are reusing a dead memory location
                    # so let's delete the dead memory location and its aliases
                    already = Memory.get_from_memory(
                        Memory.get_memory_params(params), mem_loc
                    )
                    if already:
                        Memory.delete_aliases(params, already.id)

                    params.append(new_mem)

                    base, index, offset, scale = mem_loc

                    if base in X86ComputeUnit.sp_aliases:
                        if not index is None and offset is not None:
                            Logger.log().debug(
                                "UNSUPPORTED FEATURE: Copy from sp alias with index register"
                            )
                            return

                        sp_offset = X86ComputeUnit.sp_aliases_offsets[base]

                        new_mem_loc = (
                            X86Register.R_SP,
                            index,
                            sp_offset + offset - sp,
                            scale,
                        )

                        if src_param.is_memory():
                            new_mem_param = Memory(
                                src_param.state,
                                *new_mem_loc,
                                sp,
                                new_mem.id,
                                to_ref=src_param.ref_to,
                            )
                        else:
                            new_mem_param = Memory(
                                src_param.state, *new_mem_loc, sp, new_mem.id
                            )

                        params.append(new_mem_param)
            elif dst_param:
                # NOTE: instead of setting to none, let's just delete
                # also delete those memory locations that have reference to dst_param
                Memory.delete_aliases(params, dst_param.id)
                Memory.delete_xrefs(params, dst_param)
            return

        # case 5: mem <- imm
        if src_op.type == cs.CS_OP_IMM and dst_op.type == cs.CS_OP_MEM:
            mem_loc = X86Utils.get_memory_location(dst_op, ins)
            dst_param = Memory.get_from_memory(
                Memory.get_memory_params(params), mem_loc
            )
            if dst_param:
                # NOTE: instead of setting to none, let's just delete
                # also delete those memory locations that have reference to dst_param
                Memory.delete_aliases(params, dst_param.id)
                Memory.delete_xrefs(params, dst_param)
            return

        assert 1 == 0, "Unhandled mov instruction case"

    @staticmethod
    def compute_lea(ins: cs.CsInsn, params: List[Param], sp: int) -> None:
        src_op = ins.operands[1]
        dst_op = ins.operands[0]

        dst_reg = X86Register.from_regname(ins.reg_name(dst_op.reg))  # type: ignore
        if not dst_reg:
            return

        if dst_reg in X86ComputeUnit.sp_aliases:
            X86ComputeUnit.sp_aliases.remove(dst_reg)
            X86ComputeUnit.sp_aliases_offsets.pop(dst_reg)

        mem_loc = X86Utils.get_memory_location(src_op, ins)
        base, index, offset, scale = mem_loc

        if base == dst_reg and not offset and not index:
            return

        src_param = Memory.get_from_memory(Memory.get_memory_params(params), mem_loc)

        Param.delete_from_reg(params, dst_reg)

        if src_param:
            new_mem_loc = (dst_reg, None, 0, scale)
            new_mem_param = Memory(src_param.state, *new_mem_loc, sp, to_ref=src_param)
            params.append(new_mem_param)

    @staticmethod
    def compute_xchg(ins: cs.CsInsn, params: List[Param], sp: int) -> None:
        pass

    @staticmethod
    def compute_str(ins: cs.CsInsn, params: List[Param], sp: int) -> None:
        pass

    @staticmethod
    def compute_push(ins: cs.CsInsn, params: List[Param], sp: int) -> None:
        src_op = ins.operands[0]

        assert X86ComputeUnit.func and X86ComputeUnit.bb, "Internal error"

        scale = X86ComputeUnit.func.bits // 8

        if src_op.type == cs.CS_OP_REG:
            src_reg = X86Register.from_regname(ins.reg_name(src_op.reg))  # type: ignore
            if not src_reg:
                return

            src_params = [
                param
                for param in Param.get_from_base(params, src_reg)
                if not (param.is_memory() and param.offset)  # type: ignore
            ]
            for param in src_params:
                if param.is_value():
                    src_params = [param]
                    break

            # NOTE: here it means we are only accessing part of the argument
            # and not the full argument -> do not propagate partial values
            if len(src_params) == 1:
                src_param = src_params[0]
                if src_param.size is not None:
                    if src_param.size > src_op.size:
                        return

            if src_params:
                src_param = src_params[0]

                mem_loc = (X86Register.R_SP, None, -scale, scale)

                if src_param.is_memory():
                    new_mem_param = Memory(
                        src_param.state, *mem_loc, sp, to_ref=src_param.ref_to
                    )
                else:
                    new_mem_param = Memory(src_param.state, *mem_loc, sp)

                params.append(new_mem_param)
            return

        if src_op.type == cs.CS_OP_MEM:
            mem_loc = X86Utils.get_memory_location(src_op, ins)

            src_param = Memory.get_from_memory(
                Memory.get_memory_params(params), mem_loc
            )
            if src_param:
                new_mem_loc = (X86Register.R_SP, None, -scale, scale)
                new_mem_param = Memory(
                    src_param.state, *new_mem_loc, sp, to_ref=src_param.ref_to
                )
                params.append(new_mem_param)
            return

    @staticmethod
    def compute_pop(ins: cs.CsInsn, params: List[Param], sp: int) -> None:
        dst_op = ins.operands[0]

        assert X86ComputeUnit.func and X86ComputeUnit.bb, "Internal error"

        if dst_op.type == cs.CS_OP_REG:
            dst_reg = X86Register.from_regname(ins.reg_name(dst_op.reg))  # type: ignore
            if not dst_reg:
                return

            if dst_reg in X86ComputeUnit.sp_aliases:
                X86ComputeUnit.sp_aliases.remove(dst_reg)
                X86ComputeUnit.sp_aliases_offsets.pop(dst_reg)

            Param.delete_from_reg(params, dst_reg)

            mem_loc = (X86Register.R_SP, None, 0, X86ComputeUnit.func.bits // 8)
            src_param = Memory.get_from_memory(
                Memory.get_memory_params(params), mem_loc
            )
            if src_param:
                params.append(Value(src_param.state, dst_reg, src_param.size))
                Memory.delete_aliases(params, src_param.id)
                Memory.delete_xrefs(params, src_param)

            return

        if dst_op.type == cs.CS_OP_MEM:
            mem_loc = (X86Register.R_SP, None, 0, X86ComputeUnit.func.bits // 8)
            src_param = Memory.get_from_memory(
                Memory.get_memory_params(params), mem_loc
            )

            mem_loc = X86Utils.get_memory_location(dst_op, ins)
            if src_param:
                params.append(Memory(src_param.state, *mem_loc, sp))
                Memory.delete_aliases(params, src_param.id)
                Memory.delete_xrefs(params, src_param)

            return

    @staticmethod
    def compute_call(ins: cs.CsInsn, params: List[Param], sp: int) -> None:
        for reg in X86Register.caller_saved():
            params_base = Param.get_from_base(params, reg)

            # NOTE: here we delete the references and aliases if memory
            # when internal calls are made with fastcalls, here we remove
            # locations than potentially are used by the call.
            # It's okay, we are more conservative but we have correct information
            for param in params_base:
                if param.is_memory() and reg not in X86ComputeUnit.sp_aliases:
                    Memory.delete_aliases(params, param.id)
                    for ref in param.get_refs():
                        Memory.delete_aliases(params, ref.id)

                if reg in X86ComputeUnit.sp_aliases:
                    X86ComputeUnit.sp_aliases.remove(reg)
                    X86ComputeUnit.sp_aliases_offsets.pop(reg)

                Param.delete_from_reg(params, reg)

    @staticmethod
    def compute_prolog(
        bits: int,
        cs_ins: cs.CsInsn | None,
        prev_cs_ins: cs.CsInsn,
        params: List[Param],
        sp: int,
        prev_sp: int,
    ) -> None:
        def compute_prolog_32() -> None:
            dst_reg = X86Register.R_BP
            src_reg = X86Register.R_SP

            assert X86ComputeUnit.func and X86ComputeUnit.bb, "Internal error"

            scale = X86ComputeUnit.func.bits // 8

            X86ComputeUnit.sp_aliases.add(dst_reg)
            X86ComputeUnit.sp_aliases_offsets[dst_reg] = prev_sp + scale

            sp_params = Param.get_from_base(params, src_reg)

            assert all(map(lambda x: x.is_memory(), sp_params)), "CHECK THIS PLEASE"

            for param in sp_params:
                mem_loc = (dst_reg, None, param.offset + prev_sp + scale, scale)  # type: ignore
                new_mem = Memory(param.state, *mem_loc, prev_sp, param.id)  # type: ignore
                if not new_mem in params:
                    params.append(new_mem)

        def compute_prolog_64(disp: int, base: Register, dst_reg: Register) -> None:
            src_reg = X86Register.R_SP

            assert X86ComputeUnit.func and X86ComputeUnit.bb, "Internal error"

            scale = X86ComputeUnit.func.bits // 8

            X86ComputeUnit.sp_aliases.add(dst_reg)
            X86ComputeUnit.sp_aliases_offsets[dst_reg] = disp + sp  # - scale

            sp_params = Param.get_from_base(params, src_reg)

            assert all(map(lambda x: x.is_memory(), sp_params)), "CHECK THIS PLEASE"

            for param in sp_params:
                if src_reg != base:
                    # ex WriteProcessMemory -> lea rbp, [rax - 0x57]
                    mem_loc = (dst_reg, None, param.offset + sp - disp, scale)  # type: ignore
                else:
                    mem_loc = (dst_reg, None, param.offset - disp, scale)  # type: ignore

                new_mem = Memory(param.state, *mem_loc, sp - disp, param.id)  # type: ignore
                if not new_mem in params:
                    params.append(new_mem)

        if bits == 32 and prev_sp > sp and prev_cs_ins.mnemonic in X86Utils.call_mnems:
            compute_prolog_32()
            return

        if cs_ins and bits == 64:
            if (
                prev_cs_ins.mnemonic in X86Utils.lea_mnems
                and cs_ins.mnemonic in X86Utils.sub_mnems
            ):
                src_op = prev_cs_ins.operands[1]
                dst_op = prev_cs_ins.operands[0]

                dst_reg = X86Register.from_regname(prev_cs_ins.reg_name(dst_op.reg))  # type: ignore
                if not dst_reg:
                    return

                # NOTE: we were finding the same prologue pattern in code with different sub, let's avoid those
                sub_dst_op = cs_ins.operands[0]
                dst_reg_sub = X86Register.from_regname(cs_ins.reg_name(sub_dst_op.reg))  # type: ignore
                if dst_reg_sub != X86Register.R_SP:
                    return

                mem_loc = X86Utils.get_memory_location(src_op, prev_cs_ins)
                base, index, offset, scale = mem_loc

                if offset is not None and (
                    base in X86ComputeUnit.sp_aliases or base == X86Register.R_SP
                ):
                    compute_prolog_64(offset, base, dst_reg)

            return

    @staticmethod
    def clear_used(ins: cs.CsInsn, params: List[Param], sp: int) -> None:
        _, regs_written = ins.regs_access()
        for reg in regs_written:
            reg = X86Register.from_regname(ins.reg_name(reg))  # type: ignore
            if not reg or reg == X86Register.R_SP:
                continue
            Param.delete_from_reg(params, reg)

            if reg in X86ComputeUnit.sp_aliases:
                X86ComputeUnit.sp_aliases.remove(reg)
                X86ComputeUnit.sp_aliases_offsets.pop(reg)

        for op in ins.operands:
            if op.type == cs.CS_OP_MEM:
                if not (op.access == cs.CS_AC_READ | cs.CS_AC_WRITE):
                    continue
                mem_loc = X86Utils.get_memory_location(op, ins)

                memory_params = Memory.get_memory_params(params)
                dst_param = Memory.get_from_memory(memory_params, mem_loc)

                if dst_param:
                    Memory.delete_aliases(params, dst_param.id)
                    Memory.delete_xrefs(params, dst_param)

    @staticmethod
    def compute(ins: cs.CsInsn, params: List[Param], sp: int) -> List[Param]:
        mnem = ins.mnemonic
        op = mnem.split()[1] if len(mnem.split()) > 1 else None

        if mnem in X86Utils.data_movement_mnems:
            # NOTE: we ignore cmov since we can't predict the outcome
            if mnem in X86Utils.mov_mnems:
                _X86ComputeUnitHelpers.compute_mov(ins, params, sp)
            elif mnem in X86Utils.lea_mnems:
                _X86ComputeUnitHelpers.compute_lea(ins, params, sp)
            elif mnem in X86Utils.xchg_mnems:
                _X86ComputeUnitHelpers.compute_xchg(ins, params, sp)

            # NOTE: NOT IMPLEMENTED
            elif op:
                if mnem in X86Utils.str_cpy_mnems:
                    _X86ComputeUnitHelpers.compute_str(ins, params, sp)
                elif "rep" in mnem and op in X86Utils.str_cpy_mnems:
                    _X86ComputeUnitHelpers.compute_str(ins, params, sp)

        elif mnem in X86Utils.pushpop_mnems:
            if mnem == "push":
                _X86ComputeUnitHelpers.compute_push(ins, params, sp)
            elif mnem == "pop":
                _X86ComputeUnitHelpers.compute_pop(ins, params, sp)
            else:
                pass  # NOTE: ignoring push{a,ad}/pop{a,ad}

        elif mnem in X86Utils.call_mnems:
            _X86ComputeUnitHelpers.compute_call(ins, params, sp)

        elif mnem in X86Utils.nop_mnems:
            pass  # NOTE: do nothing

        else:
            _X86ComputeUnitHelpers.clear_used(ins, params, sp)

        return params


class X86ComputeUnit(ComputeUnit):
    sp_aliases: set[Register] = set()
    sp_aliases_offsets: dict[Register, int] = {}
    func: Function | None = None
    bb: BasicBlock | None = None

    @staticmethod
    def compute(func: Function, bb: BasicBlock) -> List[Param]:
        # init class attributes used in other functions
        if func != X86ComputeUnit.func:
            X86ComputeUnit.func = func
            X86ComputeUnit.sp_aliases = set()
            X86ComputeUnit.sp_aliases_offsets = {}
        if bb != X86ComputeUnit.bb:
            X86ComputeUnit.bb = bb

        prev_ins: Instruction | None = None
        params = bb.get_par_in()

        if params is None:
            return []

        md = X86Utils.get_disassembler(func.bits)

        for ins in bb.get_instructions():
            cs_ins = X86Utils.disassemble_ins(md, ins.ins_bytes, ins.ea)

            if prev_ins:
                prev_cs_ins = X86Utils.disassemble_ins(
                    md, prev_ins.ins_bytes, prev_ins.ea
                )
                _X86ComputeUnitHelpers.compute_prolog(
                    func.bits, cs_ins, prev_cs_ins, params, ins.sp, prev_ins.sp
                )

                for param in params:
                    param.update_stack(X86Register.R_SP, ins.sp)

                # NOTE: in theory this is not needed anymore, but let's keep it
                Memory.delete_negative_sp(X86Register.R_SP, params)

                prev_ins.set_par_out(params)

                Logger.log().debug("-" * 80)
                ins.set_par_in(params)

            Logger.log().debug(f"Computing {ins}: {cs_ins.mnemonic} {cs_ins.op_str}")

            used_params = X86ComputeUnit.get_used(func, ins, params, ins.sp)
            for u_par in used_params:
                u_par.is_used = True

            # NOTE: since a call may end up overwriting an argument, we need
            # to be conservative here and remove all the locations that were previously
            # marked as used by the call
            if cs_ins.mnemonic in X86Utils.call_mnems:
                call_used = X86ComputeUnit.get_used(func, ins, params, ins.sp)
                for param in call_used:
                    params.remove(param)

            params = _X86ComputeUnitHelpers.compute(cs_ins, params, ins.sp)
            prev_ins = ins

        last_ins = bb.get_instructions()[-1]
        next_sp = set(
            [bb_succ.get_sp() for bb_succ in func.get_successors(bb.start_ea)]
        )

        if len(next_sp) == 1:
            next_sp = next_sp.pop()

            # here we fix those cases in which prolog call is the last instruction of a bb
            last_cs_ins = X86Utils.disassemble_ins(md, last_ins.ins_bytes, last_ins.ea)
            _X86ComputeUnitHelpers.compute_prolog(
                func.bits, None, last_cs_ins, params, next_sp, last_ins.sp
            )

            for param in params:
                param.update_stack(X86Register.R_SP, next_sp)
        else:
            pass
            # Logger.log().warn(f'{bb} has successors with different sp value, par_out will be wrong but successors par_in will be fixed by merge')

        Memory.delete_negative_sp(X86Register.R_SP, params)
        last_ins.set_par_out(params)

        return params

    @staticmethod
    def get_used(
        func: Function, ins: Instruction, params: List[Param], sp: int
    ) -> List[Param]:
        used_params: set[Param] = set()

        md = X86Utils.get_disassembler(func.bits)
        cs_ins = X86Utils.disassemble_ins(md, ins.ins_bytes, ins.ea)

        if cs_ins.mnemonic in X86Utils.nop_mnems:
            return list(used_params)

        for op in cs_ins.operands:
            if op.type == cs.CS_OP_MEM:
                mem_loc = X86Utils.get_memory_location(op, cs_ins)
                base, _, _, _ = mem_loc

                mem_param = Memory.get_from_memory(
                    Memory.get_memory_params(params), mem_loc
                )

                if mem_param and not (
                    op.access & (cs.CS_AC_WRITE | cs.CS_AC_READ) == cs.CS_AC_WRITE
                ):
                    for param in Memory.get_aliases(params, mem_param.id):
                        param.size = op.size
                        used_params.add(param)
                        # here's I have to add also the aliases for each aref
                        for ref in param.get_refs():
                            if ref in params:
                                ref.size = op.size
                                used_params.add(ref)

                                ref_aliases = Memory.get_aliases(params, ref.id)
                                for ref_al in ref_aliases:
                                    ref_al.size = op.size

                                used_params.update(ref_aliases)
                elif base:
                    reg_params = Param.get_from_base(params, base)
                    for param in reg_params:
                        if param.is_memory():
                            continue
                        param.size = op.size
                        used_params.add(param)

            elif op.type == cs.CS_OP_REG:
                reg = X86Register.from_regname(cs_ins.reg_name(op.reg))  # type: ignore
                if not reg:
                    continue

                if reg == X86Register.R_SP or reg in X86ComputeUnit.sp_aliases:
                    continue

                reg_params = Param.get_from_base(params, reg)
                for param in reg_params:
                    if param.is_memory() and param.offset:  # type: ignore
                        continue
                    if (
                        param.is_value()
                        and (op.access & cs.CS_AC_WRITE)
                        # parameters usage when in registers are marked when the register is used in both read and write
                        # without this check (CertEnumCertificateContextProperties arg0 not live due to use in neg rcx)
                        and not ((op.access & cs.CS_AC_READ))
                    ):
                        continue
                    if param.size is not None and op.size < param.size:
                        continue
                    param.size = op.size
                    used_params.add(param)

        assert X86ComputeUnit.func and X86ComputeUnit.bb, "Internal error"
        is_tail_jmp = X86Utils.is_tail_jump(
            X86ComputeUnit.func, X86ComputeUnit.bb, cs_ins
        )

        if cs_ins.mnemonic in X86Utils.call_mnems or is_tail_jmp:
            if not X86ComputeUnit.func.calling_convention:
                return list(used_params)

            for i, param in enumerate(params):
                if X86ComputeUnit.func.calling_convention.is_used(
                    param, sp, is_tail_jmp, func.bits, ins.nargs
                ):
                    if param.is_memory():
                        for memory in Memory.get_aliases(params, param.id):  # type: ignore
                            used_params.add(memory)
                            # here's I have to add also the aliases for each aref
                            for ref in memory.get_refs():
                                if ref in params:
                                    used_params.add(ref)
                                    used_params.update(
                                        set(Memory.get_aliases(params, ref.id))
                                    )
                    else:
                        used_params.add(param)

        return list(used_params)

    @staticmethod
    def get_sp() -> Register:
        return X86Register.R_SP

    @staticmethod
    def is_hookable(func: Function, ins: Instruction) -> bool:
        md = X86Utils.get_disassembler(func.bits)
        ins_cs = X86Utils.disassemble_ins(md, ins.ins_bytes, ins.ea)
        if "rep" in ins_cs.mnemonic:
            return False
        return True

    @staticmethod
    def is_call_mem(func: Function, ins: Instruction) -> bool:
        md = X86Utils.get_disassembler(func.bits)
        ins_cs = X86Utils.disassemble_ins(md, ins.ins_bytes, ins.ea)

        if ins_cs.mnemonic in X86Utils.call_mnems:
            used = X86ComputeUnit.get_used(func, ins, ins.get_par_in(), ins.sp)
            for param in used:
                if param.is_memory():
                    return True
        return False

    @staticmethod
    def merge(all_par_in: List[List[Param]], bb: BasicBlock) -> List[Param]:
        all_params = []
        for params in all_par_in:
            for param in params:
                param.update_stack(X86Register.R_SP, bb.get_sp())
                all_params.append(param)

        values = Value.get_value_params(all_params)
        memories = Memory.get_memory_params(all_params)
        nodes = len(all_par_in)

        unique_vals = {}
        for value in values:
            base = value.base
            if base not in unique_vals:
                unique_vals[base] = []
            unique_vals[base].append(value)

        final_vals = []
        for key in unique_vals:
            values = len(unique_vals[key])
            # if it comes from all the pred nodes
            if len(unique_vals[key]) == nodes:
                # if all the versions are equal
                if unique_vals[key].count(unique_vals[key][0]) == values:
                    # compute complessive is used
                    is_used = True
                    for value in unique_vals[key]:
                        is_used = is_used and value.is_used

                    # add to final list
                    value = unique_vals[key][0]
                    value.is_used = is_used
                    final_vals.append(value)

        unique_mems = {}
        for memory in memories:
            mem_loc = (memory.base, memory.index, memory.offset, memory.scale)
            if mem_loc not in unique_mems:
                unique_mems[mem_loc] = []
            unique_mems[mem_loc].append(memory)

        final_mems = []
        for key in unique_mems:
            mems = len(unique_mems[key])
            # if it comes from all the pred nodes
            if len(unique_mems[key]) == nodes:
                # if all the versions are equal
                if unique_mems[key].count(unique_mems[key][0]) == mems:
                    # compute complessive is used
                    is_used = False
                    for mem in unique_mems[key]:
                        is_used = is_used or mem.is_used

                    # add to final list
                    mem = unique_mems[key][0]
                    mem.is_used = is_used
                    final_mems.append(mem)

        return final_vals + final_mems
