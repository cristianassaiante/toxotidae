from __future__ import annotations

from static_analyzer.arch.x86.calling_convention import X86CallingConventionManager
from static_analyzer.arch.x86.utils import X86Utils
from static_analyzer.code.basic_block import BasicBlock
from static_analyzer.code.dll import DLL
from static_analyzer.code.function import Function
from static_analyzer.code.instruction import Instruction
from utils.ida_utils import *


def is_redirecting(api: Function) -> bool:
    md = X86Utils.get_disassembler(bits)

    for bb in api.get_exits():
        bb_bytes = idaapi.get_bytes(bb.start_ea, bb.end_ea - bb.start_ea)
        if not bb_bytes:
            continue

        ins = list(md.disasm(bb_bytes, bb.start_ea))[-1]

        if ins.mnemonic == "jmp":
            return True
    return False


def compute_calls(api: Function) -> None:
    md = X86Utils.get_disassembler(api.bits)

    for bb in api.get_basic_blocks():
        for ins in bb.get_instructions():
            cs_ins = X86Utils.disassemble_ins(md, ins.ins_bytes, ins.ea)
            is_tail_jmp = X86Utils.is_tail_jump(api, bb, cs_ins)

            if cs_ins.mnemonic in X86Utils.call_mnems or is_tail_jmp:
                func_ea = idaapi.get_first_fcref_from(ins.ea)

                tif = idaapi.tinfo_t()
                idautils.ida_nalt.get_tinfo(tif, func_ea)
                funcdata = idaapi.func_type_data_t()

                if tif.get_func_details(funcdata):
                    ins.set_nargs(funcdata.size())
                else:
                    # try extract from decompiler if no info available without
                    nargs = nargs_from_hexrays(func_ea)
                    if nargs != -1:
                        ins.set_nargs(nargs)


def compute_bb(bb: idaapi.BasicBlock, bits: int) -> BasicBlock | None:
    bb_obj = BasicBlock(bb.start_ea, bb.end_ea)

    md = X86Utils.get_disassembler(bits)

    bb_bytes = idaapi.get_bytes(bb.start_ea, bb.end_ea - bb.start_ea)
    if not bb_bytes:
        return None

    for ins in md.disasm(bb_bytes, bb.start_ea):
        spd: int = idc.get_spd(ins.address)  # type: ignore
        bb_obj.add_instruction(Instruction(ins.bytes, ins.address, spd))

    return bb_obj


def compute_func(func_ea: int, func_name: str, bits: int) -> Function | None:
    def compute_edge(api: Function):
        def get_bb_from_end(addr) -> int | None:
            for bb in api.get_basic_blocks():
                ins = idautils.DecodeInstruction(addr)
                if ins and bb.end_ea == (ins.size + addr):
                    return bb.start_ea
            return None

        for bb in api.get_basic_blocks():
            # recursion cause this to build ill-formed cfg
            if bb.start_ea == func_ea:
                continue

            current = idaapi.get_first_cref_to(bb.start_ea)
            while current != idc.BADADDR:
                src = get_bb_from_end(current)
                if src:
                    api.add_edge(src, bb.start_ea)

                current = idaapi.get_next_cref_to(bb.start_ea, current)

    tif = idaapi.tinfo_t()
    idautils.ida_nalt.get_tinfo(tif, func_ea)
    funcdata = idaapi.func_type_data_t()
    tif.get_func_details(funcdata)

    func = idaapi.get_func(func_ea)

    if not func:
        print(f"[DBG:-] Cannot retrieve {func_name}@{hex(func_ea)}")
        return None

    func_proto = idc.get_type(func_ea)
    if not func_proto:
        print(f"[DBG:-] Cannot retrieve {func_name}@{hex(func_ea)} prototype")
        return None

    calling_convention = func_proto.split("(")[0].split()[-1]
    if "_" in calling_convention:
        calling_convention = calling_convention[calling_convention.index("_") :]
    else:
        calling_convention = "__stdcall"

    # apparently IDA sometimes is not able to correctly print the calling convention
    # when it says "fastcall", "usercall" or "cdecl", it is always "stdcall"
    # so let's normalize this, eventually if this is wrong the API are goin to be considered DEAD
    # but from some manual analysis, it should do the trick
    # NOTE from the future: this is because at 64bit the cc is always the same!!!
    if calling_convention.startswith("__user"):
        calling_convention = "__stdcall"
    if calling_convention == "__fastcall":
        calling_convention = "__stdcall"
    if calling_convention == "__cdecl":
        calling_convention = "__stdcall"

    nparams = funcdata.size()

    if nparams == 0:
        print(f"[DBG:-] {func_name}@{hex(func_ea)} has no arguments retrievable")
        return None

    flow_chart = idaapi.FlowChart(func)
    api = Function(func_ea, func_name, bits)

    for bb in flow_chart:
        bb_func = idaapi.get_func(bb.start_ea)
        if not bb_func or bb_func.start_ea != func_ea:
            continue
        bb_obj = compute_bb(bb, bits)
        if bb_obj:
            api.add_basic_block(bb_obj)

    if not len(api.basic_blocks):
        print(f"[DBG:-] IDA not able to retrieve {func_name}@{hex(func_ea)}")
        return None

    compute_edge(api)
    api.cleanup()

    compute_calls(api)

    types = []
    for arg_num in range(funcdata.size()):
        arg_type = idaapi.print_tinfo(
            "", 0, 0, idc.PRTYPE_1LINE, funcdata[arg_num].type, "", ""
        )
        types.append(arg_type)

    call_conv = X86CallingConventionManager(bits, calling_convention)
    params = call_conv.get_params(nparams, types)

    if params is None:
        print(
            f"[DBG:-] Calling convention {calling_convention} not supported {func_name}@{hex(func_ea)}"
        )
        return None

    api.add_parameters(params)
    api.calling_convention = call_conv

    if is_redirecting(api):
        api.set_is_redirecting()

    return api


if __name__ == "__main__":
    idaapi.set_database_flag(idaapi.DBFL_KILL)
    idaapi.auto_wait()

    # NOTE: always rebase after autowait!
    idaapi.rebase_program(-idaapi.get_imagebase(), idaapi.MSF_FIXONCE)

    exports = set()
    for export in idautils.Entries():
        if not export[3]:
            continue
        exports.add((export[2], export[3]))

    print(f"[DBG:+] Found {len(exports)} exported functions")

    dll_name = idc.get_root_filename()
    bits = get_bits()

    dll_obj = DLL(dll_name, bits)
    for ea, name in exports:
        func = compute_func(ea, name, bits)
        if func and len(func.get_basic_blocks()) > 0:
            dll_obj.add_api(func)

    print(f"[DBG:+] {len(dll_obj.apis)} control-flow graphs correctly computed")

    dll_obj.dump(idc.ARGV[1])
    idaapi.qexit(0)
