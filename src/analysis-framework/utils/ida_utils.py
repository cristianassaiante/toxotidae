from __future__ import annotations
import idaapi
import idc
import idautils
import ida_hexrays


def get_bits() -> int:
    if idaapi.get_inf_structure().is_64bit():
        return 64
    else:
        return 32


def nargs_from_hexrays(ea):
    try:
        decompiled = ida_hexrays.decompile(ea)
        return len(decompiled.arguments)
    except:
        return -1
