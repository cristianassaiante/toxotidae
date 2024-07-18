from __future__ import annotations
from typing import List, Tuple, Type

from static_analyzer.analysis import Analysis
from static_analyzer.arch.compute_unit import ComputeUnit
from static_analyzer.code.basic_block import BasicBlock
from static_analyzer.code.function import Function
from static_analyzer.code.instruction import Instruction
from static_analyzer.logger import Logger


class VulnSpotsFinder(Analysis):
    @staticmethod
    def find_vuln_spots(func: Function, compute_unit: Type[ComputeUnit]) -> None:
        VISITED = 2
        VISITING = 1
        UNEXPLORED = 0

        Logger.log().debug("*" * 80)
        Logger.log().debug(f"Computing Vuln Spots Finding {func}")
        Logger.log().debug("*" * 80)

        def magicdfs(bb: BasicBlock, state: dict[int, int], out):
            state[bb.start_ea] = VISITING

            for ins in bb.get_instructions():
                live_params = ins.get_live_params()
                assert live_params is not None

                for par in live_params:
                    if not par.is_memory():
                        continue
                    if par.ref_to is not None:
                        continue
                    if par.base != compute_unit.get_sp():
                        continue

                    # NOTE: this is a fix for 64bit mostly but it can potentially
                    # catch issues also at 32bit when the same situation happens
                    # found_another_copy = False
                    # for par_inn in live_params:
                    #     if par_inn.is_value() and par_inn.state == par.state:
                    #         found_another_copy = True
                    # if found_another_copy:
                    #     continue
                    # do not add if there is another live copy in a register

                    real_off = par.offset + ins.sp  # type: ignore
                    key = (real_off, par.state)
                    if key not in out:
                        out[key] = [ins, ins]

                    if ins.depth > out[key][1].depth:
                        out[key][1] = ins

            for succ in func.get_successors(bb.start_ea):
                if state[succ.start_ea] == VISITED:
                    continue
                elif state[succ.start_ea] == UNEXPLORED:
                    magicdfs(succ, state, out)
                else:
                    continue

            state[bb.start_ea] = VISITED

        live = func.get_entry().get_live_params()

        if live is None:
            return None

        func.set_empty_vuln_spots()

        state = {bb.start_ea: UNEXPLORED for bb in func.get_basic_blocks()}
        out: dict[Tuple[int, int], List[Instruction]] = {}
        magicdfs(func.get_entry(), state, out)

        for off, param in out:
            wnd_start = out[(off, param)][0].depth
            wnd_end = out[(off, param)][1].depth
            assert wnd_start is not None and wnd_end is not None

            func.add_vuln_spot((param, off, wnd_start, wnd_end))

        Logger.log().debug("*" * 80)
        return None

    @staticmethod
    def analyzed(func: Function) -> bool:
        return func.vuln_spots is not None
