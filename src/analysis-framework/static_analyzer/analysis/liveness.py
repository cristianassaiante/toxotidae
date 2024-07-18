from __future__ import annotations
from typing import List, Type

from static_analyzer.analysis import Analysis
from static_analyzer.arch.compute_unit import ComputeUnit
from static_analyzer.code.basic_block import BasicBlock
from static_analyzer.code.function import Function
from static_analyzer.logger import Logger
from static_analyzer.param.memory import Memory
from static_analyzer.param.param import Param


class Liveness(Analysis):
    @staticmethod
    def liveness(func: Function, compute_unit: Type[ComputeUnit]) -> None:
        VISITED = 2
        VISITING = 1
        UNEXPLORED = 0

        Logger.log().debug("*" * 80)
        Logger.log().debug(f"Computing Liveness Analysis {func}")
        Logger.log().debug("*" * 80)

        # here we have to compute set of used parameters
        def liveness_analysis(bb: BasicBlock, state: dict[int, int], out):
            state[bb.start_ea] = VISITING
            used = [
                set(compute_unit.get_used(func, ins, ins.get_par_in(), ins.sp))  # type: ignore
                for ins in bb.get_instructions()
            ]

            # we propagate also the sp value when used so that we can check
            # if params are equal even when sp changes
            used = [
                set(map(lambda x: (x, ins.sp), used[i]))
                for i, ins in enumerate(bb.get_instructions())
            ]

            for succ in func.get_successors(bb.start_ea):
                if state[succ.start_ea] == VISITED:
                    succ_liveness = out[succ.start_ea]
                elif state[succ.start_ea] == UNEXPLORED:
                    succ_liveness = liveness_analysis(succ, state, out)
                else:
                    continue

                used[-1] = used[-1].union(succ_liveness[0])

            for i in range(len(used) - 2, -1, -1):
                used[i] = used[i].union(used[i + 1])

            out[bb.start_ea] = used
            state[bb.start_ea] = VISITED
            return used

        # remove basic blocks uncovered by propagation
        to_rem = []
        for bb in func.get_basic_blocks():
            if bb.get_par_in() is None:
                to_rem.append(bb.start_ea)
        for bb in to_rem:
            func.remove_basic_block(bb)

        state = {bb.start_ea: UNEXPLORED for bb in func.get_basic_blocks()}
        out: dict[int, List[List[Param]]] = {}
        liveness_analysis(func.get_entry(), state, out)

        for bb in out:
            instructions = func.get_basic_block(bb).get_instructions()
            for i, used_params in enumerate(out[bb]):
                live = []

                Logger.log().debug(instructions[i])

                for def_param in instructions[i].get_par_in():  # type: ignore
                    # none memory locations are not live
                    if def_param.is_memory() and def_param.state == Memory.NONE:
                        continue

                    for use_param, sp_oth in used_params:  # type: ignore
                        is_sp_def = def_param.base == compute_unit.get_sp()
                        is_sp_use = use_param.base == compute_unit.get_sp()

                        # check if they refer to the same sp offset
                        if is_sp_def and is_sp_use:
                            sp = instructions[i].sp
                            if def_param.eq_sp(use_param, sp, sp_oth):  # type: ignore
                                live.append(def_param)

                        # check if are just equal
                        elif def_param == use_param:
                            live.append(def_param)

                        # check if those refer to the same memory region -> should be good
                        elif (
                            def_param.is_memory()
                            and use_param.is_memory()
                            and def_param.id == use_param.id
                        ):
                            live.append(def_param)

                instructions[i].set_live(list(live))

        Logger.log().debug("*" * 80)
        return None

    @staticmethod
    def analyzed(func: Function) -> bool:
        # probably here is enough to check bbs,  but anyway
        return all(
            map(
                lambda x: x.live is not None,
                [
                    ins
                    for bb in func.get_basic_blocks()
                    for ins in bb.get_instructions()
                ],
            )
        )
