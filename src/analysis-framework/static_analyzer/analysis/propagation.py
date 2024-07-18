from __future__ import annotations
from typing import Type

from static_analyzer.analysis import Analysis
from static_analyzer.arch.compute_unit import ComputeUnit
from static_analyzer.code.function import Function
from static_analyzer.logger import Logger


class ParametersPropagation(Analysis):
    @staticmethod
    def propagate(func: Function, compute_unit: Type[ComputeUnit]) -> None:
        Logger.log().debug("*" * 80)
        Logger.log().debug(f"Computing Parameters Propagation {func}")
        Logger.log().debug("*" * 80)

        entry_bb = func.get_entry().start_ea
        W = [entry_bb]

        while len(W) > 0:
            v = W.pop()

            Logger.log().debug("=" * 80)
            Logger.log().debug(f"Computing {func.get_basic_block(v)}")
            Logger.log().debug("=" * 80)

            I = [
                v_pred.get_par_out()
                for v_pred in func.get_predecessors(v)
                if v_pred.get_par_out() is not None
            ]

            if len(I) > 0:
                Logger.log().debug(f"Merging from {len(I)} predecessors")
                new_in = compute_unit.merge(I, func.get_basic_block(v))  # type: ignore

                if func.get_basic_block(v).get_par_in() == new_in:
                    continue

                func.get_basic_block(v).set_par_in(new_in)

            old_out = func.get_basic_block(v).get_par_out()
            new_out = compute_unit.compute(func, func.get_basic_block(v))

            if old_out != new_out:
                for v_succ in func.get_successors(v):
                    W.append(v_succ.start_ea)

            Logger.log().debug("=" * 80)

        Logger.log().debug("*" * 80)

    @staticmethod
    def analyzed(func: Function) -> bool:
        return all(
            map(
                lambda x: x.get_par_in() is not None and x.get_par_out() is not None,
                [bb for bb in func.get_basic_blocks()],
            )
        )
