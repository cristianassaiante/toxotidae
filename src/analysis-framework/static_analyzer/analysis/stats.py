from __future__ import annotations

from static_analyzer.analysis import Analysis
from static_analyzer.code.basic_block import BasicBlock
from static_analyzer.code.function import Function
from static_analyzer.logger import Logger


class Stats(Analysis):
    @staticmethod
    def compute(func: Function) -> None:
        Stats.__compute_depth(func)

    @staticmethod
    def __compute_depth(func: Function) -> None:
        VISITED = 2
        VISITING = 1
        UNEXPLORED = 0

        Logger.log().debug("*" * 80)
        Logger.log().debug(f"Computing Depths {func}")
        Logger.log().debug("*" * 80)

        def topotraversedistanceultimate(
            bb: BasicBlock, state: dict[int, int], out: dict[int, int], depth: int
        ) -> None:
            old_val = out[bb.start_ea]
            out[bb.start_ea] = max(depth, out[bb.start_ea])

            if state[bb.start_ea] == VISITED and old_val == out[bb.start_ea]:
                return
            state[bb.start_ea] = VISITING

            for bb_succ in func.get_successors(bb.start_ea):
                if state[bb_succ.start_ea] == VISITING:
                    continue
                else:
                    topotraversedistanceultimate(
                        bb_succ, state, out, depth + len(bb.get_instructions())
                    )

            state[bb.start_ea] = VISITED

        state = {bb.start_ea: UNEXPLORED for bb in func.get_basic_blocks()}
        out = {bb.start_ea: 0 for bb in func.get_basic_blocks()}
        topotraversedistanceultimate(func.get_entry(), state, out, 0)

        for bb_ea in out:
            depth = out[bb_ea]
            bb = func.get_basic_block(bb_ea)
            bb.set_depth(depth)
            for ins in bb.get_instructions():
                ins.set_depth(depth)
                depth += 1

        Logger.log().debug("*" * 80)
        return None

    @staticmethod
    def analyzed(func: Function) -> bool:
        # probably here is enough to check bbs, but anyway
        return all(
            map(
                lambda x: x.depth is not None,
                [
                    ins
                    for bb in func.get_basic_blocks()
                    for ins in bb.get_instructions()
                ],
            )
        )
