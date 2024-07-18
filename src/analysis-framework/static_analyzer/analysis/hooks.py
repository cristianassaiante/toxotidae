from __future__ import annotations
from typing import Type

from static_analyzer.analysis import Analysis
from static_analyzer.arch.compute_unit import ComputeUnit
from static_analyzer.code.basic_block import BasicBlock
from static_analyzer.code.function import Function
from static_analyzer.code.instruction import Instruction
from static_analyzer.logger import Logger


class HooksFinder(Analysis):
    @staticmethod
    def __find_hooks_per_param(
        func: Function, param: int, compute_unit: Type[ComputeUnit]
    ) -> set[Instruction]:
        hooks = set()

        dominators = func.get_dominators()

        def deepen(bb: BasicBlock) -> Instruction:
            inss = bb.get_instructions()
            live_args_state = [ins.get_live_params_states() for ins in inss]
            for i in range(0, len(inss) - 1):
                # NOTE: this check is needed for those cases where the parameter is used multiple times
                # upon errors of the first usage (e.g., lstrcmp in kernelbase calls multiple times an 
                # internal compare function). In these cases a (usually) register copy is kept live
                # and a vulnerable memory copy is used thus the deepen function hooks the register
                # copy with fake value after the call. TLDR: limit at calls
                if compute_unit.is_call_mem(func, inss[i]) or (
                    param in live_args_state[i] and not param in live_args_state[i + 1]
                ):
                    if compute_unit.is_hookable(func, inss[i]):
                        return inss[i]
                    return inss[i - 1]
            return inss[-1]

        def red(hooks: set[BasicBlock]) -> None:
            changes = True
            while changes:
                changes = False

                for bb in func.get_dfs_nodes():
                    if bb not in hooks:
                        continue

                    succs = len(func.get_successors(bb.start_ea))
                    cnt = sum(
                        [
                            1
                            for bb_succ in func.get_successors(bb.start_ea)
                            if bb_succ in hooks
                        ]
                    )
                    if succs and cnt == succs:
                        hooks.remove(bb)
                        changes = True

        def recur(bb: BasicBlock) -> BasicBlock:
            if param not in bb.get_live_params_states():  # type: ignore
                return recur(func.get_basic_block(dominators[bb.start_ea]))
            return bb

        hooks = set()
        for bb in func.get_basic_blocks():
            hooks.add(recur(bb))
        red(hooks)

        return set(deepen(hook) for hook in hooks)

    @staticmethod
    def find_hooks(func: Function, compute_unit: Type[ComputeUnit]) -> None:
        Logger.log().debug("*" * 80)
        Logger.log().debug(f"Computing Hooks Finding {func}")
        Logger.log().debug("*" * 80)

        live = func.get_entry().get_live_params_states()

        if live is None:
            return None

        func.set_empty_hooks()

        for param in live:
            for hook in HooksFinder.__find_hooks_per_param(func, param, compute_unit):
                func.add_hook(hook, param)

        Logger.log().debug("*" * 80)
        return None

    @staticmethod
    def analyzed(func: Function) -> bool:
        return func.hooks is not None and func.params_per_hook is not None
