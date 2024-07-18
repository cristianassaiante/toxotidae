from __future__ import annotations
import json
from pathlib import Path
import sqlite3
import numpy as np

# import capstone as cs

from static_analyzer.analysis.hooks import HooksFinder
from static_analyzer.analysis.liveness import Liveness
from static_analyzer.analysis.propagation import ParametersPropagation
from static_analyzer.analysis.stats import Stats
from static_analyzer.analysis.vulnspots import VulnSpotsFinder
from static_analyzer.arch.x86.register import X86Register
from static_analyzer.arch.x86.utils import X86Utils
from static_analyzer.code.basic_block import BasicBlock
from static_analyzer.code.dll import DLL
from static_analyzer.code.function import Function
from static_analyzer.traits.vulnerable import Vulnerable
from utils.malapi import api_in_malapi

VISITED = 2
VISITING = 1
UNEXPLORED = 0

from numpy import mean, absolute


def mad(data, axis=None):
    return mean(absolute(data - mean(data, axis)), axis)


# maybe we need to redefine this to compute over linear assembly
def stolencode_depth(
    func: Function, curr: BasicBlock, state, depth, size, recoverable, min_comp=True
):
    state[curr.start_ea] = VISITING

    md = X86Utils.get_disassembler(func.bits)

    for ins in curr.get_instructions():
        ins_dis = X86Utils.disassemble_ins(md, ins.ins_bytes, ins.ea)

        # call instruction
        if ins_dis.mnemonic in X86Utils.call_mnems:
            if len(func.get_entry().get_live_params_states()):
                recoverable[ins.ea] = len(ins.get_live_params_states()) / len(
                    func.get_entry().get_live_params_states()
                )
            state[curr.start_ea] = VISITED
            depth[curr.start_ea] = ins.depth
            return ins.depth, size[curr.start_ea]

        size[curr.start_ea] += len(ins.ins_bytes)

    succs_depth, succs_sizes = [], []
    for succ in func.get_successors(curr.start_ea):
        if state[succ.start_ea] == UNEXPLORED:
            succ_depth, succ_size = stolencode_depth(
                func, succ, state, depth, size, recoverable
            )
        elif state[succ.start_ea] == VISITING:
            continue
        else:
            succ_depth, succ_size = depth[succ.start_ea], size[succ.start_ea]
        succs_sizes.append(succ_size)
        succs_depth.append(succ_depth)

    state[curr.start_ea] = VISITED
    if min_comp:
        depth[curr.start_ea] = (
            min(succs_depth) if len(succs_depth) else curr.get_instructions()[-1].depth
        )
    else:
        depth[curr.start_ea] = (
            sum(succs_depth) / len(succs_depth)
            if len(succs_depth)
            else curr.get_instructions()[-1].depth
        )
    size[curr.start_ea] += sum(succs_sizes)
    return depth[curr.start_ea], size[curr.start_ea]


class AnalysisStats:
    def __init__(self, dll: DLL):
        self.dll = dll

        self.analyzed: int = 0
        self.analyzed_with_live: int = 0

        self.redirecting = 0

    def compute(self):
        assert all([ParametersPropagation.analyzed(api) for api in self.dll.apis])
        assert all([Liveness.analyzed(api) for api in self.dll.apis])

        for api in self.dll.apis:
            self.analyzed += 1
            if len(api.get_entry().get_live_params()) > 0:  # type: ignore
                self.analyzed_with_live += 1
            if api.is_redirecting:
                self.redirecting += 1

    # print in json format
    def __str__(self):
        out = f"{{\n"
        out += f'\t"analyzed_apis" : {self.analyzed},\n'
        out += f'\t"analyzed_apis_live" : {self.analyzed_with_live},\n'
        out += f'\t"redirecting" : {self.redirecting}\n'
        out += "}"
        return out


class DefensiveStats:
    def __init__(self, dll: DLL):
        self.dll = dll

        self.avg_bb: float = 0
        self.avg_depth: float = 0
        self.avg_live_params: float = 0
        self.avg_hooks: float = 0
        self.avg_wei_hooks: float = 0
        self.avg_hooks_depth: float = 0

        self.avg_hooks_per_arg: float = 0

    def compute(self):
        assert all([Stats.analyzed(api) for api in self.dll.apis])
        assert all([ParametersPropagation.analyzed(api) for api in self.dll.apis])
        assert all([Liveness.analyzed(api) for api in self.dll.apis])
        assert all([HooksFinder.analyzed(api) for api in self.dll.apis])

        total_bb = 0
        total_depth = 0
        total_hooks = 0
        total_hooks_depth = 0
        total_live_params = 0

        total_api = 0

        avg_hooks_list = []
        weights = []

        total_avg_per_arg = 0

        for api in self.dll.apis:
            if not len(api.get_entry().get_live_params()) > 0:  # type: ignore
                continue

            total_api += 1

            total_bb += len(api.basic_blocks)

            depth = max([bb.get_instructions()[-1].depth for bb in api.get_basic_blocks()])  # type: ignore
            total_depth += depth

            total_hooks += len(api.hooks)  # type: ignore

            total_live_params += len(api.get_entry().get_live_params_states())

            total_hooks_depth += sum([hook.depth for hook in api.hooks]) / len(api.hooks)  # type: ignore

            avg_hooks_list.append(len(api.hooks))
            weights.append(len(api.get_entry().get_live_params()))

            total_avg_per_arg += len(api.hooks) / len(api.get_entry().get_live_params())

        self.avg_bb = total_bb / total_api if total_api else 0
        self.avg_depth = total_depth / total_api if total_api else 0
        self.avg_live_params = total_live_params / total_api if total_api else 0
        self.avg_hooks = total_hooks / total_api if total_api else 0
        self.avg_hooks_per_arg = total_avg_per_arg / total_api if total_api else 0
        self.avg_wei_hooks = (
            np.average(avg_hooks_list, weights=weights) if total_api else 0
        )
        self.avg_hooks_depth = total_hooks_depth / total_api if total_api else 0

    # print in json format
    def __str__(self):
        out = f"{{\n"
        out += f'\t"avg_bb" : {self.avg_bb:.4f},\n'
        out += f'\t"avg_depth" : {self.avg_depth:.4f},\n'
        out += f'\t"avg_live_params": {self.avg_live_params}, \n'
        out += f'\t"avg_hooks" : {self.avg_hooks:.4f},\n'
        out += f'\t"avg_wei_hooks" : {self.avg_wei_hooks:.4f},\n'
        out += f'\t"avg_hooks_per_arg" : {self.avg_hooks_per_arg:.4f},\n'
        out += f'\t"avg_hooks_depth" : {self.avg_hooks_depth:.4f}\n'
        out += "}"
        return out


class TocTouStats:
    def __init__(self, dll: DLL):
        self.dll = dll

        self.vulnerable: int = 0
        self.avg_vuln_args: float = 0
        self.avg_wnd_length: float = 0
        self.avg_depth: float = 0

        self.entry: float = 0
        self.area: float = 0
        self.local: float = 0

        self.regs: float = 0
        self.stack: float = 0

    def compute(self):
        assert all([Stats.analyzed(api) for api in self.dll.apis])
        assert all([ParametersPropagation.analyzed(api) for api in self.dll.apis])
        assert all([Liveness.analyzed(api) for api in self.dll.apis])
        assert all([HooksFinder.analyzed(api) for api in self.dll.apis])
        assert all([VulnSpotsFinder.analyzed(api) for api in self.dll.apis])

        total_avg_args = 0
        total_avg_wnd_length = 0
        total_avg_depth = 0

        total_entry = 0
        total_area = 0
        total_local = 0
        total_params = 0

        total_regs = 0
        total_stack = 0

        for api in self.dll.apis:
            if not len(api.vuln_spots) > 0:  # type: ignore
                continue

            if (
                api.is_redirecting
            ):  #  and not min(map(lambda x: x[0], api.vuln_spots)) < 4:
                continue

            # this means no vuln spot available
            if all(map(lambda x: x[3] < Vulnerable.THRESHOLD, api.vuln_spots)):
                continue

            nargs = len(api.get_entry().get_par_in())

            vuln_spots = list(
                filter(lambda x: x[3] >= Vulnerable.THRESHOLD, api.vuln_spots),
            )

            vuln_args = set()
            avg_wnd_length = 0
            avg_depth = 0
            for param, offset, wnd_start, wnd_end in vuln_spots:
                vuln_args.add(param)
                total_params += 1

                if self.dll.bits == 64:
                    if offset < 0:
                        total_local += 1
                    else:
                        if param < 4 and (8 <= offset <= 32):
                            total_area += 1
                        else:
                            total_entry += 1
                else:
                    if offset < 0:
                        total_local += 1
                    else:
                        total_entry += 1

                avg_wnd_length += wnd_end - wnd_start
                avg_depth += wnd_end

            regs = 0
            stack = 0
            for arg in vuln_args:
                if arg < 4 and self.dll.bits == 64:
                    regs += 1
                else:
                    stack += 1

            # if regs > 0 and len(api.get_entry().get_live_params()) < 4:
            #     print(api.name)

            total_regs += regs / nargs
            total_stack += stack / nargs

            total_avg_args += len(vuln_args) / len(api.get_entry().get_par_in())  # type: ignore
            total_avg_wnd_length += avg_wnd_length / len(vuln_spots)
            total_avg_depth += avg_depth / len(vuln_spots)

            self.vulnerable += 1

        self.avg_vuln_args = total_avg_args / self.vulnerable if self.vulnerable else 0
        self.avg_wnd_length = (
            total_avg_wnd_length / self.vulnerable if self.vulnerable else 0
        )
        self.avg_depth = total_avg_depth / self.vulnerable if self.vulnerable else 0

        self.entry = total_entry / total_params if total_params else 0
        self.area = total_area / total_params if total_params else 0
        self.local = total_local / total_params if total_params else 0

        self.regs = (
            total_regs / self.vulnerable / self.avg_vuln_args if self.vulnerable else 0
        )
        self.stack = (
            total_stack / self.vulnerable / self.avg_vuln_args if self.vulnerable else 0
        )

    # print in json format
    def __str__(self):
        out = f"{{\n"
        out += f'\t"vulnerable_apis" : {self.vulnerable},\n'
        out += f'\t"avg_vuln_args" : {self.avg_vuln_args},\n'
        out += f'\t"avg_wnd_length" : {self.avg_wnd_length},\n'
        out += f'\t"avg_depth" : {self.avg_depth},\n'
        out += f'\t"perc_regs" : {self.regs},\n'
        out += f'\t"perc_stack" : {self.stack},\n'
        out += f'\t"entry_location" : {self.entry},\n'
        out += f'\t"registers_area" : {self.area},\n'
        out += f'\t"local_variables" : {self.local}\n'
        out += "}"
        return out


class StolenCodeStats:
    def __init__(self, dll: DLL):
        self.dll = dll

        self.total: int = 0

        self.avg_depth_min: float = 0
        self.avg_depth_avg: float = 0

        self.std_min: float = 0
        self.std_avg: float = 0

        self.avg_entry: float = 0

        self.over_branch: int = 0

        self.recoverability: float = 0
        # self.single_bbs: float = 0

    def compute(self):
        assert all([Stats.analyzed(api) for api in self.dll.apis])
        assert all([ParametersPropagation.analyzed(api) for api in self.dll.apis])
        assert all([Liveness.analyzed(api) for api in self.dll.apis])
        assert all([HooksFinder.analyzed(api) for api in self.dll.apis])
        assert all([VulnSpotsFinder.analyzed(api) for api in self.dll.apis])

        total_entry_length = 0
        total_full_depth_min = 0
        total_full_depth_avg = 0

        # total_full_size = 0

        # total_bb = 0

        total_api = 0

        depth_list_min = []
        depth_list_avg = []

        recoverable = {}

        for api in self.dll.apis:
            n_ins = sum([len(bb.get_instructions()) for bb in api.get_basic_blocks()])
            if n_ins < 10:  # FIXED LIMIT!
                continue

            total_entry_length += len(api.get_entry().get_instructions())

            state = {bb: UNEXPLORED for bb in api.basic_blocks}
            depth = {bb: -1 for bb in api.basic_blocks}
            size = {bb: 0 for bb in api.basic_blocks}
            stolencode_depth(api, api.get_entry(), state, depth, size, recoverable)

            total_full_depth_min += depth[api.get_entry().start_ea]

            depth_list_min.append(depth[api.get_entry().start_ea])

            state = {bb: UNEXPLORED for bb in api.basic_blocks}
            depth = {bb: -1 for bb in api.basic_blocks}
            size = {bb: 0 for bb in api.basic_blocks}
            stolencode_depth(api, api.get_entry(), state, depth, size, {}, False)

            total_full_depth_avg += depth[api.get_entry().start_ea]

            depth_list_avg.append(depth[api.get_entry().start_ea])

            total_api += 1

            if (
                depth[api.get_entry().start_ea]
                > api.get_entry().get_instructions()[-1].depth
            ):
                self.over_branch += 1
                # total_bb += len(api.basic_blocks)

        self.avg_entry = total_entry_length / total_api if total_api else 0
        self.avg_depth_min = total_full_depth_min / total_api if total_api else 0
        self.avg_depth_avg = total_full_depth_avg / total_api if total_api else 0
        # self.avg_bytes = total_full_size / total_api if total_api else 0

        # self.single_bbs = total_bb / self.single if self.single else 0

        self.std_min = mad(depth_list_min) if total_api else 0
        self.std_avg = mad(depth_list_avg) if total_api else 0

        self.total = total_api

        self.recoverability = (
            sum(recoverable.values()) / len(recoverable) if len(recoverable) else 0
        )

    # print in json format
    def __str__(self):
        out = f"{{\n"
        out += f'\t"total" : {self.total},\n'
        out += f'\t"avg_depth_min" : {self.avg_depth_min},\n'
        out += f'\t"avg_depth_avg" : {self.avg_depth_avg},\n'
        out += f'\t"std_min" : {self.std_min},\n'
        out += f'\t"std_avg" : {self.std_avg},\n'
        out += f'\t"avg_entry" : {self.avg_entry},\n'
        # out += f'\t"avg_bytes" : {self.avg_bytes}\n'
        out += f'\t"recoverability" : {self.recoverability},\n'
        out += f'\t"over_branch" : {self.over_branch}\n'
        # out += f'\t"avg_single_size" : {self.single_bbs}\n'
        out += "}"
        return out


class VulnerableAPIStats:
    GET_ARGS = "select Id,Name,TypeId,TypeClass,IsOutput from FunctionsArgs where FuncId in (select F.Id from Functions as F,Modules as M,ModulesFuncs as MF where F.Id == MF.FuncId and M.Id = MF.ModId and F.Name like '{}');"

    # Constants in the deviare32 db from https://github.com/Cisco-Talos/pyrebox/blob/master/mw_monitor/DeviareDbParser.py
    FUND_MAPPING = {
        1: "SignedByte",
        2: "UnsignedByte",
        3: "SignedWord",
        4: "UnsignedWord",
        5: "SignedDoubleWord",
        6: "UnsignedDoubleWord",
        7: "SignedQuadWord",
        8: "UnsignedQuadWord",
        9: "Float",
        10: "Double",
        11: "LongDouble",
        12: "Void",
        13: "AnsiChar",
        14: "WideChar",
    }

    TYPE_MAPPING = {
        0: "Fundamental",
        1: "Struct",
        2: "Union",
        3: "Typedef",
        4: "Array",
        5: "Pointer",
        6: "Reference",
        7: "Enumeration",
    }

    def __init__(self, dll: DLL):
        self.dll = dll

        self.total_types_args = 0
        self.total_types_api = 0
        self.classes = {}
        self.fund = {}
        self.output_args = 0

        self.avg_depth: float = 0
        self.avg_hooks_depth: float = 0
        self.avg_stolencode_depth_min: float = 0
        self.avg_stolencode_depth_avg: float = 0
        self.avg_toctou_depth: float = 0

        script_path = Path(__file__).absolute()
        self.con = sqlite3.connect(
            script_path.__str__()[:-12] + "deviare32_populated.sqlite"
        )

    def compute(self):
        assert all([Stats.analyzed(api) for api in self.dll.apis])
        assert all([ParametersPropagation.analyzed(api) for api in self.dll.apis])
        assert all([Liveness.analyzed(api) for api in self.dll.apis])
        assert all([HooksFinder.analyzed(api) for api in self.dll.apis])
        assert all([VulnSpotsFinder.analyzed(api) for api in self.dll.apis])

        total_depth = 0
        total_hooks_depth = 0
        total_avg_depth = 0
        total_full_depth_min = 0
        total_full_depth_avg = 0

        total_api = 0

        for api in self.dll.apis:
            if not len(api.vuln_spots) > 0:  # type: ignore
                continue

            # for consistency with the stolen code depth, avoid api with less than 10 instructions?
            n_ins = sum([len(bb.get_instructions()) for bb in api.get_basic_blocks()])
            if n_ins < 10:  # FIXED LIMIT!
                continue
            if (
                api.is_redirecting
            ):  #  and not min(map(lambda x: x[0], api.vuln_spots)) < 4:
                continue

            # this means no vuln spot available
            if all(map(lambda x: x[3] < Vulnerable.THRESHOLD, api.vuln_spots)):
                continue

            # avg depth
            total_api += 1
            depth = max([bb.get_instructions()[-1].depth for bb in api.get_basic_blocks()])  # type: ignore
            total_depth += depth

            # avg toctou depth and hooks
            vuln_spots = list(
                filter(lambda x: x[3] >= Vulnerable.THRESHOLD, api.vuln_spots),
            )

            avg_depth = 0
            deepest_hook_per_arg = {}
            for param, _, _, wnd_end in vuln_spots:
                avg_depth += wnd_end

                # avg hooks depth
                if param not in deepest_hook_per_arg:
                    deepest_hook_per_arg[param] = 0

                for hook_ea in api.params_per_hook[param]:
                    for hook in api.hooks:
                        if hook_ea == hook.ea:
                            deepest_hook_per_arg[param] = max(
                                deepest_hook_per_arg[param], hook.depth
                            )

            total_hooks_depth += sum(deepest_hook_per_arg.values()) / len(
                deepest_hook_per_arg
            )

            total_avg_depth += avg_depth / len(vuln_spots)

            # avg stolencode depth
            state = {bb: UNEXPLORED for bb in api.basic_blocks}
            depth = {bb: -1 for bb in api.basic_blocks}
            size = {bb: 0 for bb in api.basic_blocks}
            recoverable = {}
            stolencode_depth(api, api.get_entry(), state, depth, size, recoverable)

            total_full_depth_min += depth[api.get_entry().start_ea]

            state = {bb: UNEXPLORED for bb in api.basic_blocks}
            depth = {bb: -1 for bb in api.basic_blocks}
            size = {bb: 0 for bb in api.basic_blocks}
            stolencode_depth(api, api.get_entry(), state, depth, size, {}, False)

            total_full_depth_avg += depth[api.get_entry().start_ea]

            # types stuff
            vuln_params = list(map(lambda x: x[0], vuln_spots))
            res = self.con.execute(
                VulnerableAPIStats.GET_ARGS.format(api.name)
            ).fetchall()
            if len(res):
                for idx, _, typeid, typeclass, isoutput in res:
                    if (idx - 1) not in vuln_params:
                        continue

                    # FIX - We need to correct the arg_class, because it seems that the db has some errors
                    # from https://github.com/Cisco-Talos/pyrebox/blob/75aca6ee6d9cb3bec32bfaf96ff8205dbba0de3b/mw_monitor/DeviareDbParser.py#L835
                    while typeclass >= 65536:
                        typeclass -= 65536

                    typeclass = VulnerableAPIStats.TYPE_MAPPING[typeclass]
                    if typeclass not in self.classes:
                        self.classes[typeclass] = 0
                    self.classes[typeclass] += 1

                    if typeclass == "Fundamental":
                        typeid = VulnerableAPIStats.FUND_MAPPING[typeid]
                        if typeid not in self.fund:
                            self.fund[typeid] = 0
                        self.fund[typeid] += 1

                    if isoutput:
                        self.output_args += 1

                    self.total_types_args += 1
                self.total_types_api += 1

        self.con.close()

        self.avg_depth = total_depth / total_api if total_api else 0
        self.avg_hooks_depth = total_hooks_depth / total_api if total_api else 0
        self.avg_stolencode_depth_min = (
            total_full_depth_min / total_api if total_api else 0
        )
        self.avg_stolencode_depth_avg = (
            total_full_depth_avg / total_api if total_api else 0
        )
        self.avg_toctou_depth = total_avg_depth / total_api if total_api else 0

    # print in json format
    def __str__(self):
        out = f"{{\n"
        out += f'\t"types" : {{\n'
        out += f'\t\t"analyzed": {self.total_types_api},\n'
        out += f'\t\t"args": {self.total_types_args},\n'
        out += f'\t\t"classes": {json.dumps(self.classes)},\n'
        out += f'\t\t"fund" : {json.dumps(self.fund)},\n'
        out += f'\t\t"output" : {self.output_args}\n'
        out += "\t},\n"
        out += f'\t"avg_depth" : {self.avg_depth},\n'
        out += f'\t"avg_hooks_depth" : {self.avg_hooks_depth},\n'
        out += f'\t"avg_stolencode_depth_min" : {self.avg_stolencode_depth_min},\n'
        out += f'\t"avg_stolencode_depth_avg" : {self.avg_stolencode_depth_avg},\n'
        out += f'\t"avg_toctou_depth" : {self.avg_toctou_depth}\n'
        out += "}"
        return out


class NonVulnerableAPIStats:
    def __init__(self, dll: DLL):
        self.dll = dll

        self.single_block: int = 0
        self.unused_stack: int = 0
        self.short_window: int = 0
        self.avg_bbs: float = 0

    def compute(self):
        assert all([Stats.analyzed(api) for api in self.dll.apis])
        assert all([ParametersPropagation.analyzed(api) for api in self.dll.apis])
        assert all([Liveness.analyzed(api) for api in self.dll.apis])
        assert all([HooksFinder.analyzed(api) for api in self.dll.apis])
        assert all([VulnSpotsFinder.analyzed(api) for api in self.dll.apis])

        total_api = 0

        for api in self.dll.apis:
            if not len(api.get_entry().get_live_params()) > 0:  # type: ignore
                continue

            if len(api.vuln_spots) > 0:  # type: ignore
                # this means no vuln spot available
                if not all(map(lambda x: x[3] < Vulnerable.THRESHOLD, api.vuln_spots)):
                    continue

            if len(api.vuln_spots) > 0 and all(
                map(lambda x: x[3] < Vulnerable.THRESHOLD, api.vuln_spots)
            ):
                self.short_window += 1

            if len(api.get_basic_blocks()) == 1:
                self.single_block += 1

            is_stack_used = False
            for bb in api.get_basic_blocks():
                for ins in bb.get_instructions():
                    for live in ins.get_live_params():
                        if live.is_memory() and live.base == X86Register.R_SP:
                            is_stack_used = True
            if not is_stack_used:
                self.unused_stack += 1

            self.avg_bbs += len(api.get_basic_blocks())
            total_api += 1

        self.avg_bbs = self.avg_bbs / total_api if total_api else 0

    # print in json format
    def __str__(self):
        out = f"{{\n"
        out += f'\t"single_block" : {self.single_block},\n'
        out += f'\t"avg_bbs" : {self.avg_bbs},\n'
        out += f'\t"short_window" : {self.short_window},\n'
        out += f'\t"unused_stack" : {self.unused_stack}\n'
        out += "}"
        return out
