#!/usr/bin/env python3

from glob import glob
from sys import argv

from static_analyzer.code.dll import DLL
from static_analyzer.arch.x86.register import *

stats = {}

reg_map = {
    "A": "r-a",
    "B": "r-c",
    "C": "r-d",
    "D": "r-b",
    "E": "r-sp",
    "F": "r-bp",
    "G": "r-si",
    "H": "r-di",
    "I": "r-8",
    "J": "r-9",
    "K": "r-10",
    "L": "r-11",
    "M": "r-12",
    "N": "r-13",
    "O": "r-14",
    "P": "r-15",
    "Q": "r-xmm0",
    "R": "r-xmm1",
    "S": "r-xmm2",
    "T": "r-xmm3",
    "U": "r-xmm4",
    "V": "r-xmm5",
    "W": "r-xmm6",
    "X": "r-xmm7",
    "Y": "r-xmm8",
    "Z": "r-xmm9",
    "a": "r-xmm10",
    "b": "r-xmm11",
    "c": "r-xmm12",
    "d": "r-xmm13",
    "e": "r-xmm14",
    "f": "r-xmm15",
    "g": "r-ip",
}


def get_reg(val):
    for key, value in reg_map.items():
        if val == value:
            return key
    return None


for dll in glob(argv[1] + "/*"):
    dll: DLL = DLL.load(dll)

    with open(f"hooks/{dll.bits}bit/{dll.name}.hooks", "w") as f:
        for api in dll.apis:
            add_entry = False
            entry = api.get_entry().get_instructions()[0]
            if entry.ea not in list(map(lambda x: x.ea, api.hooks)):
                add_entry = True

            nhooks = len(api.hooks)
            if add_entry:
                nhooks += 1

            f.write(f"{api.name} {nhooks}\n")
            for hook in api.hooks:

                params = set()
                if hook.ea == api.start_ea:
                    params = hook.get_live_params_states()
                else:
                    for param in api.params_per_hook:
                        if hook.ea in api.params_per_hook[param]:
                            params.add(param)

                locs = []
                mems = []
                for live in hook.get_live_params():
                    if live.state in params and live.is_value():
                        locs.append((get_reg(live.base.__str__()), live.state))
                    elif (
                        live.state in params
                        and live.is_memory()
                        and live.offset != None
                        and len(live.get_refs()) == 0
                    ):
                        mems.append(
                            (
                                (get_reg(live.base.__str__()), live.offset, live.state),
                                live.id,
                            )
                        )

                mems_for_id = {}
                for mem in mems:
                    if mem[1] not in mems_for_id:
                        mems_for_id[mem[1]] = []
                    mems_for_id[mem[1]].append(mem[0])
                for id, mems in mems_for_id.items():
                    if len(mems) > 1:
                        found = False
                        for mem in mems:
                            if mem[0] == "E":
                                locs.append((f"{mem[0]}|{mem[1]}", mem[2]))
                                found = True
                                break
                        if not found:
                            for mem in mems:
                                locs.append((f"{mem[0]}|{mem[1]}", mem[2]))
                    else:
                        locs.append((f"{mems[0][0]}|{mems[0][1]}", mems[0][2]))

                f.write(f"{hook.ea} {len(locs)} {-hook.sp}\n")
                for key, state in locs:
                    f.write(f"{key} {state}\n")

            if add_entry:
                f.write(f"{entry.ea} {len(entry.get_live_params())} {entry.sp}\n")
                for param in entry.get_live_params():
                    if param.is_memory():
                        key = f"{get_reg(param.base.__str__())}|{param.offset}"
                    else:
                        key = get_reg(param.base.__str__())
                    f.write(f"{key} {param.state}\n")
