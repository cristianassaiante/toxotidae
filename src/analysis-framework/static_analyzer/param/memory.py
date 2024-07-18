from __future__ import annotations
from copy import deepcopy
import random
from typing import List, Tuple

from static_analyzer.arch.register import Register
from static_analyzer.param.param import Param


class Memory(Param):
    NONE = -1

    def __init__(
        self,
        state: int,
        base: Register | None,
        index: int | Register | None = None,
        offset: int | None = None,
        scale: int = 1,
        sp: int | None = None,
        id: int | None = None,
        to_ref: Memory | None = None,
    ) -> None:
        super().__init__(state, base)

        self.index = index
        self.offset = offset
        self.scale = scale

        if id is None:
            if to_ref is None:
                id = random.randint(0, 2**16)
            else:
                # NOTE: it may happens that at merge point, two reference to
                # the same mamory have different ids and are dropped by the merge
                # so let's make the id generation dependent on the ref_to id
                # to avoid this issues
                tmp_rnd = random.Random(to_ref.id)
                id = tmp_rnd.randint(0, 2**16)
        
        self.id = id

        self.sp = sp
        self.ref_to = to_ref

    def none(self) -> None:
        self.state = Memory.NONE

    def is_none(self) -> bool:
        return self.state == Memory.NONE

    def update_stack(
        self,
        sp_reg: Register,
        sp: int,
    ) -> None:
        if self.base == sp_reg and self.offset is not None and self.sp is not None:
            self.offset = self.offset + self.sp - sp
            self.sp = sp
        return super().update_stack(sp_reg, sp)

    def is_memory(self) -> bool:
        return True

    def is_value(self) -> bool:
        return False

    def uses(self, reg: Register) -> bool:
        return super().uses(reg) or self.index == reg

    def copy_at_index(self, reg: Register) -> Memory:
        param = deepcopy(self)
        param.index = reg
        param.is_used = False
        return param

    def eq_sp(self, oth: Memory, sp: int, sp_oth: int) -> bool:
        if self.offset is not None and oth.offset is not None:
            return (self.offset + sp) == (oth.offset + sp_oth)
        return False

    def get_refs(self) -> List[Param]:
        if self.ref_to is None:
            return []
        return [self.ref_to] + self.ref_to.get_refs()

    @staticmethod
    def get_memory_params(params: List[Param]) -> List[Memory]:
        return [param for param in params if param.is_memory()]  # type: ignore

    @staticmethod
    def get_aliases(params: List[Param], id: int) -> List[Param]:
        return [param for param in params if param.is_memory() and param.id == id]  # type: ignore

    @staticmethod
    def delete_aliases(params: List[Param], id: int) -> None:
        to_rem = []
        for param in params:
            if param.is_memory() and param.id == id:  # type: ignore
                to_rem.append(param)
        for param in to_rem:
            if param in params:
                params.remove(param)

    @staticmethod
    def delete_xrefs(params: List[Param], par: Param) -> None:
        to_rem = []
        for param in params:
            if not param.is_memory():
                continue
            refs = param.get_refs()
            if par in refs:
                to_rem.append(param)
        for param in to_rem:
            if param in params:
                params.remove(param)

    @staticmethod
    def get_from_memory(
        params: List[Memory],
        mem: Tuple[Register | None, Register | None, int | None, int | None],
    ) -> Memory | None:
        for param in params:
            # param_mem = (param.base, param.index, param.offset, param.scale)
            # let's ignore scale
            param_mem = (param.base, param.index, param.offset, mem[-1])
            if param_mem == mem and param.state != Memory.NONE:
                return param

    @staticmethod
    def get_from_index(params: List[Memory], index: Register) -> List[Memory]:
        return [param for param in params if param.index == index]

    @staticmethod
    def delete_negative_sp(sp_reg: Register, params: List[Param]) -> None:
        to_rem = []
        for param in params:
            if param.is_memory():
                if param.base == sp_reg and param.offset < 0:  # type: ignore
                    to_rem.append(param)

                    # we also remove the references so that if a parameter has
                    # been passed to a function call, due to our conservative approach,
                    # it wont be available anymore
                    for ref in param.get_refs():
                        to_rem.append(ref)
        for param in to_rem:
            if param in params:
                Memory.delete_aliases(params, param.id)

    def __str__(self) -> str:
        out = super().__str__()

        if self.index is not None:
            out += f" + {self.index}"
            if self.scale > 1:
                out += f"*{self.scale}"
        if self.offset is not None:
            out += f" + {self.offset}"

        out += f"\t [id: {self.id}]"

        if self.ref_to:
            out += f"\t [ref-to: {self.ref_to.__str__()}]"

        return out

    def __eq__(self, oth: Memory) -> bool:
        eq = super().__eq__(oth)
        eq = eq and self.index == oth.index
        eq = eq and self.offset == oth.offset
        # let's ignore scale for now
        # eq = eq and self.scale == oth.scale
        eq = eq and self.id == oth.id
        return eq

    def __hash__(self) -> int:
        h = hash(self.id) ^ hash(self.index) ^ hash(self.offset)
        return super().__hash__() ^ h
