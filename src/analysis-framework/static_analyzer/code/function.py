from __future__ import annotations
import networkx as nx
import pickle
from typing import Dict, List

from static_analyzer.arch.calling_convention import CallingConventionManager
from static_analyzer.code.basic_block import BasicBlock
from static_analyzer.param.param import Param
from static_analyzer.traits.dumpable import Dumpable
from static_analyzer.traits.hooks import Hooks
from static_analyzer.traits.vulnerable import Vulnerable


class Function(Dumpable, Hooks, Vulnerable):
    def __init__(self, start_ea: int, name: str, bits: int) -> None:
        Hooks.__init__(self)
        Vulnerable.__init__(self)

        self.start_ea = start_ea
        self.name = name

        self.bits = bits

        self.cfg = nx.DiGraph()
        self.basic_blocks: Dict[int, BasicBlock] = {}

        self.calling_convention: CallingConventionManager | None = None

        self.is_redirecting: bool = False

    def get_parameters(self) -> List[Param] | None:
        return self.get_entry().get_instructions()[0].par_in

    def add_parameters(self, params: List[Param]) -> None:
        self.get_entry().get_instructions()[0].par_in = params

    def set_is_redirecting(self) -> None:
        self.is_redirecting = True

    def get_entry(self) -> BasicBlock:
        entries = []
        for bb in self.cfg.nodes:
            if not len(self.get_predecessors(bb)):
                entries.append(bb)
        assert len(entries) == 1, "CFG should have only one entry node"
        return self.basic_blocks[entries[0]]

    def get_exits(self) -> List[BasicBlock]:
        exits = []
        for bb in self.cfg.nodes:
            if not len(self.get_successors(bb)):
                exits.append(bb)
        return [self.basic_blocks[bb] for bb in exits]

    def get_basic_blocks(self) -> List[BasicBlock]:
        return list(self.basic_blocks.values())

    def get_basic_block(self, ea: int) -> BasicBlock:
        return self.basic_blocks[ea]

    def add_basic_block(self, bb: BasicBlock) -> None:
        self.cfg.add_node(bb.start_ea)
        self.basic_blocks[bb.start_ea] = bb

    def remove_basic_block(self, bb: int) -> None:
        self.cfg.remove_node(bb)
        self.basic_blocks.pop(bb)

    def add_edge(self, bb_src_ea: int, bb_dst_ea: int) -> None:
        self.cfg.add_edge(bb_src_ea, bb_dst_ea)

    def cleanup(self) -> None:
        to_rem = []

        for bb in self.get_basic_blocks():
            len_succ = len(self.get_successors(bb.start_ea))
            len_pred = len(self.get_predecessors(bb.start_ea))

            if not len_succ and not len_pred and bb.start_ea != self.start_ea:
                to_rem.append(bb.start_ea)
            elif not len_pred and bb.start_ea != self.start_ea:
                to_rem.append(bb.start_ea)

        if not to_rem:
            return

        for bb in to_rem:
            self.remove_basic_block(bb)

        self.cleanup()

    def get_successors(self, bb: int) -> List[BasicBlock]:
        return [self.basic_blocks[s] for s in self.cfg.successors(bb)]

    def get_predecessors(self, bb: int) -> List[BasicBlock]:
        return [self.basic_blocks[p] for p in self.cfg.predecessors(bb)]

    def get_dominators(self) -> Dict[int, int]:
        return nx.immediate_dominators(self.cfg, self.get_entry().start_ea)

    def get_dominance_frontier(self) -> Dict[int, set[int]]:
        return nx.dominance.dominance_frontiers(self.cfg, self.get_entry().start_ea)

    def get_dfs_nodes(self) -> List[BasicBlock]:
        return [
            self.get_basic_block(bb)
            for bb in nx.dfs_preorder_nodes(self.cfg, self.get_entry().start_ea)
        ]

    def draw(self) -> None:
        import matplotlib.pyplot as plt
        import networkx as nx
        from networkx.drawing.nx_pydot import graphviz_layout

        pos = nx.nx_agraph.graphviz_layout(self.cfg, prog="twopi")
        nx.draw(self.cfg, pos)
        plt.show()

    def __str__(self) -> str:
        out = f"{self.name}@{hex(self.start_ea)}"
        # for node in self.get_basic_blocks():
        #     out += node.__str__()
        return out

    @staticmethod
    def load(fin: str) -> Function:
        with open(fin, "rb") as f:
            return pickle.load(f)
