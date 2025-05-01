import logging
from typing import List

import angr.analyses.analysis
from angr.knowledge_plugins import CFGManager
from angr.knowledge_plugins import FunctionManager
from termcolor import colored

from util import graph
from util.graph import SuperCFGNode

logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.ERROR)
logging.getLogger('angr.sim_manager').setLevel(logging.ERROR)
logging.getLogger('angr').setLevel(logging.ERROR)


# Powered by HAPPY

class Analyzer:

    def __init__(self, filename):
        # self.super_graph: networkx.DiGraph
        self.filename: str = filename
        self.base_addr = 0

    def _load_to_angr(self, start_addr: int):
        """

        :param start_addr: start address without base
        :return:
        """
        project = angr.Project(self.filename,
                               load_options={'auto_load_libs': False, 'main_opts': {'base_addr': 0}}, )
        # do normalize to avoid overlapping blocks, disable force_complete_scan to avoid possible "wrong" blocks
        # angr.analysis.Analyses

        cfg: CFGManager = project.analyses.CFGFast(normalize=True, force_complete_scan=False,
                                                   function_starts=[start_addr])
        # cfg: CFGManager = project.analyses.CFGEmulated(context_sensitivity_level=3, keep_state=True)
        # target_function = cfg.functions.get(start)

        self.base_addr = project.loader.main_object.mapped_base >> 12 << 12
        print(f"base addr : {hex(self.base_addr)}")
        if start_addr > self.base_addr:
            print(colored(
                '''
                [WARNING] start address is higher than base address. 
                Check if the start address has stripped the base address.
                ''', 'yellow'))
        start_addr += self.base_addr

        target_function: FunctionManager = cfg.functions.get(start_addr)

        if target_function is None:
            print(colored(f"fail to find function at {hex(start_addr)}, now try blocks analysis", 'yellow'))
            exit(0)

        super_graph = graph.to_supergraph(target_function.transition_graph)
        return super_graph


class DeflatAnalyzer(Analyzer):
    prologue_node: SuperCFGNode
    return_nodes: List[SuperCFGNode]
    relevant_nodes: List[SuperCFGNode]
    irrelevant_nodes: List[SuperCFGNode]
    real_nodes: List[SuperCFGNode]  # deprecate
    main_dispatcher_node: SuperCFGNode
    filename: str
    logger: logging
    highest_address_boundary: int  # the end of the function

    manual_trampoline_addr_list: List[int]

    def add_trampoline_addr(self, trampoline_addr):
        self.manual_trampoline_addr_list.append(trampoline_addr)

    def __init__(self, filename):
        super(DeflatAnalyzer, self).__init__(filename)
        self.filename = filename
        self.relevant_nodes = []
        self.return_nodes = []
        self.real_nodes = []
        self.irrelevant_nodes = []
        self.manual_trampoline_addr_list = []
        self.highest_address_boundary = 0

        logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        # self.start_addr = 0

    def get_relevant_nodes(self, super_graph, node, founded_node):
        branch_nodes = list(super_graph.successors(node))

        has_found_branch_node = False
        for node_idx in range(len(branch_nodes)):
            if branch_nodes[node_idx] in founded_node:
                has_found_branch_node = True
        # and branch_nodes[0] in founded_node
        if len(branch_nodes) == 1 and has_found_branch_node:
            if node in self.relevant_nodes:
                for i in super_graph.predecessors(node):
                    # fix circle blocks
                    has_circle_blocks = False
                    for r_node in self.relevant_nodes:
                        if r_node.addr == i.addr:
                            has_circle_blocks = True
                    if has_circle_blocks:
                        continue
                    self.relevant_nodes.append(i)
            else:
                self.relevant_nodes.append(node)
        else:
            founded_node.append(node)
            for i in branch_nodes:
                if i not in founded_node:
                    self.get_relevant_nodes(super_graph, i, founded_node)

    def analysis_flatten_blocks(self, start_addr_without_base):
        super_graph = super(DeflatAnalyzer, self)._load_to_angr(start_addr_without_base)
        start_addr = start_addr_without_base
        if start_addr < self.base_addr:
            print(colored("add base address to start address automatically.", 'green'))
            start_addr += self.base_addr

        has_prologue_node = False
        print(f"this function has {len(super_graph.nodes())} nodes.")

        virgin_nodes: List[SuperCFGNode] = []  # to protect the potential real blocks without nop
        for node in super_graph.nodes():
            # print(f"iter node {hex(node.addr)}, to {hex(node.addr + node.size)}")
            if node.addr + node.size > self.highest_address_boundary:
                self.highest_address_boundary = node.addr + node.size
            if super_graph.in_degree(node) == 0:
                if has_prologue_node:
                    logging.warning("multiple has_prologue_node found")
                self.prologue_node = node
                has_prologue_node = True
            if super_graph.out_degree(node) == 0 and len(node.out_branches) == 0:
                self.return_nodes.append(node)
                if len(self.return_nodes) == 1:
                    # overwrite
                    # in case of canary check
                    assert len(list(super_graph.predecessors(node))) == 1
                    assert len(list(super_graph.predecessors(self.return_nodes[0]))) == 1
                    assert list(super_graph.predecessors(self.return_nodes[0]))[0] == \
                           list(super_graph.predecessors(node))[0]

                    # virgin_nodes.append(self.return_nodes[0])
                    # virgin_nodes.append(node)
                    self.return_nodes[0] = list(super_graph.predecessors(self.return_nodes[0]))[0]
                    parent_checker = self.return_nodes[0]
                    for i in list(super_graph.successors(parent_checker)):
                        virgin_nodes.append(i)
                    print(f"virgin nodes {virgin_nodes}")

                    # return_nodes : real return,  parent checker, stack_chk_fail block
                    # self.return_nodes.append(list(super_graph.predecessors(self.return_nodes[0]))[0])
                    # self.return_nodes.append(node)
                    # add here to support more return case

        # print(f"prologue addr {hex(self.prologue_node.addr)}")
        if self.prologue_node is None or self.prologue_node.addr != start_addr:
            raise Exception("Fail to recognize the correct prologue node.")

        self.main_dispatcher_node = list(super_graph.successors(self.prologue_node))[0]

        # for node in super_graph.nodes():
        #     # TODO : add instruction count > 1
        #     if self.main_dispatcher_node in list(super_graph.successors(node)) and node is not self.prologue_node:
        #         self.real_nodes.append(node)

        self.get_relevant_nodes(super_graph, self.main_dispatcher_node, [])
        self.real_nodes = [*self.relevant_nodes, self.main_dispatcher_node, self.prologue_node, *self.return_nodes]

        for node in super_graph.nodes():
            if node not in self.real_nodes and node not in virgin_nodes:
                self.irrelevant_nodes.append(node)
        print(f"irrelevant_nodes: {self.irrelevant_nodes}")

    def show_blocks_info(self, level=0):
        print(f"highest_address_boundary : {hex(self.highest_address_boundary)}")
        print(f"prologue addr {hex(self.prologue_node.addr)} ~ {hex(self.prologue_node.addr + self.prologue_node.size)}")
        print(f"main dispatch node: {hex(self.main_dispatcher_node.addr)}")
        print(f" {len(self.relevant_nodes)} relevant nodes found.")
        print(self.relevant_nodes)
        if level == 0:
            for i in self.relevant_nodes:
                print(f"{hex(i.addr)}, ", end='')
        else:
            print(self.relevant_nodes)

        print(f"\n {len(self.real_nodes)} real nodes found.")
        if level == 0:
            for i in self.real_nodes:
                print(f"{hex(i.addr)}, ", end='')
        else:
            print(self.real_nodes)

        print(f"return block : {hex(self.return_nodes[0].addr)}")


if __name__ == '__main__':
    # load_to_angr('example/lib64_example.so', 0x13C88)
    analyzer = DeflatAnalyzer('example/lib64_example.so')
    analyzer.analysis_flatten_blocks(0x13C88)
    analyzer.show_blocks_info()
