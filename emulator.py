import logging
import queue
from typing import Any
from typing import List
from typing import Tuple
from typing import Union

from capstone import Cs
from elftools.elf.elffile import ELFFile
from qiling import *
from qiling.const import *

from analyzer import DeflatAnalyzer
from arch_util import arm64_util
from arch_util import general_arch_util
from patcher import Patcher
from util.block import Block
from util.block import BlockContainer


# Powered by HAPPY

class DeflatEmu:
    block_container: BlockContainer
    deflat_analyzer: DeflatAnalyzer
    real_blocks: List[int]  # i.e. relevant_nodes in deflat analyzer
    return_blocks: List[int]
    prologue_node_id: int
    main_dispatcher_node_id: int
    emu: 'Emulator'
    filename: str
    md: Cs  # capstone
    base_addr: int
    logger: logging
    highest_address_boundary: int
    verbose_hook = False
    cached_last_instruction_address: int  # to fix the bug of unicorn hook

    arch_type: Union[Tuple[None, None], Any]

    # only for way1
    # cached_instructions_history: Dict[int, int]
    cached_instructions_history: List[int]

    # cached_predecessor_table = {}

    def _fill_node_code(self, node, ql: Qiling):
        # ensure the code length is correct
        if node.cfg_nodes[0].bytestr is not None and len(node.cfg_nodes[0].bytestr) == node.size:
            return

        node.cfg_nodes[0].bytestr = ql.mem.read(node.addr + self.base_addr, node.size)

    def __init__(self, deflat_analyzer, rootfs):
        self.dfs_start_address = 0
        self.dfs_paths = {}
        self.dfs_branch_force = False
        self.dfs_next_addr = -1
        self.dfs_success = False
        self.cached_instructions_history = []
        self.block_container = BlockContainer()
        self.deflat_analyzer = deflat_analyzer
        self.filename = self.deflat_analyzer.filename
        assert self.deflat_analyzer.prologue_node is not None
        self.highest_address_boundary = deflat_analyzer.highest_address_boundary
        self.real_blocks = []
        self.return_blocks = []

        self.rootfs = rootfs

        self.emu = Emulator(self.filename, self.rootfs)
        self.base_addr = self.emu.base_addr

        for real_block in self.deflat_analyzer.relevant_nodes:
            self._fill_node_code(real_block, self.emu.ql)
            self.real_blocks.append(self.block_container.add_cfg_node_to_block(real_block, self.base_addr))
        for return_block in self.deflat_analyzer.return_nodes:
            self._fill_node_code(return_block, self.emu.ql)
            self.return_blocks.append(self.block_container.add_cfg_node_to_block(return_block, self.base_addr))

        self._fill_node_code(deflat_analyzer.prologue_node, self.emu.ql)
        self._fill_node_code(deflat_analyzer.main_dispatcher_node, self.emu.ql)

        self.prologue_node_id = self.block_container.add_cfg_node_to_block(deflat_analyzer.prologue_node,
                                                                           self.base_addr)
        self.main_dispatcher_node_id = self.block_container.add_cfg_node_to_block(deflat_analyzer.main_dispatcher_node,
                                                                                  self.base_addr)

        # trivial stuff
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)

        self.arch_type = self.emu.ql.arch.type

    def _disasm(self, ql: Qiling, address, size):
        if self.md is None:
            self.md = general_arch_util.create_disassembler(ql)
        return next(self.md.disasm(ql.mem.read(address, size), address))

    def _get_reg_operand(self, instruction, index: int):
        # reg_info = op_str.split(',')
        # return reg_info[index].strip()
        return self._get_reg_operands(instruction)[index]

    def _get_reg_operands(self, instruction):
        # reg_info = [reg.strip() for reg in op_str.split(',')]
        # return reg_info
        reg_list = []
        for i in instruction.operands:
            if i.type == general_arch_util.get_op_reg_const(self.emu.ql.arch.type):
                reg_list.append(instruction.reg_name(i.value.reg))
        return reg_list

    def clear_cache(self):
        self.cached_last_instruction_address = -1

    def guide_hook(self, ql: Qiling, addr, size):

        if addr == self.cached_last_instruction_address:
            return
        else:
            self.cached_last_instruction_address = addr

        # self.logger.info(
        #     f"Executing: {hex(addr - self.base_addr)}, relevant : {self.block_container.get_block_id_from_address(addr) in [*self.return_blocks, *self.real_blocks]}")
        # self.logger.info(f"Executing: {hex(addr - self.base_addr)}")

        start_block_id = self.hook_data['start_block']
        # cur_bb = IDA.get_block(addr)
        current_block_id = self.block_container.get_block_id_from_address(addr)

        if addr in self.cached_instructions_history:
            # self.logger.debug(
            #     f"potential fake block {hex(self.block_container.get_block_from_id(current_block_id).start_addr - self.base_addr)} at {hex(addr - self.base_addr)}, skip it.")
            ql.emu_stop()
        self.cached_instructions_history.append(addr)

        instruction = self._disasm(ql, addr, size)

        should_skip = False

        if "force" in self.hook_data and addr in self.hook_data['force']:
            if self.hook_data['force'][addr]:
                self.logger.debug(f"force true on {hex(addr - self.base_addr)}")
                if ql.arch.type == QL_ARCH.X8664 or ql.arch.type == QL_ARCH.X86:
                    # cmov
                    reg1 = self._get_reg_operand(instruction, 0)
                    reg2 = self._get_reg_operand(instruction, 1)
                    reg2_val = ql.arch.regs.read(reg2)
                    assert reg2_val is not None
                    ql.arch.regs.write(reg1, reg2_val)
                elif ql.arch.type == QL_ARCH.ARM64:
                    # csel A B C
                    # A <- B
                    reg1 = self._get_reg_operand(instruction, 0)
                    reg2 = self._get_reg_operand(instruction, 1)
                    reg2_val = ql.arch.regs.read(reg2)
                    assert reg2_val is not None
                    ql.arch.regs.write(reg1, reg2_val)
                else:
                    raise Exception("haven't impl yet.")
            else:
                self.logger.debug(f"force false on {hex(addr - self.base_addr)}")

                if ql.arch.type == QL_ARCH.ARM64:
                    # csel A B C
                    # A <- C
                    reg1 = self._get_reg_operand(instruction, 0)
                    reg2 = self._get_reg_operand(instruction, 2)
                    reg2_val = ql.arch.regs.read(reg2)
                    assert reg2_val is not None
                    ql.arch.regs.write(reg1, reg2_val)

                # pass for x86
            should_skip = True

        if self.verbose_hook:
            self.logger.debug("> 0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))
            self.logger.debug("instruction size %d" % (size))

        if ql.arch.type != QL_ARCH.ARM64:
            raise Exception("todo")
        # if instruction.op_str.find('sp') == -1:
        #     self.logger.debug(
        #         "> skip 0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))
        #     should_skip = True

        if instruction.op_str.find('[') != -1:
            if instruction.op_str.find('[sp') == -1:
                self.logger.debug(
                    "> skip 0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))
                should_skip = True

        # skip caller
        if instruction.id in general_arch_util.get_call_types(ql.arch.type):
            self.logger.debug("skip call instruction")
            should_skip = True
        if instruction.id in general_arch_util.get_function_ret_types(ql.arch.type):
            ql.emu_stop()

        if should_skip:
            if self.verbose_hook:
                self.logger.debug(f"PC is {hex(ql.arch.regs.arch_pc)}")
                self.logger.debug(f"addr is {hex(addr)}")
            ql.arch.regs.arch_pc += size
            if self.verbose_hook:
                self.logger.debug(f"PC guided to {hex(ql.arch.regs.arch_pc)}")

        if start_block_id == current_block_id:
            return
        if current_block_id in self.real_blocks or current_block_id in self.return_blocks:
            if current_block_id not in self.paths[start_block_id]:
                assert start_block_id != current_block_id
                self.logger.debug(f"new path to {hex(addr - self.base_addr)}, i.e. {start_block_id} -> {current_block_id}")
                self.paths[start_block_id].append(current_block_id)

                # self.cached_predecessor_table[current_block_id].append(start_block_id)
            ql.emu_stop()

    def _skip_unmapped_rw(self, ql, type, addr, size, value):
        map_addr = ql.mem.align(addr)
        map_size = ql.mem.align(size)
        if not ql.mem.is_mapped(map_addr, map_size):
            self.logger.warning(f"Invalid memory R/W, trying to map {hex(map_size)} at {hex(map_addr)}")
            ql.mem.map(map_addr, map_size)
            ql.mem.write(map_addr, b'\x00' * map_size)
        return True

    def _is_branch_type_instruction(self, address, size):
        if self.emu.ql.arch.type == QL_ARCH.ARM64:
            target_branch_types = arm64_util.get_branch_instruction_types()
        else:
            raise Exception("Haven't impl yet.")
        instruction = self._disasm(self.emu.ql, address, size)
        print(instruction.op_str)
        if instruction.op_str.find("csel") != -1:
            self.logger.error("FATAL FOUND!!")
        if instruction.id in target_branch_types:
            self.logger.debug(f"find branch at {hex(instruction.address - self.base_addr)}")
            return True
        else:
            return False

    def _find_branch_in_real_block(self, block: Block):
        instruction_list = self.md.disasm(block.code, block.start_addr)

        # only support arm64 currently
        if self.emu.ql.arch.type == QL_ARCH.ARM64:
            target_branch_types = arm64_util.get_branch_instruction_types()
        else:
            raise Exception("Haven't impl yet.")
        for instruction in instruction_list:
            # if block.start_addr == 0x13E2C + self.base_addr:
            #     self.logger.debug("0x%x:\t%s\t%s,%d" % (
            #         instruction.address, instruction.mnemonic, instruction.op_str, instruction.id))

            if instruction.id in target_branch_types:
                self.logger.debug(f"find branch at {hex(instruction.address - self.base_addr)}")
                return instruction.address

        return None

    def _block_str(self, block_id):
        block = self.block_container.get_block_from_id(block_id)
        # return f"block addr: {hex(block.start_addr - self.base_addr)}, end_address :{hex(block.start_addr + block.size - self.base_addr)}"
        return f"block addr: {hex(block.start_addr - self.base_addr)} "
        # if type(block_id) is int:
        #     block_id = self.bb_mapping[block_id]
        # return f"Block id: {block_id.id}, start_address: {block_id.start_ea:x}, end_address: {block_id.end_ea:x}, type: {block_id.type}"

    def _log_paths_str(self):
        self.logger.info("-" * 30 + 'path info' + "-" * 30)
        for block_id, successors in self.paths.items():
            if len(successors) == 1:
                self.logger.info(f"{self._block_str(block_id)} -> {self._block_str(successors[0])}")
            elif len(successors) == 2:
                self.logger.info(f"{self._block_str(block_id)} --(force jump)--> {self._block_str(successors[0])}")
                self.logger.info(f"|----(skip jump)----> {self._block_str(successors[1])}")
            else:
                self.logger.info(f"{self._block_str(block_id)} as return block")

    def _log_dfs_paths_str(self):
        for address, successors in self.dfs_paths.items():
            if len(successors) == 1:
                self.logger.info(f"{hex(address)} -> {hex(successors[0])}")
            elif len(successors) == 2:
                self.logger.info(f"{hex(address)} --(force jump)--> {hex(successors[0])}")
                self.logger.info(f"|----(skip jump)----> {hex(successors[1])}")
            else:
                assert len(successors) == 0
                self.logger.info(f"{hex(address)} as return block")

    def recursive_guild_hook(self, ql: Qiling, addr, size):
        if self.dfs_success:
            # success in dfs, so stop here
            ql.emu_stop()

        if addr == self.cached_last_instruction_address:
            return
        else:
            self.cached_last_instruction_address = addr

        # PC out of bound case
        if addr - self.base_addr >= self.highest_address_boundary:
            ql.emu_stop()
            return

        self.logger.info(f"Executing: {hex(addr - self.base_addr)}")

        if self.block_container.get_block_id_from_address(addr) in self.real_blocks:
            if addr in self.cached_instructions_history:
                if self.verbose_hook:
                    self.logger.debug(
                        f"potential fake block {hex(self.block_container.get_block_address_from_address(addr) - self.base_addr)} at {hex(addr - self.base_addr)}, skip it.")
                ql.emu_stop()
            self.cached_instructions_history.append(addr)

        current_block_id = self.block_container.get_block_id_from_address(addr)
        start_block_id = self.block_container.get_block_id_from_address(self.dfs_start_address)

        if current_block_id in [*self.real_blocks, *self.return_blocks] and \
                start_block_id != current_block_id and \
                addr == self.block_container.get_block_address_from_address(addr):
            # and addr != self.block_container.get_block_address_from_address(        addr):
            self.logger.debug(f"path dfs success at {hex(addr - self.base_addr)}")
            self.dfs_success = True
            self.dfs_next_addr = addr
            ql.emu_stop()

        instruction = self._disasm(ql, addr, size)

        should_skip = False
        if ql.arch.type != QL_ARCH.ARM64:
            raise Exception("todo")

        if instruction.op_str.find('[') != -1:
            if instruction.op_str.find('[sp') == -1:
                self.logger.debug(
                    "> skip 0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))
                should_skip = True

        # skip caller
        if instruction.id in general_arch_util.get_call_types(ql.arch.type):
            self.logger.debug("skip call instruction")
            should_skip = True
        # stop at ret
        if instruction.id in general_arch_util.get_function_ret_types(ql.arch.type):
            self.logger.debug("dfs_success for ret")
            self.dfs_success = False
            ql.emu_stop()

        if instruction.id in arm64_util.get_branch_instruction_types():
            assert ql.arch.type == QL_ARCH.ARM64
            if not self.dfs_branch_force:
                # csel A B C cond
                # A <- B
                reg1 = self._get_reg_operand(instruction, 0)
                reg2 = self._get_reg_operand(instruction, 1)
                reg2_val = ql.arch.regs.read(reg2)
                assert reg2_val is not None
                ql.arch.regs.write(reg1, reg2_val)
                if self.verbose_hook:
                    self.logger.debug(f"force false on {hex(addr - self.base_addr)}")

            else:
                # csel A B C cond
                # A <- C
                reg1 = self._get_reg_operand(instruction, 0)
                reg2 = self._get_reg_operand(instruction, 2)
                reg2_val = ql.arch.regs.read(reg2)
                assert reg2_val is not None
                ql.arch.regs.write(reg1, reg2_val)
            # ql.arch.regs.arch_pc += size
            should_skip = True

        if should_skip:
            if self.verbose_hook:
                self.logger.debug(f"PC is {hex(ql.arch.regs.arch_pc)}")
                self.logger.debug(f"addr is {hex(addr)}")
            ql.arch.regs.arch_pc += size
            if self.verbose_hook:
                self.logger.debug(f"PC guided to {hex(ql.arch.regs.arch_pc)}")

    def dfs(self, address, branch=None):
        self.cached_instructions_history = []
        self.dfs_success = False
        self.dfs_next_addr = -1  # based
        self.dfs_branch_force = branch
        try:
            self.emu.run(address)
            self.dfs_start_address = address
        except Exception as e:
            pass
        if self.dfs_success:
            return self.dfs_next_addr
        else:
            return None

    def _add_to_dfs_paths(self, from_path, to_path):
        if from_path in self.dfs_paths.keys():
            self.dfs_paths[from_path].append(to_path)
        else:
            self.dfs_paths[from_path] = [to_path]

    def _convert_dfs_paths_to_paths(self):
        self.logger.debug("convert_dfs_paths_to_paths. This will clear the origin paths.")
        self.paths = {}
        for address, successors in self.dfs_paths.items():
            assert len(successors) <= 2
            address_id = self.block_container.get_block_id_from_address(address + self.base_addr)
            assert address_id != -1
            # self.logger.debug(f"{hex(address)} with {address_id}")
            # for s in successors:
            #     if self.block_container.get_block_id_from_address(s + self.base_addr) == None:
            #         self.logger.error(f"[CONVERTING WARNING] fail to find block at {hex(s)}")
            self.paths[address_id] = [self.block_container.get_block_id_from_address(s + self.base_addr) for s in successors]

    def search_path(self, strategy=0):

        reals = [self.prologue_node_id, *self.real_blocks, *self.return_blocks]

        self.paths = {block_id: [] for block_id in reals}
        self.dfs_paths = {}
        # self.cached_predecessor_table = {block_id: [] for block_id in reals}

        # self.emu.start()
        ql = self.emu.ql

        self.md = general_arch_util.create_disassembler(ql)
        self.md.detail = True
        self.hook_data = None
        ql.hook_mem_read_invalid(self._skip_unmapped_rw)
        ql.hook_mem_write_invalid(self._skip_unmapped_rw)
        ql.hook_mem_unmapped(self._skip_unmapped_rw)
        ql.hook_mem_fetch_invalid(self._skip_unmapped_rw)

        context_dict = {}

        self.clear_cache()
        # way 1 : traverse
        if strategy == 0:
            ql.hook_code(self.guide_hook)

            # cached_traversed_table = []
            for block_id in reals:
                bb = self.block_container.get_block_from_id(block_id)
                self.logger.debug(f"searching blocks in {hex(bb.start_addr - self.base_addr)}")
                branch_addr = self._find_branch_in_real_block(bb)
                self.hook_data = {
                    "start_block": block_id
                }
                self.logger.debug(f"working on {hex(bb.start_addr - self.emu.base_addr)}")

                self.clear_cache()

                if branch_addr is None:
                    # self.verbose_hook = True
                    self.cached_instructions_history = []

                    self.logger.debug("non branch block")
                    ql.run(begin=bb.start_addr)
                else:
                    # if (bb.start_addr - self.emu.base_addr) == 0x13E2C:
                    #     # or (bb.start_addr - self.emu.base_addr) == 0x13e90:
                    #     self.verbose_hook = True

                    self.logger.debug("branch block")
                    self.hook_data['force'] = {branch_addr: True}
                    self.cached_instructions_history = []
                    ql.run(begin=bb.start_addr)
                    self.hook_data['force'] = {branch_addr: False}
                    self.cached_instructions_history = []
                    ql.run(begin=bb.start_addr)

                    # if bb.start_addr - self.emu.base_addr == 0x13E2C:
                    self.verbose_hook = False
            self._log_paths_str()

        elif strategy == 1:
            # way 2 : dfs
            ql.hook_code(self.recursive_guild_hook)
            block_queue: queue.LifoQueue = queue.LifoQueue()
            prologue_addr = self.block_container.get_block_from_id(self.prologue_node_id).start_addr
            block_queue.put((prologue_addr, None))
            cached_address_lists = []
            while not block_queue.empty():
                block_environment = block_queue.get()
                current_address = block_environment[0]
                context = block_environment[1]
                self.emu.restore_context(context)
                if current_address - self.base_addr in self.dfs_paths.keys():
                    self.logger.debug(f"skip the same dfs path {hex(current_address - self.base_addr)}")
                    continue

                # cached_address_lists.append(current_address)
                # is_branch_ins = self._is_branch_type_instruction(current_address, 4)
                is_branch_ins = self._find_branch_in_real_block(self.block_container.get_block_from_id(
                    self.block_container.get_block_id_from_address(current_address)))
                if is_branch_ins:
                    self.logger.debug(f"has branch at {hex(current_address - self.base_addr)}")
                    current_context = self.emu.save_context()
                    path_true = self.dfs(address=current_address, branch=False)
                    if path_true is not None:
                        self.logger.debug(
                            f"find path 1 from {hex(current_address - self.base_addr)} -> {hex(path_true - self.base_addr)}")
                        # self.dfs_paths[self.block_container.get_block_id_from_address(current_address)] \
                        #     .append(self.block_container.get_block_id_from_address(path_true - self.base_addr))
                        self._add_to_dfs_paths(current_address - self.base_addr, path_true - self.base_addr)

                        block_queue.put((path_true, self.emu.save_context()))
                    self.emu.restore_context(current_context)

                    path_false = self.dfs(address=current_address, branch=True)
                    if path_false != path_true:
                        self.logger.debug(
                            f"find path 2 from {hex(current_address - self.base_addr)} -> {hex(path_false - self.base_addr)}")
                        self._add_to_dfs_paths(current_address - self.base_addr, path_false - self.base_addr)
                        # self.dfs_paths[self.block_container.get_block_id_from_address(current_address)].append(
                        #     self.block_container.get_block_id_from_address(path_false - self.base_addr))
                        block_queue.put((path_false, self.emu.save_context()))

                else:
                    path = self.dfs(address=current_address)
                    if path is not None:
                        block_queue.put((path, self.emu.save_context()))
                        assert isinstance(path, int)
                        self.logger.debug(
                            f"find path from {hex(current_address - self.base_addr)} -> {hex(path - self.base_addr)}")
                        # self.dfs_paths[self.block_container.get_block_id_from_address(current_address)].append(
                        #     self.block_container.get_block_id_from_address(path - self.base_addr))
                        self._add_to_dfs_paths(current_address - self.base_addr, path - self.base_addr)
            # self._log_dfs_paths_str()
            self._convert_dfs_paths_to_paths()
            self._log_paths_str()

        del self.emu
        self.emu = None

    def patch_code(self, enable_trampoline=False):
        patcher = Patcher(self.filename)
        assert len(self.paths.items()) > 1
        self.logger.info("-" * 30 + 'begin patch' + "-" * 30)
        # nop irrelevant nodes
        for node in self.deflat_analyzer.irrelevant_nodes:
            if self.arch_type == QL_ARCH.ARM64:
                start_addr = node.addr  # irrelevant nodes keeps its zero base
                self.logger.debug(f"nop at {hex(start_addr)}, size {node.size}")
                assert node.size % 4 == 0
                nop_count = int(node.size / 4)
                instruction_value = arm64_util.assemble_nop_instruction() * nop_count
                patcher.patch(start_addr, node.size, instruction_value)
            else:
                raise Exception("Unsupported Arch")

        max_trampoline_pool_cnt = 2 * len(self.paths.keys())
        trampoline_pool: List[int] = []  # only for arm64.
        used_trampoline_pool: List[int] = []  # block addr, target_addr
        if enable_trampoline:
            if self.arch_type == QL_ARCH.ARM64:
                for node in self.deflat_analyzer.irrelevant_nodes:
                    if node.size >= 4:
                        for cur_addr_offset in range(0, node.size, 4):
                            trampoline_pool.append(node.addr + cur_addr_offset)
                            if len(trampoline_pool) >= max_trampoline_pool_cnt:
                                break
                    if len(trampoline_pool) >= max_trampoline_pool_cnt:
                        break
            trampoline_pool.append(*self.deflat_analyzer.manual_trampoline_addr_list)

        # handle control flow
        for block_id, successors in self.paths.items():
            block = self.block_container.get_block_from_id(block_id)
            start_addr = block.start_addr - self.base_addr
            self.logger.debug(f"patch working on {hex(start_addr)}, {successors}")
            instructions = [ins for ins in self.md.disasm(block.code, start_addr)]
            if self.arch_type == QL_ARCH.ARM64:
                # ARM64 patch
                if len(successors) == 2:
                    # real branch

                    true_branch = self.block_container.get_block_from_id(successors[0]).start_addr - self.base_addr
                    false_branch = self.block_container.get_block_from_id(successors[1]).start_addr - self.base_addr
                    self.logger.debug(f"true {hex(true_branch)}, false {hex(false_branch)}")
                    should_trampoline = False
                    current_trampoline_addr = -1
                    if true_branch < start_addr and enable_trampoline:
                        should_trampoline = True
                        for i in range(len(trampoline_pool)):
                            if trampoline_pool[i] > start_addr:
                                current_trampoline_addr = trampoline_pool[i]
                                trampoline_pool.pop(i)
                                break
                        if current_trampoline_addr == -1:
                            self.logger.error(
                                f"Fail to find the suitable trampoline at {hex(start_addr)} with branch {hex(true_branch)}")
                            should_trampoline = False

                    if instructions[-2].id in arm64_util.get_branch_instruction_types():
                        self.logger.debug(f"at -2")
                        instruction_address = instructions[-2].address
                        if should_trampoline:
                            self.logger.debug(f"trampoline to {hex(current_trampoline_addr)}")

                            assert current_trampoline_addr != -1
                            patched_code = arm64_util.assemble_branch_instruction(
                                instruction_address, current_trampoline_addr - instruction_address, false_branch,
                                instructions[-2].op_str.split(',')[-1].strip())
                            assert len(patched_code) == 8

                            # patch in trampoline
                            used_trampoline_pool.append(current_trampoline_addr)
                            b_instruction = arm64_util.assemble_no_branch_instruction(current_trampoline_addr,
                                                                                      true_branch)
                            patcher.patch(current_trampoline_addr, 4, b_instruction)
                        else:
                            # recalculate the offset due to the keystone bug, maybe.
                            patched_code = arm64_util.assemble_branch_instruction(
                                instruction_address, true_branch - instruction_address, false_branch,
                                instructions[-2].op_str.split(',')[-1].strip())

                            assert len(patched_code) == 8
                        patcher.patch(instruction_address, 8, patched_code)

                    elif instructions[-3].id in arm64_util.get_branch_instruction_types():
                        self.logger.debug(f"at -3")
                        instruction_address = instructions[-3].address
                        branch_offset = instruction_address + 4

                        if should_trampoline:
                            self.logger.debug(f"trampoline to {hex(current_trampoline_addr)}")
                            assert current_trampoline_addr != -1
                            patched_code = arm64_util.assemble_branch_instruction(
                                branch_offset, current_trampoline_addr - branch_offset, false_branch,
                                instructions[-3].op_str.split(',')[-1].strip())
                            assert len(patched_code) == 8

                            # patch in trampoline
                            used_trampoline_pool.append(current_trampoline_addr)
                            b_instruction = arm64_util.assemble_no_branch_instruction(current_trampoline_addr, true_branch)
                            patcher.patch(current_trampoline_addr, 4, b_instruction)
                        else:
                            patched_code = arm64_util.assemble_branch_instruction(
                                branch_offset, true_branch - branch_offset, false_branch,
                                instructions[-3].op_str.split(',')[-1].strip())

                            assert len(patched_code) == 8
                        patcher.copy_to_patch(instruction_address, branch_offset, 4)
                        patcher.patch(branch_offset, 8, patched_code)
                    else:
                        assert len(instructions) > 4
                        self.logger.warning("may encounter special csel instruction with larger than 2 offset, this is an experimental patch.")
                        target_branch_instruction = None
                        # instructions[-3].id in arm64_util.get_branch_instruction_types()
                        for cursor_offset in range(len(instructions) - 1, -1, -1):
                            if instructions[cursor_offset].id in arm64_util.get_branch_instruction_types():
                                target_branch_instruction = instructions[cursor_offset]
                                break
                        if target_branch_instruction is None:
                            raise Exception("Unhandled Branch Block")
                        target_branch_instruction_address = target_branch_instruction.address
                        self.logger.debug(f"target_branch_instruction at {hex(target_branch_instruction_address)}, {target_branch_instruction.op_str}")
                        # Disable trampoline here!
                        branch_offset = start_addr + block.size - 8  # instructions[-2].addresss  # we assume the last two instructions to be branch
                        self.logger.debug(f"last two instruction at {hex(branch_offset)}")
                        assert isinstance(branch_offset, int)
                        patched_code = arm64_util.assemble_branch_instruction(
                            branch_offset, true_branch - branch_offset, false_branch,
                            target_branch_instruction.op_str.split(',')[-1].strip())

                        assert len(patched_code) == 8
                        cnt = branch_offset - target_branch_instruction_address
                        patcher.copy_to_patch(target_branch_instruction_address, target_branch_instruction_address + 4, cnt)
                        patcher.patch(branch_offset, 8, patched_code)
                elif len(successors) == 1:
                    # force jump
                    instruction_address = instructions[-1].address

                    next_block = self.block_container.get_block_from_id(successors[0]).start_addr - self.base_addr

                    self.logger.debug(f"next_block {hex(next_block)}")

                    patched_code = arm64_util.assemble_no_branch_instruction(instruction_address, next_block)
                    patcher.patch(instruction_address, 4, patched_code)
                else:
                    assert len(successors) == 0
                    # return block
                    continue

            else:
                raise Exception("Unsupported Arch")

        patcher.write_patch_to_file()
        self.logger.info("Patch code finish.")


class Emulator:
    ql: Qiling
    base_addr: int

    def __init__(self, filename, rootfs):
        self.path = filename
        self.rootfs = rootfs
        # rootfs=self.rootfs
        self.ql = Qiling([self.path], rootfs=self.rootfs)  # output="debug", verbose=1
        self.status = None
        self.exit_addr = None

        if self.ql.os.type == QL_OS.LINUX:
            f = open(self.ql.path, 'rb')
            elf_file = ELFFile(f)
            elf_header = elf_file.header
            if elf_header['e_type'] == 'ET_EXEC':
                self.base_addr = self.ql.os.elf_mem_start
            elif elf_header['e_type'] == 'ET_DYN':
                if self.ql.arch.bits == 32:
                    self.base_addr = int(self.ql.os.profile.get("OS32", "load_address"), 16)
                elif self.ql.arch.bits == 64:
                    self.base_addr = int(self.ql.os.profile.get("OS64", "load_address"), 16)
        else:
            self.base_addr = 0x0

    def run(self, begin=None, end=None):
        self.ql.run(begin, end)

    def save_context(self):
        context = self.ql.save(mem=True, reg=True, fd=False, cpu_context=True)
        return context

    def restore_context(self, context):
        if context is not None:
            self.ql.restore(context)

    def remove_ql(self):
        if self.ql is not None:
            del self.ql
            self.ql = None



class BinaryTest():
    def test_binary(self):
        ql = Qiling(["example/lib64_example.so"], "rootfs/arm64_android", verbose=QL_VERBOSE.DEBUG)
        print(ql.loader.load_address)
        base = int(ql.os.profile.get("OS64", "load_address"), 16)
        print(base)
        ql.run(begin=0x13C88 + base, end=0x13CA0 + base)