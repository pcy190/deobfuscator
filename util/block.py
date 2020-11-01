from typing import List, Any, Mapping, Dict

from util.graph import SuperCFGNode


# Powered by HAPPY

class Block:
    size: int
    start_addr: int
    idx: int
    code: bytes

    def __init__(self, start_addr: int, size: int, code: bytes, idx: int = 0):
        self.start_addr = start_addr
        self.size = size
        self.idx = idx
        self.code = code


class BlockContainer:
    block_dict: Dict[int, Block]
    _id_base: int
    _fast_lookup_table: List[int]
    _is_lookup_table_sorted: bool

    def __init__(self):
        self._id_base = 0
        self.block_dict = {}
        self._fast_lookup_table = []
        self._is_lookup_table_sorted = False
        pass

    def add_cfg_node_to_block(self, node: SuperCFGNode, base_address: int):
        assert node.cfg_nodes[0].bytestr is not None  # fill the byte in emulator
        block = Block(node.addr + base_address, node.size, node.cfg_nodes[0].bytestr)
        return self._add_block(block)

    def _add_block(self, block: Block):
        # update block index
        block.idx = self._id_base
        self._fast_lookup_table.append(block.idx)
        self.block_dict.update({self._id_base: block})
        self._id_base += 1
        return self._id_base - 1

    def get_block_from_id(self, idx: int):
        return self.block_dict.get(idx)

    def get_block_id_from_address(self, addr: int):
        """
        query block id from address
        :param addr: instruction address
        :return: block id ; -1 if fail
        """
        if not self._is_lookup_table_sorted:
            self._fast_lookup_table.sort(key=lambda x: self.block_dict.get(x).start_addr)
            self._is_lookup_table_sorted = True

        for i in range(len(self._fast_lookup_table)):
            idx = self._fast_lookup_table[i]
            current_addr = self.block_dict.get(idx).start_addr
            if current_addr > addr:
                return -1
            if current_addr <= addr < current_addr + self.block_dict.get(idx).size:
                return idx
        # for i in range(len(self._fast_lookup_table)):
        #     # Since the table is sorted, it's unnecessary to iterate it anymore.
        #     _current_start_address = self._fast_lookup_table[i][0]
        #     if _current_start_address > addr:
        #         return -1
        #     if _current_start_address <= addr < _current_start_address + self._fast_lookup_table[i][1]:
        #         return self._fast_lookup_table[i][2]  # return idx
        return -1

    def get_block_address_from_address(self, address):
        return self.get_block_from_id(self.get_block_id_from_address(addr=address)).start_addr
