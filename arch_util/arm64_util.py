from capstone.arm64 import *
from keystone import *


def get_branch_instruction_types():
    return [ARM64_INS_CSEL]


def get_call_instruction_types():
    return [ARM64_INS_BLR,ARM64_INS_BL,ARM64_INS_BRK,ARM64_INS_BR]


def get_function_ret_types():
    return [ARM64_INS_RET]


def assemble_branch_instruction(address, true_branch, false_branch, condition):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    # print(f"now assemble ", end='')
    # print("b%s #%s;b #%s" % (condition, hex(true_branch), hex(false_branch)))

    instruction, count = ks.asm("b%s #%s;b #%s" % (condition, hex(true_branch), hex(false_branch)), address)
    # print(bytes(instruction).hex())
    # print(bytes(instruction))
    return instruction


def assemble_nop_instruction(size=4):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    instruction, count = ks.asm("nop")
    assert len(instruction) == size
    return instruction


def assemble_no_branch_instruction(address, dest):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    print(f"now assemble b #0x{hex(dest)[2:]} at {hex(address)}")
    instruction, count = ks.asm(("b #%s" % hex(dest)), address)
    return instruction
