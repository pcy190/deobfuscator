from capstone import CS_MODE_ARM, CS_MODE_THUMB, CS_ARCH_ARM, Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_16, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN, \
    CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_REG
from capstone.arm_const import ARM_OP_REG
from capstone.x86_const import X86_OP_REG
from qiling import Qiling

from qiling.const import QL_ARCH, QL_ENDIAN
from qiling.exception import QlErrorArch

import arch_util.arm64_util as arm64_util


# Powered by HAPPY

def get_op_reg_const(qiling_arch):
    if qiling_arch == QL_ARCH.X86:
        return X86_OP_REG
    if qiling_arch == QL_ARCH.X8664:
        # not sure if x86 op reg is suitable
        print(f"[WARNING] X86_OP_REG might wrong.")
        return X86_OP_REG
    if qiling_arch == QL_ARCH.ARM:
        return ARM_OP_REG
    if qiling_arch == QL_ARCH.ARM64:
        return ARM64_OP_REG
    else:
        raise Exception("unsupported arch found.")


def get_function_ret_types(qiling_arch):
    if qiling_arch == QL_ARCH.X86:
        raise Exception("unsupported arch found.")
    if qiling_arch == QL_ARCH.X8664:
        raise Exception("unsupported arch found.")
    if qiling_arch == QL_ARCH.ARM:
        raise Exception("unsupported arch found.")
    if qiling_arch == QL_ARCH.ARM64:
        return arm64_util.get_function_ret_types()
    else:
        raise Exception("unsupported arch found.")


def get_call_types(qiling_arch):
    if qiling_arch == QL_ARCH.X86:
        raise Exception("unsupported arch found.")
    if qiling_arch == QL_ARCH.X8664:
        raise Exception("unsupported arch found.")
    if qiling_arch == QL_ARCH.ARM:
        raise Exception("unsupported arch found.")
    if qiling_arch == QL_ARCH.ARM64:
        return arm64_util.get_call_instruction_types()
    else:
        raise Exception("unsupported arch found.")


def create_disassembler(ql: Qiling):
    if ql.arch.type == QL_ARCH.ARM:  # QL_ARM
        reg_cpsr = ql.arch.regs.cpsr
        mode = CS_MODE_ARM
        if ql.arch.endian == QL_ENDIAN.EB:
            reg_cpsr_v = 0b100000
            # reg_cpsr_v = 0b000000
        else:
            reg_cpsr_v = 0b100000

        if reg_cpsr & reg_cpsr_v != 0:
            mode = CS_MODE_THUMB

        if ql.arch.endian == QL_ENDIAN.EB:
            md = Cs(CS_ARCH_ARM, mode)
            # md = Cs(CS_ARCH_ARM, mode + CS_MODE_BIG_ENDIAN)
        else:
            md = Cs(CS_ARCH_ARM, mode)

    elif ql.arch.type == QL_ARCH.ARM:
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    elif ql.arch.type == QL_ARCH.X86:  # QL_X86
        md = Cs(CS_ARCH_X86, CS_MODE_32)

    elif ql.arch.type == QL_ARCH.X8664:  # QL_X86_64
        md = Cs(CS_ARCH_X86, CS_MODE_64)

    elif ql.arch.type == QL_ARCH.ARM64:  # QL_ARM64
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    elif ql.arch.type == QL_ARCH.A8086:  # QL_A8086
        md = Cs(CS_ARCH_X86, CS_MODE_16)

    elif ql.arch.type == QL_ARCH.MIPS:  # QL_MIPS32
        if ql.archendian == QL_ENDIAN.EB:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
        else:
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)

    else:
        raise QlErrorArch("[!] Unknown arch defined in utils.py (debug output mode)")

    return md
