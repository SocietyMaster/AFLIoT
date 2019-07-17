#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Himyth / AAA """

import capstone
from arm_consts import *

ARM_TAINT_REG_CLEAR = """
    stmfd sp!, {{ r0, r4 }}
    
    ldr r4, =shadow_memory_register_base
    ldr r4, [r4]                    @ load base address
    
    eor r0, r0, r0
    
    STORE_LABEL
    
    ldmfd sp!, {{ r0, r4 }}
"""


ARM_TAINT_REG_COPY = """
    stmfd sp!, {{ r0, r4 }}
    
    ldr r4, =shadow_memory_register_base
    ldr r4, [r4]                    @ load base address
    
    ldr r0, [r4, #{offset_rs0}]     @ load rs0 taint label
    
    STORE_LABEL
    
    ldmfd sp!, {{ r0, r4 }}
"""


ARM_TAINT_REG_MERGE = """
    stmfd sp!, {{ r0 - r5, lr, r12 }}
    mrs r0, cpsr
    stmfd sp!, {{ r0 }}
    
    ldr r4, =shadow_memory_register_base
    ldr r4, [r4]                @ load base address
    
    ldr r0, [r4, #{offset_rs0}]      @ load rs0 taint label
    ldr r1, [r4, #{offset_rs1}]      @ load rs1 taint label
    ldr r5, =shadow_memory_op_union
    ldr r5, [r5]
    blx r5                          @ union
    
    MORE_UNION
    
    STORE_LABEL
    
    ldmfd sp!, {{ r0 }}
    msr cpsr, r0
    ldmfd sp!, {{ r0 - r5, lr, r12 }}
"""


ARM_TAINT_REG_MORE_UNION = """
    ldr r1, [r4, #{offset_rs%d}]
    blx r5
"""


ARM_TAINT_REG_STORE_LABEL = """
    str r0, [r4, #{offset_rd%d}]
"""


def register_smoffset(reg):
    if reg == capstone.arm.ARM_REG_CPSR:
        return 4 * 16
    if capstone.arm.ARM_REG_R0 <= reg <= capstone.arm.ARM_REG_R12:
        return int(4 * (reg - capstone.arm.ARM_REG_R0))
    return None


def make_intra_register_taint_block(src_regs, dst_regs):
    src_regs = list(set(src_regs))
    dst_regs = list(set(dst_regs))

    if not dst_regs:
        return ''

    params = dict()

    store_label = ''
    for index, reg in enumerate(dst_regs):
        store_label += ARM_TAINT_REG_STORE_LABEL % index
        params['offset_rd%d' % index] = register_smoffset(reg)

    # clear all destination registers
    if not src_regs:
        taint_block = ARM_TAINT_REG_CLEAR.replace('STORE_LABEL', store_label)

    # one source register only, copy its label
    elif len(src_regs) == 1:
        params['offset_rs0'] = register_smoffset(src_regs[0])
        taint_block = ARM_TAINT_REG_COPY.replace('STORE_LABEL', store_label)

    # more than one register, call union
    else:
        more_union = ''
        for index, reg in enumerate(src_regs):
            params['offset_rs%d' % index] = register_smoffset(src_regs[index])
            if index < 2:
                continue
            more_union += ARM_TAINT_REG_MORE_UNION % index
        taint_block = ARM_TAINT_REG_MERGE.replace('STORE_LABEL', store_label).\
            replace('MORE_UNION', more_union)

    taint_block = taint_block.format(**params)
    return taint_block


ARM_TAINT_MEMREG = """
    stmfd sp!, {{ r0 - r3, {reg1}, {reg2}, lr, r12 }}
    mrs {reg1}, cpsr
    stmfd sp!, {{ {reg1} }}
    
    GET_ADDRESS                 @ reg1 -> address
    GET_ADDR_ADDUP
    
    ldr {reg2}, =shadow_memory_op_get_base
    ldr {reg2}, [{reg2}]        @ reg2 -> shadow_memory_op_get_base
    
    mov r0, {reg1}
    blx {reg2}                  @ shadow_memory_op_get_base(address)
    mov {reg1}, r0              @ reg1 -> shadow memory address
    
    ldr r0, [{reg1}, #{offset_ms0}]      @ load ms0 taint label
    
    FIRST_UNION
    
    MORE_UNION
    
    ldr {reg1}, =shadow_memory_register_base
    ldr {reg1}, [{reg1}]                @ load base address
    
    str r0, [{reg1}, #{offset_rd}]
    
    ldmfd sp!, {{ {reg1} }}
    msr cpsr, {reg1}
    ldmfd sp!, {{ r0 - r3, {reg1}, {reg2}, lr, r12 }}
"""


ARM_TAINT_MEMREG_GET_ADDRESS = """
    {addsub} {{reg1}}, {rn}{operand2}
"""

ARM_TAINT_MEMREG_FIRST_UNION = """
    ldr r1, [{reg1}, #{offset_ms1}]      @ load ms1 taint label
    ldr {reg2}, =shadow_memory_op_union
    ldr {reg2}, [{reg2}]        @ reg2 -> shadow_memory_op_union
    blx {reg2}
"""

ARM_TAINT_MEMREG_MORE_UNION = """
    ldr r1, [{reg1}, #{offset_ms%d}]
    blx {reg2}
"""


def make_memory_to_register_taint_block(locate, memsize, rdst, insn, addup=0):
    cands = find_register_candidates(insn)
    params = {'reg%d' % i: cands[i] for i in xrange(len(cands))}

    # rn
    rn = locate[0][1]
    addsub = 'add'
    operand2 = ''

    for op in locate[1:]:
        if op[0] == ARM_ADDR_IMMEDIATE:
            operand2 += ', #%d' % op[1]
        if op[0] == ARM_ADDR_NEGTIVE:
            addsub = 'sub'
        if op[0] == ARM_ADDR_SHIFT:
            operand2 += ', %s' % shift_literal(op[1], op[2], insn)
        if op[0] == ARM_ADDR_REGISTER:
            operand2 = ', %s' % op[1] + operand2
    if operand2 == '':
        operand2 = ', #0'

    get_address = ARM_TAINT_MEMREG_GET_ADDRESS.format(addsub=addsub, rn=rn, operand2=operand2)
    taint_block = ARM_TAINT_MEMREG.replace('GET_ADDRESS', get_address)

    get_addr_addup = ''
    if addup != 0:
        get_addr_addup = 'add {reg1}, {reg1}, #%d' % addup
    taint_block = taint_block.replace('GET_ADDR_ADDUP', get_addr_addup)

    first_union = ARM_TAINT_MEMREG_FIRST_UNION
    if memsize == 1:
        first_union = ''
    taint_block = taint_block.replace("FIRST_UNION", first_union)

    more_union = ''
    for i in xrange(memsize):
        params['offset_ms%d' % i] = i * 4
        if i < 2:
            continue
        more_union += ARM_TAINT_MEMREG_MORE_UNION % i
    taint_block = taint_block.replace('MORE_UNION', more_union)

    params['offset_rd'] = register_smoffset(rdst)

    taint_block = taint_block.format(**params)
    return taint_block


ARM_TAINT_REGMEM = """
    stmfd sp!, {{ r0 - r3, {reg1}, {reg2}, lr, r12 }}
    mrs {reg1}, cpsr
    stmfd sp!, {{ {reg1} }}
    
    GET_ADDRESS                 @ reg1 -> address
    GET_ADDR_ADDUP
    
    ldr {reg2}, =shadow_memory_op_get_base
    ldr {reg2}, [{reg2}]        @ reg2 -> shadow_memory_op_get_base
    
    mov r0, {reg1}
    blx {reg2}                  @ shadow_memory_op_get_base(address)
    mov {reg1}, r0              @ reg1 -> shadow memory address
    
    stmfd sp!, {{ {reg1} }}

    ldr {reg1}, =shadow_memory_register_base
    ldr {reg1}, [{reg1}]                @ load base address
    
    ldr r0, [r4, #{offset_rs0}]      @ load rs0 taint label
    
    FIRST_UNION
    
    MORE_UNION

    ldmfd sp!, {{ {reg1} }}
    
    MORE_STORE
    
    ldmfd sp!, {{ {reg1} }}
    msr cpsr, {reg1}
    ldmfd sp!, {{ r0 - r3, {reg1}, {reg2}, lr, r12 }}
"""


ARM_TAINT_REGMEM_GET_ADDRESS = """
    {addsub} {{reg1}}, {rn}{operand2}
"""

ARM_TAINT_REGMEM_FIRST_UNION = """
    ldr r1, [{reg1}, #{offset_rs1}]      @ load rs1 taint label
    ldr {reg2}, =shadow_memory_op_union
    ldr {reg2}, [{reg2}]        @ reg2 -> shadow_memory_op_union
    blx {reg2}
"""

ARM_TAINT_REGMEM_MORE_UNION = """
    ldr r1, [{reg1}, #{offset_rs%d}]
    blx {reg2}
"""

ARM_TAINT_REGMEM_MORE_STORE = """
    str r0, [{reg1}, #{offset_md%d}]
"""


def make_register_to_memory_taint_block(locate, memsize, src_regs, insn, addup=0):
    if not src_regs:
        return ''

    cands = find_register_candidates(insn)
    params = {'reg%d' % i: cands[i] for i in xrange(len(cands))}

    # rn
    rn = locate[0][1]
    addsub = 'add'
    operand2 = ''

    for op in locate[1:]:
        if op[0] == ARM_ADDR_IMMEDIATE:
            operand2 += ', #%d' % op[1]
        if op[0] == ARM_ADDR_NEGTIVE:
            addsub = 'sub'
        if op[0] == ARM_ADDR_SHIFT:
            operand2 += ', %s' % shift_literal(op[1], op[2], insn)
        if op[0] == ARM_ADDR_REGISTER:
            operand2 = ', %s' % op[1] + operand2
    if operand2 == '':
        operand2 = ', #0'

    get_address = ARM_TAINT_REGMEM_GET_ADDRESS.format(addsub=addsub, rn=rn, operand2=operand2)
    taint_block = ARM_TAINT_REGMEM.replace('GET_ADDRESS', get_address)

    get_addr_addup = ''
    if addup != 0:
        get_addr_addup = 'add {reg1}, {reg1}, #%d' % addup
    taint_block = taint_block.replace('GET_ADDR_ADDUP', get_addr_addup)

    first_union = ''
    if len(src_regs) > 1:
        first_union = ARM_TAINT_REGMEM_FIRST_UNION
    taint_block = taint_block.replace("FIRST_UNION", first_union)

    more_union = ''
    for index, reg in enumerate(src_regs):
        params['offset_rs%d' % index] = register_smoffset(src_regs[index])
        if index < 2:
            continue
        more_union += ARM_TAINT_REGMEM_MORE_UNION % index
    taint_block = taint_block.replace('MORE_UNION', more_union)

    more_store = ''
    for i in xrange(memsize):
        params['offset_md%d' % i] = 4 * i
        more_store += ARM_TAINT_REGMEM_MORE_STORE % i
    taint_block = taint_block.replace("MORE_STORE", more_store)

    taint_block = taint_block.format(**params)
    return taint_block


def check_register_operands(insn):
    registers = []
    for operand in insn.operands:
        if operand.type == capstone.arm.ARM_OP_REG:     # direct register access
            registers.append(insn.reg_name(operand.value.reg))
        elif operand.type == capstone.arm.ARM_OP_MEM:
            if operand.value.mem.base != 0:             # indirect base register
                registers.append(insn.reg_name(operand.value.mem.base))
            if operand.value.mem.index != 0:            # indirect index register
                registers.append(insn.reg_name(operand.value.mem.index))
        # shift by register
        if operand.shift.type in [capstone.arm.ARM_SFT_ASR_REG,
                                  capstone.arm.ARM_SFT_LSL_REG,
                                  capstone.arm.ARM_SFT_LSR_REG,
                                  capstone.arm.ARM_SFT_ROR_REG,
                                  capstone.arm.ARM_SFT_RRX_REG]:
            registers.append(insn.reg_name(operand.shift.value))
    return registers


def find_register_candidates(insn):
    # select a free pivot registers
    registers = check_register_operands(insn)

    # r4 - r11 will be preserved by subroutines
    candidates = list({'r%d' % i for i in xrange(4, 12)} - set(registers))
    return candidates


def shift_literal(sft_type, sft_value, insn):
    if sft_type == capstone.arm.ARM_SFT_ASR:
        return 'asr #%d' % sft_value
    if sft_type == capstone.arm.ARM_SFT_LSL:
        return 'lsl #%d' % sft_value
    if sft_type == capstone.arm.ARM_SFT_LSR:
        return 'lsr #%d' % sft_value
    if sft_type == capstone.arm.ARM_SFT_ROR:
        return 'ror #%d' % sft_value
    if sft_type == capstone.arm.ARM_SFT_RRX:
        return 'rrx'

    if sft_type == capstone.arm.ARM_SFT_ASR_REG:
        return 'asr %s' % insn.reg_name(sft_value)
    if sft_type == capstone.arm.ARM_SFT_LSL_REG:
        return 'lsl %s' % insn.reg_name(sft_value)
    if sft_type == capstone.arm.ARM_SFT_LSR_REG:
        return 'lsr %s' % insn.reg_name(sft_value)
    if sft_type == capstone.arm.ARM_SFT_ROR_REG:
        return 'ror %s' % insn.reg_name(sft_value)
    if sft_type == capstone.arm.ARM_SFT_RRX_REG:
        return 'rrx'

    return None


ARM_TAINT_MEMREG_MULTIPLE = """
    stmfd sp!, {{ r0 - r3, {reg1}, {reg2}, {reg3}, lr, r12 }}
    mrs {reg1}, cpsr
    stmfd sp!, {{ {reg1} }}
    
    GET_ADDRESS                 @ reg1 -> address
    
    ldr {reg2}, =shadow_memory_op_get_base
    ldr {reg2}, [{reg2}]        @ reg2 -> shadow_memory_op_get_base
    
    mov r0, {reg1}
    blx {reg2}                  @ shadow_memory_op_get_base(address)
    mov {reg1}, r0              @ reg1 -> shadow memory address
    
    ldr {reg2}, =shadow_memory_op_union
    ldr {reg2}, [{reg2}]        @ reg2 -> shadow_memory_op_union
    
    ldr {reg3}, =shadow_memory_register_base
    ldr {reg3}, [{reg3}]                @ load base address
    
    MORE_STORE
    
    ldmfd sp!, {{ {reg1} }}
    msr cpsr, {reg1}
    ldmfd sp!, {{ r0 - r3, {reg1}, {reg2}, {reg3}, lr, r12 }}
"""

ARM_TAINT_MEMREG_MULTIPLE_MORE_STORE = """
    ldr r0, [{reg1}, #0]      @ load ms0 taint label
    ldr r1, [{reg1}, #4]      @ load rs1 taint label
    blx {reg2}
    ldr r1, [{reg1}, #8]      @ load rs1 taint label
    blx {reg2}
    ldr r1, [{reg1}, #12]      @ load rs1 taint label
    blx {reg2}
    str r0, [{reg3}, #{offset_rd%d}]
"""

ARM_TAINT_MEMREG_MULTIPLE_POINTER = """
    {addsub} {{reg1}}, {{reg1}}, 16
"""


def make_multiple_memory_to_register_taint_block(rn, reglist, inc, after, insn):
    cands = find_register_candidates(insn)
    params = {'reg%d' % i: cands[i] for i in xrange(len(cands))}

    pointer = ARM_TAINT_MEMREG_MULTIPLE_POINTER.format(addsub='add' if inc else 'sub')

    get_address = """
        mov {reg1}, %s
    """ % rn
    taint_block = ARM_TAINT_MEMREG_MULTIPLE.replace('GET_ADDRESS', get_address)

    more_store = ''
    for index, reg in enumerate(reglist):
        if not after:
            more_store += pointer
        if reg not in [capstone.arm.ARM_REG_PC,
                       capstone.arm.ARM_REG_SP,
                       capstone.arm.ARM_REG_LR]:
            params['offset_rd%d' % index] = register_smoffset(reg)
            more_store += ARM_TAINT_MEMREG_MULTIPLE_MORE_STORE % index
        if after:
            more_store += pointer
    taint_block = taint_block.replace("MORE_STORE", more_store)

    taint_block = taint_block.format(**params)
    return taint_block


ARM_TAINT_REGMEM_MULTIPLE = """
    stmfd sp!, {{ r0 - r3, {reg1}, {reg2}, lr, r12 }}
    mrs {reg1}, cpsr
    stmfd sp!, {{ {reg1} }}
    
    GET_ADDRESS                 @ reg1 -> address
    
    ldr {reg2}, =shadow_memory_op_get_base
    ldr {reg2}, [{reg2}]        @ reg2 -> shadow_memory_op_get_base
    
    mov r0, {reg1}
    blx {reg2}                  @ shadow_memory_op_get_base(address)
    mov {reg1}, r0              @ reg1 -> shadow memory address
    
    ldr {reg2}, =shadow_memory_register_base
    ldr {reg2}, [{reg2}]                @ load base address
    
    MORE_STORE
    
    ldmfd sp!, {{ {reg1} }}
    msr cpsr, {reg1}
    ldmfd sp!, {{ r0 - r3, {reg1}, {reg2}, lr, r12 }}
"""

ARM_TAINT_REGMEM_MULTIPLE_MORE_STORE = """
    ldr r0, [{reg2}, #{offset_rs%d}]
    str r0, [{reg1}, #0]      @ load ms0 taint label
    str r0, [{reg1}, #4]      @ load ms0 taint label
    str r0, [{reg1}, #8]      @ load ms0 taint label
    str r0, [{reg1}, #12]      @ load ms0 taint label
"""

ARM_TAINT_REGMEM_MULTIPLE_POINTER = """
    {addsub} {{reg1}}, {{reg1}}, 16
"""


def make_multiple_register_to_memory_taint_block(rn, reglist, inc, after, insn):
    cands = find_register_candidates(insn)
    params = {'reg%d' % i: cands[i] for i in xrange(len(cands))}

    pointer = ARM_TAINT_REGMEM_MULTIPLE_POINTER.format(addsub='add' if inc else 'sub')

    get_address = """
        mov {reg1}, %s
    """ % rn
    taint_block = ARM_TAINT_REGMEM_MULTIPLE.replace('GET_ADDRESS', get_address)

    more_store = ''
    for index, reg in enumerate(reglist):
        if not after:
            more_store += pointer
        if reg not in [capstone.arm.ARM_REG_PC,
                       capstone.arm.ARM_REG_SP,
                       capstone.arm.ARM_REG_LR]:
            params['offset_rs%d' % index] = register_smoffset(reg)
            more_store += ARM_TAINT_REGMEM_MULTIPLE_MORE_STORE % index
        if after:
            more_store += pointer
    taint_block = taint_block.replace("MORE_STORE", more_store)

    taint_block = taint_block.format(**params)
    return taint_block
