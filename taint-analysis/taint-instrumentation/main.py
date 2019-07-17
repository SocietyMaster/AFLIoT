#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Himyth / AAA """

import keystone
import capstone
from arm_consts import *
from arm_taint_tpls import *

ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)
cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
cs.detail = True


# branches, rd in [pc, sp],
def check_if_needs_taint(insn):
    rd = insn.operands[0]
    if rd.type != capstone.arm.ARM_OP_REG:
        return False
    ignore_registers = [
        capstone.arm.ARM_REG_PC,
        capstone.arm.ARM_REG_SP,
        capstone.arm.ARM_REG_LR,
    ]
    return rd not in ignore_registers


def handle_conditional(insn):
    if insn.cc == capstone.arm.ARM_CC_INVALID:
        return None
    if insn.cc == capstone.arm.ARM_CC_AL:
        return '{conditional_body}'
    ccs = {
        capstone.arm.ARM_CC_EQ: 'eq',
        capstone.arm.ARM_CC_NE: 'ne',
        capstone.arm.ARM_CC_HS: 'hs',
        capstone.arm.ARM_CC_LO: 'lo',
        capstone.arm.ARM_CC_MI: 'mi',
        capstone.arm.ARM_CC_PL: 'pl',
        capstone.arm.ARM_CC_VS: 'vs',
        capstone.arm.ARM_CC_VC: 'vc',
        capstone.arm.ARM_CC_HI: 'hi',
        capstone.arm.ARM_CC_LS: 'ls',
        capstone.arm.ARM_CC_GE: 'ge',
        capstone.arm.ARM_CC_LT: 'lt',
        capstone.arm.ARM_CC_GT: 'gt',
        capstone.arm.ARM_CC_LE: 'le',
        capstone.arm.ARM_CC_AL: 'al',
    }
    pack = """
        b%s conditional_execute
        b conditional_bypass
    conditional_execute:
        {conditional_body}
    conditional_bypass:
    """ % ccs[insn.cc]
    return pack


def handle_flexible_operand(op):
    regs = []

    # only immediate
    if op.type == capstone.arm.ARM_OP_IMM:
        pass

    elif op.type == capstone.arm.ARM_OP_REG:
        regs.append(op.reg)

        if op.shift.type in [capstone.arm.ARM_SFT_RRX,
                             capstone.arm.ARM_SFT_RRX_REG]:
            regs.append(capstone.arm.ARM_REG_CPSR)

        # register shifted by immediate
        elif op.shift.type in ARM_REG_SHIFT_IMM:
            pass

        # register shifted by register
        elif op.shift.type in ARM_REG_SHIFT_REG:
            regs.append(op.shift.value)

        else:
            return None
    else:
        return None
    return regs


def handle_ins_calc(insn):
    dst_regs = [insn.operands[0].reg]
    src_regs = [insn.operands[1].reg]

    # if update flags
    if insn.update_flags:
        dst_regs.append(capstone.arm.ARM_REG_CPSR)

    # if calculate with carry
    if insn.id in ARM_INSTYPE_WITH_CARRY:
        src_regs.append(capstone.arm.ARM_REG_CPSR)

    src_regs.extend(handle_flexible_operand(insn.operands[2]))

    taint_block = make_intra_register_taint_block(src_regs, dst_regs)
    return taint_block


def handle_ins_calc_sat(insn):
    dst_regs = [insn.operands[0].reg]
    src_regs = [insn.operands[1].reg, insn.operands[2].reg]

    taint_block = make_intra_register_taint_block(src_regs, dst_regs)
    return taint_block


def handle_ins_shift(insn):
    dst_regs = [insn.operands[0].reg]
    src_regs = [insn.operands[1].reg]

    # if update flags
    if insn.update_flags or insn.id in ARM_INSTYPE_WITH_CARRY:
        dst_regs.append(capstone.arm.ARM_REG_CPSR)

    # if calculate with carry
    if insn.id in ARM_INSTYPE_WITH_CARRY:
        src_regs.append(capstone.arm.ARM_REG_CPSR)

    # op rd, rt, rs
    if len(insn.operands) >= 2:
        src_regs.append(insn.operands[2].reg)

    taint_block = make_intra_register_taint_block(src_regs, dst_regs)
    return taint_block


def handle_ins_mul(insn):
    dst_regs = [insn.operands[0].reg]
    src_regs = []

    # if update flags
    if insn.update_flags:
        dst_regs.append(capstone.arm.ARM_REG_CPSR)

    for op in insn.operands[1:]:
        if op.type == capstone.arm.ARM_OP_REG:
            src_regs.append(op.reg)

    taint_block = make_intra_register_taint_block(src_regs, dst_regs)
    return taint_block


def handle_ins_move(insn):
    dst_regs = [insn.operands[0].reg]
    src_regs = []

    # if update flags
    if insn.update_flags:
        dst_regs.append(capstone.arm.ARM_REG_CPSR)

    op1 = insn.operands[1]
    # op rd, imm
    if op1.type == capstone.arm.ARM_OP_IMM:
        pass

    # op rd, rm
    elif op1.type == capstone.arm.ARM_OP_REG:
        src_regs.append(op1.reg)

        if op1.shift.type in [capstone.arm.ARM_SFT_RRX,
                              capstone.arm.ARM_SFT_RRX_REG]:
            src_regs.append(capstone.arm.ARM_REG_CPSR)

        # op rd, rm, shift rs
        if len(insn.operands) > 2:
            src_regs.append(insn.operands[2].reg)

    taint_block = make_intra_register_taint_block(src_regs, dst_regs)
    return taint_block


# union(lowhalf, 0) == lowhalf, no effect
def handle_ins_movt(insn):
    return ''


# movw rd, #6
def handle_ins_movw(insn):
    taint_block = make_intra_register_taint_block([], [insn.operands[0].reg])
    return taint_block


def handle_ins_cmp(insn):
    dst_regs = [capstone.arm.ARM_REG_CPSR]
    src_regs = [insn.operands[0].reg]

    src_regs.extend(handle_flexible_operand(insn.operands[1]))

    taint_block = make_intra_register_taint_block(src_regs, dst_regs)
    return taint_block


def handle_ins_clz(insn):
    dst_regs = [insn.operands[0].reg]
    src_regs = [insn.operands[1].reg]

    taint_block = make_intra_register_taint_block(src_regs, dst_regs)
    return taint_block


def handle_ins_load(insn):
    if insn.id in [capstone.arm.ARM_INS_LDRB, capstone.arm.ARM_INS_LDRSB]:
        memsize = 1
    elif insn.id in [capstone.arm.ARM_INS_LDRH, capstone.arm.ARM_INS_LDRSH]:
        memsize = 2
    else:       # capstone.arm.ARM_INS_LDR
        memsize = 4

    dst_regs = [insn.operands[0].reg]
    src_regs = []

    locate = []

    dst_regs2 = []
    src_regs2 = []

    # pre-indexed and immediate
    # ldr rd, [rn{, rs{, lsl #5}}]{!}
    # ldr rd, [rn{, #6}]{!}
    if len(insn.operands) == 2:
        op2 = insn.operands[1]
        locate.extend([(ARM_ADDR_REGISTER, insn.reg_name(op2.mem.base))])
        src_regs.append(op2.mem.base)

        # ldr rd, [rn{, #6}]
        if op2.mem.index == 0:
            locate.append((ARM_ADDR_IMMEDIATE, op2.mem.disp))
        else:
            locate.append((ARM_ADDR_REGISTER, insn.reg_name(op2.mem.index)))
            src_regs.append(op2.mem.index)

            if op2.shift.type in [capstone.arm.ARM_SFT_RRX,
                                  capstone.arm.ARM_SFT_RRX_REG]:
                src_regs.append(capstone.arm.ARM_REG_CPSR)
                if insn.writeback:
                    src_regs2.append(capstone.arm.ARM_REG_CPSR)

            if insn.writeback:
                dst_regs2.append(op2.mem.base)
                src_regs2.append(dst_regs2[0])
                src_regs2.append(op2.mem.index)

            # ldr rd, [rn, rs, lsr #5]
            if op2.shift.type != capstone.arm.ARM_SFT_INVALID:
                locate.append((ARM_ADDR_SHIFT, op2.shift.type, op2.shift.value))

            if op2.subtracted:
                locate.append((ARM_ADDR_NEGTIVE, ))

    # ldr rd, [rn], rs{, lsl #5}
    # ldr rd, [rn], #5
    else:
        mem = insn.operands[1].mem
        locate.extend([(ARM_ADDR_REGISTER, insn.reg_name(mem.base))])
        src_regs.append(mem.base)

        if insn.operands[2].type == capstone.arm.ARM_OP_REG:
            if insn.operands[2].shift.type in [capstone.arm.ARM_SFT_RRX,
                                               capstone.arm.ARM_SFT_RRX_REG]:
                src_regs2.append(capstone.arm.ARM_REG_CPSR)

            dst_regs2.append(mem.base)
            src_regs2.append(dst_regs2[0])
            src_regs2.append(insn.operands[2].reg)

    taint_block = make_memory_to_register_taint_block(locate, memsize, dst_regs[0], insn)
    src_regs.append(dst_regs[0])
    taint_block += make_intra_register_taint_block(src_regs, dst_regs)
    if dst_regs[0] in dst_regs2:
        src_regs2.append(dst_regs[0])
    taint_block += make_intra_register_taint_block(src_regs2, dst_regs2)

    return taint_block


def handle_ins_load_double(insn):
    src_regs = []

    locate = []

    dst_regs2 = []
    src_regs2 = []

    # pre-indexed and immediate
    # ldrd rt, rt2, [rn{, rs}]{!}
    # ldrd rt, rt2, [rn{, #6}]{!}
    if len(insn.operands) == 3:
        op2 = insn.operands[2]
        locate.extend([(ARM_ADDR_REGISTER, insn.reg_name(op2.mem.base))])
        src_regs.append(op2.mem.base)

        # ldr rd, [rn{, #6}]
        if op2.mem.index == 0:
            locate.append((ARM_ADDR_IMMEDIATE, op2.mem.disp))
        else:
            locate.append((ARM_ADDR_REGISTER, insn.reg_name(op2.mem.index)))
            src_regs.append(op2.mem.index)

            if insn.writeback:
                dst_regs2.append(op2.mem.base)
                src_regs2.append(dst_regs2[0])
                src_regs2.append(op2.mem.index)

            if op2.subtracted:
                locate.append((ARM_ADDR_NEGTIVE, ))

    # ldrd rt, rt2, [rn], rs
    # ldrd rt, rt2, [rn], #6
    else:
        mem = insn.operands[2].mem
        locate.extend([(ARM_ADDR_REGISTER, insn.reg_name(mem.base))])
        src_regs.append(mem.base)

        if insn.operands[3].type == capstone.arm.ARM_OP_REG:
            dst_regs2.append(mem.base)
            src_regs2.append(dst_regs2[0])
            src_regs2.append(insn.operands[3].reg)

    dst = insn.operands[0].reg
    taint_block = make_memory_to_register_taint_block(locate, 4, dst, insn)
    taint_block += make_intra_register_taint_block(src_regs + [dst], [dst])
    if dst in dst_regs2:
        taint_block += make_intra_register_taint_block(src_regs2 + [dst], dst_regs2)
    else:
        taint_block += make_intra_register_taint_block(src_regs2, dst_regs2)

    dst = insn.operands[1].reg
    taint_block += make_memory_to_register_taint_block(locate, 4, dst, insn, addup=4)
    taint_block += make_intra_register_taint_block(src_regs + [dst], [dst])
    if dst in dst_regs2:
        taint_block += make_intra_register_taint_block(src_regs2 + [dst], dst_regs2)
    else:
        taint_block += make_intra_register_taint_block(src_regs2, dst_regs2)

    return taint_block


def handle_ins_store(insn):
    if insn.id in [capstone.arm.ARM_INS_STRB]:
        memsize = 1
    elif insn.id in [capstone.arm.ARM_INS_STRH]:
        memsize = 2
    else:       # capstone.arm.ARM_INS_STR
        memsize = 4

    src_regs = [insn.operands[0].reg]

    locate = []

    dst_regs2 = []
    src_regs2 = []

    # pre-indexed and immediate
    # str rd, [rn{, rs{, lsl #5}}]{!}
    # str rd, [rn{, #6}]{!}
    if len(insn.operands) == 2:
        op2 = insn.operands[1]
        locate.extend([(ARM_ADDR_REGISTER, insn.reg_name(op2.mem.base))])
        src_regs.append(op2.mem.base)

        # str, [rn{, #6}]
        if op2.mem.index == 0:
            locate.append((ARM_ADDR_IMMEDIATE, op2.mem.disp))
        else:
            locate.append((ARM_ADDR_REGISTER, insn.reg_name(op2.mem.index)))
            src_regs.append(op2.mem.index)

            if op2.shift.type in [capstone.arm.ARM_SFT_RRX,
                                  capstone.arm.ARM_SFT_RRX_REG]:
                src_regs.append(capstone.arm.ARM_REG_CPSR)
                if insn.writeback:
                    src_regs2.append(capstone.arm.ARM_REG_CPSR)

            if insn.writeback:
                dst_regs2.append(op2.mem.base)
                src_regs2.append(dst_regs2[0])
                src_regs2.append(op2.mem.index)

            # ldr rd, [rn, rs, lsr #5]
            if op2.shift.type != capstone.arm.ARM_SFT_INVALID:
                locate.append((ARM_ADDR_SHIFT, op2.shift.type, op2.shift.value))

            if op2.subtracted:
                locate.append((ARM_ADDR_NEGTIVE, ))

    # str rd, [rn], rs{, lsl #5}
    # str rd, [rn], #5
    else:
        mem = insn.operands[1].mem
        locate.extend([(ARM_ADDR_REGISTER, insn.reg_name(mem.base))])
        src_regs.append(mem.base)

        if insn.operands[2].type == capstone.arm.ARM_OP_REG:
            if insn.operands[2].shift.type in [capstone.arm.ARM_SFT_RRX,
                                               capstone.arm.ARM_SFT_RRX_REG]:
                src_regs2.append(capstone.arm.ARM_REG_CPSR)

            dst_regs2.append(mem.base)
            src_regs2.append(dst_regs2[0])
            src_regs2.append(insn.operands[2].reg)

    taint_block = make_register_to_memory_taint_block(locate, memsize, src_regs, insn)
    taint_block += make_intra_register_taint_block(src_regs2, dst_regs2)

    return taint_block


def handle_ins_store_double(insn):
    src_regs = []

    locate = []

    dst_regs2 = []
    src_regs2 = []

    # pre-indexed and immediate
    # strd rt, rt2, [rn{, rs}]{!}
    # strd rt, rt2, [rn{, #6}]{!}
    if len(insn.operands) == 3:
        op2 = insn.operands[2]
        locate.extend([(ARM_ADDR_REGISTER, insn.reg_name(op2.mem.base))])
        src_regs.append(op2.mem.base)

        # ldr rd, [rn{, #6}]
        if op2.mem.index == 0:
            locate.append((ARM_ADDR_IMMEDIATE, op2.mem.disp))
        else:
            locate.append((ARM_ADDR_REGISTER, insn.reg_name(op2.mem.index)))
            src_regs.append(op2.mem.index)

            if insn.writeback:
                dst_regs2.append(op2.mem.base)
                src_regs2.append(dst_regs2[0])
                src_regs2.append(op2.mem.index)

            if op2.subtracted:
                locate.append((ARM_ADDR_NEGTIVE, ))

    # strd rt, rt2, [rn], rs
    # strd rt, rt2, [rn], #6
    else:
        mem = insn.operands[2].mem
        locate.extend([(ARM_ADDR_REGISTER, insn.reg_name(mem.base))])
        src_regs.append(mem.base)

        if insn.operands[3].type == capstone.arm.ARM_OP_REG:
            dst_regs2.append(mem.base)
            src_regs2.append(dst_regs2[0])
            src_regs2.append(insn.operands[3].reg)

    src = insn.operands[0].reg
    taint_block = make_register_to_memory_taint_block(locate, 4, src_regs + [src], insn)
    taint_block += make_intra_register_taint_block(src_regs2, dst_regs2)

    src = insn.operands[1].reg
    taint_block += make_register_to_memory_taint_block(locate, 4, src_regs + [src], insn, addup=4)

    return taint_block


def handle_ins_ldm(insn):
    rn = insn.reg_name(insn.operands[0].reg)
    reglist = [insn.operands[i].reg for i in xrange(1, len(insn.operands))]
    inc = insn.id in [capstone.arm.ARM_INS_LDM, capstone.arm.ARM_INS_LDMIB]
    after = insn.id in [capstone.arm.ARM_INS_LDM, capstone.arm.ARM_INS_LDMDA]
    taint_block = make_multiple_memory_to_register_taint_block(rn, reglist, inc, after, insn)
    return taint_block


def handle_ins_stm(insn):
    rn = insn.reg_name(insn.operands[0].reg)
    reglist = [insn.operands[i].reg for i in xrange(1, len(insn.operands))]
    inc = insn.id in [capstone.arm.ARM_INS_STM, capstone.arm.ARM_INS_STMIB]
    after = insn.id in [capstone.arm.ARM_INS_STM, capstone.arm.ARM_INS_STMDA]
    taint_block = make_multiple_register_to_memory_taint_block(rn, reglist, inc, after, insn)
    return taint_block


def handle_ins_push(insn):
    rn = insn.reg_name(capstone.arm.ARM_REG_SP)
    reglist = [insn.operands[i].reg for i in xrange(0, len(insn.operands))]
    inc = False
    after = False
    taint_block = make_multiple_register_to_memory_taint_block(rn, reglist, inc, after, insn)
    return taint_block


def handle_ins_pop(insn):
    rn = insn.reg_name(capstone.arm.ARM_REG_SP)
    reglist = [insn.operands[i].reg for i in xrange(0, len(insn.operands))]
    inc = True
    after = True
    taint_block = make_multiple_memory_to_register_taint_block(rn, reglist, inc, after, insn)
    return taint_block


def generate_taint_block(insn):
    if not check_if_needs_taint(insn):
        return ''

    handlers = {
        ARM_INSTYPE_CALC: handle_ins_calc,
        ARM_INSTYPE_CALC_SAT: handle_ins_calc_sat,
        ARM_INSTYPE_CMP: handle_ins_cmp,
        ARM_INSTYPE_CLZ: handle_ins_clz,
        ARM_INSTYPE_SHIFT: handle_ins_shift,
        ARM_INSTYPE_MOVE: handle_ins_move,
        ARM_INSTYPE_MOVT: handle_ins_movt,
        ARM_INSTYPE_MOVW: handle_ins_movw,
        ARM_INSTYPE_MUL: handle_ins_mul,
        ARM_INSTYPE_LOAD: handle_ins_load,
        ARM_INSTYPE_LOAD_DOUBLE: handle_ins_load_double,
        ARM_INSTYPE_STORE: handle_ins_store,
        ARM_INSTYPE_STORE_DOUBLE: handle_ins_store_double,
        ARM_INSTYPE_LDM: handle_ins_ldm,
        ARM_INSTYPE_STM: handle_ins_stm,
        ARM_INSTYPE_PUSH: handle_ins_push,
        ARM_INSTYPE_POP: handle_ins_pop,
    }

    for _type in ARM_INSTYPES:
        if insn.id in ARM_INSTYPES[_type]:
            taint_block = handlers[_type](insn)
            taint_block = handle_conditional(insn).format(conditional_body=taint_block)
            return taint_block

    return None


def main():
    target = """
    str r1, [r2]
    str r1, [r2, #0x20]
    str r1, [r2, #0x20]!
    str r1, [r2, r3]
    str r1, [r2, r3]!
    str r1, [r2, -r3, lsr #3]
    str r1, [r2, r3, lsr #3]!
    str r1, [r2], r3
    str r1, [r2], r3, lsr #3
    strd r0, r1, [r2, r3]!
        """
    target = """
    ldm r1!, {r2, r3, r4}
    stm r1!, {r2, r3, r4}
    push {r2, r3, r4}
    pop {r2, r3, r4}
        """
    # def symbol_resolver(symbol, value):
    #     value[0] = 0x1000
    #     return True
    #
    # ks.sym_resolver = symbol_resolver
    for insn in cs.disasm(ks.asm(target, as_bytes=True)[0], 0):
        print insn.mnemonic, insn.op_str
        taint_block = generate_taint_block(insn)
        print taint_block + 'nop'
        # print ks.asm(taint_block + 'nop', as_bytes=True)


if __name__ == '__main__':
    main()
