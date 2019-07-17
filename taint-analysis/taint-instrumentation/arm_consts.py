#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Himyth / AAA """

import keystone
import capstone

# data-processing instructions
ARM_INSTYPE_CALC = 0
ARM_INSTYPE_CALC_SAT = 1
ARM_INSTYPE_CMP = 2
ARM_INSTYPE_CLZ = 3
ARM_INSTYPE_SHIFT = 4
ARM_INSTYPE_MOVE = 5
ARM_INSTYPE_MOVT = 6
ARM_INSTYPE_MUL = 7
ARM_INSTYPE_LOAD = 8
ARM_INSTYPE_LOAD_DOUBLE = 9
ARM_INSTYPE_STORE = 10
ARM_INSTYPE_STORE_DOUBLE = 11
ARM_INSTYPE_MOVW = 12
ARM_INSTYPE_LDM = 13
ARM_INSTYPE_STM = 14
ARM_INSTYPE_PUSH = 15
ARM_INSTYPE_POP = 16

ARM_INSTYPES = {
    ARM_INSTYPE_CALC: [
        capstone.arm.ARM_INS_ADD,
        capstone.arm.ARM_INS_SUB,
        capstone.arm.ARM_INS_RSB,
        capstone.arm.ARM_INS_AND,
        capstone.arm.ARM_INS_ORR,
        capstone.arm.ARM_INS_EOR,
        capstone.arm.ARM_INS_BIC,
        capstone.arm.ARM_INS_ADC,
        capstone.arm.ARM_INS_SBC,
        capstone.arm.ARM_INS_RSC,
    ],

    ARM_INSTYPE_CALC_SAT: [
        capstone.arm.ARM_INS_QADD,
        capstone.arm.ARM_INS_QSUB,
        capstone.arm.ARM_INS_QDADD,
        capstone.arm.ARM_INS_QDSUB,
    ],

    ARM_INSTYPE_CMP: [
        capstone.arm.ARM_INS_CMN,
        capstone.arm.ARM_INS_CMP,
        capstone.arm.ARM_INS_TEQ,
        capstone.arm.ARM_INS_TST,
    ],

    ARM_INSTYPE_CLZ: [
        capstone.arm.ARM_INS_CLZ,
    ],

    ARM_INSTYPE_SHIFT: [
        capstone.arm.ARM_INS_ASR,
        capstone.arm.ARM_INS_LSR,
        capstone.arm.ARM_INS_LSL,
        capstone.arm.ARM_INS_ROR,
        capstone.arm.ARM_INS_RRX,
    ],

    ARM_INSTYPE_MOVE: [
        capstone.arm.ARM_INS_MOV,
        capstone.arm.ARM_INS_MVN,
    ],

    ARM_INSTYPE_MOVT: [
        capstone.arm.ARM_INS_MOVT,
    ],

    ARM_INSTYPE_MOVW: [
        capstone.arm.ARM_INS_MOVW,
    ],

    ARM_INSTYPE_MUL: [
        capstone.arm.ARM_INS_MUL,
        capstone.arm.ARM_INS_MLA,
        capstone.arm.ARM_INS_MLS,
    ],

    ARM_INSTYPE_LOAD: [
        capstone.arm.ARM_INS_LDR,
        capstone.arm.ARM_INS_LDRB,
        capstone.arm.ARM_INS_LDRSB,
        capstone.arm.ARM_INS_LDRH,
        capstone.arm.ARM_INS_LDRSH,
    ],

    ARM_INSTYPE_LOAD_DOUBLE: [
        capstone.arm.ARM_INS_LDRD,
    ],

    ARM_INSTYPE_STORE: [
        capstone.arm.ARM_INS_STR,
        capstone.arm.ARM_INS_STRB,
        capstone.arm.ARM_INS_STRH,
    ],

    ARM_INSTYPE_STORE_DOUBLE: [
        capstone.arm.ARM_INS_STRD,
    ],

    ARM_INSTYPE_LDM: [
        capstone.arm.ARM_INS_LDM,
        capstone.arm.ARM_INS_LDMDA,
        capstone.arm.ARM_INS_LDMDB,
        capstone.arm.ARM_INS_LDMIB,
    ],

    ARM_INSTYPE_STM: [
        capstone.arm.ARM_INS_STM,
        capstone.arm.ARM_INS_STMDA,
        capstone.arm.ARM_INS_STMDB,
        capstone.arm.ARM_INS_STMIB,
    ],

    ARM_INSTYPE_PUSH: [
        capstone.arm.ARM_INS_PUSH,
    ],

    ARM_INSTYPE_POP: [
        capstone.arm.ARM_INS_POP,
    ],
}

ARM_INSTYPE_WITH_CARRY = [
    capstone.arm.ARM_INS_ADC,
    capstone.arm.ARM_INS_SBC,
    capstone.arm.ARM_INS_RSC,
    capstone.arm.ARM_INS_RRX,
]


ARM_REG_SHIFT_IMM = [
    capstone.arm.ARM_SFT_INVALID,
    capstone.arm.ARM_SFT_ASR,
    capstone.arm.ARM_SFT_LSL,
    capstone.arm.ARM_SFT_LSR,
    capstone.arm.ARM_SFT_ROR,
]

ARM_REG_SHIFT_REG = [
    capstone.arm.ARM_SFT_ASR_REG,
    capstone.arm.ARM_SFT_LSL_REG,
    capstone.arm.ARM_SFT_LSR_REG,
    capstone.arm.ARM_SFT_ROR_REG,
]

ARM_ADDR_REGISTER = 0
ARM_ADDR_NEGTIVE = 1
ARM_ADDR_SHIFT = 2
ARM_ADDR_IMMEDIATE = 3
