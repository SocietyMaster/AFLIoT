#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Himyth / AAA """

import re
import keystone
import capstone

from elf_consts import *
from elf_utils import verbose_log


class Assembler(object):

    def __init__(self, elf):
        self.machine = elf.ehdr.e_machine
        self.ei_data = elf.ehdr.e_ident.ei_data
        self.packer = elf.packer
        self.missing_symbol = None

        opts = {ELFDATA2LSB: (capstone.CS_MODE_LITTLE_ENDIAN,
                              keystone.KS_MODE_LITTLE_ENDIAN),
                ELFDATA2MSB: (capstone.CS_MODE_BIG_ENDIAN,
                              keystone.KS_MODE_BIG_ENDIAN)}
        cs_mode, ks_mode = opts[self.ei_data]

        assemblers = {EM_ARM: ARM_Assembler,
                      EM_386: x86_Assembler,
                      EM_X86_64: x64_Assembler}
        if self.machine not in assemblers:
            raise ValueError("No assembler found for current architecture")
        ArchASM = assemblers[self.machine]
        self.archasm = ArchASM(packer=self.packer, asm=self.do_assemble,
                               disasm=self.do_disassemble)

        opts = {EM_386: (keystone.KS_ARCH_X86, keystone.KS_MODE_32 | ks_mode),
                EM_X86_64: (keystone.KS_ARCH_X86, keystone.KS_MODE_64 | ks_mode),
                EM_ARM: (keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM | ks_mode)}
        self.ks = keystone.Ks(*opts[self.machine])

        opts = {EM_386: (capstone.CS_ARCH_X86, capstone.CS_MODE_32 | cs_mode),
                EM_X86_64: (capstone.CS_ARCH_X86, capstone.CS_MODE_64 | cs_mode),
                EM_ARM: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | cs_mode)}
        self.cs = capstone.Cs(*opts[self.machine])
        self.cs.detail = True

    def do_assemble(self, code, vaddr):
        try:
            # if the code ends with newline, keystone will ignore the last line,
            # so we add an extra blank space to the end, then asm shall return count
            # which equals to line counts in the code
            code += ' ' if code[-1] == '\n' else ''
            asm, count = self.ks.asm(code, addr=vaddr, as_bytes=True)
        except keystone.KsError, e:
            if keystone.KS_ERR_ASM_SYMBOL_MISSING == e.errno:
                raise ValueError('Missing symbol "%s"' % self.missing_symbol)
            raise e
        if count != code.count('\n') + 1:
            raise ValueError('Assembly count does not match')
        return asm, count

    # applying resolved symbol address to assembly and compile
    #
    # by simply replacing label to integer literal could result in unexpected behaviors,
    # for example, say we want to pick a qword from some fixed address like this,
    # mov rax, qword ptr [0x08040000]
    # mov rcx, qword ptr [0x08040000]
    # these 2 similar instructions will behave differently after assembling
    # movabs rax, qword ptr [0x8040000]
    # mov rcx, qword ptr [rip + 0x8040000]
    #
    # this happens when x86-64 introducing the pc-relative addressing, which is not a
    # problem in 32 bit mode. I quote some text from intel manual:
    # In 64-bit mode, instructions that use ModR/M addressing can use RIP-relative
    # addressing. Without RIP-relative addressing, all ModR/M instruction modes address
    # memory relative to zero. RIP-relative addressing allows specific ModR/M modes to
    # address memory relative to the 64-bit RIP using a signed 32-bit displacement. This
    # provides an offset range of ±2GB from the RIP.
    #
    # so when pc-relative addressing activates, the immediate displacement is treated as
    # a signed 32 bit integer, the higher bits are ignored, if we supply 0xdeaddeadbeef
    # as displacement, the result displacement will be 0xffffffffdeadbeef. in the former
    # context, rax assignment using a absolute addressing, and rcx assignment activates
    # pc-relative addressing. note that rax is the only register could use a 64 bit
    # absolute address.
    #
    # we are not totally rejecting pc-relative, this is a fine feature which may even
    # eliminate relocation when turned into PIC mode. the problem here is, when we supply
    # an address to an instruction which using register other than rax, we wish keystone
    # knowing this is a offset, and generate instruction like this,
    # mov rcx, qword ptr [rip + address - next_pc]
    # but not the former one, where it treat the address as a displacement.
    #
    # funny thing is, if we supply address as a label in the assembly, keystone will do
    # what we want. this means keystone will do right on address or offset. so if we can
    # somehow tell keystone the number serves as a address or offset, there may not be
    # problems any more.
    #
    # actually, keystone provides an interface for symbol resolving, but not in the widely
    # used 0.9.1 version. in order to apply dynamic symbol resolving instead of simply
    # replacing the label literal, newer version is needed.
    #
    # emmm... after fixing several bugs in keystone-engine, now we have a working version
    # here: https://github.com/Himyth/keystone
    #
    # so here is the plan. we will supply a symbol resolver to keystone instead of replacing
    # symbol to number literal ourselves, this will show keystone a hint about addresses
    # or offsets. the resolver will return 0 for every symbol on the first run, and return
    # exact symbol value after finalization.
    def generate_code(self, code, vaddr=0, finder=None, disp=None):
        if finder is None:
            # return True for all symbols, wired value 0xdeadbeef to keep assembler
            # from doing something like "jz near" optimization.
            def symbol_resolver(_, value):
                value[0] = 0xdeadbeef
                return True
        else:
            def symbol_resolver(symbol, value):
                _value = finder(symbol)
                if _value is not None:
                    value[0] = _value
                    return True
                # record which symbol is missing
                self.missing_symbol = symbol
                return False

        # we should replace some constants
        if disp is not None:
            placeholder, offset = disp
            code = re.sub(r'\b' + placeholder + r'\b', '(%d)' % offset, code)

        if not hasattr(self.ks, 'sym_resolver'):
            raise ValueError("Use a newer version of keystone")
        self.ks.sym_resolver = symbol_resolver
        return self.do_assemble(code, vaddr)

    # do actual disassemble work
    def do_disassemble(self, code, vaddr, count=0):
        textcodes, insns, total_size = [], [], 0
        for insn in self.cs.disasm(code, offset=vaddr, count=count):
            textcodes.append(' '.join([insn.mnemonic, insn.op_str]))
            insns.append(insn)
            total_size += insn.size
        textcode = '\n'.join(textcodes)
        return textcode, insns, total_size

    # disassemble instruction at vaddr, and wrap it
    def wrap_insert_code(self, sdata, offset, vaddr, nbound):
        nbound = 2 ** 64 if nbound is None else nbound
        bback = self.check_branch_bound(sdata, offset, vaddr, nbound)
        return self.archasm.wrap_insert_code(sdata, offset, vaddr, bback)

    # return jump instruction literal
    def make_branch(self, target):
        return self.archasm.make_branch(target)

    # return code snippet which call init_entries between 2 labels
    def make_csu_init(self, init_array_offset, init_array_count):
        return self.archasm.make_csu_init(init_array_offset, init_array_count)

    # check if the given bound fits for a branch, and return branch back head
    def check_branch_bound(self, sdata, offset, vaddr, nbound):
        # make a probe branch instruction
        branch = self.make_branch('target')
        asm, _ = self.generate_code(branch, vaddr=vaddr)

        # find the first instruction we can branch back
        _, insns, _ = self.do_disassemble(sdata[offset:offset + 0x10], vaddr, count=10)
        cursize = 0
        for insn in insns:
            cursize += insn.size
            if cursize >= len(asm):
                break
        else:
            raise ValueError('Abnormal long branch "%s" for %#x' % (branch, offset))

        # check if bound is too small or return branch back target
        bback = cursize + vaddr
        if nbound < bback:
            raise ValueError("Bound is too small for insertion(%#x)" % vaddr)
        return bback

    # add relocation for inserted code, only works under PIE
    def make_code_relative(self, elf, verbose):
        if not elf.pie:
            return False
        verbose_log('Adding relative relocations for inserted patch code.', verbose)
        return self.archasm.make_code_relative(elf)


# interface for assemblers from different architectures
class Arch_Assembler(object):

    def __init__(self, packer, asm, disasm):
        self.packer = packer
        self.asm = asm
        self.disasm = disasm

    def wrap_insert_code(self, sdata, offset, vaddr, bback):
        raise ValueError('Current architecture does not support code insertion')

    def make_branch(self, target):
        raise ValueError('Current architecture does not have a jumper generator')

    def make_csu_init(self, init_array_offset, init_array_count):
        raise ValueError('Current architecture does not have a csu_init generator')

    def make_code_relative(self, elf):
        raise ValueError('Current architecture does not support code relocation')


class x64_Assembler(Arch_Assembler):

    def __init__(self, packer, asm, disasm):
        super(x64_Assembler, self).__init__(packer, asm, disasm)

    def wrap_insert_code(self, sdata, offset, vaddr, bback):
        code = sdata[offset:offset + (bback - vaddr)]
        _, insns, size = self.disasm(code, vaddr, 0x10)  # 0x10 will do
        if size < bback - vaddr:
            return '', 0

        totalsize = 0
        wrappers = []
        disp = None
        for insn in insns:
            wrap_type, instr = self.check_wrap_type(insn)

            # take the original instruction
            if wrap_type == X64_WRAP_NONE:
                wrappers.append(instr)

            # for rip-relative addressing, replace rip to sum(rip, displacement),
            # where displacement should be replaced when patch code is determined.
            elif wrap_type == X64_WRAP_NORMAL:
                disp = 'disp_x64_%x' % vaddr    # offset from wrapper to home
                adjust = re.sub(r'\brip\b',
                                '(rip + %s + %#x)' % (disp, totalsize),
                                instr)
                wrappers.append(adjust)

            totalsize += insn.size

        wrappers.append('jmp {bback}'.format(bback=bback))
        wrapper = '\n'.join(wrappers)
        return wrapper, None, bback - vaddr, disp

    # check if there are pc-related addressings, there are only 2 types of pc-relative
    # instruction, the first is control-transfer instruction, which we will ignore just as
    # x86. the second is memory addressing with rip + displacement, this is what we shall
    # deal with.
    def check_wrap_type(self, insn):
        instr = ' '.join([insn.mnemonic, insn.op_str])

        for operand in insn.operands:
            if (operand.type == capstone.x86.X86_OP_MEM and
                    operand.mem.base == capstone.x86.X86_REG_RIP):
                return X64_WRAP_NORMAL, instr

        return X64_WRAP_NONE, instr

    def make_branch(self, target):
        return 'jmp %s' % str(target)

    def make_csu_init(self, init_array_offset, init_array_count):
        csu_init = """
            push r12    # save registers
            push rbx
            push rbp
            push rdx    # save args for init function
            push rsi
            push rdi
            lea r12, qword ptr [{init_array_offset}]    # array start address
            mov rbp, {init_array_count}                 # array count
            xor rbx, rbx
        nextcall:
            pop rdi     # restore args, and stack
            pop rsi
            pop rdx
            sub rsp, 0x18
            call qword ptr [r12 + rbx * 8]              # call init function
            add rbx, 1
            cmp rbp, rbx
            jnz nextcall    # loop control
            add rsp, 0x18
            pop rbp         # restore
            pop rbx
            pop r12
            ret
        """.format(init_array_offset=init_array_offset, init_array_count=init_array_count)
        return csu_init


class x86_Assembler(Arch_Assembler):

    def __init__(self, packer, asm, disasm):
        super(x86_Assembler, self).__init__(packer, asm, disasm)

    # according to intel assembly manual here:
    # In IA-32 architecture and compatibility mode, addressing relative to the instruction
    # pointer is available only with control-transfer instructions.
    #
    # there is no eip-relative addressing in x86, and for all control-transfer instruction,
    # such as jmp/jcc/call etc. we do not have to worry about them because all relative
    # control-transfers using an immediate number as offset, which capstone will take care
    # of during disassembling. so all that left is wrapping it with a branch back
    def wrap_insert_code(self, sdata, offset, vaddr, bback):
        code = sdata[offset:offset + (bback - vaddr)]
        textcode, insns, size = self.disasm(code, vaddr, 0x10)  # 0x10 will do
        if size < bback - vaddr:
            return '', 0
        wrapper = '\n'.join([
            textcode,
            'jmp {bback}'.format(bback=bback)
        ])
        return wrapper, None, bback - vaddr, None

    def make_branch(self, target):
        return 'jmp %s' % str(target)

    def make_csu_init(self, init_array_offset, init_array_count):
        csu_init = """
            push ebx    # save registers
            push edi
            push esi
            lea ebx, dword ptr [{init_array_offset}]    # array start address
            mov esi, {init_array_count}                 # array count
            xor edi, edi
        nextcall:
            push dword ptr [esp + 0x18]             # push args onto stack
            push dword ptr [esp + 0x18]
            push dword ptr [esp + 0x18]
            call dword ptr [ebx + edi * 4]          # call init function
            add esp, 0xc
            add edi, 1
            cmp edi, esi
            jnz nextcall  # loop control
            pop esi
            pop edi
            pop ebx               # restore
            ret
        """.format(init_array_offset=init_array_offset, init_array_count=init_array_count)
        return csu_init


class ARM_Assembler(Arch_Assembler):

    def __init__(self, packer, asm, disasm):
        super(ARM_Assembler, self).__init__(packer, asm, disasm)

    def wrap_insert_code(self, sdata, offset, vaddr, bback):
        code = sdata[offset:offset + Elf32_Addr]
        _, insns, size = self.disasm(code, vaddr, 1)    # only 1 instruction
        if size == 0:
            return '', 0

        if bback != vaddr + size:
            msg = "Insertion(%#x) only support 1 instruction wrap for ARM." % vaddr
            raise ValueError(msg)

        textcode, rlabels = self.do_wrap_insert_code(insns[0])
        return textcode, rlabels, size, None

    # when wrapping ARM instructions, we have to save the context if any will be changed,
    # that is, saving the registers as well as the flags. registers are straightforward,
    # for flags(etc. cpsr), i quote following from the ARM manual:
    # http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0801a/Chdijedg.html
    #
    # Most instructions update the condition flags only if the S suffix is specified. The
    # instructions CMP, CMN, TEQ, and TST always update the flags.
    #
    # so if the instructions we wrapped with have no S suffix specified, and we do not use
    # instructions like CMP, CMN, TEQ, and TST, there is no need to save the flags, since
    # it will not be changed at all, this shall be taken into consideration in the future
    def do_wrap_insert_code(self, insn):
        wrap_type, instr, registers = self.check_wrap_type(insn)
        wrapper = ''
        rlabels = dict()
        candidates = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8',
                      'sb', 'sl', 'fp', 'ip', 'lr']

        # we dont have to do any trick here, just execute the original instruction
        # and jump back to next instruction after it
        if wrap_type == ARM_WRAP_NONE:
            wrapper = '\n'.join([
                instr,
                'b {entry} + 4'.format(entry=insn.address)
            ])

        # for following types, we have to select a pivot register, save its content and
        # assign it with original vaddr plus 8, which is the pc when executing this instrution
        # back home. then replace pc register in the instruction with this pivot, after
        # executing it, we can restore the pivot and jump back to home.
        # + add reg, pc, operand2
        # + ldr reg, [pc(, operand2)?]
        # + mov reg, pc
        #
        # PS: x64 strategy by adding replacement wont work exactly the same for arm, since
        # the range of immediate is limited to 12 bits, which is [-0x1000, +0x1000], and
        # normally the arm binary page is aligned to 0x10000, this is absolutely too large
        # in terms of displacement.
        if wrap_type == ARM_WRAP_NORMAL:

            # select a free pivot registers
            pivot = list(set(candidates) - set(registers))[0]

            # replace pc register to pivot
            instr = instr.replace('pc', pivot)

            # using label instead of absolute number in case of PIE situation
            original_pc_label = 'wrap_normal_opc_%x' % insn.address
            rlabels[original_pc_label] = insn.address

            # we only change the pivot register, nothing else including flags is changed
            wrapper = """
            stmdb sp, {{{pivot}}}       @ store pivot into stack, but do not change sp
            ldr {pivot}, ={entry} + 8   @ load original pc into pivot, pipeline add 8
            {instr}                     @ pc reference replaced to pivot
            ldmdb sp, {{{pivot}}}       @ restore pivot, still, sp stays put
            b {entry} + 4               @ jump back to home
            """.format(pivot=pivot, entry=original_pc_label, instr=instr)

        # this type of instruction pushs a list of registers(contain pc) onto stack, push works by
        # placing the registers onto the stack with order, where the highest numbered register will
        # stay on the top of the stack and vise versa. so we can push pc manually, who will always
        # be on the top, restore pivot and push the rest.
        # + push {(... ,)pc}
        if wrap_type == ARM_WRAP_PUSHPC:

            # select a free pivot registers
            pivot = list(set(candidates) - set(registers))[0]

            # rest of the registers
            oregs = list(set(registers) - {'pc'})
            push_others = 'push {%s}' % ', '.join(oregs) if oregs else ''

            # using label instead of absolute number in case of PIE situation
            original_pc_label = 'wrap_pushpc_opc_%x' % insn.address
            rlabels[original_pc_label] = insn.address

            # check if we will execute this
            bback = ''
            rcond = self.negate_condition(insn.cc)
            if rcond:
                bback = 'b{rcond} {entry} + 4 @ jump back home if condition failed'
                bback = bback.format(rcond=rcond, entry=original_pc_label)

            # we only change the pivot register, nothing else including flags is changed
            wrapper = """
            {bback}
            sub sp, sp, 4               @ make room for pc
            stmdb sp, {{{pivot}}}       @ store pivot into stack, but do not change sp
            ldr {pivot}, ={entry} + 8   @ load original pc into pivot, pipeline add 8
            stmia sp, {{{pivot}}}       @ store pivot(pc), do not change sp
            ldmdb sp, {{{pivot}}}       @ restore pivot, still, sp stays put
            {push_others}               @ push the rest
            b {entry} + 4               @ jump back to home
            """.format(pivot=pivot, entry=original_pc_label, push_others=push_others,
                       bback=bback)

        # for 2 types of switch branch here, we can wrap them up using a same strategy. the problem
        # here is both `ldr` and `add` operate directly on pc, which will then make a instant
        # branch to the target location. if we use a pivot, we have to restore it at the same time
        # we make the final branch. so we will store the pivot and the target pc onto the stack, and
        # pop back to them in a single instruction.
        # + ldr.. pc, [pc, reg, lsl#2] ; switch jump
        # + add.. pc, pc, reg, lsl#2 ; switch jump
        if wrap_type == ARM_WRAP_JUMPTABLE:

            # select a free pivot registers
            pivot = list(set(candidates) - set(registers))[0]

            # replace pc register to pivot
            instr = instr.replace('pc', pivot)

            # using label instead of absolute number in case of PIE situation
            original_pc_label = 'wrap_jumptable_opc_%x' % insn.address
            rlabels[original_pc_label] = insn.address

            # check if we will execute this
            bback = ''
            rcond = self.negate_condition(insn.cc)
            if rcond:
                bback = 'b{rcond} {entry} + 4 @ jump back home if condition failed'
                bback = bback.format(rcond=rcond, entry=original_pc_label)

            # we only change the pivot register, nothing else including flags is changed
            wrapper = """
            {bback}
            sub sp, sp, 4               @ make room for pc
            stmdb sp, {{{pivot}}}       @ store pivot into stack, but do not change sp
            add sp, sp, 4               @ restore sp above pc
            ldr {pivot}, ={entry} + 8   @ load original pc into pivot, pipeline add 8
            {instr}                     @ pivot will be target pc value
            stmdb sp, {{{pivot}}}       @ store pivot into stack, but do not change sp
            ldmdb sp, {{{pivot}, pc}}   @ pop pivot with pc, pc always takes higher one
            """.format(pivot=pivot, entry=original_pc_label, instr=instr, bback=bback)

        return wrapper, rlabels

    def negate_condition(self, cc):
        opposites = {
            capstone.arm.ARM_CC_EQ: 'ne',
            capstone.arm.ARM_CC_NE: 'eq',
            capstone.arm.ARM_CC_HS: 'lo',
            capstone.arm.ARM_CC_LO: 'hs',
            capstone.arm.ARM_CC_MI: 'pl',
            capstone.arm.ARM_CC_PL: 'mi',
            capstone.arm.ARM_CC_VS: 'vc',
            capstone.arm.ARM_CC_VC: 'vs',
            capstone.arm.ARM_CC_HI: 'ls',
            capstone.arm.ARM_CC_LS: 'hi',
            capstone.arm.ARM_CC_GE: 'lt',
            capstone.arm.ARM_CC_LT: 'ge',
            capstone.arm.ARM_CC_GT: 'le',
            capstone.arm.ARM_CC_LE: 'gt'
        }
        return opposites.get(cc, None)

    def check_register_operands(self, insn):
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

    # check if there are pc-related addressings, and we need wrap it
    # return with wrap type, instruction literal and all registers it use
    def check_wrap_type(self, insn):
        instr = ' '.join([insn.mnemonic, insn.op_str])

        # omit all branch instruction, since they are either followed by a immediate,
        # which we can reassemble it without additional efforts, or followed by a
        # register, then current pc will not affect the behavior
        if insn.id in [capstone.arm.ARM_INS_BL, capstone.arm.ARM_INS_BLX,
                       capstone.arm.ARM_INS_BX, capstone.arm.ARM_INS_BXJ,
                       capstone.arm.ARM_INS_B]:
            return ARM_WRAP_NONE, instr, None

        # omit all instructions without referencing pc
        registers = self.check_register_operands(insn)
        if 'pc' not in registers:
            return ARM_WRAP_NONE, instr, None

        # loading to pc from non-pc-related location, it is safe to ignore these types:
        # + ldr pc, [...](, ...)?, but pc shall not appear in the second part
        # + ldm.. reg, {(..., )pc}
        # + pop {(..., )pc}, this equals to ldm with reg == sp
        # + mov.. pc, lr, typical return with condition
        # + sub pc, ...
        if ((instr.startswith('ldr pc, [') and 'pc' not in instr[9:]) or
                instr.startswith('ldm') or
                insn.id == capstone.arm.ARM_INS_POP or
                (insn.id == capstone.arm.ARM_INS_MOV and insn.op_str == 'pc, lr') or
                (instr.startswith('sub pc, ') and 'pc' not in instr[8:])):
            return ARM_WRAP_NONE, instr, None

        # here are 2 types of switch branch, the first one uses a jump table for direct jump,
        # and the second one uses multiple branch instructions with a relative jump:
        # + ldr.. pc, [pc, reg, lsl#2] ; switch jump
        # + add.. pc, pc, reg, lsl#2 ; switch jump
        if ((insn.id == capstone.arm.ARM_INS_LDR and insn.op_str.startswith('pc, [pc, ')) or
                (insn.id == capstone.arm.ARM_INS_ADD and insn.op_str.startswith('pc, pc, '))):
            return ARM_WRAP_JUMPTABLE, instr, registers

        # push a list of registers(contain pc) onto stack
        # + push {(... ,)pc}
        if insn.id == capstone.arm.ARM_INS_PUSH:
            return ARM_WRAP_PUSHPC, instr, registers

        # what is left here should be one of these, where the first register shall
        # not be pc itself. this is the situation where we should handle normally:
        # + add reg, pc, operand2
        # + ldr reg, [pc(, operand2)?]
        # + mov reg, pc
        if not ((insn.id == capstone.arm.ARM_INS_ADD and
                 re.match(r'(?!pc)\w+, pc, ', insn.op_str)) or
                (insn.id == capstone.arm.ARM_INS_LDR and
                 re.match(r'(?!pc)\w+, \[pc(, .*)?\]', insn.op_str)) or
                (insn.id == capstone.arm.ARM_INS_MOV and
                 re.match(r'(?!pc)\w+, pc', insn.op_str))):
            raise ValueError('Unexcepted Instruction "%s" @ %#x found.' % (instr, insn.address))
        return ARM_WRAP_NORMAL, instr, registers

    def make_branch(self, target):
        return 'b %s' % str(target)

    def make_csu_init(self, init_array_offset, init_array_count):
        csu_init = """
            stmfd sp!, {{r3 - r6, lr}}      @ save registers
            stmfd sp!, {{r0 - r2}}          @ save args
            ldr r5, ={init_array_offset}    @ array start address
            ldr r6, ={init_array_count}     @ array count
            eor r4, r4, r4
        nextcall:
            ldmfd sp, {{r0 - r2}}       @ restore args, stack do not change
            ldr r3, [r5], #4
            blx r3                      @ call init function
            add r4, r4, 1
            cmp r4, r6                  @ loop control
            bne nextcall
            add sp, sp, 0xc             @ pop 3 saved args
            ldmfd sp!, {{r3 - r6, pc}}  @ restore
        """.format(init_array_offset=init_array_offset, init_array_count=init_array_count)
        return csu_init

    # add relative relocation on ldr xx, =xxx when xxx is a address
    def make_code_relative(self, elf):

        rgx_ldr = re.compile(r'.*ldr .*,.*=', re.IGNORECASE)
        rgx_ldrsym = re.compile(r'.*ldr .*,.*=.*\b(%s)\b' % '|'.join(list(elf.relocatable_labels)),
                                re.IGNORECASE)

        relatives = []
        for label, (code, asm) in elf.pcodes.iteritems():
            insn_count = data_count = 0
            rel_datas = []

            # check instruction literal for offset information
            for line in code.split('\n'):

                # remove comment
                if '@' in line:
                    line = line[:line.index('@')]

                # strip whitespaces, bypass label or empty lines
                line = line.strip()
                if ':' in line or line == '':
                    continue

                # check if additional data part advances
                if rgx_ldr.match(line):
                    if rgx_ldrsym.match(line):
                        rel_datas.append(data_count)
                    data_count += 1

                # instruction sure advances
                insn_count += 1

            # check if our literal parse is correct comparing to keystone compilation
            if (insn_count + data_count) * 4 != len(asm):
                raise ValueError('Parsing failed for code:\n%s' % code)

            # now add relative relocation for all additional data part
            for rel in rel_datas:
                offset = (rel + insn_count) * 4
                rlabel = 'patch_code_%s_%d' % (label, offset)
                elf.add_relative_label(rlabel, label, offset)
                relatives.append(rlabel)

        # finalize `many` relative relocations, this shall be faster
        elf.reloc.add_relative_many(relatives)

        # add DT_TEXTREL in case we need to relocatin on .text
        if not elf.dynamic.find_by_type(DT_TEXTREL):
            elf.dynamic.add(DT_TEXTREL, 0)

        return True
