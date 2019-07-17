#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Himyth / AAA """

from elfpatcher import ELF


def test_x64(infile, outfile):
    elf = ELF(infile)

    # add imported function from external library
    elf.add_imported_library('lib_x64_library.so')
    elf.add_imported_symbol('export_function', '_export_function', 'lib_x64_library.so')

    elf.add_data('constdata', 'C' * 5 + '\x00')
    elf.add_pointer('constdata_pointer', 'constdata')
    elf.add_code('pointer_verifier', """
        push rdi
        mov rdi, qword ptr [constdata_pointer]
        call qword ptr [_puts]
        pop rdi
        ret
    """)
    elf.add_init_function('pointer_verifier')

    elf.add_tls_bss_data('tls_bss_long', 0x4, 'tls_bss_long_offset')
    elf.add_tls_bss_data('tls_bss_char_array', 0x100, 'tls_bss_char_array_offset')

    elf.add_imported_symbol('puts', '_puts')
    elf.add_data('init_message', 'Hello From Init Array\x00')
    elf.add_code("new_init_function", """
        push rdi
        lea rdi, byte ptr [init_message]
        call qword ptr [_puts]
        pop rdi
        ret
    """)
    elf.add_init_function("new_init_function")

    # hook function_2, call export_function
    elf.patch_code(fromwhere=0x40068C,
                   towhere=0x400697,
                   label='patch_40068C',
                   code="""
                        call qword ptr [_export_function]
                        push rbp
                        mov rbp, rsp
                        lea rdi, [_commandline]
                        """)
    elf.add_data('_commandline', '/bin/sh')

    # .text:00000000004006E2    lea     rdi, aParent    ; "parent"
    # .text:00000000004006E9    call    _puts
    # .text:00000000004006EE    lea     rax, function_3
    elf.insert_code(where=0x4006e9, label="patch_4006e9", code="""
    add rdi, 1  # rdi -> "arent"
    """, nbound=0x4006ee)

    # .text:0000000000400678    lea     rdi, a255s      ; "%255s"
    # .text:000000000040067F    mov     eax, 0
    elf.insert_code(where=0x400678, label="patch_400678", code="""
    lea rdi, [_commandline]
    call 0x400540
    xor rax, rax
    leave
    ret
    """, nbound=0x40067f)

    # add imported function from libc
    elf.add_imported_symbol('getpid', '_getpid')

    # data and code manipulate
    elf.add_data('global_data', 'A' * 0x20)

    # x64 has problems with direct addressing
    elf.add_code('entry1',
                 """
                 mov rax, [global_data2222]
                 mov rbx, [entry2]
                 mov rax, [_getpid]
                 """)

    elf.add_code('entry2',
                 """
                 mov rax, [global_data]
                 mov rbx, [entry1]
                 mov rcx, [_getpid]
                 """)

    elf.add_data('global_data2222', 'B' * 0x20)

    elf.add_code('entry3',
                 """
                 lea rcx, [global_data2222]
                 mov rax, [global_data2222]
                 mov rbx, [entry1]
                 mov rcx, [entry2]
                 mov rcx, [entry3]
                 mov rcx, [_getppid]
                 """)

    elf.add_imported_symbol('getppid', '_getppid')

    elf.add_code('entry4',
                 """
                 mov rcx, [_getppid]
                 """)

    elf.save(outfile)


def test_386(infile, outfile):
    elf = ELF(infile)

    # add imported function from external library
    elf.add_imported_library('lib_x86_library.so')
    elf.add_imported_symbol('export_function', '_export_function', 'lib_x86_library.so')

    elf.add_tls_bss_data('tls_bss_long', 0x4, 'tls_bss_long_offset')
    elf.add_tls_bss_data('tls_bss_char_array', 0x100, 'tls_bss_char_array_offset')

    elf.add_data('constdata', 'C' * 5 + '\x00')
    elf.add_pointer('constdata_pointer', 'constdata')
    elf.add_code('pointer_verifier', """
        mov eax, dword ptr [constdata_pointer]
        push eax
        call dword ptr [_puts]
        add esp, 4
        ret
    """)
    elf.add_init_function('pointer_verifier')

    elf.add_imported_symbol('puts', '_puts')
    elf.add_data('init_message', 'Hello From Init Array\x00')
    elf.add_code("new_init_function", """
        push edi
        lea edi, byte ptr [init_message]
        push edi
        call dword ptr [_puts]
        add esp, 4
        pop edi
        ret
    """)
    elf.add_init_function("new_init_function")

    # hook function_2, call export_function
    elf.patch_code(fromwhere=0x0804857C,
                   towhere=0x08048583,
                   label='patch_804857C',
                   code="""
                        call dword ptr[_export_function]
                        push ebp
                        mov ebp, esp
                        push ebx
                        sub esp, 4
                        """)

    # .text:0804860B    lea     eax, (aParent - 804A000h)[ebx] ; "parent"
    # .text:08048611    push    eax             ; s
    # .text:08048612    call    _puts
    # .text:08048617    add     esp, 10h
    elf.insert_code(where=0x08048611, label="patch_08048611", code="""
    add eax, 1  # eax -> "arent"
    """, nbound=0x08048617)

    # add imported function from libc
    elf.add_imported_symbol('getpid', '_getpid')

    # data and code manipulate
    elf.add_data('global_data', 'A' * 0x20)

    elf.add_code('entry1',
                 """
                 mov eax, [global_data2222]
                 mov ebx, [entry2]
                 mov ecx, [_getpid]
                 """)

    elf.add_code('entry2',
                 """
                 mov eax, [global_data]
                 mov ebx, [entry1]
                 mov ecx, [_getpid]
                 """)

    elf.add_data('global_data2222', 'B' * 0x20)

    elf.add_code('entry3',
                 """
                 mov eax, [global_data2222]
                 mov ebx, [entry1]
                 mov ebx, [entry2]
                 mov ebx, [entry3]
                 mov ecx, [_getppid]
                 """)

    elf.add_imported_symbol('getppid', '_getppid')

    elf.add_code('entry4',
                 """
                 mov ecx, [_getppid]
                 """)

    elf.save(outfile)


def test_arm(infile, outfile):
    elf = ELF(infile)

    # add imported function from external library
    elf.add_imported_library('lib_arm_library.so')
    elf.add_imported_symbol('export_function', '_export_function', 'lib_arm_library.so')

    elf.add_tls_bss_data('tls_bss_long', 0x4, 'tls_bss_long_offset')
    elf.add_tls_bss_data('tls_bss_char_array', 0x100, 'tls_bss_char_array_offset')

    elf.add_data('constdata', 'C' * 5 + '\x00')
    elf.add_pointer('constdata_pointer', 'constdata')
    elf.add_code('pointer_verifier', """        
        stmfd sp!, {r0, r3, lr}
        ldr r0, =constdata_pointer
        ldr r0, [r0]
        ldr r3, =_puts
        ldr r3, [r3]
        blx r3
        ldmfd sp!, {r0, r3, pc}
    """)
    elf.add_init_function('pointer_verifier')

    elf.add_imported_symbol('puts', '_puts')
    elf.add_data('init_message', 'Hello From Init Array\x00')
    elf.add_code("new_init_function", """
        stmfd sp!, {r0, r3, lr}
        ldr r0, =init_message
        ldr r3, =_puts
        ldr r3, [r3]
        blx r3
        ldmfd sp!, {r0, r3, pc}
    """)
    elf.add_init_function("new_init_function")

    # hook function_2, call export_function
    elf.insert_code(where=0x10610, label="patch_10610", code="""
    stmfd sp!, {r3, lr}
    ldr r3, =_export_function
    ldr r3, [r3, #0x0]
    blx r3
    ldmfd sp!, {r3, lr}
    """)

    # test pc-related instruction wrap
    elf.insert_code(where=0x10684, label="patch_10684", code="nop")

    # add imported function from libc
    elf.add_imported_symbol('getpid', '_getpid')

    # data and code manipulate
    elf.add_data('global_data', 'A' * 0x20)

    elf.add_code('entry1',
                 """
                 ldr r1, =global_data2222
                 ldr r1, =entry2
                 ldr r1, =_getpid
                 """)

    elf.add_code('entry2',
                 """
                 ldr r1, =global_data
                 ldr r1, =entry1
                 ldr r1, =_getpid
                 """)

    elf.add_data('global_data2222', 'B' * 0x20)

    elf.add_code('entry3',
                 """
                 ldr r1, =global_data2222
                 ldr r1, =entry1
                 ldr r1, =entry2
                 ldr r1, =entry3
                 ldr r1, =_getppid
                 """)

    elf.add_imported_symbol('getppid', '_getppid')

    elf.add_code('entry4',
                 """
                 ldr r1, =_getppid
                 """)

    elf.save(outfile)


def test_arm_pie(infile, outfile):
    elf = ELF(infile)

    elf.add_imported_symbol('puts', '_puts', 'libc.so.0')

    elf.add_data('init_message', 'Hello From Init Array\x00')
    elf.add_code("new_init_function", """
        stmfd sp!, {r0, r3, lr}
        ldr r0, =init_message
        ldr r3, =_puts
        ldr r3, [r3]
        blx r3
        ldmfd sp!, {r0, r3, pc}
    """)
    elf.add_init_function("new_init_function")

    # hook function_2, call export_function
    elf.insert_code(where=0x90c, label="patch_90c", code="""
        stmfd sp!, {r0, r3}
        ldr r0, =init_message
        ldr r3, =5
        ldr r3, =_puts
        ldr r3, [r3]
        ldmfd sp!, {r0, r3}
    """)

    # hook function_2, call export_function
    elf.insert_code(where=0x920, label="patch_920", code="""
        stmfd sp!, {r0, r3}
        ldr r0, =init_message
        ldr r3, =5
        ldr r3, =_puts
        ldr r3, [r3]
        ldmfd sp!, {r0, r3}
    """)

    # test pc-related instruction wrap
    elf.insert_code(where=0x8C4, label="patch_8C4", code="nop")

    trampoline_template_with_tls = """
    stmfd sp!, {{r0 - r4}}      @ save registers
    ldr r0, =afl_prev_loc_offset
    ldr r1, [r0]                @ afl_prev_loc offset
    mrc p15, 0, r0, c13, c0, 3  @ tls pointer
    ldrh r2, [r0, r1]           @ load afl_prev_loc, zero-extended
    movw r4, #{magic:#x}        @ cur_loc, zero-extended
    eor r2, r2, r4              @ afl_prev_loc ^ cur_loc
    ldr r3, =shm_pointer
    ldr r3, [r3]                @ shm_pointer
    ldrb r4, [r3, r2]
    add r4, r4, #1              @ shm[xored] += 1
    strb r4, [r3, r2]
    movw r2, #{magic_shift:#x}  @ cur_loc >> 1
    strh r2, [r0, r1]           @ afl_prev_loc = cur_loc >> 1
    ldmfd sp!, {{r0 - r4}}      @ restore registers
    """

    afl_init = """
    stmfd sp!, {lr}
    ldr r3, =afl_init_entry
    ldr r3, [r3]
    blx r3                  @ call afl_init_entry(r0, r1, r2)
    ldr r3, =shm_pointer
    str r0, [r3]            @ save shm_pointer
    ldmfd sp!, {pc}
    """

    init_entry = 'afl_manual_init'
    elf.add_imported_symbol(init_entry, 'afl_init_entry', 'libaflinit.so')

    # avoid write to invalid address before initialization complete
    elf.add_data('afl_area_initial', '\x00' * 0x10000)
    elf.add_pointer('shm_pointer', 'afl_area_initial')

    elf.add_code('afl_init', afl_init)
    elf.add_init_function('afl_init')

    elf.add_tls_bss_data('afl_prev_loc', 4, 'afl_prev_loc_offset')
    trampoline_template = trampoline_template_with_tls

    for index, bb in enumerate([0x938, 0x8E8]):
        magic = bb * 0xdeadbeef % 2 ** 16
        trampoline = trampoline_template.format(magic=magic, magic_shift=magic >> 1)
        elf.insert_code(where=bb, label="patch_%#x" % bb, code=trampoline)

    elf.save(outfile)


def test_arm_afl(target, output, daemon_mode, disable_tls, bbs):
    import sys
    import datetime

    def die(s):
        sys.stdout.write(s + '\n') or exit()

    def log(s):
        sys.stdout.write(s + '\n')

    def tlog(msg):
        log('%s %s' % (str(datetime.datetime.now()), msg))

    trampoline_template_with_tls = """
    stmfd sp!, {{r0 - r4}}      @ save registers
    ldr r0, =afl_prev_loc_offset
    ldr r1, [r0]                @ afl_prev_loc offset
    mrc p15, 0, r0, c13, c0, 3  @ tls pointer
    ldrh r2, [r0, r1]           @ load afl_prev_loc, zero-extended
    movw r4, #{magic:#x}        @ cur_loc, zero-extended
    eor r2, r2, r4              @ afl_prev_loc ^ cur_loc
    ldr r3, =shm_pointer
    ldr r3, [r3]                @ shm_pointer
    ldrb r4, [r3, r2]
    add r4, r4, #1              @ shm[xored] += 1
    strb r4, [r3, r2]
    movw r2, #{magic_shift:#x}  @ cur_loc >> 1
    strh r2, [r0, r1]           @ afl_prev_loc = cur_loc >> 1
    ldmfd sp!, {{r0 - r4}}      @ restore registers
    """

    trampoline_template_single_thread = """
    stmfd sp!, {{r0, r2 - r4}}  @ save registers
    ldr r0, =afl_prev_loc
    ldrh r2, [r0]               @ load afl_prev_loc, zero-extended
    movw r4, #{magic:#x}        @ cur_loc, zero-extended
    eor r2, r2, r4              @ afl_prev_loc ^ cur_loc
    ldr r3, =shm_pointer
    ldr r3, [r3]                @ shm_pointer
    ldrb r4, [r3, r2]
    add r4, r4, #1              @ shm[xored] += 1
    strb r4, [r3, r2]
    movw r2, #{magic_shift:#x}  @ cur_loc >> 1
    strh r2, [r0]               @ afl_prev_loc = cur_loc >> 1
    ldmfd sp!, {{r0, r2 - r4}}  @ restore registers
    """

    afl_init = """
    stmfd sp!, {lr}
    ldr r3, =afl_init_entry
    ldr r3, [r3]
    blx r3                  @ call afl_init_entry(r0, r1, r2)
    ldr r3, =shm_pointer
    str r0, [r3]            @ save shm_pointer
    ldmfd sp!, {pc}
    """

    # it is okay we have duplicate magics, since what we actually need is making
    # magic1 ^ magic2 unique. it helps nothing by making magic itself unique.
    # magics = []
    from zlib import crc32

    def new_magic(seed):
        return crc32(str(seed)) % 2 ** 16

    elf = ELF(target)

    tlog('Start patching for %s' % target)

    if (not elf.check_imported_library('libc.so.6') and
            not elf.check_imported_library('libc.so.0')):
        die('The binary does not have libc.so.6/0 imported.')

    if daemon_mode == 'desock':
        init_entry = 'afl_manual_init'
        elf.add_imported_library('libdesock.so')
    elif daemon_mode == 'client':
        init_entry = 'afl_manual_init_daemon'
    else:
        init_entry = 'afl_manual_init'
    elf.add_imported_symbol(init_entry, 'afl_init_entry', 'libaflinit.so')

    # avoid write to invalid address before initialization complete
    elf.add_data('afl_area_initial', '\x00' * 0x10000)
    elf.add_pointer('shm_pointer', 'afl_area_initial')

    elf.add_code('afl_init', afl_init)
    elf.add_init_function('afl_init')

    if disable_tls:
        elf.add_data('afl_prev_loc', '\x00' * 4)
        trampoline_template = trampoline_template_single_thread
    else:
        elf.add_tls_bss_data('afl_prev_loc', 4, 'afl_prev_loc_offset')
        trampoline_template = trampoline_template_with_tls

    for index, bb in enumerate(bbs):
        magic = new_magic(bb)
        trampoline = trampoline_template.format(magic=magic, magic_shift=magic >> 1)
        try:
            elf.insert_code(where=bb, label="patch_%#x" % bb, code=trampoline)
        except Exception, e:
            log('[-] No.%d basic block @ %#x failed: %s.' % (index + 1, bb, str(e)))
            continue
        if (index + 1) % 10000 == 0:
            tlog('%d basic blocks processed.' % (index + 1))
        # log('No.%d basic block @ %#x (magic = %#x).' % (index + 1, bb, magic))

    tlog('%d basic blocks processed.' % len(bbs))

    tlog('Save binary to %s.' % output)
    elf.save(output, verbose=True)


def test_arm_wrap_cov(infile, idalst):
    print 'ARM Wrap Test: %s' % infile

    # When size is omitted or negative, the entire contents of the file will be read and
    # returned; it’s your problem if the file is twice as large as your machine’s memory.
    with open(idalst, 'rb') as fp:
        data = fp.read()

    elf = ELF(infile)

    head, tail = 0xffffffff, 0
    for shdr in elf.codeshdrs:
        if shdr.sh_addr < head:
            head = shdr.sh_addr
        if shdr.sh_addr + shdr.sh_size > tail:
            tail = shdr.sh_addr + shdr.sh_size

    curindex = 0
    for addr in xrange(head, tail, 4):
        addrtag = ':%08X ' % addr
        try:
            curhead = data.index(addrtag, curindex)
            curtail = data.index('\n', curhead)
        except Exception:
            continue
        curindex = curtail
        if ' DCD ' in data[curhead:curtail]:
            continue
        if addr % 0x8000 == 0:
            print hex(addr)
        try:
            elf.insert_code(addr, 'p%#x' % addr, "nop")
        except Exception, e:
            print '%#x: %s' % (addr, str(e))


def main():
    basedir = r".\samples\%s"

    for target in ['x64_sample', 'x64_sample_strip']:
        test_x64(basedir % target, basedir % ('%s_patch' % target))

    for target in ['x86_sample', 'x86_sample_strip']:
        test_386(basedir % target, basedir % ('%s_patch' % target))

    for target in ['arm_sample', 'arm_sample_strip']:
        test_arm(basedir % target, basedir % ('%s_patch' % target))

    for target in ['libutil-0.9.33.2.so']:
        test_arm_pie(basedir % target, basedir % ('%s_patch.so' % target[:-3]))

    import json
    basedir = r".\samples\armelfs\%s"

    armelfs = [
        ('samba_multicall', 'samba_multicall-patch', 'samba_multicall.config', 'desock'),
        ('libthrift-0.9.1.so', 'libthrift-0.9.1-patch.so', 'libthrift-0.9.1.so.config', ''),
    ]

    for target, output, config, desock in armelfs:
        bbs = json.loads(open(basedir % config, 'r').read())
        test_arm_afl(basedir % target, basedir % output, desock, False, bbs)

    basedir = r".\samples\armlibs\%s"

    armlibs = [
        ('libcrypto++.so.8.0.0', 'libcrypto++.so.8.0.lst'),
        ('libcrypto.so.1.0.0', 'libcrypto.so.1.0.lst'),
        ('libdns.so.95.1.1  ', 'libdns.so.95.1.lst'),
        ('libevent-2.0.so.5.1.10', 'libevent-2.0.so.5.1.lst'),
        ('libgcc_s.so.1  ', 'libgcc_s.so.lst'),
        ('libglib-2.0.so.0.2600.1', 'libglib-2.0.so.0.2600.lst'),
        ('libMagickCore-6.Q16.so.1.0.0', 'libMagickCore-6.Q16.so.1.0.lst'),
        ('libMagickWand-6.Q16.so.1.0.0', 'libMagickWand-6.Q16.so.1.0.lst'),
        ('libstdc++.so.6.0.18', 'libstdc++.so.6.0.lst'),
        ('libuClibc-0.9.33.2.so', 'libuClibc-0.9.33.2.lst'),
    ]

    for target, idalst in armlibs:
        test_arm_wrap_cov(basedir % target, basedir % idalst)


if __name__ == '__main__':
    main()
