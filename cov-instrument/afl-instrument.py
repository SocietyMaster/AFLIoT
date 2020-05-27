#!/usr/bin/env python
# -*- coding: utf-8 -*-
from getopt import getopt
import random
import sys
import os
import json
from zlib import crc32
import subprocess
import ntpath
import datetime


bbfinder_script = """
from idaapi import *
from idautils import *
import idc
import json

def get_text_segment():
    for ea in Segments():
        if SegName(ea) == '.text':
            segment_head = SegStart(ea)
            segment_tail = SegEnd(ea)
            return segment_head, segment_tail
    return None, None

def main():
    autoWait()

    info = get_inf_structure()
    if not info.procName.upper().startswith('ARM') or info.is_64bit():
        print 'Wrong Architecture.'
        return

    bbs = []
    for func in Functions(*get_text_segment()):
        bbs.extend(map(lambda x: x.startEA, FlowChart(get_func(func))))
    bbs = filter(lambda x: GetReg(x, "T") == 0, bbs)
    bbs = sorted(list(set(bbs)))

    if len(idc.ARGV) == 2:
        open(idc.ARGV[1], "w").write(json.dumps(bbs))

if __name__ == '__main__':
    main()
    idc.Exit(0)
"""


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


# coverage enabled instrumentation

trampoline_template_with_tls_cov = """
stmfd sp!, {{r0 - r4}}      @ save registers
ldr r0, =afl_prev_loc_offset
ldr r1, [r0]                @ afl_prev_loc offset
mrc p15, 0, r0, c13, c0, 3  @ tls pointer
ldrh r2, [r0, r1]           @ load afl_prev_loc, zero-extended
movw r4, #{magic:#x}        @ cur_loc, zero-extended
eor r2, r2, r4              @ afl_prev_loc ^ cur_loc
ldr r3, =shm_cov_pointer
ldr r3, [r3]                @ shm_cov_pointer
add r3, r3, r4              @ basic block id
movw r4, #0xff
strb r4, [r3]               @ set to 0xff
ldr r3, =shm_pointer
ldr r3, [r3]                @ shm_pointer
ldrb r4, [r3, r2]
add r4, r4, #1              @ shm[xored] += 1
strb r4, [r3, r2]
movw r2, #{magic_shift:#x}  @ cur_loc >> 1
strh r2, [r0, r1]           @ afl_prev_loc = cur_loc >> 1
ldmfd sp!, {{r0 - r4}}      @ restore registers
"""


trampoline_template_single_thread_cov = """
stmfd sp!, {{r0, r2 - r4}}  @ save registers
ldr r0, =afl_prev_loc
ldrh r2, [r0]               @ load afl_prev_loc, zero-extended
movw r4, #{magic:#x}        @ cur_loc, zero-extended
eor r2, r2, r4              @ afl_prev_loc ^ cur_loc
ldr r3, =shm_cov_pointer
ldr r3, [r3]                @ shm_cov_pointer
add r3, r3, r4              @ basic block id
movw r4, #0xff
strb r4, [r3]               @ set to 0xff
ldr r3, =shm_pointer
ldr r3, [r3]                @ shm_pointer
ldrb r4, [r3, r2]
add r4, r4, #1              @ shm[xored] += 1
strb r4, [r3, r2]
movw r2, #{magic_shift:#x}  @ cur_loc >> 1
strh r2, [r0]               @ afl_prev_loc = cur_loc >> 1
ldmfd sp!, {{r0, r2 - r4}}  @ restore registers
"""

# detailed coverage enabled instrumentation

trampoline_template_with_tls_detailed_cov = """
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
ldr r3, =shm_detailed_cov_pointer
ldr r3, [r3]                @ shm_detailed_cov_pointer
movw r4, #{block_index:#x}        
add r3, r3, r4              @ basic block unique id
movw r4, #0x01
strb r4, [r3]               @ set to 0x01
ldmfd sp!, {{r0 - r4}}      @ restore registers
"""


trampoline_template_single_thread_detailed_cov = """
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
ldr r3, =shm_detailed_cov_pointer
ldr r3, [r3]                @ shm_detailed_cov_pointer
movw r4, #{block_index:#x}        
add r3, r3, r4              @ basic block unique id
movw r4, #0x01
strb r4, [r3]               @ set to 0x01
ldmfd sp!, {{r0, r2 - r4}}  @ restore registers
"""

# path output enabled instrumentation

trampoline_template_with_tls_path = """
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
ldr r4, =shm_path_index_pointer
ldr r4, [r4]                @ shm_path_index_pointer
ldr r2, [r4]                @ current shm_path_index
add r3, r2, #1
ldr r1, =0x3ffff
and r3, r3, r1              
str r3, [r4]                @ shm_path_index++
ldr r3, =shm_path_pointer
ldr r3, [r3]                @ shm_path_pointer
ldr r4, ={offset:#x}        
str r4, [r3, r2, LSL #2]    @ store offset
ldmfd sp!, {{r0 - r4}}      @ restore registers
"""

trampoline_template_single_thread_path = """
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
ldr r4, =shm_path_index_pointer
ldr r4, [r4]                @ shm_path_index_pointer
ldr r2, [r4]                @ current shm_path_index
add r3, r2, #1
ldr r0, =0x3ffff
and r3, r3, r0              
str r3, [r4]                @ shm_path_index++
ldr r3, =shm_path_pointer
ldr r3, [r3]                @ shm_path_pointer
ldr r4, ={offset:#x}        
str r4, [r3, r2, LSL #2]    @ store offset
ldmfd sp!, {{r0, r2 - r4}}  @ restore registers
"""

afl_init_cov = """
stmfd sp!, {lr}
ldr r3, =afl_init_entry
ldr r3, [r3]
blx r3                  @ call afl_init_entry(r0, r1, r2)
ldr r2, =shm_cov_pointer
ldr r3, =shm_pointer
ldr r1, [r0, #4]
ldr r0, [r0]
str r1, [r2]            @ save shm_cov_pointer
str r0, [r3]            @ save shm_pointer
ldmfd sp!, {pc}
"""

afl_init_detailed_cov = """
stmfd sp!, {lr}
ldr r3, =afl_init_entry
ldr r3, [r3]
blx r3                  @ call afl_init_entry(r0, r1, r2)
ldr r2, =shm_detailed_cov_pointer
ldr r1, [r0, #4]
str r1, [r2]
ldr r3, =shm_pointer
ldr r0, [r0]
str r0, [r3]            @ save shm_pointer
ldmfd sp!, {pc}
"""

afl_init_path = """
stmfd sp!, {lr}
ldr r3, =afl_init_entry
ldr r3, [r3]
blx r3                  @ call afl_init_entry(r0, r1, r2)
ldr r2, =shm_path_pointer
ldr r1, [r0, #4]
str r1, [r2]            @ save shm_path_pointer
ldr r2, =shm_path_index_pointer
ldr r1, [r0, #8]
str r1, [r2]            @ save shm_path_index_pointer
ldr r3, =shm_pointer
ldr r0, [r0]
str r0, [r3]            @ save shm_pointer
ldmfd sp!, {pc}
"""

magic_pool = None

# if we need to record basic block coverage information, we need to set the magic id
# unique, but if we just record paths only, it is okay to have duplicate magics, since
# what we actually need is unique magic1 ^ magic2.


def new_magic(seed, uniq=False):
    magic = crc32(str(seed)) % 2 ** 16
    if not uniq:
        return magic

    global magic_pool

    # if the total requests exceeded 0x10000, duplication is unavoidable
    if not magic_pool:
        magic_pool = range(0x10000)

    index = magic % len(magic_pool)
    magic = magic_pool[index]

    del magic_pool[index]

    return magic


def do_instrument(target, output, bbs, disable_tls, daemon_mode, verbose,
                  daemonize, interp, bbcoverage, stateful, detailed_bbcoverage, bb_index_path, path):
    ELFPATCHER_PATH = os.path.abspath(os.path.join("..", "ELFPatcher"))
    sys.path.append(ELFPATCHER_PATH)
    from elfpatcher import ELF

    elf = ELF(target)

    tlog('Start patching for %s' % target)

    if (not elf.check_imported_library('libc.so.6') and
            not elf.check_imported_library('libc.so.0')):
        die('The binary does not have libc.so.6/0 imported.')

    if daemon_mode == 'desock':
        init_entry = 'afl_manual_init'
        if stateful:
            elf.add_imported_library('libdesock-state.so')
        else:
            elf.add_imported_library('libdesock.so')
            # elf.add_imported_library('libdesock3-xiaomithrift.so')
    elif daemon_mode == 'client':
        # init_entry = 'afl_manual_init_daemon'
        die('Historical use only.')
    else:
        init_entry = 'afl_manual_init'

    libaflinit_so = 'libaflinit.so'
    if bbcoverage:
        libaflinit_so = 'libaflinit-cov.so'
    elif detailed_bbcoverage:
        libaflinit_so = 'libaflinit-detailed-cov.so'
    elif path:
        libaflinit_so = 'libaflinit-path.so'
    elf.add_imported_symbol(init_entry, 'afl_init_entry', libaflinit_so)

    if daemonize:
        elf.add_imported_library('libdedaemon.so')

    if interp:
        elf.change_interp(interp)

    # avoid write to invalid address before initialization complete
    elf.add_data('afl_area_initial', '\x00' * 0x10000)
    elf.add_pointer('shm_pointer', 'afl_area_initial')

    if bbcoverage:
        elf.add_data('afl_area_cov_initial', '\x00' * 0x10000)
        elf.add_pointer('shm_cov_pointer', 'afl_area_cov_initial')
    elif detailed_bbcoverage:
        elf.add_data('afl_area_detailed_cov_initial', '\x00' * 0x10000)
        elf.add_pointer('shm_detailed_cov_pointer',
                        'afl_area_detailed_cov_initial')
    elif path:
        elf.add_data('afl_area_path_initial', '\xff\xff\xff\xff' * 0x40000)
        elf.add_pointer('shm_path_pointer',
                        'afl_area_path_initial')
        elf.add_data('afl_area_path_index_initial', '\x00\x00\x00\x00')
        elf.add_pointer('shm_path_index_pointer', 'afl_area_path_index_initial')
        
    afl_init_stub = afl_init
    if bbcoverage:
        afl_init_stub = afl_init_cov
    elif detailed_bbcoverage:
        afl_init_stub = afl_init_detailed_cov
    elif path:
        afl_init_stub = afl_init_path
    elf.add_code('afl_init', afl_init_stub)
    elf.add_init_function('afl_init')

    if disable_tls:
        elf.add_data('afl_prev_loc', '\x00' * 4)
        trampoline_template = trampoline_template_single_thread
        if bbcoverage:
            trampoline_template = trampoline_template_single_thread_cov
        elif detailed_bbcoverage:
            trampoline_template = trampoline_template_single_thread_detailed_cov
        elif path:
            trampoline_template = trampoline_template_single_thread_path
    else:
        elf.add_tls_bss_data('afl_prev_loc', 4, 'afl_prev_loc_offset')
        trampoline_template = trampoline_template_with_tls
        if bbcoverage:
            trampoline_template = trampoline_template_with_tls_cov
        elif detailed_bbcoverage:
            trampoline_template = trampoline_template_with_tls_detailed_cov
        elif path:
            trampoline_template = trampoline_template_with_tls_path

    bb_index = ['bb,index,magic\n']

    for index, bb in enumerate(bbs):
        magic = new_magic(bb, bbcoverage)
        trampoline = ''
        if detailed_bbcoverage:
            trampoline = trampoline_template.format(
                magic=magic, magic_shift=magic >> 1, block_index=index)
        elif path:
            trampoline = trampoline_template.format(
                magic=magic, magic_shift=magic >> 1, offset=bb)
        else:
            trampoline = trampoline_template.format(
                magic=magic, magic_shift=magic >> 1)

        try:
            elf.insert_code(where=bb, label="patch_%#x" % bb, code=trampoline)
        except Exception, e:
            log('[-] No.%d basic block @ %#x failed: %s.' %
                (index + 1, bb, str(e)))
            continue
        if (index + 1) % 10000 == 0:
            tlog('%d/%d basic blocks processed.' % (index + 1, len(bbs)))
        if verbose:
            log('No.%d basic block @ %#x (magic = %#x).' %
                (index + 1, bb, magic))
        if detailed_bbcoverage:
            bb_index.append('%#x,%d,%#x\n' % (bb, index, magic))

    tlog('%d basic blocks processed.' % len(bbs))

    tlog('Save binary to %s.' % output)
    elf.save(output, verbose=True)

    if detailed_bbcoverage:
        tlog('Save basic block index to %s.' % bb_index_path)
        outputBbIndex(bb_index_path, bb_index)


def outputBbIndex(path, content):
    fd = open(path, 'w')
    fd.writelines(content)
    fd.flush()
    fd.close()


def die(s):
    sys.stdout.write(s + '\n') or exit()


def log(s):
    sys.stdout.write(s + '\n')


def tlog(msg):
    log('%s %s' % (str(datetime.datetime.now()), msg))


def usage():
    die("Usage: %s -f elfpath [-o output] [-i idapath] [-d mode] \n"
        "[-l interpreter_path] [-b basic_block_index_path] [-p] [-c]\n"
        "[-D] [-s] [-S] [-v] [-h]\n\n"
        "-f\ttarget elf file path\n"
        "-o\tpatched output file path, default is elfpath-patch\n"
        "-i\tida pro executable path, default is hardcoded\n"
        "-d\ttarget is daemon, using 'desock' or 'client' mode\n"
        "-l\tspecify new interpreter absolute path\n"
        "-b\tadd detailed basic block coverage support, and output\n"
        "\teach basic block index to the path specified\n"
        "-p\tadd execution path support\n"
        "-c\tadd basic block coverage support\n"
        "-D\ttarget will daemonize\n"
        "-s\tsingle thread mode without TLS\n"
        "-S\tstateful library support\n"
        "-v\tverbose log every instrumentation\n"
        "-h\tshow this\n" % sys.argv[0]
        )


def setup():
    idapath = "C:\\Program Files\\IDA 7.0\\ida.exe"
    target, output, bb_index_path = None, None, None

    disable_tls = False
    daemon_mode = None
    xiaomithrift_template_mode = None
    daemonize = False
    verbose = False
    interp = None
    bbcoverage = False
    stateful = False
    detailed_bbcoverage = False
    path = False

    try:
        opts, _ = getopt(sys.argv[1:], "hvspScDl:b:d:f:i:o:")
    except:
        usage()

    for opt, value in opts:
        if opt == '-f':
            target = value
        elif opt == '-i':
            idapath = value
        elif opt == '-o':
            output = value
        elif opt == '-s':
            disable_tls = True
        elif opt == '-S':
            stateful = True
        elif opt == '-D':
            daemonize = True
        elif opt == '-c':
            bbcoverage = True
        elif opt == '-p':
            path = True
        elif opt == '-l':
            interp = value.strip()
        elif opt == '-v':
            verbose = True
        elif opt == '-b':
            detailed_bbcoverage = True
            bb_index_path = value
        elif opt == '-d':
            if value.strip() == 'desock':
                daemon_mode = 'desock'
            elif value.strip() == 'client':
                daemon_mode = 'client'
            else:
                usage()
        else:
            usage()

    if target is None:
        usage()

    target = os.path.abspath(target)
    idapath = os.path.abspath(idapath)
    bb_index_path = os.path.abspath(bb_index_path)

    if not os.path.exists(target):
        die('Target "%s" do not exist.' % target)

    if not os.path.exists(idapath):
        die('IDA executable "%s" do not exist.' % idapath)

    if output is None:
        output = '%s-patch' % target

    bbfinder = os.path.abspath('./bbfinder.py')
    open(bbfinder, 'w').write(bbfinder_script)

    target_filename = ntpath.basename(target)
    jsonconfig = os.path.abspath('./%s.config' % target_filename)

    if '.' in target_filename:
        idbfile = target_filename[:target_filename.rindex('.')] + '.idb'
    else:
        idbfile = target_filename + '.idb'
    idbfile = ntpath.join(ntpath.dirname(target), idbfile)

    bbfinder_command = '"%s" "%s"' % (bbfinder, jsonconfig)
    subprocess.call([idapath, '-A', '-S%s' % bbfinder_command, target])
    bbs = json.loads(open(jsonconfig, 'r').read())

    for trash in [bbfinder, jsonconfig, idbfile]:
        os.unlink(trash)

    if detailed_bbcoverage and len(bbs) > 65536:
        die("Currently not support output detailed basic block coverage\n"
            "of program whose total basic block exceeds 65536"
            )

    parameters = (target, output, bbs, disable_tls, daemon_mode,
                  verbose, daemonize, interp, bbcoverage, stateful, detailed_bbcoverage, bb_index_path, path)
    return parameters


def main():
    parameters = setup()
    do_instrument(*parameters)


if __name__ == "__main__":
    main()
