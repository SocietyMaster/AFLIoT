#!/usr/bin/env python
# -*- coding: utf-8 -*-
from getopt import getopt
import random
import sys, os, json
from zlib import crc32
import subprocess, ntpath

bbfinder_script = """
from idaapi import *
from idautils import *
import idc
import json
import capstone

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
        bbs.extend(map(lambda x: (x.startEA, x.endEA), FlowChart(get_func(func))))
        # break
    bbs = filter(lambda (x, y): GetReg(x, "T") == 0 and y > x, bbs)
    bbs = sorted(list(set(bbs)))

    cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    insns = dict()
    for start, end in bbs:
        try:
            for insn in cs.disasm(idc.GetManyBytes(start, end - start), 0):
                if insn.id not in insns:
                    insns[insn.id] = [1, insn.insn_name()]
                else:
                    insns[insn.id][0] += 1
        except Exception, e:
            print 'Error @ %#x - %#x: %s' % (start, end, str(e))

    insns = insns.items()
    insns.sort(key=lambda x: x[1][0], reverse=True)
    insns = [(x[1][1], x[1][0]) for x in insns]

    if len(idc.ARGV) == 2:
        open(idc.ARGV[1], "w").write(json.dumps(insns, indent=4))

if __name__ == '__main__':
    main()
    idc.Exit(0)
"""

def die(s):
    sys.stdout.write(s + '\n') or exit()

def log(s):
    sys.stdout.write(s + '\n')

def usage():
    die("usage: this.py -f target [-o output] [-i idapath] [-h]")

def main():
    idapath = 'D:\\ScriptHigh\\IDA Pro 7.0\\ida.exe'

    bbfinder = os.path.abspath('./bbfinder.py')
    open(bbfinder, 'w').write(bbfinder_script)

    for target in os.walk('./bins').next()[2]:
        if target.endswith('.idb'):
            continue
        outputjson = os.path.abspath('./jsons/%s.json' % target)
        if os.path.exists(outputjson):
            print '%s already done' % target
            continue

        bbfinder_command = '"%s" "%s"' % (bbfinder, outputjson)
        rtarget = os.path.abspath('./bins/%s' % target)
        subprocess.call([idapath, '-A', '-S%s' % bbfinder_command, rtarget])
        print '%s done' % target
        # bbs = json.loads(open(jsonconfig, 'r').read())

        # for trash in [bbfinder, jsonconfig]:
        #     os.unlink(trash)

        # return target, output, bbs
    print

def puts():
    insns = dict()
    for jsonfile in os.walk('./jsons').next()[2]:
        obj = json.loads(open('./jsons/%s' % jsonfile, 'rb').read())
        for name, count in obj:
            if name not in insns:
                insns[name] = count
            else:
                insns[name] += count

    insns = insns.items()
    insns.sort(key=lambda x: x[1], reverse=True)
    open('./all-instrucitons.json', 'wb').write(json.dumps(insns, indent=4))
    total = sum(map(lambda x: x[1], insns))
    now = 0
    print 'Total instruction count: %d' % total
    for name, count in insns:
        now += count
        print '%s\t%d\t%.3f' % (name, count, now * 100.0 / total)


if __name__ == "__main__":
    main()
    puts()
