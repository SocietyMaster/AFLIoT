
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
