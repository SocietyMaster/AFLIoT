import os, re

for directory in os.walk('.').next()[1]:
    data = open(os.path.join(directory, 'fuzzer_stats'), 'r').read()
    result = dict(re.findall(r'(\w+) +: (.*)', data))
    totaltime = int(result['last_update']) - int(result['start_time'])
    print '\t'.join([
        result['afl_banner'],
        result['command_line'],
        result['unique_crashes'],
        result['bitmap_cvg'],
        result['cycles_done'],
        result['paths_total'],
        str(totaltime / 3600.0),
        str(int(result['execs_done']) / 1000.0),
        str(int(result['execs_done']) * 1.0 / totaltime),
        ])
