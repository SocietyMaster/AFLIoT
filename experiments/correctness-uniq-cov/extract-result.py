import os, re

for directory in os.walk('.').next()[1]:
    data = open(os.path.join(directory, 'fuzzer_stats'), 'r').read()
    result = dict(re.findall(r'(\w+) +: (.*)', data))
    totaltime = int(result['last_update']) - int(result['start_time'])
    print '\t'.join([
        directory,
        result['unique_crashes'],
        result['basic_block_cvg'],
        result['paths_total'],
        str(totaltime / 3600.0),
        ])
