import os, re
import sys
# target = './base64-afl/records'
target = sys.argv[1] + '/records'
for file in os.walk(target).next()[2]:
    data = open(os.path.join(target, file), 'r').read()
    result = dict(re.findall(r'(\w+) +: (.*)', data))
    # timeh = (int(result['last_update']) - int(result['start_time'])) / 3600.0
    print '\t'.join([
        file,
        result['start_time'],
        result['last_update'],
        result['fuzzer_pid'],
        result['cycles_done'],
        result['execs_done'],
        result['execs_per_sec'],
        result['paths_total'],
        result['paths_favored'],
        result['paths_found'],
        result['paths_imported'],
        result['max_depth'],
        result['cur_path'],
        result['pending_favs'],
        result['pending_total'],
        result['variable_paths'],
        result['stability'],
        result['bitmap_cvg'],
        result['unique_crashes'],
        result['unique_hangs'],
        result['last_path'],
        result['last_crash'],
        result['last_hang'],
        result['execs_since_crash'],
        result['exec_timeout'],
        result['afl_banner'],
        result['afl_version'],
        result['target_mode'],
        result['command_line'],
        ])
