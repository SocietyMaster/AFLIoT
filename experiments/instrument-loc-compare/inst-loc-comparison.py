#!/usr/bin/env python
# -*- coding: utf-8 -*-
from getopt import getopt
import sys, os, json

def die(s):
    sys.stdout.write(s + '\n') or exit()

def log(s):
    sys.stdout.write(s + '\n')

def usage():
    die("usage: this.py -a target_a -b target_b [-h]")

def load_config(target):
    if target is None:
        return []
    target = os.path.abspath(target)
    if not os.path.exists(target):
        die('Target "%s" do not exist.' % target)
    config = json.loads(open(target).read())
    return config

def setup():
    target_a, target_b = None, None
    opts, args = getopt(sys.argv[1:], "ha:b:")
    for opt, value in opts:
        if opt == '-a': target_a = value
        elif opt == '-b': target_b = value
        else: usage()
    if target_a == target_b == None:
        usage()
    config_a = load_config(target_a)
    config_b = load_config(target_b)
    return [config_a, config_b]

def count_per_func(config):
    counter = dict()
    for func, ref in config:
        if func in counter:
            counter[func].add(ref)
        else:
            counter[func] = set([ref])
    counter = dict(map(lambda x: (x[0], len(x[1])), counter.items()))
    return counter

def main():
    counter_a, counter_b = map(count_per_func, setup())
    functions = list(set(counter_a.keys()).union(set(counter_b.keys())))
    counter = [(func, counter_a.get(func, 0), counter_b.get(func, 0))
               for func in functions]
    counter.sort(key=lambda x: x[1], reverse=True)
    for func, refa, refb in counter:
        log("%s\t%d\t%d" % (func, refa, refb))

if __name__ == '__main__':
    main()
