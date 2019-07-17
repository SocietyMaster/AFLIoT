#!/usr/bin/python
# -*- coding: utf-8 -*-

import os

targets = [
    ('libaflinit.so',  'libaflinit.c -shared -fPIC'),
    ('libaflinit-cov.so',  'libaflinit-cov.c -shared -fPIC'),
    ('libdesock.so',  'libdesock3.c -std=c99 -shared -fPIC -ldl -lpthread'),
    ('libdesock-state.so',  'libdesock3-state.c -std=c99 -shared -fPIC -ldl -lpthread'),
    ('libdedaemon.so',  'libdedaemon.c -shared -fPIC -L./build -laflinit'),
]

servers = [
    ('192.168.31.1', '/userdisk/fuzz/libraries/', 'root', 'qwe123123', 'scp'),
    ('192.168.50.1', '/tmp/mnt/Elements/fuzz/libraries/', 'listasus', 'listasus', 'scp'),
    ('192.168.51.1', '/tmp/mnt/usb0/part1/fuzz/libraries/', 'root', 'qwe123123', 'utils/x86-scp-profile'),
]

for build, options in targets:
    command = 'arm-linux-gcc %s -o ./build/%s' % (options, build)
    print 'compiling %s...' % build
    # print command
    os.system(command)

    for ip, rpath, user, pwd, scp in servers:
        command = 'sshpass -p "%s" %s ./build/%s %s@%s:%s' % (pwd, scp, build, user, ip, rpath)
        print 'uploading %s to %s...' % (build, ip)
        # print command
        os.system(command)

servers = [
    ('192.168.31.1', '/userdisk/fuzz/', 'root', 'qwe123123', 'scp'),
    ('192.168.50.1', '/tmp/mnt/Elements/fuzz/', 'listasus', 'listasus', 'scp'),
    ('192.168.51.1', '/tmp/mnt/usb0/part1/fuzz/', 'root', 'qwe123123', 'utils/x86-scp-profile'),
]

build = 'afl-fuzz-cov'
for ip, rpath, user, pwd, scp in servers:
    command = 'sshpass -p "%s" %s ./utils/%s %s@%s:%s' % (pwd, scp, build, user, ip, rpath)
    print 'uploading %s to %s...' % (build, ip)
    # print command
    os.system(command)
