#!/usr/bin/python
# -*- coding: utf-8 -*-

import os

# some compling parameters.
targets = [
    ('libaflinit.so',  'libaflinit.c -shared -fPIC'),
    ('libaflinit-cov.so',  'libaflinit-cov.c -shared -fPIC'),
    ('libdesock.so',  'libdesock3.c -std=c99 -shared -fPIC -ldl -lpthread'),
    ('libdesock-state.so',  'libdesock3-state.c -std=c99 -shared -fPIC -ldl -lpthread'),
    ('libdedaemon.so',  'libdedaemon.c -shared -fPIC -L./build -laflinit'),
]

servers = [
    ('192.168.ip.ip', '/userdisk/fuzz/libraries/', 'username', 'password', 'scp'),
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
    ('192.168.ip.ip', '/userdisk/fuzz/', 'username', 'password', 'scp'),
]

build = 'afl-fuzz-cov'
for ip, rpath, user, pwd, scp in servers:
    command = 'sshpass -p "%s" %s ./utils/%s %s@%s:%s' % (pwd, scp, build, user, ip, rpath)
    print 'uploading %s to %s...' % (build, ip)
    # print command
    os.system(command)
