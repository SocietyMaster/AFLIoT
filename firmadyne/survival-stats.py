#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Himyth / AAA """

import os
import re
import subprocess

firmadyne_root = '/home/zhumengfan/firmadyne'
firmware_root = '/home/zhumengfan/firmware/firmwares'
log_root = '/home/zhumengfan/firmware/logs'
logs = ''

def join_abspath(a, b):
    return os.path.abspath(os.path.join(a, b))

def docall(command):
    # print ' '.join(command)
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as ex:
        output = ex.output
    return output

def step_extract(image_path):
    print 'processing step_extract'
    global logs
    extractor = join_abspath(firmadyne_root, 'sources/extractor/extractor.py')
    images = join_abspath(firmadyne_root, 'images')
    extractor_result = docall(['timeout', '--preserve-status', '--signal', 'SIGINT', '30', 'python', extractor, '-b', 'ARM', '-sql', '127.0.0.1', '-np', '-nk', image_path, images])
    logs += extractor_result
    if 'Extraction failed!' in extractor_result:
        raise ValueError('Extraction failed! %s' % image_path)
    image_id = int(re.findall(r'>> Database Image ID: (\d+)', extractor_result)[0])
    return image_id

def step_getarch(image_id):
    print 'processing step_getarch'
    global logs
    getarch = join_abspath(firmadyne_root, 'scripts/getArch.sh')
    image_path = join_abspath(firmadyne_root, 'images/%d.tar.gz' % image_id)
    getarch_result = docall([getarch, image_path])
    logs += getarch_result

def step_tar2db(image_id):
    print 'processing step_tar2db'
    global logs
    tar2db = join_abspath(firmadyne_root, 'scripts/tar2db.py')
    image_path = join_abspath(firmadyne_root, 'images/%d.tar.gz' % image_id)
    tar2db_result = docall(['python', tar2db, '-i', str(image_id), '-f', image_path])
    logs += tar2db_result

def step_makeimage(image_id):
    print 'processing step_makeimage'
    global logs
    makeimage = join_abspath(firmadyne_root, 'scripts/makeImage.sh')
    makeimage_result = docall(['sudo', makeimage, str(image_id)])
    logs += makeimage_result

def step_infernetwork(image_id):
    print 'processing step_infernetwork'
    global logs
    infernetwork = join_abspath(firmadyne_root, 'scripts/inferNetwork.sh')
    infernetwork_result = docall(['sudo', infernetwork, str(image_id)])
    logs += infernetwork_result

    kernel_log = join_abspath(firmadyne_root, 'scratch/%d/qemu.initial.serial.log' % image_id)
    if os.path.exists(kernel_log):
        logs += open(kernel_log, 'rb').read()

def step_finalrun(image_id):
    print 'processing step_finalrun'
    global logs
    finalrun = join_abspath(firmadyne_root, 'scratch/%d/run.sh' % image_id)
    finalrun_result = docall(['sudo', 'timeout', '--preserve-status', '--signal', 'SIGINT', '60', finalrun])   # running final script for 60s
    logs += finalrun_result

    kernel_log = join_abspath(firmadyne_root, 'scratch/%d/qemu.final.serial.log' % image_id)
    if os.path.exists(kernel_log):
        logs += open(kernel_log, 'rb').read()

def handle_image(image_path):
    try:
        image_id = step_extract(image_path)
        print 'image id: %d' % image_id
        step_getarch(image_id)
        step_tar2db(image_id)
        step_makeimage(image_id)
        docall(['sudo', 'killall', 'qemu-system-arm'])
        step_infernetwork(image_id)
        docall(['sudo', 'killall', 'qemu-system-arm'])
        step_finalrun(image_id)
    except KeyboardInterrupt, e:
        raise KeyboardInterrupt()
        return False
    except Exception, e:
        print str(e)
    return True

def main():
    global logs
    os.chdir(firmadyne_root)
    os.environ['PGPASSWORD'] = 'firmadyne'
    subprocess.check_output(['sudo', 'ls']) # make me a suder!

    for image_file in os.walk(firmware_root).next()[2]:
        logs = ''
        print image_file
        log_file = image_file[:image_file.index('.')] + '.log'
        log_path = join_abspath(log_root, log_file)
        if os.path.exists(log_path):
            continue
        image_path = join_abspath(firmware_root, image_file)
        shouldcontinue = handle_image(image_path)
        with open(log_path, 'wb') as f:
            f.write(logs)
        if not shouldcontinue:
            break

    # image_path = '/home/zhumengfan/firmware/netgear.zip'
    # handle_image(image_path)
    # log_file = image_path[image_path.rindex('/') + 1:image_path.index('.')] + '.log'
    # log_path = join_abspath(log_root, log_file)
    # with open(log_path, 'wb') as f:
    #     f.write(logs)


if __name__ == '__main__':
    main()
