#!/bin/sh

cp /tmp/mnt/usb0/part1/enablessh/shadow /tmp/config/shadow
cp /tmp/mnt/usb0/part1/enablessh/passwd /tmp/samba/private/passwd

/tmp/mnt/usb0/part1/enablessh/dropbear -r /tmp/mnt/usb0/part1/enablessh/rsakey

