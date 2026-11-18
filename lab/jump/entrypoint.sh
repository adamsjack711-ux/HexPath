#!/bin/sh
set -eu

ssh-keygen -A
touch /root/.ssh/authorized_keys
chmod 0600 /root/.ssh/authorized_keys

exec /usr/sbin/sshd -D -e
