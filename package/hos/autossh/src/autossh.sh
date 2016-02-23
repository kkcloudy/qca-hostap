#!/bin/sh

if [ $# -ne 4 ]; then
echo "usage: start ssh service automatically"
echo "usage: autossh.sh [server] [port] [user] [passwd]"
echo "example: autossh.sh cloud1.autelan.com 30000 chenxuefeng 123456"
exit 1;
fi

/usr/sbin/autossh_funcs.sh $1 $2 $3 $4

