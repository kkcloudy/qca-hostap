#!/bin/sh

if [ $# -ne 4 ]; then
echo "usage: start ssh service automatically"
echo "usage: reversessh.sh [server] [port] [user] [passwd]"
echo "example: reversessh.sh cloud1.autelan.com 30000 chenxuefeng 123456"
exit 1;
fi

/usr/sbin/reversessh_funcs.sh $1 $2 $3 $4

