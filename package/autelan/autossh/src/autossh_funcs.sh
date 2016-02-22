#!/usr/bin/expect

set timeout 5
set server [lindex $argv 0]
set port [lindex $argv 1]
set user [lindex $argv 2]
set passwd [lindex $argv 3]

spawn ssh -R $port:localhost:22 $user@$server
expect {
"(y/n)" { send "y\r"; exp_continue }
"password:" { send "$passwd\r" }
}
while (true) {}
#interact

