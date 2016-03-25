#!/bin/sh

source cp_start.sh





CP_DNAT="CP_DNAT"
CP_FILTER="CP_FILTER"
#MAC_PRE_DNAT="MAC_PRE_DNAT"
#MAC_PRE_FILTER="MAC_PRE_FILTER"
#MAC_PRE_AUTH_N="MAC_PRE_AUTH_N"
#MAC_PRE_AUTH_F="MAC_PRE_AUTH_F"
#MAC_PRE_IPHASH_SET="MAC_PRE_AUTH_SET"
CP_FILTER_DEFAULT="CP_F_DEFAULT"
CP_FILTER_AUTHORIZED_DEFAULT="CP_F_AUTH_DEFAULT"
CP_NAT_DEFAULT="CP_N_DEFAULT"
CP_NAT_AUTHORIZED_DEFAULT="CP_N_AUTH_DEFAULT"
#CP_IPHASH_SET="CP_AUTHORIZED_SET"

CP_ID_FILE="/var/run/cpp/CC"

if [ ! -e $CP_ID_FILE ] ; then 
    echo "Captive Portal Profile $CP_ID_FILE not exist!"
 #   exit 4;
fi

CPS_IF=$(ls /var/run/cpp/CP_IF_INFO* 2>/dev/null)
if [ $CPS_IF ];then
    for file in $CPS_IF
    do
        id=$(cat $file)
       # if [ "x$id" == "x${CP_ID_TYPE}${CP_ID}" ]; then
        #    echo "${CP_ID_TYPE}${CP_ID} has $file not del! you should del it first!"
         #   exit 4
        #fi
    done
fi


#iptables -D $MAC_PRE_FILTER -j $MAC_PRE_AUTH_F
#iptables -F $MAC_PRE_AUTH_F
#iptables -X $MAC_PRE_AUTH_F
#echo 111
#iptables -t nat -D $MAC_PRE_DNAT -j $MAC_PRE_AUTH_N
#iptables -F $MAC_PRE_AUTH_N -t nat
#iptables -X $MAC_PRE_AUTH_N -t nat


echo 222
iptables -F $CP_FILTER_DEFAULT
iptables -X $CP_FILTER_DEFAULT
echo 333
iptables -t nat -F $CP_NAT_DEFAULT
iptables -t nat -X $CP_NAT_DEFAULT
echo 444

iptables -D $CP_FILTER_AUTHORIZED_DEFAULT -j FW_FILTER
iptables -F $CP_FILTER_AUTHORIZED_DEFAULT
iptables -X $CP_FILTER_AUTHORIZED_DEFAULT
echo 555
#iptables -t nat -D $CP_NAT_AUTHORIZED_DEFAULT -j FW_DNAT
#iptables -t nat -F $CP_NAT_AUTHORIZED_DEFAULT
#iptables -t nat -X $CP_NAT_AUTHORIZED_DEFAULT
echo 666

rm -rf /var/run/cpp 
