#!/bin/sh
#
###########################################################################
#
#              Copyright (C) Autelan Technology
#
#This software file is owned and distributed by Autelan Technology 
#
############################################################################
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
#ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
#WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
#DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
#ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
#(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
#LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
#ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
#(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
#SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##############################################################################
#
# eag_init
#
# CREATOR:
# autelan.software.shaojunwu. team
# 
# DESCRIPTION: 
#    init $IPTABLES bash chain!!!
#    for firewall captive portal and asd prev auth
#  filter like!!!
#Chain INPUT (policy ACCEPT 5891 packets, 640047 bytes)
#    pkts      bytes target     prot opt in     out     source               destination         
#
#Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
#    pkts      bytes target     prot opt in     out     source               destination         
#       0        0 ASD_FILTER  0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#       0        0 CP_FILTER  0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#       0        0 FW_FILTER  0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain OUTPUT (policy ACCEPT 1777 packets, 940641 bytes)
#    pkts      bytes target     prot opt in     out     source               destination         
#
#Chain ASD_FILTER (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#       0        0 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain CP_FILTER (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#       0        0 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain FW_FILTER (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#       0        0 TRAFFIC_CONTROL  0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain TRAFFIC_CONTROL (1 references)
#    pkts      bytes target     prot opt in     out     source               destination
#       0        0 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0
#  nat like!!!
#sh-3.1# /opt/bin/$IPTABLES -t nat -nvxL
#Chain PREROUTING (policy ACCEPT 2 packets, 96 bytes)
#    pkts      bytes target     prot opt in     out     source               destination         
#    3877   330542 ASD_DNAT   0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#    3877   330542 CP_DNAT    0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#    4345   373105 FW_DNAT    0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain POSTROUTING (policy ACCEPT 1 packets, 69 bytes)
#    pkts      bytes target     prot opt in     out     source               destination         
#      11     2346 FW_SNAT    0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain OUTPUT (policy ACCEPT 12 packets, 2415 bytes)
#    pkts      bytes target     prot opt in     out     source               destination         
#
#Chain ASD_DNAT (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#    3877   330542 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain CP_DNAT (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#    3870   330178 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain FW_DNAT (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#    4343   373009 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#Chain FW_SNAT (1 references)
#    pkts      bytes target     prot opt in     out     source               destination         
#      11     2346 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0           
#
#
#############################################################################
IPTABLES="iptables"

FW_FILTER="FW_FILTER"
#FW_INPUT="FW_INPUT"
FW_DNAT="FW_DNAT"
#FW_SNAT="FW_SNAT"

CP_DNAT="CP_DNAT"
CP_FILTER="CP_FILTER"
#MAC_PRE_DNAT="MAC_PRE_DNAT"
#MAC_PRE_FILTER="MAC_PRE_FILTER"
#EAP_DNAT="EAP_DNAT"
#EAP_FILTER="EAP_FILTER"


$IPTABLES -nL $FW_FILTER > /dev/null 2>&1
if [ ! $? -eq 0 ];then
    $IPTABLES -N $FW_FILTER
    $IPTABLES -I FORWARD -j $FW_FILTER
    $IPTABLES -A $FW_FILTER -j ACCEPT
fi


#$IPTABLES -nL $FW_INPUT > /dev/null 2>&1
#if [ ! $? -eq 0 ];then
#    $IPTABLES -N $FW_INPUT
#    $IPTABLES -I INPUT -j $FW_INPUT
#    $IPTABLES -A $FW_INPUT -j RETURN
#fi

#$IPTABLES -t nat -nL $FW_DNAT > /dev/null 2>&1
#if [ ! $? -eq 0 ];then
#    $IPTABLES -t nat -N $FW_DNAT
#    $IPTABLES -t nat -I PREROUTING -j $FW_DNAT
#    $IPTABLES -t nat -A $FW_DNAT -j ACCEPT
#fi

#$IPTABLES -t nat -nL $FW_SNAT > /dev/null 2>&1
#if [ ! $? -eq 0 ];then
#    $IPTABLES -t nat -N $FW_SNAT
#    $IPTABLES -t nat -I POSTROUTING -j $FW_SNAT
#    $IPTABLES -t nat -A $FW_SNAT -j ACCEPT
#fi

$IPTABLES -nL $CP_FILTER > /dev/null 2>&1
if [ ! $? -eq 0 ];then                        
    $IPTABLES -N $CP_FILTER
    $IPTABLES -I FORWARD -j $CP_FILTER
    $IPTABLES -A $CP_FILTER -j RETURN
fi

$IPTABLES -nL $CP_DNAT -t nat > /dev/null 2>&1
if [ ! $? -eq 0 ];then                        
    $IPTABLES -t nat -N $CP_DNAT
    $IPTABLES -t nat -I PREROUTING -j $CP_DNAT
    $IPTABLES -t nat -A $CP_DNAT -j RETURN
fi

#$IPTABLES -nL $MAC_PRE_FILTER > /dev/null 2>&1
#if [ ! $? -eq 0 ];then                        
#    $IPTABLES -N $MAC_PRE_FILTER
#    $IPTABLES -I FORWARD -j $MAC_PRE_FILTER
#    $IPTABLES -A $MAC_PRE_FILTER -j RETURN
#fi

#$IPTABLES -nL $MAC_PRE_DNAT -t nat > /dev/null 2>&1
#if [ ! $? -eq 0 ];then                        
#    $IPTABLES -t nat -N $MAC_PRE_DNAT
#    $IPTABLES -t nat -I PREROUTING -j $MAC_PRE_DNAT
#    $IPTABLES -t nat -A $MAC_PRE_DNAT -j RETURN
#fi

#$IPTABLES -nL $EAP_FILTER > /dev/null 2>&1
#if [ ! $? -eq 0 ];then                        
#    $IPTABLES -N $EAP_FILTER
#    $IPTABLES -I FORWARD -j $EAP_FILTER
#    $IPTABLES -A $EAP_FILTER -j RETURN
#fi

#$IPTABLES -nL $EAP_DNAT -t nat > /dev/null 2>&1
#if [ ! $? -eq 0 ];then                        
 #   $IPTABLES -t nat -N $EAP_DNAT
 #   $IPTABLES -t nat -I PREROUTING -j $EAP_DNAT
  #  $IPTABLES -t nat -A $EAP_DNAT -j RETURN
#fi






source cp_start.sh
#delete the username or password
if [ ! $# -eq 2 ] ; then
	echo "Usage: cp_create_profile.sh  PORTALIP PORTALPORT  "
	exit 1;
fi

#prepare params
#CP_ID=$1
#CP_ID_TYPE=$2
CP_IP=$1
CP_PORT=$2

#FW_FILTER="FW_FILTER"
#FW_DNAT="FW_DNAT"
CP_DNAT="CP_DNAT"
CP_FILTER="CP_FILTER"
#MAC_PRE_DNAT="MAC_PRE_DNAT"
#MAC_PRE_FILTER="MAC_PRE_FILTER"
#EAP_DNAT="EAP_DNAT"
#EAP_FILTER="EAP_FILTER"
#MAC_PRE_AUTH_N="MAC_PRE_AUTH_N"
#MAC_PRE_AUTH_F="MAC_PRE_AUTH_F"
#MAC_PRE_IPHASH_SET="MAC_PRE_AUTH_SET"
#add for eap authorize or none-authenticate 
#EAP_PRE_AUTH_N="EAP_PRE_AUTH_N"
#EAP_PRE_AUTH_F="EAP_PRE_AUTH_F"
#end
CP_FILTER_DEFAULT="CP_F_DEFAULT"
CP_FILTER_AUTHORIZED_DEFAULT="CP_F_AUTH_DEFAULT"
CP_NAT_DEFAULT="CP_N_DEFAULT"
#CP_NAT_AUTHORIZED_DEFAULT="CP_N_AUTH_DEFAULT"
#CP_IPHASH_SET="CP_AUTHORIZED_SET"

CP_ID_FILE="/var/run/cpp/CP"

[ -d /var/run/cpp ] || mkdir /var/run/cpp

#CP_ID+CP_ID_TYPEΨһ
if [ -e $CP_ID_FILE ] ; then 
    ip=$(cat $CP_ID_FILE)
    echo "Captive Portal Profile already exist with IP ${ip}"
    exit 4;
fi
printf "${CP_IP} ${CP_PORT}" > $CP_ID_FILE


#iptables -nL $CP_FILTER > /dev/null 2>&1
#if [ ! $? -eq 0 ];then                        
#    iptables -N $CP_FILTER
#    iptables -I FORWARD -j $CP_FILTER
#    iptables -A $CP_FILTER -j RETURN
#fi

#iptables -nL $CP_DNAT -t nat > /dev/null 2>&1
#if [ ! $? -eq 0 ];then                        
#    iptables -t nat -N $CP_DNAT
#    iptables -t nat -I PREROUTING -j $CP_DNAT
#    iptables -t nat -A $CP_DNAT -j RETURN
#fi


#iptables -nL $MAC_PRE_AUTH_F  > /dev/null 2>&1
#if [ ! $? -eq 0 ];then   
#	iptables -N $MAC_PRE_AUTH_F
#	iptables -I $MAC_PRE_FILTER -j $MAC_PRE_AUTH_F
#	iptables -A $MAC_PRE_AUTH_F -j RETURN
#fi

#iptables -nL $MAC_PRE_AUTH_N -t nat > /dev/null 2>&1
#if [ ! $? -eq 0 ];then   
#	iptables -t nat -N $MAC_PRE_AUTH_N
#	iptables -t nat -I $MAC_PRE_DNAT -j $MAC_PRE_AUTH_N
#	iptables -t nat -A $MAC_PRE_AUTH_N -j RETURN
#fi

#eap authorize or none-authenticate

#iptables -nL $EAP_PRE_AUTH_F  > /dev/null 2>&1
#if [ ! $? -eq 0 ];then   
#	iptables -N $EAP_PRE_AUTH_F
#	iptables -I $EAP_FILTER -j   $EAP_PRE_AUTH_F
#	iptables -A $EAP_PRE_AUTH_F -j RETURN
#fi

#iptables -nL $EAP_PRE_AUTH_N -t nat > /dev/null 2>&1
#if [ ! $? -eq 0 ];then   
#	iptables -N $EAP_PRE_AUTH_N -t nat
#	iptables -t nat -I $EAP_DNAT -j $EAP_PRE_AUTH_N
#	iptables -t nat -A $EAP_PRE_AUTH_N -j RETURN
#fi

#end eap authorize or none-authenticate

iptables -N $CP_FILTER_DEFAULT
iptables -I $CP_FILTER_DEFAULT -j DROP
iptables -I $CP_FILTER_DEFAULT -p udp --sport 68 --dport 67 -j ACCEPT
iptables -I $CP_FILTER_DEFAULT -p udp --sport 67 --dport 68 -j ACCEPT
iptables -I $CP_FILTER_DEFAULT -d $CP_IP -j ACCEPT

iptables -t nat -N $CP_NAT_DEFAULT
iptables -t nat -I $CP_NAT_DEFAULT -j RETURN
iptables -t nat -I $CP_NAT_DEFAULT -p tcp -m tcp --dport 80 -j DNAT --to-destination ${CP_IP}:${CP_PORT}
iptables -t nat -I $CP_NAT_DEFAULT -p tcp -m tcp --dport 8080 -j DNAT --to-destination ${CP_IP}:${CP_PORT}
#iptables -t nat -I $CP_NAT_DEFAULT -p tcp -m tcp --dport 443 -j DNAT --to-destination ${CP_IP}:${CP_PORT}
iptables -t nat -I $CP_NAT_DEFAULT -d $CP_IP -j ACCEPT
#
iptables -N $CP_FILTER_AUTHORIZED_DEFAULT
iptables -I $CP_FILTER_AUTHORIZED_DEFAULT -j FW_FILTER

#iptables -t nat -N $CP_NAT_AUTHORIZED_DEFAULT
#iptables -t nat -I $CP_NAT_AUTHORIZED_DEFAULT -j FW_DNAT


