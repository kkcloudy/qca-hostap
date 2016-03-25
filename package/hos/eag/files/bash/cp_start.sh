#!/bin/sh

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin

CP_DB_FILE='/opt/services/conf/portal_conf.conf'
#CP_USER_INFO='/opt/services/option/portal_option'
CP_WHITE_BLACK_LIST='/opt/services/option/portal_option'
CP_WHITE_LIST_DOMAIN_TEMP='/opt/services/option/white_list_domain_temp'           #add by liusheng

#CP_EAG_USER_PROCFILE='/var/run/eag_portal_username'							#modify by liusheng
CP_EAG_ID_PROCFILE='/var/run/eag_portal_id'
CP_EAG_IF_PROCFILE='/var/run/eag_portal_interface'
CP_RECORD_DB='/var/run/cpp/cp_user_record.db'

CP_WHITE_LIST_FLAG=0
CP_BLACK_LIST_FLAG=1
CP_WHITE_LIST_FLAG_DOMAIN=3
CP_BLACK_LIST_FLAG_DOMAIN=4
#description of the first flag.
#0  white list with IP
#1  black list with IP
#3  white list with domain
#4  black list with domain
#-----add by wk-----


#domain num
CP_RECORD_ID_INDEX=1
CP_RECORD_PORTALIP_INDEX=2
CP_RECORD_PORTALPORT_INDEX=3
CP_RECORD_USERNAME_INDEX=4
CP_RECORD_USERPWD_INDEX=5
CP_RECORD_IF_INDEX=6
CP_RECORD_DOMAIN_NUM=6
#end define record domain

#两种模式
CP_MODE_IPSET=1
CP_MODE_IPTABLES=2
#使用哪种模式
#使用iptables能统计流量
CP_CUR_MODE=${CP_MODE_IPTABLES}



DEBUG_LOG=1
WARNING_LOG=1
ERROR_LOG=1

log()
{
	FACILITY="daemon"
	LEVEL="$1"
	PREFIX="eag:"
	MESSAGE="$2"
	DEVICE="/dev/log"
	
	logger -u ${DEVICE} -p ${FACILITY}.${LEVEL} -t ${PREFIX} "${MESSAGE}"
}


log_dbg()
{
	if [ "x$DEBUG_LOG" == "x1" ];then
		log debug "DEBUG: $1"
	fi
}

log_warning()
{
	if [ "x$WARNING_LOG" == "x1" ];then
		log warning "WARNING: $1"
	fi
}

log_error()
{
	echo "param = $#"
	if [ "x$ERROR_LOG" == "x1" ];then
		log error "ERROR: $1"
	fi
}


get_user_interface()
{
	IP_GET_INTF_LINE="";
	EEERRR=1;
	if [ $# -eq 1 ];then
		IP_EXMASK=`echo $1|awk -v FS="." '{printf $1"."$2"."$3}'`;
		IP_GET_INTF_LINE=`ip addr | grep inet | grep $IP_EXMASK".255"`;
		if [ "x${IP_GET_INTF_LINE}" == "x" ];then
			IP_EXMASK=`echo $1|awk -v FS="." '{printf $1"."$2}'`;
			IP_GET_INTF_LINE=`ip addr | grep inet | grep $IP_EXMASK".255.255"`;
		fi
		if [ "x${IP_GET_INTF_LINE}" != "x" ];then
			echo $IP_GET_INTF_LINE | awk '{printf $7}'
			EEERRR=0;
		fi
		return $EEERRR;
	else
		return 1;
	fi
}


