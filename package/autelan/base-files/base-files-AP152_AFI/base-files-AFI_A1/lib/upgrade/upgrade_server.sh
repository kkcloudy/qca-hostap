#!/bin/sh

get_upgrade_server_address()
{
	local svr_addr
	local svr_addr_temp
	local ap_mode
	
	# zhouke modify del WorkMode definition
	local ident_port
	ident_port="$(/sbin/uci get wtpd.@wtp[0].ident_port)" > /dev/null 2>&1
	if [ "" == "$ident_port" ]; then
		ap_mode="$(/sbin/uci get system.runmode.ap_mode)" > /dev/null 2>&1
		if [ "cloud" == "$ap_mode" ]; then
			ident_port="(/sbin/uci get system.cloudmode.ident_port)" > /dev/null 2>&1
		else
			ident_port="default"
		fi
		/sbin/uci set wtpd.@wtp[0].ident_port=$ident_port
		/sbin/uci commit wtpd	
		/sbin/uci delete system.runmode > /dev/null 2>&1
		/sbin/uci delete system.cloudmode > /dev/null 2>&1
		/sbin/uci commit system
	fi
	#ap_mode="$(/sbin/uci get system.runmode.ap_mode)" > /dev/null 2>&1
	#if [ "cloud" != "$ap_mode" ]; then
	if [ "default" == "$ident_port" ]; then
		svr_addr="$(partool -part mtd2 -show recovery.domain.ac)"
		if [ "$svr_addr" == "recovery.domain.ac not exist" ]; then
			svr_addr=""
		fi
	else
		svr_addr_temp="$(/sbin/uci -c /etc/.system get baton.wtpd.current_ac)" > /dev/null 2>&1
		[ x"$svr_addr_temp" != x ] && svr_addr=${svr_addr_temp}" "
		svr_addr_temp="$(/sbin/uci get wtpd.@wtp[0].ac_addr)" > /dev/null 2>&1
		[ x"$svr_addr_temp" != x ] && svr_addr=${svr_addr}${svr_addr_temp}" "
		svr_addr_temp="$(/sbin/uci get wtpd.@wtp[0].ac_domain_name)" > /dev/null 2>&1
		[ x"$svr_addr_temp" != x ] && svr_addr=${svr_addr}${svr_addr_temp}" "
		svr_addr=${svr_addr// /,}
	fi
	
	echo "$svr_addr"
}

get_upgrade_port()
{
	local server_port
	local ap_mode
	
	# zhouke modify del WorkMode definition
	local ident_port
	ident_port="$(/sbin/uci get wtpd.@wtp[0].ident_port)" > /dev/null 2>&1
	if [ "" == "$ident_port" ]; then
		ap_mode="$(/sbin/uci get system.runmode.ap_mode)" > /dev/null 2>&1
		if [ "cloud" == "$ap_mode" ]; then
			ident_port="(/sbin/uci get system.cloudmode.ident_port)" > /dev/null 2>&1
		else
			ident_port="default"
		fi
		/sbin/uci set wtpd.@wtp[0].ident_port=$ident_port
		/sbin/uci commit wtpd	
		/sbin/uci delete system.runmode > /dev/null 2>&1
		/sbin/uci delete system.cloudmode > /dev/null 2>&1
		/sbin/uci commit system
	fi
	#ap_mode="$(/sbin/uci get system.runmode.ap_mode)" > /dev/null 2>&1
	#if [ "cloud" == "$ap_mode" ]; then
	if [ "default" != "$ident_port" ]; then
		#server_port="$(/sbin/uci get system.cloudmode.ident_port)" > /dev/null 2>&1
		#if  [ x"$server_port" != x ]; then
		#	server_port=$((server_port+1))
		#else
		#	server_port="80"
		#fi
		server_port=$((ident_port+1))
	else
		server_port="80"
	fi
	echo "$server_port" > /tmp/server_port
	echo "$server_port"
}

get_upgrade_url()
{
	local upgrade_url=""
	local sever_port=""
	upgrade_url="$(cat /tmp/addrinfo)"
	if [ $? -ne 0 ] || [ "$upgrade_url" = "" ] || [ "$upgrade_url" = "recovery.path not exist" ]; then
		echo "upgrade url error!"
		return 1
	fi
	
	server_port="$(cat /tmp/server_port)"
	if [ $? -ne 0 ] || [ "$server_port" = "" ]; then
		echo "$upgrade_url"
	else
		eval upgrade_url="$(sed -e 's/80\//$server_port\//g' /tmp/addrinfo)"
		echo "$upgrade_url"
	fi
	
	return 0
}
