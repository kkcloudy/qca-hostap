#!/bin/sh

RESULT_FILE="/tmp/tech_support_command_result"

( [ "$1" = "-h" ] || [ "$1" = "-help" ] ) && usage
if [ $# -ne 1 ];then
	echo "parameter is wrong ,please retry !"
	exit 1
fi

#usage()
#print usage
usage()
{
	echo "usage:"
	echo "0 show extended info"
	echo "1 show system info"
	echo "2 show WIFI info"
	echo "3 reserve"
	exit 0
}

show_extended_info()
{
	echo "show_extended_info"
}

show_system_info()
{
	[ -f "${RESULT_FILE}" ] && rm -rf ${RESULT_FILE}

	echo -e "\ndf -h" >> ${RESULT_FILE}
	df -h >> ${RESULT_FILE}
	echo -e "\nsar 1 1" >> ${RESULT_FILE}
	sar 1 1 >> ${RESULT_FILE}
	echo -e "\nfree" >> ${RESULT_FILE}
	free >> ${RESULT_FILE}
}

show_wifi_info()
{
	[ -f "${RESULT_FILE}" ] && rm -rf ${RESULT_FILE}
	
	echo -e "\niwconfig" >> ${RESULT_FILE}
	iwconfig >> ${RESULT_FILE}
	
	IFNAME="$(iwconfig  | grep 'ath' |awk '{print$1}')"
	for line in ${IFNAME}
	do
		echo $line
		echo -e "\nwlanconfig $line list" >> ${RESULT_FILE}
		wlanconfig $line list >> ${RESULT_FILE}
	done
}

case "$1" in
	0)
		show_extended_info
	;;
	1)
		show_system_info
	;;
	2)
		show_wifi_info
	;;
	*)
		usage
	;;
esac
