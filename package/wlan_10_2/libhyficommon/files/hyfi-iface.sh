WLAN_DEVICES=
WLAN_DEVICE_NUM=
ETHER_DEVICES=
PLC_DEVICE=
ALL_DEVICES=

local ieee1905managed_found=0
local ieee1905managed_bridge=""
local bound_bridge=""

__hyfi_get_wlan_vifnum() {
	local config="$1"
	local iface network disabled
	local phydev phydisabled

	config_get network "$config" network
	config_get disabled "$config" disabled '0'
	config_get phydev "$config" device ""

	if [ -z "$phydev" ]; then
		return
	fi

	config_get phydisabled ${phydev} disabled 0
	if [ $phydisabled -eq 0 -a "$2" = "$network" -a "$disabled" -eq 0 ]; then
		WLAN_DEVICE_NUM=$((WLAN_DEVICE_NUM + 1))
	fi
}

# hyfi_get_wlan_vifnum()
# input: $1 IEEE1905.1 managed bridge interface
# output: $2 number of WLAN interfaces bound to the bridge
hyfi_get_wlan_vifnum() {
	local ieee1905managed="$1"

	WLAN_DEVICE_NUM=0
	config_load wireless
	config_foreach __hyfi_get_wlan_vifnum wifi-iface $ieee1905managed

	eval "$2='${WLAN_DEVICE_NUM}'"
}

__hyfi_get_wlan_ifaces() {
	local config="$1"
	local iface network disabled

	config_get iface "$config" ifname
	config_get network "$config" network
	config_get disabled "$config" disabled '0'

	if [ -n "$iface" -a "$2" = "$network" -a "$disabled" -eq 0 ]; then
		WLAN_DEVICES="${WLAN_DEVICES}${WLAN_DEVICES:+","}${iface}:WLAN"
	fi
}

# hyfi_get_wlan_ifaces()
# input: $1 IEEE1905.1 managed bridge interface
# output: $2 List of all WLAN interfaces bound to the bridge
hyfi_get_wlan_ifaces() {
	local ieee1905managed="$1"

	WLAN_DEVICES=""
	hyfi_network_sync
	config_load wireless
	config_foreach __hyfi_get_wlan_ifaces wifi-iface $ieee1905managed

	eval "$2='${WLAN_DEVICES}'"
}

__hyfi_get_switch_iface() {
	local loc_switch_iface
	local ref_design

	config_load hyd
	config_get loc_switch_iface config SwitchInterface ""

	if [ -z "$loc_switch_iface" ]; then
		eval "$1=''"
		return
	fi
	if [ "$loc_switch_iface" = "auto" ]; then
		ref_design=`cat /tmp/sysinfo/board_name`

		# List of supported reference designs. For other designs
		# either add to cases, or setup SwitchInterface.
		case "$ref_design" in
		ap148|ap145|db149)
		# S17c switch
			loc_switch_iface="eth1"
			;;
		ap135)
		# ap135 has S17 switch, which is not fully supported by
		# the multicast switch wrapper. Disable it for now until
		# support for S17 will be added.
			loc_switch_iface=""
			;;
		*)
			loc_switch_iface=""
			;;
		esac
	fi

	local loc_switch_cpu_port
	__hyfi_get_switch_cpu_port loc_switch_cpu_port

	local lan_vid
	__hyfi_get_switch_lan_vid lan_vid

	if [ -z "$switch_cpu_port_tagged" ]; then
		eval "$1='$loc_switch_iface'"
	else
		eval "$1='${loc_switch_iface}.${lan_vid}'"
	fi
}

__hyfi_get_switch_lan_vid() {
	local loc_lan_vid

	config_load hyd
	config_get loc_lan_vid config SwitchLanVid ""

	eval "$1='$loc_lan_vid'"
}

__hyfi_get_switch_cpu_port_iterate() {
	config_get vlan "$1" "vlan"
	config_get ports "$1" "ports"

	if [ "${vlan}" = "$2" ]; then
		switch_cpu_port=`echo ${ports} |sed 's/t//g' |cut -f 1 -d " "`
		switch_cpu_port_tagged=`echo ${ports} |grep t`
	fi
}

__hyfi_get_switch_cpu_port() {
	local lan_vid
	__hyfi_get_switch_lan_vid lan_vid

	config_load network
	config_foreach __hyfi_get_switch_cpu_port_iterate switch_vlan $lan_vid

	eval "$1='$switch_cpu_port'"
}

__hyfi_get_ether_ifaces() {
	local config="$1"
	local ifnames network plciface

	config_get ifnames "$config" device

	config_load plc
	config_get plciface config PlcIfname


	local switch_iface
	__hyfi_get_switch_iface switch_iface

	if [ "$2" = "$config" ]; then
	   for iface in $ifnames; do
		   [ "$iface" = "$plciface" ] && continue
		if [ "$iface" = "$switch_iface" ]; then
			ETHER_DEVICES="${ETHER_DEVICES}${ETHER_DEVICES:+","}${iface}:ESWITCH"
		else
			ETHER_DEVICES="${ETHER_DEVICES}${ETHER_DEVICES:+","}${iface}:ETHER"
		fi
	   done
	fi
}

# hyfi_get_ether_ifaces()
# input: $1 IEEE1905.1 managed bridge interface
# output: $2 List of all Ethernet interfaces bound to the bridge
hyfi_get_ether_ifaces() {
	local ieee1905managed="$1"

	ETHER_DEVICES=""
	hyfi_network_sync
	config_load network
	config_foreach __hyfi_get_ether_ifaces interface $ieee1905managed

	eval "$2='${ETHER_DEVICES}'"
}

__hyfi_get_plc_iface() {
	local plciface iface
	local ieee1905managed="$1"

	config_load plc
	config_get plciface config PlcIfname

	[ -z "$plciface" ] && return

	config_load network
	config_get ifnames $ieee1905managed device

	for iface in $ifnames; do
		if [ "$iface" = "$plciface" ]; then
			PLC_DEVICE=${plciface}:PLC
			return
		fi
	done
}

# hyfi_get_plc_iface()
# input: $1 IEEE1905.1 managed bridge interface
# output: $2 PLC interface bound to the bridge
hyfi_get_plc_iface() {
	local ieee1905managed="$1"

	PLC_DEVICE=""
	hyfi_network_sync

	__hyfi_get_plc_iface $ieee1905managed
	eval "$2='${PLC_DEVICE}'"
}

# hyfi_get_ifaces()
# input: $1 IEEE1905.1 managed bridge interface
# output: $2 List of ALL interface bound to the bridge
hyfi_get_ifaces() {
	local ieee1905managed="$1"

	WLAN_DEVICES=""
	ETHER_DEVICES=""
	PLC_DEVICE=""
	hyfi_network_sync

	config_load network
	config_foreach __hyfi_get_ether_ifaces interface $ieee1905managed

	config_load wireless
	config_foreach __hyfi_get_wlan_ifaces wifi-iface $ieee1905managed

	__hyfi_get_plc_iface $ieee1905managed

	ALL_DEVICES=$WLAN_DEVICES
	if [ -n "$ETHER_DEVICES" ]; then
		[ -z "$ALL_DEVICES" ] || ALL_DEVICES="${ALL_DEVICES},"
		ALL_DEVICES="${ALL_DEVICES}${ETHER_DEVICES}"
	fi
	if [ -n "$PLC_DEVICE" ]; then
		[ -z "$ALL_DEVICES" ] || ALL_DEVICES="${ALL_DEVICES},"
		ALL_DEVICES="${ALL_DEVICES}${PLC_DEVICE}"
	fi

	eval "$2='${ALL_DEVICES}'"
}

__hyfi_iterate_networks() {
	local config="$1"
	local type ieee1905managed

	[ "$ieee1905managed_found" -eq "1" ] && return

	config_get type "$config" type
	[ -z "$type" -o ! "$type" = "bridge" ] && return

	config_get_bool ieee1905managed "$config" ieee1905managed

	[ -z "$ieee1905managed" ] && return

	if [ "$ieee1905managed" -eq "1" ]; then
		ieee1905managed_found=1
		ieee1905managed_bridge="$config"
	fi
}

__hyfi_iterate_networks2() {
	local config="$1"
	local my_iface="$2"
	local ifnames iface type

	[ -n "$bound_bridge" ] && return

	config_get type "$config" type
	[ -z "$type" -o ! "$type" = "bridge" ] && return

	config_get ifnames "$config" device

	for iface in $ifnames; do
		if [ "$iface" = "$my_iface" ]; then
			bound_bridge=br-$config
			return
		fi
	done
}

# hyfi_get_ieee1905_managed_iface()
# output: $1 IEEE1905.1 managed bridge interface
# Note: If no entry exists, the function will set the "lan"
# interface as the default managed bridge
hyfi_get_ieee1905_managed_iface() {
	ieee1905managed_found=0
	ieee1905managed_bridge=""

	config_load network
	config_foreach __hyfi_iterate_networks interface
	eval "$1='$ieee1905managed_bridge'"
	[ "$ieee1905managed_found" -eq "1" ] && return

	ieee1905managed_bridge="lan"
	uci_set network $ieee1905managed_bridge ieee1905managed 1
	uci_commit network

	config_load network
	__hyfi_iterate_networks $ieee1905managed_bridge

	eval "$1='$ieee1905managed_bridge'"
}

# hyfi_strip_list
# input: $1 list of interfaces with attached type
# output: $2 same list with type stripped
hyfi_strip_list() {
	eval "$2='`echo $1 | sed 's/:[A-Z]*,/ /g' | sed 's/:[A-Z]*//g`'"
}

# hyfi_get_bridge_from_iface()
# input: $1 interface name
# output: $2 bridge the interface is bound to
hyfi_get_bridge_from_iface() {
	bound_bridge=""
	local iface="$1"

	config_load network
	config_foreach __hyfi_iterate_networks2 interface $iface

	eval "$2='$bound_bridge'"
}
