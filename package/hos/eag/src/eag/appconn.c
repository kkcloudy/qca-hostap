/*******************************************************************************
Copyright (C) Autelan Technology


This software file is owned and distributed by Autelan Technology 
********************************************************************************


THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
********************************************************************************
* appconn.c
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* appconn
*
*
*******************************************************************************/
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <iptables.h>

#include "nm_list.h"
#include "hashtable.h"
#include "eag_mem.h"
#include "eag_log.h"
#include "eag_blkmem.h"
#include "eag_thread.h"
#include "eag_conf.h"  //not need
#include "eag_time.h"
#include "eag_util.h"
#include "nmp_process.h"

#include "eag_ipinfo.h"
#include "eag_wireless.h"
#include "appconn.h"
#include "eag_iptables.h"
#include "eag_ins.h"
#include "eag_interface.h"


#define debug_appconn(fmt,args...)	eag_log_debug("appconn", fmt, ##args)
#define error_appconn				eag_log_err

#define APPCONN_BLKMEM_NAME 		"appconn_blkmem"
#define APPCONN_BLKMEM_ITEMNUM		1024
#define APPCONN_BLKMEM_MAXNUM		16

#define EAG_DBUS_DHCP_BUSNAME	"aw.dhcp" 
#define EAG_DBUS_DHCP_OBJPATH	"/aw/dhcp"
#define EAG_DBUS_DHCP_INTERFACE	"aw.dhcp"

#define EAG_DBUS_METHOD_SHOW_DHCP_LEASE_BY_IP	"dhcp_show_lease_by_ip"
#define EAG_DBUS_METHOD_GET_DHCP_LEASE_INFO		"dhcp_get_lease_info"
#define FLUX_INTERVAL_FOR_IPTABLES_OR_WIRELESS	20

extern nmp_mutex_t eag_iptables_lock;

/*data base of appconn */
struct appconn_db {
	struct list_head head;
	eag_blk_mem_t *conn_blkmem;

	uint32_t appindex;
	hashtable *ip_htable;
	hashtable *mac_htable;
	hashtable *name_htable;

	
	struct nasid_conf *nasidconf;
	struct nasportid_conf *nasportidconf;
	struct portal_conf *portalconf;
	
	int force_wireless;
	int check_nasportid;
	unsigned long idle_timeout;
	uint64_t idle_flow;

	uint32_t input_correct_factor;
	uint32_t output_correct_factor;

	eag_ins_t *eagins;
	int authed_user_num; /* now is used for trap online_user_num */ 
};

appconn_db_t *appconn_db_create(uint32_t size)
{
	appconn_db_t *appdb = NULL;
	
	if (0 == size) {
		error_appconn("appconn_db_create input error");
		return NULL;
	}

	appdb = eag_malloc(sizeof(appconn_db_t));
	if (NULL == appdb) {
		error_appconn("appconn_db_create malloc failed");
		goto failed_0;
	}
	
	memset(appdb, 0, sizeof(appconn_db_t));
	if (EAG_RETURN_OK != hashtable_create_table(&(appdb->ip_htable), size)) {
		eag_log_err("appconn_db_create ip hashtable create failed");
		goto failed_1;
	}

	if (EAG_RETURN_OK != hashtable_create_table(&(appdb->mac_htable), size)) {
		eag_log_err("appconn_db_create mac hashtable create failed");
		goto failed_2;
	}
	if (EAG_RETURN_OK != hashtable_create_table(&(appdb->name_htable), size)) {
		eag_log_err("appconn_db_create name hashtable create failed");
		goto failed_3;
	}
	if (EAG_RETURN_OK != eag_blkmem_create(&(appdb->conn_blkmem),
							APPCONN_BLKMEM_NAME,
							sizeof(struct app_conn_t),
							APPCONN_BLKMEM_ITEMNUM, 
							APPCONN_BLKMEM_MAXNUM)) {
		eag_log_err("appconn_db_create blkmem_create failed");
		goto failed_4;
	}
	INIT_LIST_HEAD(&(appdb->head));
	appdb->force_wireless = 1;
	appdb->idle_timeout = DEFAULT_IDLE_TIMEOUT;
	appdb->idle_flow = DEFAULT_IDLE_FLOW;
	appdb->input_correct_factor = 1000;
	appdb->output_correct_factor = 1000;
	eag_log_info("appconn_db create ok");
	
	return appdb;

failed_4:
	hashtable_destroy_table(&(appdb->name_htable));
failed_3:
	hashtable_destroy_table(&(appdb->mac_htable));
failed_2:
	hashtable_destroy_table(&(appdb->ip_htable));
failed_1:
	eag_free(appdb);
failed_0:
	return NULL;
}

int
appconn_db_destroy(appconn_db_t *appdb)
{
	if (NULL == appdb) {
		eag_log_err("appconn_db_destroy input error");
		return -1;
	}
	
	if (NULL != appdb->conn_blkmem) {
		eag_blkmem_destroy(&(appdb->conn_blkmem));
	}
	if (NULL != appdb->ip_htable) {
		hashtable_destroy_table(&(appdb->ip_htable));
	}
	if (NULL != appdb->mac_htable) {
		hashtable_destroy_table(&(appdb->mac_htable));
	}
	if (NULL != appdb->name_htable) {
		hashtable_destroy_table(&(appdb->name_htable));
	}
	eag_free(appdb);

	eag_log_info("appconn db destroy ok");

	return 0;
}

struct app_conn_t *
appconn_new(appconn_db_t *appdb)
{
	struct timeval tv = {0};
	time_t timenow = 0;
	struct app_conn_t *appconn = NULL;
	
	if (NULL == appdb) {
		eag_log_err("appconn_new input error");
		return NULL;
	}
	appconn = eag_blkmem_malloc_item(appdb->conn_blkmem);
	if (NULL == appconn) {
		eag_log_err("appconn_new blkmem_malloc_item failed");
		return NULL;
	}

	memset(appconn, 0, sizeof(struct app_conn_t));
	appdb->appindex++;
	appconn->session.index = appdb->appindex;
	appconn->appdb = appdb;

	eag_time_gettimeofday(&tv, NULL);
	timenow = tv.tv_sec;
	appconn->last_active_time = timenow;
	appconn->session.session_start_time = timenow;
	appconn->session.accurate_start_time = time(NULL);
	appconn->session.last_connect_ap_time = timenow;
	appconn->session.idle_check = 1;
	appconn->session.idle_timeout = appdb->idle_timeout;
	appconn->session.idle_flow = appdb->idle_flow;

	return appconn;
}

int
appconn_free(struct app_conn_t *appconn)
{
	appconn_db_t *appdb = NULL;
	
	if (NULL == appconn) {
		eag_log_err("appconn_free input error");
		return -1;
	}
	appdb = appconn->appdb;
	
	eag_blkmem_free_item(appdb->conn_blkmem, appconn);

	return EAG_RETURN_OK;
}

static int
appconn_update_ip_htable(appconn_db_t *appdb,
						struct app_conn_t *appconn)
{
	return hashtable_check_add_node(appdb->ip_htable,
					&(appconn->session.user_ip),
					sizeof(appconn->session.user_ip),
					&(appconn->ip_hnode));

}

static int
appconn_update_mac_htable(appconn_db_t *appdb,
						struct app_conn_t *appconn)
{
	return hashtable_check_add_node(appdb->mac_htable,
					appconn->session.usermac,
					sizeof(appconn->session.usermac),
					&(appconn->mac_hnode));
}

int
appconn_update_name_htable(appconn_db_t *appdb,
						struct app_conn_t *appconn)
{
	return hashtable_check_add_node(appdb->name_htable,
					appconn->session.username,
					strlen(appconn->session.username),
					&(appconn->name_hnode));
}

int
appconn_del_name_htable(struct app_conn_t *appconn)
{
	hlist_del(&(appconn->name_hnode));
	
	return EAG_RETURN_OK;
}

int
appconn_add_to_db(appconn_db_t *appdb, 
					struct app_conn_t *appconn)
{
	if (NULL == appdb || NULL == appconn) {
		eag_log_err("appconn_add_to_db input error");
		return -1;
	}
	
	list_add_tail(&(appconn->node), &(appdb->head));
	appconn_update_ip_htable(appdb, appconn);
	appconn_update_mac_htable(appdb, appconn);

	return EAG_RETURN_OK;
}

int
appconn_del_from_db(struct app_conn_t *appconn)
{
	if (NULL == appconn) {
		eag_log_err("appconn_del_from_db input error");
		return -1;
	}

	list_del(&(appconn->node));
	hlist_del(&(appconn->ip_hnode));
	hlist_del(&(appconn->mac_hnode));

	return EAG_RETURN_OK;
}

struct app_conn_t *
appconn_find_by_userip(appconn_db_t *appdb,
					uint32_t userip)
{
	struct app_conn_t *appconn = NULL;
	struct hlist_head *head = NULL;
	struct hlist_node *node = NULL;

	head = hashtable_get_hash_list(appdb->ip_htable, &userip, sizeof(userip));
	if (NULL == head) {
		eag_log_err("appconn_find_by_userip "
			"hashtable_get_hash_list failed, userip %#x", userip);
		return NULL;
	}

	hlist_for_each_entry(appconn, node, head, ip_hnode) {
		if (userip == appconn->session.user_ip) {
			return appconn;
		}
	}

	debug_appconn("appconn_find_by_userip, not find user, userip=%#x",
			userip);
	return NULL;
}

struct app_conn_t *
appconn_find_by_usermac(appconn_db_t *appdb,
					const uint8_t *usermac)
{	
	struct app_conn_t *appconn = NULL;
	struct hlist_head *head = NULL;
	struct hlist_node *node = NULL;
	char macstr[32] = "";
	
	mac2str(usermac, macstr, sizeof(macstr), '-');	
	head = hashtable_get_hash_list(appdb->mac_htable, usermac, 6);
	if (NULL == head) {
		eag_log_err("appconn_find_by_usermac "
			"hashtable_get_hash_list failed, usermax %s", macstr);
		return NULL;
	}

	hlist_for_each_entry(appconn, node, head, mac_hnode) {
		if (0 == memcmp(appconn->session.usermac, usermac,
						sizeof(appconn->session.usermac))) {
			return appconn;
		}
	}

	debug_appconn("appconn_find_by_usermac, not find user, usermac=%s",
			macstr);
	return NULL;
}

struct app_conn_t *
appconn_find_by_username(appconn_db_t *appdb,
					const char *username)
{
	struct app_conn_t *appconn = NULL;
	struct hlist_head *head = NULL;
	struct hlist_node *node = NULL;

	head = hashtable_get_hash_list(appdb->name_htable, username, strlen(username));
	if (NULL == head) {
		eag_log_err("appconn_find_by_username "
			"hashtable_get_hash_list failed, username %s", username);
		return NULL;
	}

	hlist_for_each_entry(appconn, node, head, name_hnode) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state
			&& 0 == strcmp(appconn->session.username, username)) {
			return appconn;
		}
	}

	debug_appconn("appconn_find_by_username, not find user, username=%s",
			username);
	return NULL;
}

int
appconn_count_authed(appconn_db_t *appdb)
{
	int num = 0;
	struct app_conn_t *appconn = NULL;
		printf("%s,%d\n",__func__,__LINE__);

	if (NULL == appdb) {
		eag_log_err("appconn_count_authed db null");
		return 0;
	}
	printf("%s,%d\n",__func__,__LINE__);

	list_for_each_entry(appconn, &(appdb->head), node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			num++;
		}
	}
	printf("%s,%d\n",__func__,__LINE__);

	return num;
}

int
appconn_count_by_username(appconn_db_t *appdb,
					const char *username)
{
	int num = 0;
	struct app_conn_t *appconn = NULL;

	if (NULL == appdb || NULL == username) {
		eag_log_err("appconn_count_by_username param error");
		return 0;
	}
	
	list_for_each_entry(appconn, &(appdb->head), node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state
			&& strcmp(username, appconn->session.username) == 0) {
			num++;
		}
	}

	return num;
}

int
appconn_count_by_userip(appconn_db_t *appdb,
								uint32_t userip)
{
	int num = 0;
	struct app_conn_t *appconn = NULL;

	if (NULL == appdb) {
		eag_log_err("appconn_count_by_userip param error");
		return 0;
	}
	
	list_for_each_entry(appconn, &(appdb->head), node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state
			&& userip == appconn->session.user_ip) {
			num++;
		}
	}

	return num;
}

int
appconn_count_by_usermac(appconn_db_t *appdb,
								uint8_t usermac[6])
{
	int num = 0;
	struct app_conn_t *appconn = NULL;

	if (NULL == appdb || NULL == usermac) {
		eag_log_err("appconn_count_by_usermac param error");
		return 0;
	}
	
	list_for_each_entry(appconn, &(appdb->head), node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state
			&& memcmp(usermac, appconn->session.usermac, 6) == 0) {
			num++;
		}
	}

	return num;
}

int
appconn_set_debug_prefix(struct app_conn_t *appconn)
{
	char ipstr[32] = "";
	char macstr[32] = "";
	
	ip2str(appconn->session.user_ip, ipstr, sizeof (ipstr));
	mac2str(appconn->session.usermac, macstr, sizeof(macstr), '-');
	
	snprintf(appconn->log_prefix, sizeof(appconn->log_prefix)-1,
			"%s:%s", ipstr, macstr);

	return 0;
}

int
appconn_set_filter_prefix(struct app_conn_t *appconn)
{
	char ipstr[32] = "";
	char macstr[32] = "";
	char *username = NULL;

	if (NULL == appconn) {
		return -1;
	}
	ip2str(appconn->session.user_ip, ipstr, sizeof (ipstr));
	mac2str(appconn->session.usermac, macstr, sizeof(macstr), '-');
	username = appconn->session.username;
	
	snprintf(appconn->session_filter_prefix, sizeof(appconn->session_filter_prefix)-1,
				"USERLOG: %s", ipstr);
	if (0 != strcmp(macstr,"")) {
		strncat(appconn->session_filter_prefix, ": ",
			sizeof(appconn->session_filter_prefix)-strlen(appconn->session_filter_prefix)-1);
		strncat(appconn->session_filter_prefix, macstr,
			sizeof(appconn->session_filter_prefix)-strlen(appconn->session_filter_prefix)-1);
	}
	if (NULL != username && 0 != strcmp(username,"")) {
		strncat(appconn->session_filter_prefix, ": ",
			sizeof(appconn->session_filter_prefix)-strlen(appconn->session_filter_prefix)-1);
		strncat(appconn->session_filter_prefix, username,
			sizeof(appconn->session_filter_prefix)-strlen(appconn->session_filter_prefix)-1);
	}
	strncat(appconn->session_filter_prefix, ":",
		sizeof(appconn->session_filter_prefix)-strlen(appconn->session_filter_prefix)-1);
	
	return 0;
}


static int
appconn_set_sessionid(struct app_conn_t *appconn)
{
	time_t time_now = 0;
	appconn_db_t *appdb = NULL;
	uint32_t hansi_id = 0;
	uint32_t index = 0;

	time_now = time(NULL);
	appdb = appconn->appdb;
	index = (appconn->session.index & 0XFFFFFFF) | (hansi_id << 28);
	
	snprintf(appconn->session.sessionid, sizeof(appconn->session.sessionid),
		"%08lx%08x", time_now, index);
	log_app_debug(appconn, "set sessionid = %s", appconn->session.sessionid);

	return 0;
}

static int
is_sub_interface(const char *intf_name)
{
	if (NULL == intf_name) {
		return 0;
	}

	if (strncmp(intf_name, "eth.", 4) == 0
		|| strncmp(intf_name, "ve.", 3) == 0) {
		return 1;
	}

	return 0;
}

static int
appconn_get_sub_interface(struct app_conn_t *appconn)
{
	int i = 0;
	char mac_str[32] = "";
	char ip_str[32] = "";
	char sub_if_name[MAX_IF_NAME_LEN] = "";
	char if_name[MAX_IF_NAME_LEN] = "";

	if (NULL == appconn) {
		eag_log_err("appconn_get_sub_interface input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	mac2str(appconn->session.usermac, mac_str, sizeof(mac_str), ':');
	ip2str(appconn->session.user_ip, ip_str, sizeof(ip_str));

	if (is_sub_interface(appconn->session.intf)) {
		strncpy(appconn->sub_intf, appconn->session.intf,
					sizeof(appconn->sub_intf)-1);
		return EAG_RETURN_OK;
	}
	
	if (0 != strncmp(appconn->session.intf, "ebr", 3)) {
		eag_log_debug("appconn", "appconn_get_sub_interface, intf is not ebr");
		return EAG_ERR_APPCONN_APP_DOWN_IF_UNKNOWN;
	}

	if (0 == strcmp(mac_str, "00:00:00:00:00:00")) {
		eag_log_warning("appconn_get_sub_interface, "
				"user mac is 0, cannot get sub_intf");
		return EAG_ERR_APPCONN_APP_MAC_IS_EMPTY;
	}
	
	memset(sub_if_name, 0, sizeof(sub_if_name));
	strncpy(if_name, appconn->session.intf, sizeof(if_name)-1);
	for (i=0; i<5; i++) {
		brctl_show(mac_str, if_name, sub_if_name);
		
		if (0 != strcmp(sub_if_name, ""))
		{
			strncpy(appconn->sub_intf, sub_if_name, sizeof(appconn->sub_intf)-1);
			eag_log_debug("appconn", "appconn_get_sub_interface, %s",
					appconn->sub_intf);
			return EAG_RETURN_OK;
		}

		usleep(100);
	}

	return EAG_ERR_UNKNOWN;
}

int
get_vlanid_by_intf(const char *intf)
{
	int vlanid = 0;
	char *p = NULL;
	
	if (NULL == intf) {
		return 0;
	}

	if (strncmp("vlan", intf, 4) == 0) {
		sscanf(intf, "vlan%d", &vlanid);
	} else if (strncmp("eth", intf, 3) == 0) {
		if ( (p = strchr(intf, '.')) != NULL) {
			p++;
			vlanid = strtol(p, NULL, 10);
		}
	} else if (strncmp("ve", intf, 2) == 0) {
		if ( (p = strchr(intf, '.')) != NULL) {
			p++;
			vlanid = strtol(p, NULL, 10);
		}
	}

	eag_log_debug("appconn", "get_vlanid_by_intf vlanid=%d", vlanid);
	
	return vlanid;
}

int
appconn_set_nasid(struct app_conn_t *appconn,
					struct nasid_conf *nasidconf)
{
	int i = 0;
	struct nasid_map_t *map = NULL;
	struct iprange_t *iprange = NULL;
	 
	if (NULL == appconn || NULL == nasidconf) {
		eag_log_err("appconn_set_nasid input error");
		return -1;
	}
	
	for (i = 0; i < nasidconf->current_num; i++) {
		map = &(nasidconf->nasid_map[i]);
		switch (map->key_type) {
		case NASID_KEYTYPE_WLANID:
			if (appconn->session.wlanid >= map->key.wlanidrange.id_begin 
				&& appconn->session.wlanid <= map->key.wlanidrange.id_end) {
				strncpy(appconn->session.nasid, map->nasid, RADIUS_MAX_NASID_LEN-1);
				appconn->nascon = map->conid;
				return EAG_RETURN_OK;
			}
			break;
		case NASID_KEYTYPE_VLANID:
			if (appconn->session.vlanid >= map->key.vlanidrange.id_begin
				&& appconn->session.vlanid <= map->key.vlanidrange.id_end) {
				strncpy(appconn->session.nasid, map->nasid, RADIUS_MAX_NASID_LEN-1);
				appconn->nascon = map->conid;
				return EAG_RETURN_OK;
			}
			break;
		case NASID_KEYTYPE_WTPID:
			if (appconn->session.wtpid >= map->key.wtpidrange.id_begin
				&& appconn->session.wtpid <= map->key.wtpidrange.id_end) {
				strncpy(appconn->session.nasid, map->nasid, RADIUS_MAX_NASID_LEN-1);
				appconn->nascon = map->conid;
				return EAG_RETURN_OK;
			}
			break;
		case NASID_KEYTYPE_IPRANGE:
			iprange = &(map->key.iprange);
			if (appconn->session.user_ip >= iprange->ip_begin
				&& appconn->session.user_ip <= iprange->ip_end) {
				strncpy(appconn->session.nasid, map->nasid, RADIUS_MAX_NASID_LEN-1);
				appconn->nascon = map->conid;
				return EAG_RETURN_OK;
			}
			break;
		case NASID_KEYTYPE_INTF:
			if (strcmp(map->key.intf, appconn->session.intf) == 0) {
				strncpy(appconn->session.nasid, map->nasid, RADIUS_MAX_NASID_LEN-1);
				appconn->nascon = map->conid;
				return EAG_RETURN_OK;
			}
			break;
		default:
			eag_log_err("appconn_set_nasid unknown nasid map keytype %d",
					map->key_type);
			break;
		}
	}

	if (nasidconf->current_num > 0) {
		map = &(nasidconf->nasid_map[0]);
		strncpy(appconn->session.nasid, map->nasid, RADIUS_MAX_NASID_LEN-1);
		appconn->nascon = map->conid;
		eag_log_debug("appconn", "appconn_set_nasid not match nasid, use default");
	}
	return EAG_ERR_UNKNOWN;
}

int
appconn_set_nasportid(struct app_conn_t *appconn,
						struct nasportid_conf *nasportidconf)
{
	int i = 0;
	struct nasportid_map_t *map = NULL;

	if (NULL == appconn || NULL == nasportidconf) {
		eag_log_err("appconn_set_nasportid input error");
		return -1;
	}

	for (i = 0; i < nasportidconf->current_num; i++) {
		map = &(nasportidconf->nasportid_map[i]);
		switch(map->key_type) {
		case NASPORTID_KEYTYPE_WLAN_WTP:
			if (appconn->session.wlanid >= map->key.wlan_wtp.wlanid_begin
				&& appconn->session.wlanid <= map->key.wlan_wtp.wlanid_end
				&& appconn->session.wtpid >= map->key.wlan_wtp.wtpid_begin
				&& appconn->session.wtpid <= map->key.wlan_wtp.wtpid_end) {
				snprintf(appconn->session.nas_port_id, MAX_NASPORTID_LEN-1,
					"%02u%08u", appconn->nascon, map->nasportid);
				return EAG_RETURN_OK;
			}
			break;
		case NASPORTID_KEYTYPE_VLAN:
			if (appconn->session.vlanid >= map->key.vlan.vlanid_begin
				&& appconn->session.vlanid <= map->key.vlan.vlanid_end) {
				snprintf(appconn->session.nas_port_id, MAX_NASPORTID_LEN-1,
					"%02u%08u", appconn->nascon, map->nasportid);
				return EAG_RETURN_OK;
			}
			break;
		default:
			break;
		}
	}

	snprintf( appconn->session.nas_port_id, MAX_NASPORTID_LEN-1,
			"%02u%08u", appconn->nascon, appconn->session.vlanid);
	
	return EAG_RETURN_OK;
}

static int
appconn_check_nasportid(struct app_conn_t *appconn)
{
	int check_value = 0;

	check_value = atoi(appconn->session.nas_port_id+2);
	if (check_value > 0)
		return EAG_RETURN_OK;
	return -1;
}

int
appconn_check_is_conflict(uint32_t userip, appconn_db_t *appdb, struct appsession *session, struct app_conn_t **app)
{
	char ipstr[32] = "";
	char ipstr2[32] = "";
	char macstr[32] = "";
	uint8_t zero_mac[6] = {0};
	struct app_conn_t *appconn = NULL;

	if (NULL == appdb || NULL == session || NULL == app) {
		eag_log_err("appconn_check_with_session input err");
		return EAG_ERR_INPUT_PARAM_ERR;
	}	
	ip2str(userip, ipstr, sizeof(ipstr));

	*app = NULL;
	session->user_ip = userip;
	eag_log_warning("ipinfo_get", "eag_ipinfo_get before userip=%s", ipstr);
	eag_ipinfo_get(session->bridge, sizeof(session->bridge)-1, session->usermac, userip);
	mac2str(session->usermac, macstr, sizeof(macstr), ':');
	eag_log_warning("ipinfo_get", "eag_ipinfo_get after userip=%s,usermac=%s,interface=%s",
		ipstr, macstr, session->bridge);

	eag_log_warning("appconn", "appconn_check_is_conflict eag_ipinfo_get "
		"userip %s, interface(%s), usermac(%s)", ipstr, session->bridge, macstr);

	if (memcmp(zero_mac, session->usermac, 6) == 0) {
		return EAG_RETURN_OK;
	}
	
	appconn = appconn_find_by_usermac(appdb, session->usermac);
	if (NULL != appconn && userip != appconn->session.user_ip) {
		ip2str(appconn->session.user_ip, ipstr2, sizeof(ipstr2));
		eag_log_warning("appconn_check_is_conflict user mac %s conflict"
			"ip1=%s, ip2=%s", macstr, ipstr, ipstr2);
		*app = appconn;
		return EAG_ERR_APPCONN_APP_IS_CONFLICT;
	}

	return EAG_RETURN_OK;

}

struct app_conn_t *
appconn_create_no_arp(appconn_db_t * appdb, struct appsession *session)
{
	struct app_conn_t *appconn = NULL;
	int ret = 0;
	char ipstr[32] = "";
	char macstr[32] = "";
	uint8_t zero_mac[6] = {0};
	unsigned int security_type = 0;

	if(NULL == appdb) {
		eag_log_err("appconn_create_no_arp appdb is NULL!");
		return NULL;
	}	
	
	appconn = appconn_new(appdb);
	if (NULL == appconn) {
		eag_log_err("appconn_create_no_arp new conn failed!");
		return NULL;
	}
	
	appconn->session.nasip = eag_ins_get_nasip(appdb->eagins);
	ip2str(session->user_ip, ipstr, sizeof(ipstr));
	appconn->session.user_ip = session->user_ip;
	memcpy(appconn->session.usermac, session->usermac, sizeof(appconn->session.usermac));
	strncpy(appconn->session.intf, session->intf, sizeof(appconn->session.intf)-1);

	mac2str(appconn->session.usermac, macstr, sizeof(macstr), ':');
	
	if (0 == memcmp(zero_mac, appconn->session.usermac, 6)
		&& appdb->force_wireless) {
		eag_log_warning("appconn_create_no_arp"
			"userip %s, usermac is zero, force_wireless enable, appconn free",
			ipstr);
		appconn_free(appconn);
		return NULL;
	}

	if (strlen(appconn->session.intf) == 0) {
		eag_log_warning("appconn_create_no_arp"
			"userip %s, interface not found, appconn free",
			ipstr);
		appconn_free(appconn);
		return NULL;
	}

/*	ret = eag_get_sta_info_by_mac_v2(appdb->eagdbus, appdb->hansi_type, appdb->hansi_id,
				appconn->session.usermac, &(appconn->session), &security_type);*/
	if (0 != ret && appdb->force_wireless) {
		eag_log_err("appconn_create_no_arp "
			"eag_get_sta_info_by_mac_v2 failed, userip=%s, usermac=%s, ret=%d",
			ipstr, macstr, ret);
		appconn_free(appconn);
		return NULL;
	}
	if (0 == ret && NO_NEED_AUTH == security_type) {
		eag_log_err("appconn_create_no_arp failed security_type=NO_NEED_AUTH"
			" failed , userip=%s, usermac=%s",
			ipstr, macstr);
		appconn_free(appconn);
		return NULL;
	}

	appconn_set_debug_prefix(appconn);
	appconn_set_filter_prefix(appconn); /* for debug-filter,add by zhangwl */
	appconn_set_sessionid(appconn);
	eag_log_debug("get_sub_intf", "appconn_get_sub_interface before");
 	appconn_get_sub_interface(appconn);
	eag_log_debug("get_sub_intf", "appconn_get_sub_interface after");
	
	if (appconn->session.vlanid <= 0) {
		appconn->session.vlanid = get_vlanid_by_intf(appconn->sub_intf);
	}
	if (appconn->session.vlanid <= 0) {
		appconn->session.vlanid = get_vlanid_by_intf(appconn->session.intf);
	}
		
	appconn_set_nasid(appconn, appdb->nasidconf);
	appconn_set_nasportid(appconn, appdb->nasportidconf);
	ret = appconn_check_nasportid(appconn); 
	if (EAG_RETURN_OK != ret && (1 == appdb->check_nasportid)) 
	{
		appconn_free(appconn);
		return NULL;
	}
	appconn_add_to_db(appdb, appconn);
		
	return appconn;
}

struct app_conn_t *
appconn_find_by_ip_autocreate(appconn_db_t *appdb, uint32_t userip)
{	
	struct app_conn_t *appconn = NULL;
	int ret = 0;
	char ipstr[32] = "";
	char macstr[32] = "";
	uint8_t zero_mac[6] = {0};
	unsigned int security_type = 0;
	
	if (NULL == appdb) {
		eag_log_err("appconn_find_by_ip_autocreate input error");
		return NULL;
	}

	ip2str(userip, ipstr, sizeof(ipstr));
	appconn = appconn_find_by_userip(appdb, userip);
	if (NULL != appconn) {
		return appconn;
	}

	appconn = appconn_new(appdb);
	if (NULL == appconn) {
		eag_log_err("appconn_find_by_ip_autocreate appconn_new failed");
		return NULL;
	}
	appconn->session.user_ip = userip;
	appconn->session.nasip = eag_ins_get_nasip(appdb->eagins);

	eag_log_debug("ipinfo_get", "eag_ipinfo_get before userip=%s", ipstr);
	eag_ipinfo_get(appconn->session.intf, sizeof(appconn->session.intf)-1,
				appconn->session.usermac, userip);
	mac2str(appconn->session.usermac, macstr, sizeof(macstr), '-');
	eag_log_debug("ipinfo_get", "eag_ipinfo_get after userip=%s,usermac=%s,interface=%s",
		ipstr, macstr, appconn->session.intf);
	debug_appconn("eag_ipinfo_get userip %s, interface(%s), usermac(%s)",
		ipstr, appconn->session.intf, macstr);
	if (0 == memcmp(zero_mac, appconn->session.usermac, 6)
		&& appdb->force_wireless) {
		eag_log_warning("appconn_find_by_ip_autocreate"
			"userip %s, usermac is zero, force_wireless enable, appconn free",
			ipstr);
		appconn_free(appconn);
		return NULL;
	}
	#if 0
	if (strlen(appconn->session.intf) == 0) {
		ip_interface(userip, appconn->session.intf, 
					sizeof(appconn->session.intf)-1);
		debug_appconn("ip_interface userip %s, interface(%s)",
		ipstr, appconn->session.intf);
		if (strlen(appconn->session.intf) == 0) {
			eag_log_warning("appconn_find_by_ip_autocreate"
				"ip_interface userip %s, interface not found, appconn free",
				ipstr);
			appconn_free(appconn);
			return NULL;
		}
	}
	#endif
	if (strlen(appconn->session.intf) == 0) {
		eag_log_warning("appconn_find_by_ip_autocreate"
			"userip %s, interface not found, appconn free",
			ipstr);
		appconn_free(appconn);
		return NULL;
	}
	appconn_set_debug_prefix(appconn);
	appconn_set_filter_prefix(appconn); /* for debug-filter,add by zhangwl */
		
/*	ret = eag_get_sta_info_by_mac_v2(appdb->eagdbus, appdb->hansi_type, appdb->hansi_id,
				appconn->session.usermac, &(appconn->session), &security_type);*/
	if (0 != ret && appdb->force_wireless) {
		eag_log_err("appconn_find_by_ip_autocreate "
			"eag_get_sta_info_by_mac_v2 failed, userip=%s, usermac=%s, ret=%d",
			ipstr, macstr, ret);
		appconn_free(appconn);
		return NULL;
	}
	if (0 == ret && NO_NEED_AUTH == security_type) {
		eag_log_err("appconn_find_by_ip_autocreate failed security_type=NO_NEED_AUTH"
			" failed , userip=%s, usermac=%s",
			ipstr, macstr);
		appconn_free(appconn);
		return NULL;
	}
	
	appconn_set_sessionid(appconn);
 	eag_log_debug("get_sub_intf", "appconn_get_sub_interface before");
 	appconn_get_sub_interface(appconn);
	eag_log_debug("get_sub_intf", "appconn_get_sub_interface after");
	
	if (appconn->session.vlanid <= 0)
	{
		appconn->session.vlanid = get_vlanid_by_intf(appconn->sub_intf);
	}
	if (appconn->session.vlanid <= 0)
	{
		appconn->session.vlanid = get_vlanid_by_intf(appconn->session.intf);
	}
		
	appconn_set_nasid(appconn, appdb->nasidconf);
	appconn_set_nasportid(appconn, appdb->nasportidconf);
	appconn_config_portalsrv(appconn, appdb->portalconf);
	ret = appconn_check_nasportid(appconn); 
	if (EAG_RETURN_OK != ret && (1 == appdb->check_nasportid)) 
	{
		appconn_free(appconn);
		return NULL;
	}
	appconn_add_to_db(appdb, appconn);

	return appconn;
}

struct app_conn_t *
appconn_create_by_sta_v2(appconn_db_t * appdb, struct appsession *session)
{
	struct app_conn_t *appconn = NULL;
	int ret = 0;
	char ipstr[32] = "";
	uint8_t zero_mac[6] = {0};

	DEBUG_FUNCTION_BEGIN();
	if( NULL == appdb ){
		eag_log_err("appconn_create_by_sta_v2 appdb is NULL!");
		return NULL;
	}	
	
	appconn = appconn_new(appdb);
	if( NULL == appconn ){
		eag_log_err("appconn_create_by_sta_v2 new conn failed!");
		return NULL;
	}
	
	appconn->session.nasip = eag_ins_get_nasip(appdb->eagins);
	ip2str(session->user_ip, ipstr, sizeof(ipstr));
	appconn->session.user_ip = session->user_ip;
	memcpy(appconn->session.usermac, session->usermac, sizeof(appconn->session.usermac));
	strncpy(appconn->session.intf, session->intf, sizeof(appconn->session.intf)-1);
	strncpy(appconn->session.bridge, session->bridge, sizeof(appconn->session.bridge)-1);
         	memcpy(appconn->session.sock_path, session->sock_path, strlen(appconn->session.sock_path));

	
	if (0 == memcmp(zero_mac, appconn->session.usermac, 6)
		&& appdb->force_wireless) {
		eag_log_warning("appconn_create_by_sta_v2"
			"userip %s, usermac is zero, force_wireless enable, appconn free",
			ipstr);
		appconn_free(appconn);
		return NULL;
	}
	#if 0
	if (strlen(appconn->session.intf) == 0) {
		ip_interface(session->user_ip, appconn->session.intf,  
				sizeof(appconn->session.intf)-1);
		debug_appconn("ip_interface userip %s, interface(%s)",
			ipstr, appconn->session.intf);
		if (strlen(appconn->session.intf) == 0) {
			eag_log_warning("appconn_create_by_sta_v2"
				"ip_interface userip %s, interface not found, appconn free",
				ipstr);
			appconn_free(appconn);
			return NULL;
		}
	}
	#endif
	if (strlen(appconn->session.bridge) == 0) {
		eag_log_warning("appconn_create_by_sta_v2"
			"userip %s, interface not found, appconn free",
			ipstr);
		appconn_free(appconn);
		return NULL;
	}
	appconn->session.wlanid = session->wlanid;
	appconn->session.g_radioid = session->g_radioid;
	appconn->session.radioid = session->radioid;
	appconn->session.wtpid = session->wtpid;	
	strncpy(appconn->session.essid, session->essid, 
			sizeof(appconn->session.essid)-1);
	strncpy(appconn->session.apname, session->apname, 
			sizeof(appconn->session.apname)-1);
	memcpy(appconn->session.apmac, session->apmac,
			sizeof(appconn->session.apmac));
	appconn->session.vlanid = session->vlanid;


	appconn_set_debug_prefix(appconn);
	appconn_set_filter_prefix(appconn); /* for debug-filter,add by zhangwl */
	appconn_set_sessionid(appconn);
 	eag_log_debug("get_sub_intf", "appconn_get_sub_interface before");
 	appconn_get_sub_interface(appconn);
	eag_log_debug("get_sub_intf", "appconn_get_sub_interface after");
	
	if (appconn->session.vlanid <= 0)
	{
		appconn->session.vlanid = get_vlanid_by_intf(appconn->sub_intf);
	}
	if (appconn->session.vlanid <= 0)
	{
		appconn->session.vlanid = get_vlanid_by_intf(appconn->session.intf);
	}
		
	appconn_set_nasid(appconn, appdb->nasidconf);
	appconn_set_nasportid(appconn, appdb->nasportidconf);
	appconn_config_portalsrv(appconn, appdb->portalconf);
	ret = appconn_check_nasportid(appconn); 
	if (EAG_RETURN_OK != ret && (1 == appdb->check_nasportid)) 
	{
		appconn_free(appconn);
		return NULL;
	}
	appconn_add_to_db(appdb, appconn);
	
	DEBUG_FUNCTION_END();
	
	return appconn;
}

static int
appconn_match_portalsrv(struct app_conn_t *appconn,
				struct portal_srv_t *portal_srv)
{
	switch (portal_srv->key_type) {
	case PORTAL_KEYTYPE_ESSID:
		if (0 == strcmp(portal_srv->key.essid, appconn->session.essid)) {
			eag_log_debug("appconn", "appconn_match_portalsrv "
					"get portal srv by essid = %s",
					appconn->session.essid);
			return EAG_TRUE;
		}
		break;
	case PORTAL_KEYTYPE_WLANID:
		if (portal_srv->key.wlanid == appconn->session.wlanid) {
			eag_log_debug("appconn", "appconn_match_portalsrv "
					"get portal srv by wlanid = %d",
					appconn->session.wlanid);
			return EAG_TRUE;
		}
		break;
	case PORTAL_KEYTYPE_VLANID:
		if (portal_srv->key.vlanid == appconn->session.vlanid) {
			eag_log_debug("appconn","appconn_match_portalsrv "
					"get portal srv by vlanid = %d",
					appconn->session.vlanid);
			return EAG_TRUE;
		}
		break;
	case PORTAL_KEYTYPE_WTPID:
		if (portal_srv->key.wtpid == appconn->session.wtpid ) {
			eag_log_debug("appconn","appconn_match_portalsrv "
					"get portal srv by wtpid = %d",
					appconn->session.wtpid);
			return EAG_TRUE;
		}
		break;
	case PORTAL_KEYTYPE_INTF:
		if (0 == strcmp(portal_srv->key.intf, appconn->session.intf)) {
			eag_log_debug("appconn","appconn_match_portalsrv "
							"get portal srv by interface = %s",
							appconn->session.intf );
			return EAG_TRUE;
		}
		break;
	default:
		eag_log_err("appconn_match_portalsrv unknown keytype %d",
				portal_srv->key_type);
		break;
	}	

	return EAG_FALSE;
}

int 
appconn_config_portalsrv(struct app_conn_t *appconn,
					struct portal_conf *portalconf)
{
	struct portal_srv_t *portal_srv = NULL;
	int i = 0;

	if (0 == portalconf->current_num) {
		eag_log_err("appconn_config_portalsrv portal_srv num = 0");
		return EAG_ERR_UNKNOWN;
	}

	for (i = 0; i < portalconf->current_num; i++) {
		portal_srv = &(portalconf->portal_srv[i]);
		if (appconn_match_portalsrv(appconn, portal_srv)) {
			break;
		}
	}
	if (i >= portalconf->current_num) {
		portal_srv = &(portalconf->portal_srv[0]);
		eag_log_debug("appconn", 
			"appconn_config_portalsrv not match portal srv, "
			"use the first portal srv as default");
	}
	
	eag_log_debug("appconn",
		"appconn_config_portalsrv domain=%s, portal-url=%s",
		portal_srv->domain, portal_srv->portal_url);

	memcpy(&(appconn->portal_srv), portal_srv, 
			sizeof(struct portal_srv_t));
	strncpy(appconn->session.domain_name, portal_srv->domain,
			sizeof(appconn->session.domain_name)-1);
	
	return EAG_RETURN_OK;
}

int 
appconn_config_portalsrv_bk(struct app_conn_t *appconn,
					struct portal_conf *portalconf)
{
	struct portal_srv_t *portal_srv = NULL;
	int i = 0;

	if (0 == portalconf->current_num) {
		eag_log_err("appconn_config_portalsrv portal_srv num = 0");
		return EAG_ERR_UNKNOWN;
	}

	for (i = 0; i < portalconf->current_num; i++) {
		portal_srv = &(portalconf->portal_srv[i]);
		if (appconn_match_portalsrv(appconn, portal_srv)) {
			break;
		}
	}
	if (i >= portalconf->current_num) {
		portal_srv = &(portalconf->portal_srv[0]);
		eag_log_debug("appconn", 
			"appconn_config_portalsrv not match portal srv, "
			"use the first portal srv as default");
	}
	
	eag_log_debug("appconn",
		"appconn_config_portalsrv domain=%s, portal-url=%s",
		portal_srv->domain, portal_srv->portal_url);

	memcpy(&(appconn->portal_srv), portal_srv, 
			sizeof(struct portal_srv_t));
	
	return EAG_RETURN_OK;
}

int
appconn_config_radiussrv_by_domain(struct app_conn_t *appconn,
									struct radius_conf *radiusconf)
{
	struct radius_srv_t *radius_srv = NULL;
	const char *domain_name = "";
	int i = 0;

	if (NULL == appconn || NULL == radiusconf) {
		eag_log_err("appconn_config_radiussrv_by_domain input error");
		return EAG_ERR_NULL_POINTER;
	}

	domain_name = appconn->session.domain_name;
	
	for (i = 0; i < radiusconf->current_num; i++) {
		radius_srv = &(radiusconf->radius_srv[i]);
		if (strcmp(domain_name, radius_srv->domain) == 0) {
			memcpy(&(appconn->session.radius_srv), radius_srv,
					sizeof(appconn->session.radius_srv));
			debug_appconn("appconn_config_radiussrv_by_domain, "
				"find radius srv, domain=%s", domain_name);
			return EAG_RETURN_OK;
		}
	}
	
	if (radiusconf->current_num > 0) {
		memcpy(&(appconn->session.radius_srv), &(radiusconf->radius_srv[0]),
					sizeof(appconn->session.radius_srv));
		debug_appconn("appconn_config_radiussrv_by_domain, "
			"not found radius srv by domain %s, use default radius srv %s",
			domain_name, radiusconf->radius_srv[0].domain);
		return EAG_RETURN_OK;
		
	}
	
	eag_log_err("appconn_config_radiussrv_by_domain, radius srv not configed");
	return -1;
}

int
appconn_check_redir_count(struct app_conn_t *appconn,
									uint32_t max_count,
									uint32_t interval)
{
	struct timeval tv;
	time_t timenow = 0;
	
	eag_time_gettimeofday(&tv,NULL);
	timenow = tv.tv_sec;

	if (0 == appconn->session.last_redir_check_time
		&& 0 == appconn->session.redir_count) {
		appconn->session.last_redir_check_time = timenow;
		appconn->session.redir_count = 1;
		return EAG_RETURN_OK;
	}

	if (timenow > appconn->session.last_redir_check_time + interval) {
		appconn->session.last_redir_check_time = timenow;
		appconn->session.redir_count = 1;
		return EAG_RETURN_OK;
	}
	
	appconn->session.redir_count++;
	if (appconn->session.redir_count > max_count) {
		return -1;
	}
	
	return EAG_RETURN_OK;
}
#if 0
static int
eag_show_dhcplease_by_userip(DBusConnection *dbus_conn,
							uint32_t user_ip,
							uint8_t mac[6])
{
	DBusMessage *query = NULL;
	DBusMessage *reply = NULL;
	DBusError err;
	DBusMessageIter iter;
	DBusMessageIter iter_struct;
	DBusMessageIter iter_array;
	uint32_t ip_nums = 32;
	uint32_t op_ret = -1;
	uint32_t count = 0;
	int i = 0;
	int j = 0;
	int ret = -1;
	uint32_t ip_temp = 0;
	uint8_t mac_temp[6] = {0};
	char mac_temp_str[32] = "";

	eag_log_debug("appconn", "eag_show_dhcplease_by_userip, user_ip=%#x",
				user_ip);
	query = dbus_message_new_method_call(EAG_DBUS_DHCP_BUSNAME,
									EAG_DBUS_DHCP_OBJPATH,
									EAG_DBUS_DHCP_INTERFACE,
									EAG_DBUS_METHOD_SHOW_DHCP_LEASE_BY_IP);
	dbus_error_init(&err);
	dbus_message_append_args(query,
							DBUS_TYPE_UINT32, &user_ip,
							DBUS_TYPE_UINT32, &ip_nums,
							DBUS_TYPE_INVALID);
		   
	reply = dbus_connection_send_with_reply_and_block(dbus_conn, query, 1000, &err);
	dbus_message_unref(query);
	if (NULL == reply) {
		eag_log_err("eag_show_dhcplease_by_userip reply is null");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_show_dhcplease_by_userip %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		return ret;
	}
	
	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_get_basic(&iter, &op_ret);
	dbus_message_iter_next(&iter);
	
	dbus_message_iter_get_basic(&iter, &count);
	dbus_message_iter_next(&iter);
	eag_log_debug("appconn", "eag_show_dhcplease_by_userip, "
			"user_ip=%#x, op_ret=%d, count=%d", user_ip, op_ret, count);
	if (0 == op_ret && count > 0) {
		dbus_message_iter_recurse(&iter, &iter_array);
		for (i = 0; i < count; i++) {
			dbus_message_iter_recurse(&iter_array, &iter_struct);
	
			dbus_message_iter_get_basic(&iter_struct, &ip_temp);
			dbus_message_iter_next(&iter_struct);	
				
			for (j = 0; j < 6; j++) {
				dbus_message_iter_get_basic(&iter_struct, &mac_temp[j]);
				dbus_message_iter_next(&iter_struct);
			}
			
			if (ip_temp == user_ip) {
				ret = 0;
				memcpy(mac, mac_temp, 6);
				mac2str(mac, mac_temp_str, sizeof(mac_temp_str), '-');
				eag_log_debug("appconn", 
					"eag_show_dhcplease_by_userip, userip %#x, get mac %s",
					user_ip, mac_temp_str);
			}	
			dbus_message_iter_next(&iter_array);
		}
	}
	dbus_message_unref(reply);
	
	eag_log_debug("appconn", "eag_show_dhcplease_by_userip, ret=%d", ret);
	return ret;
}
#endif
int
appconn_check_dhcplease(struct app_conn_t *appconn)
{
	int ret = 0;
	uint8_t mac[6] = {0};
	appconn_db_t *appdb = NULL;
	//DBusConnection *dbus_conn = NULL;
	char user_macstr[32] = "";
	char get_macstr[32] = "";
	struct timeval tv = {0};
	time_t time_now = 0;
	int time_interval = 2;
	
	appdb = appconn->appdb;
	//dbus_conn = eag_dbus_get_dbus_conn(appdb->eagdbus);
	eag_time_gettimeofday(&tv, NULL);
	time_now = tv.tv_sec;
	
	if (time_now - appconn->last_check_dhcp_time < time_interval)  {
		eag_log_debug("appconn", "appconn_check_dhcplease not timeout,"
			"time_now=%lu, last_check_dhcp_time=%lu, time gap=%lu < time interval=%d,"
			"last_check_dhcp_resault = %d",
			time_now, appconn->last_check_dhcp_time,
			time_now -appconn->last_check_dhcp_time, time_interval,
			appconn->last_check_dhcp_resault);
		return appconn->last_check_dhcp_resault;
	}
	appconn->last_check_dhcp_time = time_now;
	
            /*ret = eag_show_dhcplease_by_userip(dbus_conn, appconn->session.user_ip, mac);*/
	if (0 == ret && memcmp(appconn->session.usermac, mac, 6) == 0) {
		log_app_debug(appconn, "appconn_check_dhcplease success");
		appconn->last_check_dhcp_resault = EAG_RETURN_OK;
		return EAG_RETURN_OK;
	}

	mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr), '-');
	mac2str(mac, get_macstr, sizeof(get_macstr), '-');
	eag_log_warning("appconn_check_dhcplease ret=%d, "
			"usermac %s, get mac %s from dhcplease",
			ret, user_macstr, get_macstr);
	appconn->last_check_dhcp_resault = -1;
	return -1;
}
#if 0
int 
eag_get_sta_dhcplease_info(DBusConnection *dbus_conn,
				uint32_t sta_ip,
				unsigned int *addr_in_pool_flag,
				unsigned int *addr_lease_status)
{
	DBusMessage 	*query = NULL;
	DBusMessage		*reply = NULL;
	DBusError		err;
	DBusMessageIter iter;
	unsigned int op_ret = -1;
	/* 1: can find from ip pool; 0 : can't find from ip pool */
	unsigned int in_pool_flag = 0;
	/* Lease states:
		#define FTS_FREE		1
		#define FTS_ACTIVE	2
		#define FTS_EXPIRED	3
	*/
	unsigned int lease_states = 0;
	char user_ipstr[32] = "";

	ip2str(sta_ip, user_ipstr, sizeof(user_ipstr));
	eag_log_debug("appconn", "eag_get_sta_dhcplease_info sta_ip=%s", user_ipstr);
	query = dbus_message_new_method_call(EAG_DBUS_DHCP_BUSNAME, 
									EAG_DBUS_DHCP_OBJPATH, 
									EAG_DBUS_DHCP_INTERFACE, 
									EAG_DBUS_METHOD_GET_DHCP_LEASE_INFO);
	dbus_error_init(&err);
	dbus_message_append_args(query,
							DBUS_TYPE_UINT32, &sta_ip,
							DBUS_TYPE_INVALID);
	
	reply = dbus_connection_send_with_reply_and_block (dbus_conn,query, 1000, &err);
	dbus_message_unref(query);
	if (NULL == reply) {
		eag_log_err("eag_get_sta_dhcplease_info reply is null userip=%s", user_ipstr);
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_get_sta_dhcplease_info %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		return EAG_ERR_DBUS_FAILED;
	}

	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_get_basic(&iter, &op_ret);
	
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &in_pool_flag);
	*addr_in_pool_flag = in_pool_flag;
	
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &lease_states);
	*addr_lease_status = lease_states;
	dbus_message_unref(reply);
	
	eag_log_debug("appconn", "eag_get_sta_dhcplease_info "
		"userip=%s, op_ret=%d, in_pool_flag=%d, lease_states=%d",
		user_ipstr, op_ret, in_pool_flag, lease_states);
	
	return op_ret;
}
#endif
int
appconn_db_set_nasid_conf(appconn_db_t *appdb,
				struct nasid_conf *nasidconf)
{
	appdb->nasidconf = nasidconf;
	return EAG_RETURN_OK;
}

int
appconn_db_set_nasportid_conf(appconn_db_t *appdb,
				struct nasportid_conf *nasportidconf)
{
	appdb->nasportidconf = nasportidconf;
	return EAG_RETURN_OK;
}

int
appconn_db_set_portal_conf(appconn_db_t *appdb,
				struct portal_conf *portalconf)
{
	appdb->portalconf = portalconf;
	return EAG_RETURN_OK;
}

/*int
appconn_db_set_eag_dbus(appconn_db_t *appdb,
				eag_dbus_t *eagdbus)
{
	appdb->eagdbus = eagdbus;
	return EAG_RETURN_OK;
}*/

int
appconn_db_set_idle_params(appconn_db_t *appdb,
		unsigned long idle_timeout, uint64_t idle_flow)
{
	appdb->idle_timeout = idle_timeout;
	appdb->idle_flow = idle_flow;

	return 0;
}

int
appconn_db_get_idle_params(appconn_db_t *appdb,
		unsigned long *idle_timeout, uint64_t *idle_flow)
{
	*idle_timeout = appdb->idle_timeout;
	*idle_flow = appdb->idle_flow;

	return 0;
}

int
appconn_db_set_force_wireless(appconn_db_t *appdb,
		int force_wireless)
{
	appdb->force_wireless = force_wireless;
	
	return 0;
}

int
appconn_db_get_force_wireless(appconn_db_t *appdb)
{
	return appdb->force_wireless;
}

int
appconn_db_set_check_nasportid(appconn_db_t *appdb,
		int check_nasportid)
{
	appdb->check_nasportid = check_nasportid;
	
	return 0;
}

int
appconn_db_get_check_nasportid(appconn_db_t *appdb)
{
	return appdb->check_nasportid;
}

int
appconn_db_set_correct_factor(appconn_db_t *appdb,
		uint32_t input_correct_factor, uint32_t output_correct_factor)
{
	appdb->input_correct_factor = input_correct_factor;
	appdb->output_correct_factor = output_correct_factor;
	
	return 0;
}

int
appconn_db_get_correct_factor(appconn_db_t *appdb,
		uint32_t *input_correct_factor, uint32_t *output_correct_factor)
{
	*input_correct_factor = appdb->input_correct_factor;
	*output_correct_factor = appdb->output_correct_factor;

	return 0;
}

int
appdb_authed_user_num_increase(appconn_db_t *appdb)
{
	appdb->authed_user_num++;
	eag_log_debug("appconn",
			"appdb_authed_user_num_increase authed_user_num=%d",
				appdb->authed_user_num);
	
	return appdb->authed_user_num;
}

int
appdb_authed_user_num_decrease(appconn_db_t *appdb)
{
	if (appdb->authed_user_num <= 0) {
		eag_log_warning("ERROR: authed_user_num data error!");
		return 0;
	}
	appdb->authed_user_num--;
	eag_log_debug("appconn",
			"appdb_authed_user_num_decrease authed_user_num=%d", 
				appdb->authed_user_num);
	
	return appdb->authed_user_num;
}

void
appdb_log_all_appconn(appconn_db_t *appdb)
{
	struct app_conn_t *appconn = NULL;
	struct app_conn_t *next = NULL;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char *userintf = "";
	int authed_num = 0;
	int unauth_num = 0;
	
	list_for_each_entry_safe(appconn, next, &(appdb->head), node) {
		ip2str(appconn->session.user_ip, user_ipstr, sizeof (user_ipstr));
		mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr), '-');
		userintf = appconn->session.intf;
		
		if (APPCONN_STATUS_AUTHED == appconn->session.state ) {
			authed_num++;
			eag_log_info("appconn:ip %s mac %s from interface %s, username=%s"
					" start=%lu last=%lu input=%llu output=%llu",
					user_ipstr, user_macstr, userintf, appconn->session.username,
					appconn->session.session_start_time, appconn->session.last_flux_time,
					appconn->session.input_octets,appconn->session.output_octets);
		} else {
			unauth_num++;
			eag_log_info("appconn:ip %s mac %s from interface %s not do auth!",
					user_ipstr, user_macstr, userintf);
		}
	}
	eag_log_info("appdb_log_all_appconn total-num:%d, authed:%d, unauth:%d",
			(authed_num + unauth_num), authed_num, unauth_num);

	return;
}

struct list_head *
appconn_db_get_head(appconn_db_t *appdb)
{
	return &(appdb->head);
}

int
set_appconn_flux(struct app_conn_t *appconn)
{
	appconn_db_t *appdb = NULL;
	int flux_from = 0;

	appdb = appconn->appdb;
	flux_from = eag_ins_get_flux_from(appdb->eagins);
	uint32_t input_factor = appdb->input_correct_factor;
	uint32_t output_factor = appdb->output_correct_factor;
	
	switch(flux_from) {
	case FLUX_FROM_IPTABLES:
		appconn->session.input_octets = appconn->bk_input_octets
			+ (appconn->iptables_data.input_octets*input_factor/1000);
		appconn->session.input_packets = appconn->bk_input_packets + appconn->iptables_data.input_packets;
		appconn->session.output_octets = appconn->bk_output_octets
			+ (appconn->iptables_data.output_octets*output_factor/1000);
		appconn->session.output_packets = appconn->bk_output_packets + appconn->iptables_data.output_packets;
		break;
	case FLUX_FROM_IPTABLES_L2:
		appconn->iptables_data.input_octets += appconn->iptables_data.input_packets*18;
		appconn->iptables_data.output_octets += appconn->iptables_data.output_packets*18;
		
		appconn->session.input_octets = appconn->bk_input_octets
			+ (appconn->iptables_data.input_octets*input_factor/1000);
		appconn->session.input_packets = appconn->bk_input_packets + appconn->iptables_data.input_packets;
		appconn->session.output_octets = appconn->bk_output_octets
			+ (appconn->iptables_data.output_octets*output_factor/1000);
		appconn->session.output_packets = appconn->bk_output_packets + appconn->iptables_data.output_packets;
		break;
	case FLUX_FROM_WIRELESS:
		if ( (0 != appconn->session.wireless_data.cur_input_octets
				&& appconn->session.wireless_data.cur_input_octets < appconn->session.wireless_data.last_input_octets)
			|| (0 != appconn->session.wireless_data.cur_input_packets
				&& appconn->session.wireless_data.cur_input_packets < appconn->session.wireless_data.last_input_packets)
			|| (0 != appconn->session.wireless_data.cur_output_octets
				&& appconn->session.wireless_data.cur_output_octets < appconn->session.wireless_data.last_output_octets)
			|| (0 != appconn->session.wireless_data.cur_output_packets
				&& appconn->session.wireless_data.cur_output_packets < appconn->session.wireless_data.last_output_packets))

		{
			appconn->session.wireless_data.fixed_input_octets += appconn->session.wireless_data.last_input_octets;
			appconn->session.wireless_data.fixed_input_packets += appconn->session.wireless_data.last_input_packets;
			appconn->session.wireless_data.fixed_output_octets += appconn->session.wireless_data.last_output_octets;
			appconn->session.wireless_data.fixed_output_packets += appconn->session.wireless_data.last_output_packets;
			eag_log_info("set_appconn_flux by wireless userip=%#x flux reduced",
					appconn->session.user_ip);
		}
		if (appconn->session.wireless_data.fixed_input_octets + appconn->session.wireless_data.cur_input_octets
			> appconn->session.wireless_data.init_input_octets)
		{
			appconn->session.input_octets = appconn->session.wireless_data.fixed_input_octets
				+ appconn->session.wireless_data.cur_input_octets - appconn->session.wireless_data.init_input_octets;
		}
		if (appconn->session.wireless_data.fixed_input_packets + appconn->session.wireless_data.cur_input_packets
			> appconn->session.wireless_data.init_input_packets)
		{
			appconn->session.input_packets = appconn->session.wireless_data.fixed_input_packets
				+ appconn->session.wireless_data.cur_input_packets - appconn->session.wireless_data.init_input_packets;
		}
		if (appconn->session.wireless_data.fixed_output_octets + appconn->session.wireless_data.cur_output_octets
			> appconn->session.wireless_data.init_output_octets)
		{
			appconn->session.output_octets = appconn->session.wireless_data.fixed_output_octets
				+ appconn->session.wireless_data.cur_output_octets - appconn->session.wireless_data.init_output_octets;
		}
		if (appconn->session.wireless_data.fixed_output_packets + appconn->session.wireless_data.cur_output_packets
			> appconn->session.wireless_data.init_output_packets)
		{
			appconn->session.output_packets = appconn->session.wireless_data.fixed_output_packets
				+ appconn->session.wireless_data.cur_output_packets - appconn->session.wireless_data.init_output_packets;
		}
		appconn->session.wireless_data.last_input_octets = appconn->session.wireless_data.cur_input_octets;
		appconn->session.wireless_data.last_input_packets = appconn->session.wireless_data.cur_input_packets;
		appconn->session.wireless_data.last_output_octets = appconn->session.wireless_data.cur_output_octets;
		appconn->session.wireless_data.last_output_packets = appconn->session.wireless_data.cur_output_packets;
		break;
	case FLUX_FROM_FASTFWD:
		appconn->session.input_octets = appconn->bk_input_octets + appconn->fastfwd_data.input_octets;
		appconn->session.input_packets = appconn->bk_input_packets + appconn->fastfwd_data.input_packets;
		appconn->session.output_octets = appconn->bk_output_octets + appconn->fastfwd_data.output_octets;
		appconn->session.output_packets = appconn->bk_output_packets + appconn->fastfwd_data.output_packets;
		break;
	case FLUX_FROM_FASTFWD_IPTABLES:
		appconn->session.input_octets = appconn->bk_input_octets
			+ appconn->iptables_data.input_octets
			+ appconn->fastfwd_data.input_octets;
		appconn->session.input_packets = appconn->bk_input_packets 
			+ appconn->iptables_data.input_packets
			+ appconn->fastfwd_data.input_packets;
		appconn->session.output_octets = appconn->bk_output_octets
			+ appconn->iptables_data.output_octets
			+ appconn->fastfwd_data.output_octets;
		appconn->session.output_packets = appconn->bk_output_packets 
			+ appconn->iptables_data.output_packets
			+ appconn->fastfwd_data.output_packets;
		break;
	default:
		break;
	}
	return 0;
}

int
appconn_check_flux(struct app_conn_t *appconn, time_t time_now)
{
	char user_ipstr[32] = "";
	
	if (APPCONN_STATUS_AUTHED == appconn->session.state
		&& (appconn->session.output_octets - appconn->session.last_idle_check_output_octets > 0)	/*上行流量大于0*/
		&& (appconn->session.output_octets + appconn->session.input_octets
			> appconn->session.last_idle_check_octets + appconn->session.idle_flow))	/*上下行流量之和大于阀值*/
	{
   		appconn->session.last_flux_time = time_now;
		appconn->session.last_idle_check_output_octets = appconn->session.output_octets;
		appconn->session.last_idle_check_octets = appconn->session.output_octets + appconn->session.input_octets;
		ip2str(appconn->session.user_ip, user_ipstr, sizeof(user_ipstr));
		eag_log_info("appconn_check_flux userip=%s, output_octets=%llu, total_octets=%llu",
			user_ipstr, appconn->session.last_idle_check_output_octets,
			appconn->session.last_idle_check_octets);
	}

	return 0;
}

static int
appconn_check_flux_all(appconn_db_t *appdb, time_t time_now)
{
	struct app_conn_t *appconn=NULL;

	list_for_each_entry(appconn, &(appdb->head), node)
	{
		appconn_check_flux(appconn, time_now);
	}
	
	return 0;
}

int
flush_all_appconn_flux_from_wireless(appconn_db_t *appdb, int time_interval)
{
	int ret = -1;
//	DBusConnection *dbus_conn = NULL;
	static time_t last_time = 0;
	struct timeval tv = {0};
	time_t time_now = 0;
	struct WtpStaInfo *StaHead =NULL;
	struct WtpStaInfo *StaNode =NULL;
	struct app_conn_t *appconn = NULL;
	uint8_t usermac[6] = {0};
	
	//dbus_conn = eag_dbus_get_dbus_conn(appdb->eagdbus);
	eag_time_gettimeofday(&tv, NULL);
	time_now = tv.tv_sec;
	
	if (time_now - last_time < time_interval) {
		eag_log_debug("appconn", "flush_all_appconn_flux_from_wireless not timeout,"
			"time_now=%lu, last_time=%lu, time gap=%lu < time interval=%d",
			time_now, last_time, time_now - last_time, time_interval);
		return EAG_ERR_WIRELESS_NOT_TIMR_YET;
	}
	last_time = time_now;
	
/*	StaHead = eag_show_sta_info_of_all_wtp(appdb->hansi_id, appdb->hansi_type, dbus_conn, &ret);*/
#if 0	
	if (NULL != StaHead && EAG_RETURN_OK == ret) {
		for (StaNode = StaHead; StaNode; StaNode=StaNode->next) {
			#if 0
			userip = StaNode->wtpStaIp;
			appconn = appconn_find_by_userip(appdb, userip);
			#endif
			str2mac(StaNode->wtpTerminalMacAddr, usermac);
			appconn = appconn_find_by_usermac(appdb, usermac);
			if (NULL != appconn && APPCONN_STATUS_AUTHED == appconn->session.state) {
				appconn->session.wireless_data.cur_input_octets = StaNode->wtpTerminalRecvByteMount;
				appconn->session.wireless_data.cur_input_packets = StaNode->wtpTerminalRecvPackMount;
				appconn->session.wireless_data.cur_output_octets = StaNode->wtpSendTerminalByteMount;
				appconn->session.wireless_data.cur_output_packets = StaNode->wtpSendTerminalPackMount;
				set_appconn_flux(appconn);
				appconn_check_flux(appconn, time_now);
			}
		}
		eag_free_wtp_sta_info_head(StaHead);
	} else {
		eag_log_err("flush_all_appconn_flux_from_wireless StaHead=%p, ret=%d",
			StaHead, ret);
	}
#endif
	return EAG_RETURN_OK;
}

int
flush_all_appconn_flux_from_iptables(appconn_db_t *appdb, int time_interval)
{
	static time_t last_time = 0;
	struct timeval tv = {0};
	time_t time_now = 0;
	struct iptc_handle *handle = NULL;
	const char *chain_name = NULL;
	const struct ipt_entry *p_entry = NULL;
	struct ipt_counters *my_counter = NULL;
	unsigned int rule_num = 0;
	struct app_conn_t *appconn = NULL;
	uint32_t userip = 0;

	
	eag_time_gettimeofday(&tv, NULL);
	time_now = tv.tv_sec;

	if (time_now - last_time < time_interval) {
		eag_log_debug("appconn", "flush_all_appconn_flux_from_iptables not timeout,"
			"time_now=%lu, last_time=%lu, time gap=%lu < time interval=%d",
			time_now, last_time, time_now - last_time, time_interval);
		return EAG_ERR_WIRELESS_NOT_TIMR_YET;
	}
	last_time = time_now;

	eag_log_info("flush_all_appconn_flux_from_iptables iptables lock");
	nmp_mutex_lock(&eag_iptables_lock);
	handle = iptc_init("filter");
	eag_log_info("flush_all_appconn_flux_from_iptables iptables unlock");
	nmp_mutex_unlock(&eag_iptables_lock);
	if (NULL == handle) {
		eag_log_err("flush_all_appconn_flux_from_iptables can't init iptc handle");
		return -1;
	}

	for (chain_name = iptc_first_chain(handle); chain_name; chain_name = iptc_next_chain(handle))
	{
		int sscanf_ret = -1;
		char chain_name_ifname[64] = "";
		char chain_name_in[4] = "";
		
		eag_log_debug("appconn", "flush_all_appconn_flux_from_iptables chain_name=%s", chain_name);

		sscanf_ret = sscanf(chain_name, "CP_F_%63[^_]_%3s",
						 chain_name_ifname, chain_name_in);
		
		eag_log_debug("appconn", "flush_all_appconn_flux_from_iptables "
				"sscanf_ret=%d if=%s in=%s",
				sscanf_ret, chain_name_ifname, chain_name_in);
		if (2 == sscanf_ret)/* ret=2 means has "IN" in the last chain,this is the downflux chain */
		{
			rule_num = 0;
			for (p_entry = iptc_first_rule(chain_name, handle);
				p_entry;
				p_entry = iptc_next_rule(p_entry, handle))
			{
				rule_num++;
				eag_log_debug("appconn", "flush_all_appconn_flux_from_iptables dst addr = %#x",
						p_entry->ip.dst.s_addr);
				if (p_entry->ip.dst.s_addr == 0)
				{
					continue;
				}
				my_counter = iptc_read_counter(chain_name, rule_num, handle);
				userip = ntohl(p_entry->ip.dst.s_addr);
				appconn = appconn_find_by_userip(appdb, userip);
				if (NULL != appconn) {
					appconn->iptables_data.input_octets = my_counter->bcnt;
					appconn->iptables_data.input_packets = my_counter->pcnt;
					set_appconn_flux(appconn);
				}
			}
		}
		else if (1 == sscanf_ret)/* ret=1 means doesn't have "IN" in the last chain,this is the upflux chain */
		{
			rule_num = 0;
			for (p_entry = iptc_first_rule(chain_name, handle);
				p_entry;
				p_entry = iptc_next_rule(p_entry, handle))
			{
				rule_num++;
				eag_log_debug("appconn", "flush_all_appconn_flux_from_iptables src addr = %#x",
						p_entry->ip.src.s_addr);
				if (p_entry->ip.src.s_addr == 0)
				{
 					continue;
				}
				my_counter = iptc_read_counter(chain_name,rule_num, handle);
				userip = ntohl(p_entry->ip.src.s_addr);
				appconn = appconn_find_by_userip(appdb, userip);
				if (NULL != appconn) {
					appconn->iptables_data.output_octets = my_counter->bcnt;
					appconn->iptables_data.output_packets = my_counter->pcnt;
					set_appconn_flux(appconn);
				}	
			}
		}
	}
	
	iptc_free(handle);
	appconn_check_flux_all( appdb, time_now);

	return EAG_RETURN_OK;
}

int
appconn_init_flux_from_wireless(struct app_conn_t *appconn)
{
	appconn_db_t *appdb = NULL;
	struct WtpStaInfo *StaHead = NULL;
	struct WtpStaInfo *StaNode = NULL;
//	DBusConnection *dbus_conn = NULL;
	int ret = 0;
	char userip_str[32] = "";
	int found = 0;
	
	if (NULL == appconn) {
		eag_log_err("appconn_init_flux_from_wireless input error");
		return EAG_ERR_NULL_POINTER;
	}
	
	appdb = appconn->appdb;
	//dbus_conn = eag_dbus_get_dbus_conn(appdb->eagdbus);
	ip2str(appconn->session.user_ip, userip_str, sizeof(userip_str));
#if 0	
	StaHead = eag_show_sta_info_of_all_wtp(appdb->hansi_id,
							appdb->hansi_type, dbus_conn, &ret);
	eag_log_debug("appconn", 
			"eag_show_sta_info_of_all_wtp StaHead=%p, ret=%d", StaHead, ret);

	if (NULL != StaHead && EAG_RETURN_OK == ret) {
		for (StaNode=StaHead; StaNode; StaNode=StaNode->next) {
			uint8_t usermac[6] = {0};
			str2mac(StaNode->wtpTerminalMacAddr, usermac);
			// if (StaNode->wtpStaIp == appconn->session.user_ip) {
			if (0 == memcmp(usermac, appconn->session.usermac, sizeof(usermac))) {
				found = 1;
				appconn->session.wireless_data.init_input_octets
							= StaNode->wtpTerminalRecvByteMount;
				appconn->session.wireless_data.init_input_packets
							= StaNode->wtpTerminalRecvPackMount;
				appconn->session.wireless_data.init_output_octets
							= StaNode->wtpSendTerminalByteMount;
				appconn->session.wireless_data.init_output_packets
							= StaNode->wtpSendTerminalPackMount;
				
				appconn->session.wireless_data.last_input_octets
							= StaNode->wtpTerminalRecvByteMount;
				appconn->session.wireless_data.last_input_packets
							= StaNode->wtpTerminalRecvPackMount;
				appconn->session.wireless_data.last_output_octets
							= StaNode->wtpSendTerminalByteMount;
				appconn->session.wireless_data.last_output_packets
							= StaNode->wtpSendTerminalPackMount;
				
				eag_log_debug("appconn",
					"appconn_init_flux_from_wireless userip %s, "
					"input_octets %llu, input_packets %u, "
					"output_octets %llu, output_packets %u",
					userip_str,
					appconn->session.wireless_data.init_input_octets,
					appconn->session.wireless_data.init_input_packets,
					appconn->session.wireless_data.init_output_octets,
					appconn->session.wireless_data.init_output_packets);
				break;
			}				
		}
		eag_free_wtp_sta_info_head(StaHead);
	}
	
	if (!found) {
		eag_log_err("appconn_init_flux_from_wireless not found sta %s",
			userip_str);
		return -1;
	}
	#endif
	return EAG_RETURN_OK;
}

int
flush_all_appconn_flux_immediate(appconn_db_t *appdb)
{
	int flux_interval = FLUX_INTERVAL_FOR_IPTABLES_OR_WIRELESS;
	int flux_from = 0;
	
	if (NULL == appdb) {
		eag_log_err("flush_all_appconn_flux_immediate input error");
		return -1;
	}
	
	flux_from = eag_ins_get_flux_from(appdb->eagins);
	if (FLUX_FROM_IPTABLES == flux_from
		||FLUX_FROM_IPTABLES_L2 == flux_from
		||FLUX_FROM_FASTFWD_IPTABLES == flux_from) {
		flush_all_appconn_flux_from_iptables(appdb, flux_interval);
	}
	else if (FLUX_FROM_WIRELESS == flux_from) {
		flush_all_appconn_flux_from_wireless(appdb, flux_interval);
	}
	
	return 0;
}

int
appconn_db_set_eagins(appconn_db_t *appdb,
		eag_ins_t *eagins)
{
	appdb->eagins = eagins;

	return 0;
}

eag_ins_t *
appconn_db_get_eagins(appconn_db_t *appdb)
{
	if (NULL == appdb) {
		eag_log_err("appconn_db_get_eagins input error");
		return NULL;
	}

	return appdb->eagins;
}

