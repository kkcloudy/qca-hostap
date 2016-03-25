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
* appconn.h
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

#ifndef _APPCONN_H
#define _APPCONN_H

#include <stdint.h>
#include "eag_def.h"
#include "nm_list.h"
#include "hashtable.h"
#include "session.h"
#include "eag_conf.h"
//#include "dbus/asd/ASDDbusDef1.h"

#define log_app_info(appconn,fmt,args...)	eag_log_info("%s "fmt,appconn->log_prefix,##args)
#define log_app_err(appconn,fmt,args...)	eag_log_err("%s "fmt,appconn->log_prefix,##args)
#define log_app_debug(appconn,fmt,args...)	eag_log_debug(appconn->log_prefix,fmt,##args)

#define log_app_filter(appconn,fmt,args...)   eag_log_filter(appconn->session_filter_prefix,fmt,##args)  

#define APPCONN_STATUS_NONE		0
#define APPCONN_STATUS_AUTHED	1
#define NO_NEED_AUTH				11

struct app_conn_t {
	struct list_head node;
	struct hlist_node ip_hnode;
	struct hlist_node mac_hnode;
	struct hlist_node name_hnode;
	appconn_db_t *appdb;
	char sub_intf[MAX_IF_NAME_LEN];

	uint32_t nascon;
	struct appsession session;
	struct portal_srv_t portal_srv;

	uint32_t bk_input_packets;
	uint64_t bk_input_octets;
	uint32_t bk_output_packets;
	uint64_t bk_output_octets;
	struct iptables_data_t iptables_data;
	struct fastfwd_data_t fastfwd_data;

	char log_prefix[64];
	int on_auth;
	int on_ntf_logout;

	time_t last_active_time;
	time_t last_check_dhcp_time; /* last call dhcp_interface(dhcp_show_lease_by_ip) time */
	int last_check_dhcp_resault;
	char user_agent[256];
	char session_filter_prefix[512]; /* fmt like "ip:mac:uname" */
};

appconn_db_t *appconn_db_create(uint32_t size);

int
appconn_db_destroy(appconn_db_t *appdb);

struct app_conn_t *
appconn_new(appconn_db_t *appdb);

int
appconn_free(struct app_conn_t *appconn);

int
appconn_update_name_htable(appconn_db_t *appdb,
						struct app_conn_t *appconn);

int
appconn_del_name_htable(struct app_conn_t *appconn);

int
appconn_add_to_db(appconn_db_t *appdb,
		struct app_conn_t *appconn);

int
appconn_del_from_db(struct app_conn_t *appconn);

struct app_conn_t *
appconn_find_by_userip(appconn_db_t *appdb,
		uint32_t userip);

struct app_conn_t *
appconn_find_by_usermac(appconn_db_t *appdb,
		const uint8_t *usermac);

struct app_conn_t *
appconn_find_by_username(appconn_db_t *appdb,
					const char *username);

int
appconn_count_authed(appconn_db_t *appdb);

int
appconn_count_by_username(appconn_db_t *appdb,
		const char *username);

int
appconn_count_by_userip(appconn_db_t *appdb,
		uint32_t userip);

int
appconn_count_by_usermac(appconn_db_t *appdb,
		uint8_t usermac[6]);

int
appconn_set_debug_prefix(struct app_conn_t *appconn);

int
appconn_set_filter_prefix(struct app_conn_t *appconn);

int
appconn_set_nasid(struct app_conn_t *appconn,
		struct nasid_conf *nasidconf);

int
appconn_set_nasportid(struct app_conn_t *appconn,
		struct nasportid_conf *nasportidconf);

int
appconn_check_is_conflict(uint32_t userip, appconn_db_t *appdb, struct appsession *session, struct app_conn_t **app);

struct app_conn_t *
appconn_create_no_arp(appconn_db_t * appdb, struct appsession *session);

struct app_conn_t *
appconn_find_by_ip_autocreate(appconn_db_t *appdb,
		uint32_t userip);

struct app_conn_t *
appconn_create_by_sta_v2(appconn_db_t *appdb, struct appsession *session);

int 
appconn_config_portalsrv(struct app_conn_t *appconn,
		struct portal_conf *portalconf);

int
appconn_config_portalsrv_bk(struct app_conn_t *appconn,
		struct portal_conf *portalconf);

int
appconn_config_radiussrv_by_domain(struct app_conn_t *appconn,
		struct radius_conf *radiusconf);

int
appconn_check_redir_count(struct app_conn_t *appconn,
		uint32_t max_count,
		uint32_t interval);

int
appconn_check_dhcplease(struct app_conn_t *appconn);

int
appconn_db_set_nasid_conf(appconn_db_t *appdb,
		struct nasid_conf *nasidconf);

int
appconn_db_set_nasportid_conf(appconn_db_t *appdb,
		struct nasportid_conf *nasportidconf);

int
appconn_db_set_portal_conf(appconn_db_t *appdb,
		struct portal_conf *portalconf);


int
appconn_db_set_idle_params(appconn_db_t *db,
		unsigned long idle_timeout, uint64_t idle_flow);

int
appconn_db_get_idle_params(appconn_db_t *appdb,
		unsigned long *idle_timeout, uint64_t *idle_flow);

int
appconn_db_set_force_wireless(appconn_db_t *appdb,
		int force_wireless);

int
appconn_db_get_force_wireless(appconn_db_t *appdb);

int
appconn_db_set_check_nasportid(appconn_db_t *appdb, int check_nasportid);

int
appconn_db_get_check_nasportid(appconn_db_t *appdb);

int
appconn_db_set_correct_factor(appconn_db_t *appdb,
		uint32_t input_correct_factor, uint32_t output_correct_factor);

int
appconn_db_get_correct_factor(appconn_db_t *appdb,
		uint32_t *input_correct_factor, uint32_t *output_correct_factor);

int
appdb_authed_user_num_increase(appconn_db_t *appdb);

int
appdb_authed_user_num_decrease(appconn_db_t *appdb);

void
appdb_log_all_appconn(appconn_db_t *appdb);

struct list_head *
appconn_db_get_head(appconn_db_t *appdb);

int
set_appconn_flux(struct app_conn_t *appconn);

int
appconn_check_flux(struct app_conn_t *appconn, time_t time_now);

int
flush_all_appconn_flux_from_wireless(appconn_db_t *appdb, int time_interval);

int
flush_all_appconn_flux_from_iptables(appconn_db_t *appdb, int time_interval);

int
appconn_init_flux_from_wireless(struct app_conn_t *appconn);

int
appconn_db_set_eagins(appconn_db_t *appdb,
		eag_ins_t *eagins);

eag_ins_t *
appconn_db_get_eagins(appconn_db_t *appdb);

int
flush_all_appconn_flux_immediate(appconn_db_t *appdb);



#endif		/* _APPCONN_H */
