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
* eag_ins.c
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* eag ins
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
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "nm_list.h"
#include "hashtable.h"
#include "eag_mem.h"
#include "eag_log.h"
#include "eag_blkmem.h"
#include "eag_thread.h"
#include "eag_conf.h"  //not need
#include "eag_time.h"
#include "eag_util.h"

#include "radius_packet.h"
#include "eag_redir.h"
#include "eag_portal.h"
#include "eag_radius.h"
#include "eag_captive.h"
#include "appconn.h"
#include "eag_statistics.h"
#include "eag_stamsg.h"
#include "eag_coa.h"
#include "eag_authorize.h"
#include "eag_ins.h"
#include "eag_iptables.h"
#include "eag_wireless.h"
#include "portal_packet.h"
#include "eag_macauth.h"
#include "eag_arp.h"

#define CLI_PATH  "/var/run/cli"
#define EAG_PATH  "/var/run/eag"



/* prime number */
#define EAG_APPCONN_DB_HASHSIZE			2011
#define EAG_BSS_STAT_DB_HASHSIZE		2011


#define CM_TEST_NOTICE_ASD		"/var/run/eag_notice_asd"
#define CM_TEST_NOTICE_PDC		"/var/run/eag_notice_pdc"
#define CM_TEST_NOTICE_FWD		"/var/run/eag_notice_fwd"
#define CM_TEST_ARP_LEARN		"/var/run/eag_arp_learn"
#define CM_TEST_AUTHORIZE		"/var/run/eag_authorize"

/* 1: no notice; 0: default */
int cmtest_no_notice_to_asd = 0;
int cmtest_no_notice_to_pdc = 0;
int cmtest_no_notice_to_fastfwd = 0;
int cmtest_no_arp_learn = 0;
int cmtest_no_authorize = 0;
int l2super_vlan_switch_t = 0;
int local_database_switch = 0;
extern int eag_macauth_type;
extern int local_database_switch;
struct eag_cli{
	int sockfd;
	eag_thread_t *t_read;
	eag_thread_master_t *master;
	char sockpath[128];
};

struct eag_ins {
	int status;
	eag_redir_t *redir;
	eag_portal_t *portal;
	eag_radius_t *radius;
	eag_captive_t *captive;
	appconn_db_t *appdb;
	eag_stamsg_t *stamsg;
	eag_coa_t *coa;
	eag_statistics_t *eagstat;
	eag_fastfwd_t *fastfwd;
	eag_macauth_t *macauth;
	eag_arplisten_t *arp;
	
	eag_thread_master_t *master;
	//eag_dbus_t *eagdbus;
	//eag_hansi_t *eaghansi;

	//uint8_t slot_id;
	//uint8_t hansi_type;
	
	//uint8_t hansi_id;
	//int is_distributed;
	//int rdc_distributed;
	//int pdc_distributed;
           struct eag_cli *cli;
	struct portal_conf portalconf;
	struct radius_conf radiusconf;
	struct nasid_conf nasidconf;
	struct nasportid_conf nasportidconf;

	uint32_t nasip;
	int flux_from;
	int flux_interval;
#if 0
	backup_type_t *syn_user;
	backup_type_t *ack_user;
	backup_type_t *syn_finish_flag;
	backup_type_t *ack_finish_flag;
	backup_type_t *syn_statistic;
	backup_type_t *ack_statistic;
#endif
	int trap_switch_abnormal_logoff;
	/* for trap threshold */
	int trap_onlineusernum_switch;
	int threshold_onlineusernum;
};

//char EAG_DBUS_NAME[MAX_DBUS_BUSNAME_LEN]="";
//char EAG_DBUS_OBJPATH[MAX_DBUS_BUSNAME_LEN]="";
//char EAG_DBUS_INTERFACE[MAX_DBUS_BUSNAME_LEN]="";

//static void
//eagins_register_all_dbus_method(eag_ins_t *eagins);

static int
eagins_read_file_switch()
{
	FILE *fp = NULL;
	
	fp = fopen(CM_TEST_NOTICE_ASD, "r");
	if (NULL != fp) {
		if (1 != fscanf(fp, "%d", &cmtest_no_notice_to_asd)) {
			cmtest_no_notice_to_asd = 0;
		}
		fclose(fp);
		fp = NULL;
	}
	fp = fopen(CM_TEST_NOTICE_PDC, "r");
	if (NULL != fp) {
		if (1 != fscanf(fp, "%d", &cmtest_no_notice_to_pdc)) {
			cmtest_no_notice_to_pdc = 0;
		}
		fclose(fp);
		fp = NULL;
	}
	fp = fopen(CM_TEST_NOTICE_FWD, "r");
	if (NULL != fp) {
		if (1 != fscanf(fp, "%d", &cmtest_no_notice_to_fastfwd)) {
			cmtest_no_notice_to_fastfwd = 0;
		}
		fclose(fp);
		fp = NULL;
	}
	fp = fopen(CM_TEST_ARP_LEARN, "r");
	if (NULL != fp) {
		if (1 != fscanf(fp, "%d", &cmtest_no_arp_learn)) {
			cmtest_no_arp_learn = 0;
		}
		fclose(fp);
		fp = NULL;
	}
	fp = fopen(CM_TEST_AUTHORIZE, "r");
	if (NULL != fp) {
		if (1 != fscanf(fp, "%d", &cmtest_no_authorize)) {
			cmtest_no_authorize = 0;
		}
		fclose(fp);
		fp = NULL;
	}

	eag_log_info("notice_asd=%d notice_pdc=%d notice_fwd=%d arp_learn=%d auth=%d\n", 
			cmtest_no_notice_to_asd, cmtest_no_notice_to_pdc, cmtest_no_notice_to_fastfwd, 
			cmtest_no_arp_learn, cmtest_no_authorize);
	return 0;
}

static int eag_set_l2super_vlan_status(int l2super_vlan_switch)
{
	if(0 != l2super_vlan_switch && 1 != l2super_vlan_switch) {
		return EAG_ERR_UNKNOWN;
	}
	
	l2super_vlan_switch_t = l2super_vlan_switch;

	return EAG_RETURN_OK;
}

static int eag_set_l2super_vlan( eag_ins_t *eagins, int l2super_vlan_switch )
{
	char nasip_str[32]= "";
	uint32_t nasip = 0;
	char dns_udp_dnat[256] = "";	/*udp port 53 dnat when dns hold*/
	char dns_tcp_dnat[256] = "";	/*tcp port 53 dnat when dns hold*/
	char redir_tcp_dnat[256] = "";	/*tcp port 80 to 3.4.5.6 dnat to nasip*/
	char portal_udp_dnat[256] = "";	/*udp port 2000 to 3.4.5.6 dnat to nasip*/
	char opt[8] = "";
	int ret = 0;
	#if 0
	struct in_addr ipaddr_begin;
	struct in_addr ipaddr_end;
	char port[32] = "all";
	memset(&ipaddr_begin, 0, sizeof(ipaddr_begin));
	memset(&ipaddr_end, 0, sizeof(ipaddr_end));
	#endif
	memset(dns_udp_dnat, 0, sizeof(dns_udp_dnat));
	memset(dns_tcp_dnat, 0, sizeof(dns_tcp_dnat));
	memset(redir_tcp_dnat, 0, sizeof(redir_tcp_dnat));
	memset(portal_udp_dnat, 0, sizeof(portal_udp_dnat));
	memset(opt, 0, sizeof(opt));
	
	nasip = eag_ins_get_nasip(eagins);
	ip2str(nasip, nasip_str, sizeof(nasip_str));
	
	if(1 == l2super_vlan_switch) {	
		strncpy(opt, "-I", sizeof(opt)-1);
	} else if(0 == l2super_vlan_switch) {
		strncpy(opt, "-D", sizeof(opt)-1);
	} else {
		return EAG_ERR_UNKNOWN;
	}
	
	snprintf(dns_udp_dnat, sizeof(dns_udp_dnat) - 1,
		" iptables -t nat %s PREROUTING -p udp -m udp --dport 53 -m string --hex-string '|617574656c616e39323303636f6d|' --algo bm --from 0 --to 65535 -j DNAT --to-destination %s", 
		opt, nasip_str);
	snprintf(dns_tcp_dnat, sizeof(dns_tcp_dnat) - 1,
		" iptables -t nat %s PREROUTING -p tcp -m tcp --dport 53 -m string --hex-string '|617574656c616e39323303636f6d|' --algo bm --from 0 --to 65535 -j DNAT --to-destination %s", 
		opt, nasip_str);
	snprintf(redir_tcp_dnat, sizeof(redir_tcp_dnat) - 1,
		" iptables -t nat %s PREROUTING -d 3.4.5.6/32 -p tcp -m tcp --dport 80 -j DNAT --to-destination %s", 
		opt, nasip_str);
	snprintf(portal_udp_dnat, sizeof(portal_udp_dnat) - 1, 
		"iptables -t nat %s OUTPUT -d 3.4.5.6/32 -p udp -m udp --dport 2000 -j DNAT --to-destination %s", 
		opt, nasip_str);

	ret = system(dns_udp_dnat);
	ret = WEXITSTATUS(ret); 
	if( 0 != ret) {
		return EAG_ERR_UNKNOWN;
	}
	ret = system(dns_tcp_dnat);
	ret = WEXITSTATUS(ret); 
	if( 0 != ret) {
		return EAG_ERR_UNKNOWN;
	}
	ret = system(redir_tcp_dnat);
	ret = WEXITSTATUS(ret); 
	if( 0 != ret) {
		return EAG_ERR_UNKNOWN;
	}
	ret = system(portal_udp_dnat);
	ret = WEXITSTATUS(ret); 
	if( 0 != ret) {
		return EAG_ERR_UNKNOWN;
	}
	#if 0
	inet_aton("3.4.5.6", &ipaddr_begin);
	inet_aton("3.4.5.6", &ipaddr_end);
	if(1 == l2super_vlan_switch) {
		ret = eag_captive_add_white_list(eagins->captive, RULE_IPADDR, ipaddr_begin.s_addr,ipaddr_end.s_addr,port,"","");
	} else if(0 == l2super_vlan_switch) {
        ret = eag_captive_del_white_list(eagins->captive, RULE_IPADDR, ipaddr_begin.s_addr,ipaddr_end.s_addr,port,"","");
	} else {
		return EAG_ERR_UNKNOWN;
	}
	#endif
	return EAG_RETURN_OK;
}
#if 0
static void 
eag_dbus_path_init(int type,int insid)
{
	snprintf(EAG_DBUS_NAME, sizeof(EAG_DBUS_NAME),
				EAG_DBUS_NAME_FMT, 
				(HANSI_LOCAL==type)?"l":"r",insid);
	snprintf(EAG_DBUS_OBJPATH, sizeof(EAG_DBUS_OBJPATH),
				EAG_DBUS_OBJPATH_FMT,
				(HANSI_LOCAL==type)?"l":"r",insid);
	snprintf(EAG_DBUS_INTERFACE, sizeof(EAG_DBUS_INTERFACE),
				EAG_DBUS_INTERFACE_FMT,
				(HANSI_LOCAL==type)?"l":"r",insid);
	return;
}

static int
eag_eagins_register_hansi_param_forward( 
					eag_hansi_t * eaghansi, int hansitype, int insid )
{
#define PDC_DBUS_NAME_FMT		"aw.pdc_%s_%d"
#define PDC_DBUS_OBJPATH_FMT	"/aw/pdc_%s_%d"
#define PDC_DBUS_INTERFACE_FMT	"aw.pdc_%s_%d"

#define RDC_DBUS_NAME_FMT		"aw.rdc_%s_%d"
#define RDC_DBUS_OBJPATH_FMT	"/aw/rdc_%s_%d"
#define RDC_DBUS_INTERFACE_FMT	"aw.rdc_%s_%d"

	char PDC_DBUS_NAME[MAX_DBUS_BUSNAME_LEN]="";
	char PDC_DBUS_OBJPATH[MAX_DBUS_BUSNAME_LEN]="";
	char PDC_DBUS_INTERFACE[MAX_DBUS_BUSNAME_LEN]="";
	
	char RDC_DBUS_NAME[MAX_DBUS_BUSNAME_LEN]="";
	char RDC_DBUS_OBJPATH[MAX_DBUS_BUSNAME_LEN]="";
	char RDC_DBUS_INTERFACE[MAX_DBUS_BUSNAME_LEN]="";

	char *instype = (HANSI_LOCAL==hansitype)?"l":"r";

	if( NULL == eaghansi ){
		eag_log_err("eag_eagins_register_hansi_param_forward input error!");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	snprintf( PDC_DBUS_NAME, sizeof(PDC_DBUS_NAME)-1,
				PDC_DBUS_NAME_FMT, instype, insid );
	snprintf( PDC_DBUS_OBJPATH, sizeof(PDC_DBUS_OBJPATH)-1,
				PDC_DBUS_OBJPATH_FMT, instype, insid );
	snprintf( PDC_DBUS_INTERFACE, sizeof(PDC_DBUS_INTERFACE)-1,
				PDC_DBUS_INTERFACE_FMT, instype, insid );	
	eag_hansi_add_hansi_param_forward(eaghansi,
				PDC_DBUS_OBJPATH, PDC_DBUS_NAME, PDC_DBUS_INTERFACE,
				"eag_hansi_dbus_vrrp_state_change_func" );

	snprintf( RDC_DBUS_NAME, sizeof(RDC_DBUS_NAME)-1,
				RDC_DBUS_NAME_FMT, instype, insid );
	snprintf( RDC_DBUS_OBJPATH, sizeof(RDC_DBUS_OBJPATH)-1,
				RDC_DBUS_OBJPATH_FMT, instype, insid );
	snprintf( RDC_DBUS_INTERFACE, sizeof(RDC_DBUS_INTERFACE)-1,
				RDC_DBUS_INTERFACE_FMT, instype, insid );	
	eag_hansi_add_hansi_param_forward(eaghansi,
				RDC_DBUS_OBJPATH, RDC_DBUS_NAME, RDC_DBUS_INTERFACE,
				"eag_hansi_dbus_vrrp_state_change_func" );

	return EAG_RETURN_OK;
	
}
#endif
#if 0
static int
eag_ins_do_syn_user_data(void *cbp, void *data, struct timeval *cb_tv)
{
	eag_ins_t *eagins = (eag_ins_t *)cbp;
	struct appsession *usersession = (struct appsession *)data;
	struct app_conn_t *appconn = NULL;
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	int ret = EAG_RETURN_OK;
	
	userip = usersession->user_ip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	appconn = appconn_find_by_userip(eagins->appdb, userip);
	if (NULL == appconn) {
		if (APPCONN_STATUS_NONE == usersession->state) {
			eag_log_err("eag_ins_do_syn_user_data "
					"receive user offline backup info, but appconn not found, "
					"userip %s", user_ipstr);
			ret = EAG_RETURN_OK;
			goto ack_data;
		}
		appconn = appconn_new(eagins->appdb);
		if (NULL == appconn) {
			eag_log_err("eag_ins_do_syn_user_data appconn_new failed, "
					"userip %s", user_ipstr);
			ret = EAG_ERR_UNKNOWN;
			goto ack_data;
		}
		
		//memcpy(&(appconn->session), usersession, sizeof(struct appsession));
		appsession_copy(&(appconn->session), usersession, cb_tv);
                appconn_config_portalsrv_bk(appconn, &(eagins->portalconf));
		appconn->bk_input_octets = usersession->input_octets;
		appconn->bk_input_packets = usersession->input_packets;
		appconn->bk_output_octets = usersession->output_octets;
		appconn->bk_output_packets = usersession->output_packets;
		
		ret = set_down_interface_by_virtual_ip(eagins->eaghansi,
					appconn->session.virtual_ip, appconn->session.intf);
		if (EAG_RETURN_OK != ret) {
			eag_log_err("eag_ins_do_syn_user_data "
				"set_down_interface_by_virtual_ip failed, userip %s", user_ipstr);
			appconn_free(appconn);
			goto ack_data;
		}
		ret = eag_captive_authorize(eagins->captive, &(appconn->session));
		if (EAG_RETURN_OK != ret) {
			eag_log_err("eag_ins_do_syn_user_data "
				"set_down_interface_by_virtual_ip failed, userip %s", user_ipstr);
			appconn_free(appconn);
			goto ack_data;
		}
		appconn_add_to_db(eagins->appdb, appconn);
		appconn_update_name_htable(eagins->appdb, appconn);
		if (FLUX_FROM_FASTFWD == eagins->flux_from
			||FLUX_FROM_FASTFWD_IPTABLES == eagins->flux_from)
		{
			eag_log_info("eag_ins_do_syn_user_data fastfwd_send userip:%s online",
					user_ipstr);
			eag_fastfwd_send(eagins->fastfwd, userip, SE_AGENT_USER_ONLINE);
		}
		
		/* online user count++,add by zhangwl 2012-8-1*/
		appdb_authed_user_num_increase(eagins->appdb);

		appconn_set_debug_prefix(appconn);
		appconn_set_filter_prefix(appconn, eagins->hansi_type, eagins->hansi_id); /* for debug-filter,add by zhangwl */
		eag_log_info("eag_ins_do_syn_user_data new appconn userip %s, state authed",
				user_ipstr);
	} else {
		if (appconn->session.virtual_ip != usersession->virtual_ip) {
			eag_log_err("eag_ins_do_syn_user_data current appconn virtual_ip %#X "
				"is not equal backup data virtual_ip %#X, userip %#X",
				appconn->session.virtual_ip, usersession->virtual_ip, userip);
		} else {
			//memcpy(&(appconn->session), usersession, sizeof(struct appsession));
			appsession_copy(&(appconn->session), usersession, cb_tv);
			set_down_interface_by_virtual_ip(eagins->eaghansi,
				appconn->session.virtual_ip, appconn->session.intf);
		}
		
        appconn_config_portalsrv_bk(appconn, &(eagins->portalconf));
		appconn->bk_input_octets = usersession->input_octets;
		appconn->bk_input_packets = usersession->input_packets;
		appconn->bk_output_octets = usersession->output_octets;
		appconn->bk_output_packets = usersession->output_packets;
	
		eag_log_debug("eagins", "eag_ins_do_syn_user_data "
				"found appconn userip %s, state %d",
				user_ipstr, usersession->state);
		
		if (APPCONN_STATUS_NONE == usersession->state) {
			eag_log_info("eag_ins_do_syn_user_data "
				"found appconn userip %s, user offline",
				user_ipstr);
			eag_captive_deauthorize(eagins->captive, &(appconn->session));
			if (FLUX_FROM_FASTFWD == eagins->flux_from
				||FLUX_FROM_FASTFWD_IPTABLES == eagins->flux_from)
			{
				eag_log_info("eag_ins_do_syn_user_data fastfwd_send userip:%s offline",
					user_ipstr);
				eag_fastfwd_send(eagins->fastfwd, userip, SE_AGENT_USER_OFFLINE);
			}
			
			/* online user count--, add by zhangwl 2012-8-1 */
			appdb_authed_user_num_decrease(eagins->appdb);
			
			appconn_del_from_db(appconn);
			appconn_del_name_htable(appconn);
			appconn_free(appconn);
		}
	}
	ret = EAG_RETURN_OK;
	
ack_data:
	eag_hansi_queue_data(eagins->eaghansi,eagins->ack_user, &ret, sizeof(ret));
	return EAG_RETURN_OK;
}

static int
eag_ins_do_ack_user_data(void *cbp, void *data, struct timeval *cb_tv)
{
	int ret = *((int *)data);
	
	if (EAG_RETURN_OK != ret) {
		eag_log_err("eag_ins_do_ack_user_data error, ret=%d", ret);
	}
	eag_log_debug("eagins", "eag_ins_do_ack_user_data ret=%d", ret);

	return EAG_RETURN_OK;
}

static int
eag_ins_do_syn_finish_flag_data(void *cbp, void *data, struct timeval *cb_tv)
{
	int ret = 0;
	eag_ins_t *eagins = NULL;

	if (NULL == cbp || NULL == data) {
		eag_log_err("eag_ins_do_syn_finish_flag_data input error");
		return EAG_ERR_UNKNOWN;
	}
		
	eagins = (eag_ins_t *)cbp;
	ret = *((int *)data);

	eag_hansi_notify_had_backup_finished(eagins->eaghansi);
	
	eag_hansi_queue_data(eagins->eaghansi, eagins->ack_finish_flag,
			&ret, sizeof(ret));
	
	eag_log_info("eag_ins_do_syn_finish_flag_data "
				"backup get all users from master");
	
	return EAG_RETURN_OK;

}

static int
eag_ins_do_ack_finish_flag_data(void *cbp, void *data, struct timeval *cb_tv)
{
	int ret = 0;
	eag_ins_t *eagins = NULL;

	if (NULL == cbp || NULL == data) {
		eag_log_err("eag_ins_do_ack_finish_flag_data input error");
		return EAG_ERR_UNKNOWN;
	}
		
	eagins = (eag_ins_t *)cbp;
	ret = *((int *)data);

	eag_hansi_notify_had_backup_finished(eagins->eaghansi);
	
	eag_log_info("eag_ins_do_ack_finish_flag_data "
			"master receive backup response after backup all users");
	
	return EAG_RETURN_OK; 
}

static int
eag_ins_do_syn_statistic_data(void *cbp, void *data, struct timeval *cb_tv)
{
//	int ret = 0;
//	eag_ins_t *eagins = cbp;
	

	return EAG_RETURN_OK;
}

static int
eag_ins_do_ack_statistic_data(void *cbp, void *data, struct timeval *cb_tv)
{
	int ret = *((int *)data);
	
	if (EAG_RETURN_OK != ret) {
		eag_log_err("eag_ins_do_ack_statistic_data error, ret=%d", ret);
	}
	eag_log_debug("eagins", "eag_ins_do_ack_statistic_data ret=%d", ret);

	return EAG_RETURN_OK;
}

static int
eag_ins_register_all_backup_type(eag_ins_t *eagins)
{
	eagins->syn_user = eag_hansi_register_backup_type(eagins->eaghansi,
									BACKUP_TYPE_SYN_USER,
									eagins,
									eag_ins_do_syn_user_data);
	eagins->ack_user = eag_hansi_register_backup_type(eagins->eaghansi,
									BACKUP_TYPE_ACK_USER,
									eagins,
									eag_ins_do_ack_user_data);
	eagins->syn_finish_flag = eag_hansi_register_backup_type(eagins->eaghansi,
									BACKUP_TYPE_SYN_FINISH_FLAG,
									eagins,
									eag_ins_do_syn_finish_flag_data);
	eagins->ack_finish_flag = eag_hansi_register_backup_type(eagins->eaghansi,
									BACKUP_TYPE_ACK_FINISH_FLAG,
									eagins,
									eag_ins_do_ack_finish_flag_data);
	eagins->syn_statistic = eag_hansi_register_backup_type(eagins->eaghansi,
									BACKUP_TYPE_SYN_STATISTIC,
									eagins,
									eag_ins_do_syn_statistic_data);
	eagins->ack_statistic = eag_hansi_register_backup_type(eagins->eaghansi,
									BACKUP_TYPE_ACK_STATISTIC,
									eagins,
									eag_ins_do_ack_statistic_data);

	return 0;
}

int
eag_ins_syn_user(eag_ins_t *eagins, struct app_conn_t *appconn)
{
	struct appsession usersession = {0};
	int ret = 0;

	if (!eag_hansi_is_master(eagins->eaghansi)
		|| !eag_hansi_is_connected(eagins->eaghansi)) {
		eag_log_debug("eagins",
			"eag_ins_syn_user hansi is not master or not connected, "
			"can not syn user");
		return 0;
	}
		
	memset(&usersession, 0, sizeof(usersession));
	ret = get_virtual_ip_by_down_interface(eagins->eaghansi,
				appconn->session.intf, &(appconn->session.virtual_ip));
	if (EAG_RETURN_OK != ret) {
		eag_log_err("eag_ins_syn_user "
				"get_virtual_ip_by_down_interface failed, ret=%d", ret);
		return -1;
	}

	memcpy(&usersession, &(appconn->session), sizeof(usersession));
		
	eag_hansi_queue_data(eagins->eaghansi, eagins->syn_user,
			&usersession, sizeof(usersession));

	return EAG_RETURN_OK;
}

int
eag_ins_syn_finish_flag(eag_ins_t *eagins)
{
	int ret = 0;

	if (eag_hansi_is_master(eagins->eaghansi)
		&& eag_hansi_is_connected(eagins->eaghansi)) {
		eag_hansi_queue_data(eagins->eaghansi, eagins->syn_finish_flag,
					&ret, sizeof(ret));
	}

	return EAG_RETURN_OK;
}

int
eag_ins_syn_statistic(eag_ins_t *eagins,
		struct eag_bss_statistics *bss)
{
	return 0;
}

static int eag_send_trap_user_logoff_abnormal(struct app_conn_t *appconn,
							eag_ins_t *eagins, int terminate_cause)
{
	int eag_trap = EAG_TRAP;
	char stamac_str[32] = "";
	char apmac_str[32] = "";
	char staip_str[32] = "";
	int hansi_id = eagins->hansi_id;
	int hansi_type = eagins->hansi_type;

	if (0 == eagins->trap_switch_abnormal_logoff) {
		eag_log_debug("eag_trap","eag_send_trap_user_logoff_abnormal switch off");
		return 0;
	}
	ip2str(appconn->session.user_ip,staip_str,sizeof(staip_str));
	mac2str(appconn->session.apmac,apmac_str,sizeof(apmac_str)-1,'-');
	mac2str(appconn->session.usermac,stamac_str,sizeof(stamac_str)-1,'-');

	const char *apmac = apmac_str;
	const char *staip = staip_str;
	const char *stamac = stamac_str;
	const char *username = appconn->session.username;
	eag_log_debug("eag_trap","eag_send_trap_user_logoff_abnormal eag_trap:%d, apmac:%s, wtpid:%d, stamac:%s, username:%s, "\
		"staip:%s, terminate_cause:%d, ins_id:%d, hansi_type:%d",
		eag_trap, apmac, appconn->session.wtpid, stamac, username, 
		staip, terminate_cause, eagins->hansi_id, eagins->hansi_type);

	eag_send_trap_signal(EAG_TRAP_USER_LOGOFF_ABNORMAL, 
						DBUS_TYPE_INT32, &eag_trap,
						DBUS_TYPE_STRING, &apmac,
						DBUS_TYPE_UINT32, &appconn->session.wtpid,
						DBUS_TYPE_STRING, &stamac,
						DBUS_TYPE_STRING, &username,
						DBUS_TYPE_STRING, &staip,
						DBUS_TYPE_INT32, &terminate_cause,
						DBUS_TYPE_INT32, &hansi_id,
						DBUS_TYPE_INT32, &hansi_type,
						DBUS_TYPE_INVALID );

	return 0;
}
#endif
void
terminate_appconn(struct app_conn_t *appconn,
				eag_ins_t *eagins, int terminate_cause)
{
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	const char *terminate_cause_str = "";
	int authed_user_num = 0;
	
	if (NULL == appconn || NULL == eagins) {
		eag_log_err("terminate_appconn input error");
		return;
	}

	ip2str(appconn->session.user_ip, user_ipstr, sizeof(user_ipstr));
	mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
	mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
	ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
	ip2str(appconn->portal_srv.ip, portal_ipstr, sizeof(portal_ipstr));
	terminate_cause_str = radius_terminate_cause_to_str(terminate_cause);
	
	if (RADIUS_TERMINATE_CAUSE_USER_REQUEST == terminate_cause
			|| RADIUS_TERMINATE_CAUSE_LOST_CARRIER == terminate_cause) {
		eag_bss_message_count(eagins->eagstat, appconn, BSS_NORMAL_LOGOFF_COUNT, 1);
	} else {
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(eagins->eagstat, appconn, BSS_ABNORMAL_LOGOFF_COUNT, 1);
		} else {
            eag_bss_message_count(eagins->eagstat, appconn, BSS_MACAUTH_ABNORMAL_LOGOFF_COUNT, 1);
		}
		//eag_send_trap_user_logoff_abnormal(appconn, eagins, terminate_cause);
	}

    if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
        eag_bss_message_count(eagins->eagstat, appconn, BSS_USER_CONNECTED_TOTAL_TIME, 
                (appconn->session.session_stop_time - appconn->session.last_connect_ap_time));
    } else {
        eag_bss_message_count(eagins->eagstat, appconn, BSS_MACAUTH_USER_CONNECTED_TOTAL_TIME, 
                (appconn->session.session_stop_time - appconn->session.last_connect_ap_time));
    }

	appconn->session.terminate_cause = terminate_cause;
	if(0 == local_database_switch)
	        radius_acct(eagins->radius, appconn, RADIUS_STATUS_TYPE_STOP);

	if (eag_macauth_get_macauth_switch(eagins->macauth)
		&& appconn->session.wlanid > 0
		&& appconn->portal_srv.mac_server_ip != 0
		&& 1 == notice_to_bindserver)
	{
		eag_portal_ntf_user_logoff(eagins->portal, appconn);
	}
	
	eag_captive_deauthorize(eagins->captive, &(appconn->session));
	admin_log_notice("PortalUserOffline___UserName:%s,UserIP:%s,UserMAC:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,OfflineReason:%s(%d),Onlinetime:%lu",
		appconn->session.username, user_ipstr, user_macstr, ap_macstr, 
		appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, 
		appconn->session.nasid, terminate_cause_str, terminate_cause,
		appconn->session.session_stop_time-appconn->session.session_start_time);
	log_app_filter(appconn,"PortalUserOffline___Username:%s,UserIP:%s,UserMAC:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,OfflineReason:%s(%d),Onlinetime:%lu",
		appconn->session.username, user_ipstr, user_macstr, ap_macstr, 
		appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, 
		appconn->session.nasid, terminate_cause_str, terminate_cause,
		appconn->session.session_stop_time-appconn->session.session_start_time);
	eag_henan_log_notice("PORTAL_USER_LOGOFF:-UserName=%s-IPAddr=%s-IfName=%s-VlanID=%u-MACAddr=%s-Reason=%s"
		"-InputOctets=%u-OutputOctets=%u-InputGigawords=%u-OutputGigawords=%u; User logged off.",
		appconn->session.username, user_ipstr, appconn->session.intf, appconn->session.vlanid, user_macstr, 
		terminate_cause_str,  (uint32_t)(appconn->session.output_octets), (uint32_t)(appconn->session.input_octets), 
		(uint32_t)((appconn->session.output_octets)>>32), (uint32_t)((appconn->session.input_octets)>>32));
	appconn->session.state = APPCONN_STATUS_NONE;
	
	//eag_ins_syn_user(eagins, appconn);
	if ( EAG_AUTH_TYPE_MAC == appconn->session.server_auth_type)
	{
		eag_stamsg_send(eagins->stamsg, &(appconn->session), EAG_MAC_DEL_AUTH);
	}
	else if (EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type)
	{
		eag_stamsg_send(eagins->stamsg, &(appconn->session), EAG_DEL_AUTH);
	}
	if (FLUX_FROM_FASTFWD == eagins->flux_from
		||FLUX_FROM_FASTFWD_IPTABLES == eagins->flux_from)
	{
		eag_log_debug("eag_fastfwd","terminate_appconn fastfwd_send userip:%#x offline",
			appconn->session.user_ip);
		
	}

	if (eag_macauth_get_macauth_switch(eagins->macauth)
		&& appconn->session.wlanid > 0
		&& RADIUS_TERMINATE_CAUSE_LOST_CARRIER != terminate_cause
		&& appconn->portal_srv.mac_server_ip != 0)
	{
		eag_add_mac_preauth(eagins->macauth, appconn->session.user_ip, appconn->session.usermac);
	}
	/* online user count--,add by zhangwl 2012-8-1 */
	authed_user_num = appdb_authed_user_num_decrease(eagins->appdb);
	#if 0
	if (1 == eagins->trap_onlineusernum_switch
		&& authed_user_num == eagins->threshold_onlineusernum)
	{
		int eag_trap=EAG_TRAP_CLEAR;
		int hansi_type = eagins->hansi_type;
		int hansi_id = eagins->hansi_id;
		eag_send_trap_signal(EAG_ONLINE_USER_NUM_THRESHOLD_SIGNAL, 
							DBUS_TYPE_INT32, &eag_trap,
							DBUS_TYPE_INT32, &hansi_type,
							DBUS_TYPE_INT32, &hansi_id,
							DBUS_TYPE_INT32, &eagins->threshold_onlineusernum,
							DBUS_TYPE_INVALID );
		eag_log_info("Eag send OnlineUserNumTrapClear: hansi_type(%d),ins_id(%d),"\
				"authed_user_num(%d),threshold(%d)", hansi_type, hansi_id,
					authed_user_num, eagins->threshold_onlineusernum);
	}
	#endif
	appconn_del_from_db(appconn);
	appconn_del_name_htable(appconn);
	appconn_free(appconn);
}

void
terminate_appconn_nowait(struct app_conn_t *appconn,
				eag_ins_t *eagins, int terminate_cause)
{
	struct timeval tv = {0};
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	const char *terminate_cause_str = "";
	int authed_user_num = 0;

	if (NULL == appconn || NULL == eagins) {
		eag_log_err("terminate_appconn_nowait input error");
		return;
	}

	ip2str(appconn->session.user_ip, user_ipstr, sizeof(user_ipstr));
	mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
	mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
	ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
	ip2str(appconn->portal_srv.ip, portal_ipstr, sizeof(portal_ipstr));
	terminate_cause_str = radius_terminate_cause_to_str(terminate_cause);
	
	eag_time_gettimeofday(&tv, NULL);
	appconn->session.session_stop_time = tv.tv_sec;

	if (RADIUS_TERMINATE_CAUSE_USER_REQUEST == terminate_cause
			|| RADIUS_TERMINATE_CAUSE_LOST_CARRIER == terminate_cause) {
		eag_bss_message_count(eagins->eagstat, appconn, BSS_NORMAL_LOGOFF_COUNT, 1);
	} else {
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(eagins->eagstat, appconn, BSS_ABNORMAL_LOGOFF_COUNT, 1);
		} else {
            eag_bss_message_count(eagins->eagstat, appconn, BSS_MACAUTH_ABNORMAL_LOGOFF_COUNT, 1);
		}
		//eag_send_trap_user_logoff_abnormal(appconn, eagins, terminate_cause);
	}
	
    if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
        eag_bss_message_count(eagins->eagstat, appconn, BSS_USER_CONNECTED_TOTAL_TIME, 
                (appconn->session.session_stop_time - appconn->session.last_connect_ap_time));
    } else {
        eag_bss_message_count(eagins->eagstat, appconn, BSS_MACAUTH_USER_CONNECTED_TOTAL_TIME, 
                (appconn->session.session_stop_time - appconn->session.last_connect_ap_time));
    }

	eag_portal_notify_logout_nowait(eagins->portal, appconn);
	
	appconn->session.terminate_cause = terminate_cause;
	if( 0 == local_database_switch)
	        radius_acct_nowait(eagins->radius, appconn, RADIUS_STATUS_TYPE_STOP);

	if (eag_macauth_get_macauth_switch(eagins->macauth)
		&& appconn->session.wlanid > 0
		&& appconn->portal_srv.mac_server_ip != 0
		&& 1 == notice_to_bindserver)
	{
		eag_portal_ntf_user_logoff(eagins->portal, appconn);
	}
	
	eag_captive_deauthorize(eagins->captive, &(appconn->session));
	admin_log_notice("PortalUserOffline___UserName:%s,UserIP:%s,UserMAC:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,OfflineReason:%s(%d),Onlinetime:%lu",
		appconn->session.username, user_ipstr, user_macstr, ap_macstr, 
		appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, 
		appconn->session.nasid, terminate_cause_str, terminate_cause,
		appconn->session.session_stop_time-appconn->session.session_start_time);
	log_app_filter(appconn,"PortalUserOffline___Username:%s,UserIP:%s,UserMAC:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,OfflineReason:%s(%d),Onlinetime:%lu",
		appconn->session.username, user_ipstr, user_macstr, ap_macstr, 
		appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, 
		appconn->session.nasid, terminate_cause_str, terminate_cause,
		appconn->session.session_stop_time-appconn->session.session_start_time);
	eag_henan_log_notice("PORTAL_USER_LOGOFF:-UserName=%s-IPAddr=%s-IfName=%s-VlanID=%u-MACAddr=%s-Reason=%s"
		"-InputOctets=%u-OutputOctets=%u-InputGigawords=%u-OutputGigawords=%u; User logged off.",
		appconn->session.username, user_ipstr, appconn->session.intf, appconn->session.vlanid, user_macstr, 
		terminate_cause_str,  (uint32_t)(appconn->session.output_octets), (uint32_t)(appconn->session.input_octets), 
		(uint32_t)((appconn->session.output_octets)>>32), (uint32_t)((appconn->session.input_octets)>>32));
	appconn->session.state = APPCONN_STATUS_NONE;
	
	//eag_ins_syn_user(eagins, appconn);
	
	if (EAG_AUTH_TYPE_MAC == appconn->session.server_auth_type)
	{
		eag_stamsg_send(eagins->stamsg, &(appconn->session), EAG_MAC_DEL_AUTH);
	}
	else if (EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type)
	{
		eag_stamsg_send(eagins->stamsg, &(appconn->session), EAG_DEL_AUTH);
	}
	if (FLUX_FROM_FASTFWD == eagins->flux_from
		||FLUX_FROM_FASTFWD_IPTABLES == eagins->flux_from)
	{
		eag_log_info("terminate_appconn_nowait fastfwd_send userip:%#x offline",
			appconn->session.user_ip);
		
	}
	
	/* online user count--,add by zhangwl 2012-8-1 */
	authed_user_num = appdb_authed_user_num_decrease(eagins->appdb);
	#if 0
	if (1 == eagins->trap_onlineusernum_switch
		&&authed_user_num == eagins->threshold_onlineusernum)
	{
		int eag_trap=EAG_TRAP_CLEAR;
		int hansi_type = eagins->hansi_type;
		int hansi_id = eagins->hansi_id;
		eag_send_trap_signal(EAG_ONLINE_USER_NUM_THRESHOLD_SIGNAL, 
							DBUS_TYPE_INT32, &eag_trap,
							DBUS_TYPE_INT32, &hansi_type,
							DBUS_TYPE_INT32, &hansi_id,
							DBUS_TYPE_INT32, &eagins->threshold_onlineusernum,
							DBUS_TYPE_INVALID );
		eag_log_info("Eag send OnlineUserNumTrapClear: hansi_type(%d),ins_id(%d),"\
				"authed_user_num(%d),threshold(%d)", hansi_type, hansi_id,
					authed_user_num, eagins->threshold_onlineusernum);
	}
	#endif
	appconn_del_from_db(appconn);
	appconn_del_name_htable(appconn);
	appconn_free(appconn);
}

static void
terminate_appconn_without_ntf(struct app_conn_t *appconn,
						eag_ins_t *eagins)
{

	if (NULL == appconn || NULL == eagins) {
		eag_log_err("terminate_appconn_without_ntf input error");
		return;
	}

	eag_captive_deauthorize(eagins->captive, &(appconn->session));
	
	eag_stamsg_send(eagins->stamsg, &(appconn->session), EAG_DEL_AUTH);
	
	if ((FLUX_FROM_FASTFWD == eagins->flux_from)
		||FLUX_FROM_FASTFWD_IPTABLES == eagins->flux_from)
	{
		eag_log_info("terminate_appconn_without_ntf fastfwd_send userip:%#x offline",
			appconn->session.user_ip);
	
	}
	
	/* online user count--,add by zhangwl 2012-8-1 */
	appdb_authed_user_num_decrease(eagins->appdb);

	appconn_del_from_db(appconn);
	appconn_del_name_htable(appconn);
	appconn_free(appconn);
}

/* for vrrp change from disable to master */
static void
terminate_appconn_without_backup(struct app_conn_t *appconn,
				eag_ins_t *eagins, int terminate_cause)
{
	struct timeval tv = {0};
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	const char *terminate_cause_str = "";
	int authed_user_num = 0;

	if (NULL == appconn || NULL == eagins) {
		eag_log_err("terminate_appconn_without_backup input error");
		return;
	}

	ip2str(appconn->session.user_ip, user_ipstr, sizeof(user_ipstr));
	mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
	mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
	ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
	ip2str(appconn->portal_srv.ip, portal_ipstr, sizeof(portal_ipstr));
	terminate_cause_str = radius_terminate_cause_to_str(terminate_cause);
	
	eag_time_gettimeofday(&tv, NULL);
	appconn->session.session_stop_time = tv.tv_sec;	

	if (RADIUS_TERMINATE_CAUSE_USER_REQUEST == terminate_cause
			|| RADIUS_TERMINATE_CAUSE_LOST_CARRIER == terminate_cause) {
		eag_bss_message_count(eagins->eagstat, appconn, BSS_NORMAL_LOGOFF_COUNT, 1);
	} else {
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(eagins->eagstat, appconn, BSS_ABNORMAL_LOGOFF_COUNT, 1);
		} else {
            eag_bss_message_count(eagins->eagstat, appconn, BSS_MACAUTH_ABNORMAL_LOGOFF_COUNT, 1);
		}
		//eag_send_trap_user_logoff_abnormal(appconn, eagins, terminate_cause);
	}

    if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
        eag_bss_message_count(eagins->eagstat, appconn, BSS_USER_CONNECTED_TOTAL_TIME, 
                (appconn->session.session_stop_time - appconn->session.last_connect_ap_time));
    } else {
        eag_bss_message_count(eagins->eagstat, appconn, BSS_MACAUTH_USER_CONNECTED_TOTAL_TIME, 
                (appconn->session.session_stop_time - appconn->session.last_connect_ap_time));
    }
	
	eag_portal_notify_logout_nowait(eagins->portal, appconn);
	
	appconn->session.terminate_cause = terminate_cause;
	radius_acct_nowait(eagins->radius, appconn, RADIUS_STATUS_TYPE_STOP);

	if (eag_macauth_get_macauth_switch(eagins->macauth)
		&& appconn->session.wlanid > 0
		&& appconn->portal_srv.mac_server_ip != 0
		&& 1 == notice_to_bindserver)
	{
		eag_portal_ntf_user_logoff(eagins->portal, appconn);
	}
	
	eag_captive_deauthorize(eagins->captive, &(appconn->session));
	admin_log_notice("PortalUserOffline___UserName:%s,UserIP:%s,UserMAC:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,OfflineReason:%s(%d),Onlinetime:%lu",
		appconn->session.username, user_ipstr, user_macstr, ap_macstr, 
		appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, 
		appconn->session.nasid, terminate_cause_str, terminate_cause,
		appconn->session.session_stop_time-appconn->session.session_start_time);
	log_app_filter(appconn,"PortalUserOffline___Username:%s,UserIP:%s,UserMAC:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,OfflineReason:%s(%d),Onlinetime:%lu",
		appconn->session.username, user_ipstr, user_macstr, ap_macstr, 
		appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, 
		appconn->session.nasid, terminate_cause_str, terminate_cause,
		appconn->session.session_stop_time-appconn->session.session_start_time);
	eag_henan_log_notice("PORTAL_USER_LOGOFF:-UserName=%s-IPAddr=%s-IfName=%s-VlanID=%u-MACAddr=%s-Reason=%s"
		"-InputOctets=%u-OutputOctets=%u-InputGigawords=%u-OutputGigawords=%u; User logged off.",
		appconn->session.username, user_ipstr, appconn->session.intf, appconn->session.vlanid, user_macstr, 
		terminate_cause_str,  (uint32_t)(appconn->session.output_octets), (uint32_t)(appconn->session.input_octets), 
		(uint32_t)((appconn->session.output_octets)>>32), (uint32_t)((appconn->session.input_octets)>>32));
	appconn->session.state = APPCONN_STATUS_NONE;
	
	if (EAG_AUTH_TYPE_MAC == appconn->session.server_auth_type)
	{
		eag_stamsg_send(eagins->stamsg, &(appconn->session), EAG_MAC_DEL_AUTH);
	}
	else if ( EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type)
	{
		eag_stamsg_send(eagins->stamsg, &(appconn->session), EAG_DEL_AUTH);
	}
	if ((FLUX_FROM_FASTFWD == eagins->flux_from)
		||FLUX_FROM_FASTFWD_IPTABLES == eagins->flux_from)
	{
		eag_log_info("terminate_appconn_without_backup fastfwd_send userip:%#x offline",
			appconn->session.user_ip);

	}

	/* online user count--,add by zhangwl 2012-8-1 */
	authed_user_num = appdb_authed_user_num_decrease(eagins->appdb);
	#if 0
	if (1 == eagins->trap_onlineusernum_switch
		&&authed_user_num == eagins->threshold_onlineusernum)
	{
		int eag_trap=EAG_TRAP_CLEAR;
		int hansi_type = eagins->hansi_type;
		int hansi_id = eagins->hansi_id;
		eag_send_trap_signal(EAG_ONLINE_USER_NUM_THRESHOLD_SIGNAL, 
							DBUS_TYPE_INT32, &eag_trap,
							DBUS_TYPE_INT32, &hansi_type,
							DBUS_TYPE_INT32, &hansi_id,
							DBUS_TYPE_INT32, &eagins->threshold_onlineusernum,
							DBUS_TYPE_INVALID );
		eag_log_info("Eag send OnlineUserNumTrapClear: hansi_type(%d),ins_id(%d),"\
				"authed_user_num(%d),threshold(%d)", hansi_type, hansi_id,
					authed_user_num, eagins->threshold_onlineusernum);
	}
	#endif
	appconn_del_from_db(appconn);
	appconn_del_name_htable(appconn);
	appconn_free(appconn);
}

static void
terminate_appconn_all(eag_ins_t *eagins)
{
	struct app_conn_t *appconn = NULL;
	struct app_conn_t *next = NULL;
	struct list_head *head = NULL;

	head = appconn_db_get_head(eagins->appdb);
	list_for_each_entry_safe(appconn, next, head, node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			terminate_appconn_nowait(appconn, eagins,
						RADIUS_TERMINATE_CAUSE_ADMIN_REBOOT);
		} else {
			appconn_del_from_db(appconn);
			appconn_free(appconn);
		}
	}
}

static void
terminate_appconn_all_without_ntf(eag_ins_t *eagins)
{
	struct app_conn_t *appconn = NULL;
	struct app_conn_t *next = NULL;
	struct list_head *head = NULL;

	head = appconn_db_get_head(eagins->appdb);
	list_for_each_entry_safe(appconn, next, head, node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			terminate_appconn_without_ntf(appconn, eagins);
		} else {
			appconn_del_from_db(appconn);
			appconn_free(appconn);
		}
	}
}

static void
terminate_appconn_all_without_backup(eag_ins_t *eagins)
{
	struct app_conn_t *appconn = NULL;
	struct app_conn_t *next = NULL;
	struct list_head *head = NULL;

	head = appconn_db_get_head(eagins->appdb);
	list_for_each_entry_safe(appconn, next, head, node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			terminate_appconn_without_backup( appconn, eagins,
					RADIUS_TERMINATE_CAUSE_ADMIN_REBOOT);
		} else {
			appconn_del_from_db(appconn);
			appconn_free(appconn);
		}
	}
}

static void
terminate_appconn_by_interface(eag_ins_t *eagins,
						const char *captive_interface)
{
	struct app_conn_t *appconn = NULL;
	struct app_conn_t *next = NULL;
	struct list_head *head = NULL;

	if (NULL == captive_interface || NULL == eagins) {
		eag_log_err("terminate_appconn_by_interface input error");
		return;
	}
	eag_log_info("terminate_appconn_by_interface %s", captive_interface);
	
	head = appconn_db_get_head(eagins->appdb);
	list_for_each_entry_safe(appconn, next, head, node) {
		if (0 == strcmp(appconn->session.intf, captive_interface)) {
			terminate_appconn_nowait(appconn, eagins,
						RADIUS_TERMINATE_CAUSE_ADMIN_REBOOT);
		}
	}
}
#if 0
static int 
master_backup_all_user_data(eag_hansi_t *eag_hansi, void *cbp)
{
	struct app_conn_t *appconn = NULL;
	eag_ins_t *eagins = (eag_ins_t *)cbp;
	struct list_head *head = NULL;
#if 0
	eag_hansi_syn_time(eagins->eaghansi);
#endif
	head = appconn_db_get_head(eagins->appdb);
	list_for_each_entry(appconn, head, node){
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			eag_ins_syn_user(eagins, appconn);
		}
	}

	eag_ins_syn_finish_flag(eagins);
	
	eag_log_info("master_backup_all_user_data on master_accept ok");

	return EAG_RETURN_OK;
}

static int 
backup_clean_all_user_data(eag_hansi_t *eag_hansi, void *cbp)
{
	eag_ins_t *eagins = (eag_ins_t *)cbp;

	terminate_appconn_all_without_ntf(eagins);
	eag_statistics_clear(eagins->eagstat);

	eag_log_info("backup_clean_all_user_data on backup_connect ok");

	return EAG_RETURN_OK;
}
#endif
static void
flush_all_appconn_last_flux_time(eag_ins_t *eagins)
{
	struct app_conn_t *appconn = NULL;
	struct list_head *head = NULL;
	struct timeval tv = {0};

	eag_time_gettimeofday(&tv, NULL);
	head = appconn_db_get_head(eagins->appdb);
	list_for_each_entry(appconn, head, node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			appconn->session.last_flux_time = tv.tv_sec;
		}
	}
}
#if 0
static int
eag_vrrp_status_switch_proc(eag_hansi_t *eag_hansi, void *cbp)
{
	int ret = 0;
	eag_ins_t *eagins = (eag_ins_t*)cbp;

	if (1 != eagins->status) {
		eag_log_info("eag_vrrp_status_switch_proc service not start");
		return EAG_RETURN_OK;
	}
	/*
	* master : 3
	* back : 1,2,4,5,6
	* disable : 99
	* TN:terminate_appconn_all_without_ntf
	* T:terminate_appconn_all_without_backup
	* C : eag_statistics_clear
	* X : do nothing
	* master->back : 		TN, C  
	* master->disable : 	TN, C
	* back->master : 		X,X
	* back->back : 		TN,C
	* back->disable : 		TN,C
	* disable->master :	 T, C
	* disable->back :		 T, C
	*/
	eag_redir_stop(eagins->redir);
	eag_coa_stop(eagins->coa);
	if (eag_macauth_get_macauth_switch(eagins->macauth)) {
		eag_macauth_stop(eagins->macauth);
	}
	if (!eag_hansi_prev_is_enable(eagins->eaghansi)) {
		terminate_appconn_all_without_backup(eagins);
	}
	else if (!eag_hansi_is_master(eagins->eaghansi)) {
		terminate_appconn_all_without_ntf(eagins);
	}
	eag_portal_stop(eagins->portal);
	eag_radius_stop(eagins->radius);
	eag_statistics_clear(eagins->eagstat);
	eag_arp_stop(eagins->arp);
	
	if( eag_hansi_is_master(eagins->eaghansi)) {
		flush_all_appconn_last_flux_time(eagins);
		if ( (ret = eag_redir_start(eagins->redir)) != 0) {
			goto failed_0;
		}
		if ( (ret = eag_portal_start(eagins->portal)) != 0) {
			goto failed_1;
		}
		if ( (ret = eag_radius_start(eagins->radius)) != 0) {
			goto failed_2; 
		}
		if ( (ret = eag_coa_start(eagins->coa)) != 0) {
			goto failed_3; 
		}
		if ( (ret = eag_arp_start(eagins->arp)) != 0) {
			goto failed_4; 
		}
		if (eag_macauth_get_macauth_switch(eagins->macauth)) {
			if ((ret = eag_macauth_start(eagins->macauth)) != 0) {
				goto failed_5;
			}
		}
	}
	return 0;
failed_5:
	eag_arp_stop(eagins->arp);
failed_4:
	eag_coa_stop(eagins->coa);
failed_3:
	eag_radius_stop(eagins->radius);
failed_2:
	eag_portal_stop(eagins->portal);
failed_1:
	eag_redir_stop(eagins->redir);
failed_0:
	return ret;
}
#endif
struct cli_parameter
{
	int argc;
	char *argv[10];
};
extern struct eag_ins *eagins;
struct cli_parameter * eag_cli_get_parameter(char *buf)
{
        char * token= NULL;
	int i = 0;
        struct cli_parameter *parameter= NULL;
	if(buf == NULL)
		return NULL;
        parameter = (struct cli_parameter *)malloc(sizeof(struct cli_parameter ));
	if(parameter == NULL)
		return NULL;
	printf("%s,%d\n",__func__,__LINE__);

	printf("%s,%d,%s\n",__func__,__LINE__,buf);
	for (token = strtok(buf, " "); token; token = strtok(NULL, " ")) 
	{
		parameter->argv[i] = token;
		printf("%s\n",token);
		i++;
	}
         parameter->argc = i;
	return parameter;
}
int  eag_method_conf_captive_list(char *white_or_black,char *add_or_del ,char *iprange)
{
	eag_captive_t *captive = NULL;
	char *port ="all";
 	char intfs[16] = {0};
	uint32_t tag = 0;
	char *domain = NULL;
 	int ret = -1, type = 0;
	char ipbegin[128] = {0};
	char ipend[128] = {0};
	char *ip_tmp = NULL;
	struct in_addr ipaddr_begin;
	struct in_addr ipaddr_end;
	memset(&ipaddr_begin, 0, sizeof(ipaddr_begin));
	memset(&ipaddr_end, 0, sizeof(ipaddr_end));
	type = RULE_IPADDR;

 	captive = (eag_captive_t *)eagins->captive;
	if( NULL == captive){
            	eag_log_err("eag_method_conf_captive_list user_data error!");

            	ret = EAG_ERR_UNKNOWN;
            	return ret;
	}
		 
	if((NULL != iprange) && (0 != strcmp(iprange,"")))
	{
		ip_tmp = strtok(iprange, "-");
		if(ip_tmp!=NULL)
		{
			strncpy(ipbegin, ip_tmp, sizeof(ipbegin)-1);
		}
		ip_tmp = strtok(NULL, "-");
		if(ip_tmp!=NULL)
		{
			strncpy(ipend, ip_tmp, sizeof(ipend)-1);
		}
	}

	if(strcmp(white_or_black, CP_WHITE_LIST) == 0)
	{	

		if( (add_or_del!=NULL) && (0 == strcmp(add_or_del, CP_ADD_LIST)))
		{		

			inet_aton(ipbegin, &ipaddr_begin);
			inet_aton(ipend, &ipaddr_end);
			ret = eag_captive_add_white_list(captive, (RULE_TYPE)type, ipaddr_begin.s_addr,ipaddr_end.s_addr,port,domain,intfs,tag);
		}
		else if( (add_or_del!=NULL) && (0 == strcmp(add_or_del, CP_DEL_LIST)))
		{
			inet_aton(ipbegin, &ipaddr_begin);
			inet_aton(ipend, &ipaddr_end);
			ret = eag_captive_del_white_list(captive, type, ipaddr_begin.s_addr,ipaddr_end.s_addr,port,domain,intfs,tag);
		}
	}
	else if(strcmp(white_or_black, CP_BLACK_LIST) == 0)
	{
		if( (add_or_del!=NULL) && (0 == strcmp(add_or_del, CP_ADD_LIST)))
		{
			inet_aton(ipbegin, &ipaddr_begin);
			inet_aton(ipend, &ipaddr_end);
			ret = eag_captive_add_black_list(captive, (RULE_TYPE)type, ipaddr_begin.s_addr,ipaddr_end.s_addr,port,domain,intfs,tag);
		}
		else if( (add_or_del!=NULL) && (0 == strcmp(add_or_del, CP_DEL_LIST)))
		{		
			inet_aton(ipbegin, &ipaddr_begin);
			inet_aton(ipend, &ipaddr_end);
			ret = eag_captive_del_black_list(captive, type, ipaddr_begin.s_addr,ipaddr_end.s_addr,port,domain,intfs,tag);
		}
	}
	 
	return 0;
}


int eag_cli_send(int sockfd,char *buf)
{		
	struct sockaddr_un sock_address;
	socklen_t  address_len=0;

	sock_address.sun_family = AF_UNIX;
	strcpy(sock_address.sun_path,CLI_PATH);
	address_len = sizeof(sock_address);
	if (sendto(sockfd, buf, strlen(buf), 0,(struct sockaddr *)&sock_address,address_len) < 0) {
		printf("%s,%d,%s\n",__func__,__LINE__,safe_strerror(errno));
		return NULL;
	}
}

int eag_cli_cmd_add_portal_server(int sockfd,char* cmd)
{
	  struct cli_parameter *parameter= NULL;
	  unsigned int keytype = 0;
	 // char *keyid = NULL;
	char *keystr = NULL;
	char *portal_url = NULL;
	unsigned int ntfport = 0;
	char *domain = NULL;
	uint32_t mac_server_ip = 0;
	uint16_t mac_server_port = 0;
	int ret = -1;
	char str[1024]={0};

	if (cmd == NULL) {
		printf(" the cmd is NULL.\n");
		return -1;
	}
	
	parameter = eag_cli_get_parameter(cmd);
	if(parameter == NULL)
		return -1;
	if (parameter ->argc != 3)
	{
		eag_cli_send(sockfd,"input parameters erro");
		free(parameter);
		return ret;
	}
    	keytype = PORTAL_KEYTYPE_ESSID;
	keystr = parameter->argv[0];
	portal_url = parameter->argv[1];
	ntfport =  atoi(parameter->argv[2]);
	if( NULL != portal_srv_get_by_key(&(eagins->portalconf),keytype,keystr) ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			eag_cli_send(sockfd,"the key exist");
			free(parameter);
			return ret;
	}			
	ret = portal_conf_add_srv( &(eagins->portalconf),
						keytype,keystr,portal_url,ntfport,domain,
						mac_server_ip, mac_server_port);
	if (ret ==0)
	{
	    
	       eag_cli_send(sockfd,"the command sucsessful");
	}
	else
	{
                sprintf(str,"error  num =  %d\n",ret);
	     eag_cli_send(sockfd,str);
	}
	
	free(parameter);
	printf("%s,%d\n",__func__,__LINE__);
	return 0;
}

int eag_cli_cmd_del_portal_server(int sockfd,char* cmd)
{
	  struct cli_parameter *parameter= NULL;
	  unsigned int keytype = 0;
	 // char *keyid = NULL;
	char *keystr = NULL;
	char *portal_url = NULL;
	unsigned int ntfport = 0;
	char *domain = NULL;
	uint32_t mac_server_ip = 0;
	uint16_t mac_server_port = 0;
	int ret = -1;
	char str[1024]={0};

	if (cmd == NULL) {
		printf(" the cmd is NULL.\n");
		return -1;
	}
	
	parameter = eag_cli_get_parameter(cmd);
	if(parameter == NULL)
		return -1;
	if (parameter ->argc != 1)
	{
		eag_cli_send(sockfd,"input parameters erro");
		free(parameter);
		return ret;
	}
    	keytype = PORTAL_KEYTYPE_ESSID;
	keystr = parameter->argv[0];
	if( NULL == portal_srv_get_by_key(&(eagins->portalconf),keytype,keystr) ){
			ret = EAG_ERR_PORTAL_DEL_SRV_NOT_EXIST;
			eag_cli_send(sockfd,"the key not exist");
			free(parameter);
			return ret;
	}			
	ret = portal_conf_del_srv( &(eagins->portalconf),
						keytype,keystr);
	if (ret ==0)
	{
	    
	       eag_cli_send(sockfd,"the command sucsessful");
	}
	else
	{
                sprintf(str,"error  num =  %d\n",ret);
	     eag_cli_send(sockfd,str);
	}
	
	free(parameter);
	printf("%s,%d\n",__func__,__LINE__);
	return 0;
}


int eag_cli_cmd_modify_portal_server(int sockfd,char* cmd)
{
	  struct cli_parameter *parameter= NULL;
	  unsigned int keytype = 0;
	 // char *keyid = NULL;
	char *keystr = NULL;
	char *portal_url = NULL;
	unsigned int ntfport = 0;
	char *domain = NULL;
	uint32_t mac_server_ip = 0;
	uint16_t mac_server_port = 0;
	int ret = -1;
	char str[1024]={0};

	if (cmd == NULL) {
		printf(" the cmd is NULL.\n");
		return -1;
	}
	
	parameter = eag_cli_get_parameter(cmd);
	if(parameter == NULL)
		return -1;
	if (parameter ->argc != 3)
	{
		eag_cli_send(sockfd,"input parameters erro");
		free(parameter);
		return ret;
	}
    	keytype = PORTAL_KEYTYPE_ESSID;
	keystr = parameter->argv[0];
	portal_url = parameter->argv[1];
	ntfport =  atoi(parameter->argv[2]);
	if( NULL == portal_srv_get_by_key(&(eagins->portalconf),keytype,keystr) ){
			ret = EAG_ERR_PORTAL_ADD_SRV_KEY_EXIST;
			eag_cli_send(sockfd,"the key not exist");
			free(parameter);
			return ret;
	}			
	ret = portal_conf_modify_srv( &(eagins->portalconf),
						keytype,keystr,portal_url,ntfport,domain,
						mac_server_ip, mac_server_port);
	if (ret ==0)
	{
	    
	       eag_cli_send(sockfd,"the command sucsessful");
	}
	else
	{
                sprintf(str,"error  num =  %d\n",ret);
	     eag_cli_send(sockfd,str);
	}
	
	free(parameter);
	printf("%s,%d\n",__func__,__LINE__);
	return 0;
}


 int eag_cli_cmd_add_captive_interface( int sockfd,char* cmd)
{
	char *token;
          struct cli_parameter *parameter= NULL;
	int ret = -1;
	char str[1024]={0};
	if (cmd == NULL) {
		printf("  the cmd is NULL.\n");
		return -1;
	}
            parameter = eag_cli_get_parameter(cmd);
	if(parameter == NULL)
		return -1;
	if (parameter ->argc != 1)
	{
		eag_cli_send(sockfd,"input parameters erro");
		free(parameter);
		return ret;
	}
	ret = eag_captive_add_interface( eagins->captive, parameter->argv[0]);
	if (ret ==0)
	{
	    
	       eag_cli_send(sockfd,"the command sucsessful");
	}
	else
	{
                sprintf(str,"error  num =  %d\n",ret);
	     eag_cli_send(sockfd,str);
	}
	
        	free(parameter);
	printf("%s,%d\n",__func__,__LINE__);
	return 0;
}

  int eag_cli_cmd_del_captive_interface( int sockfd,char* cmd)
{
	char *token;
          struct cli_parameter *parameter= NULL;
	int ret = -1;
	char str[1024]={0};
	if (cmd == NULL) {
		printf("  the cmd is NULL.\n");
		return -1;
	}
            parameter = eag_cli_get_parameter(cmd);
	if(parameter == NULL)
		return -1;
	if (parameter ->argc != 1)
	{
		eag_cli_send(sockfd,"input parameters erro");
		free(parameter);
		return ret;
	}
	ret = eag_captive_del_interface( eagins->captive, parameter->argv[0]);
	terminate_appconn_by_interface(eagins, parameter->argv[0]);
	if (ret ==0)
	{
	    
	       eag_cli_send(sockfd,"the command sucsessful");
	}
	else
	{
                sprintf(str,"error  num =  %d\n",ret);
	     eag_cli_send(sockfd,str);
	}
	
        	free(parameter);
	printf("%s,%d\n",__func__,__LINE__);
	return 0;
}


  int eag_cli_cmd_set_nasip( int sockfd,char* cmd)
{
	char *token;
          struct cli_parameter *parameter= NULL;
	int ret = -1;
	char str[1024]={0};
	struct in_addr inaddr;
	if (cmd == NULL) {
		printf("  the cmd is NULL.\n");
		return -1;
	}
            parameter = eag_cli_get_parameter(cmd);
	if(parameter == NULL)
		return -1;
	if (parameter ->argc != 1)
	{
		eag_cli_send(sockfd,"input parameters erro");
		free(parameter);
		return ret;
	}
	ret = inet_aton(parameter->argv[0],&inaddr);
	if (!ret) {
            printf( "%% invalid ip address\n");
            return ret;
	}
	ret = eag_ins_set_nasip(eagins, inaddr.s_addr);
	if (ret ==0)
	{
	    
	       eag_cli_send(sockfd,"the command sucsessful");
	}
	else
	{
                sprintf(str,"error  num =  %d\n",ret);
	     eag_cli_send(sockfd,str);
	}
	
        	free(parameter);
	printf("%s,%d\n",__func__,__LINE__);
	return 0;
}

  int eag_cli_cmd_service_status( int sockfd,char* cmd)
{
	char *token;
          struct cli_parameter *parameter= NULL;
	int ret = -1;
	char str[1024]={0};
	if (cmd == NULL) {
		printf("  the cmd is NULL.\n");
		return -1;
	}
            parameter = eag_cli_get_parameter(cmd);
	if(parameter == NULL)
		return -1;
	if (parameter ->argc != 1)
	{
		eag_cli_send(sockfd,"input parameters erro");
		free(parameter);
		return ret;
	}
	if(!strcmp(parameter->argv[0],"enable"))
                    ret = eag_ins_start(eagins);
	else if (!strcmp(parameter->argv[0],"disable"))
		ret = eag_ins_stop(eagins);

		
	if (ret ==0)
	{
	    
	       eag_cli_send(sockfd,"the command sucsessful");
	}
	else
	{
                sprintf(str,"error  num =  %d\n",ret);
	     eag_cli_send(sockfd,str);
	}
	
        	free(parameter);
	printf("%s,%d\n",__func__,__LINE__);
	return 0;
}

int eag_cli_set_local_database_switch(int sockfd,char *cmd)
{
	char *token;
          struct cli_parameter *parameter= NULL;
	int ret = 0;
	char str[1024]={0};
	if (cmd == NULL) {
		printf("  the cmd is NULL.\n");
		return -1;
	}
            parameter = eag_cli_get_parameter(cmd);
	if(parameter == NULL)
		return -1;
	if (parameter ->argc != 1)
	{
		eag_cli_send(sockfd,"input parameters erro");
		free(parameter);
		return ret;
	}
	if(!strcmp(parameter->argv[0],"enable"))
                 local_database_switch = 1;
	else if (!strcmp(parameter->argv[0],"disable"))
		local_database_switch = 0;
    	       eag_cli_send(sockfd,"the command sucsessful");
	
        	free(parameter);
	printf("%s,%d\n",__func__,__LINE__);
	return 0;
}
  int eag_cli_cmd_add_white_list( int sockfd,char* cmd)
{
	char *token;
          struct cli_parameter *parameter= NULL;
	int ret = -1;
	char str[1024]={0};
	if (cmd == NULL) {
		printf("  the cmd is NULL.\n");
		return -1;
	}
            parameter = eag_cli_get_parameter(cmd);
	if(parameter == NULL)
		return -1;
	if (parameter ->argc != 1)
	{
		eag_cli_send(sockfd,"input parameters erro");
		free(parameter);
		return ret;
	}
	printf("add: %s\n",parameter->argv[0]);
	ret = eag_method_conf_captive_list(CP_WHITE_LIST,CP_ADD_LIST,parameter->argv[0]);
	if (ret ==0)
	{
	    
	       eag_cli_send(sockfd,"the command sucsessful");
	}
	else
	{
                sprintf(str,"error  num =  %d\n",ret);
	     eag_cli_send(sockfd,str);
	}
	
        	free(parameter);
	printf("%s,%d\n",__func__,__LINE__);
	return 0;
}
    int eag_cli_cmd_delete_white_list( int sockfd,char* cmd)
{
	char *token;
          struct cli_parameter *parameter= NULL;
	int ret = -1;
	char str[1024]={0};
	if (cmd == NULL) {
		printf("  the cmd is NULL.\n");
		return -1;
	}
            parameter = eag_cli_get_parameter(cmd);
	if(parameter == NULL)
		return -1;
	if (parameter ->argc != 1)
	{
		eag_cli_send(sockfd,"input parameters erro");
		free(parameter);
		return ret;
	}
       	ret = eag_method_conf_captive_list(CP_WHITE_LIST,CP_DEL_LIST,parameter->argv[0]);
	if (ret ==0)
	{
	    
	       eag_cli_send(sockfd,"the command sucsessful");
	}
	else
	{
                sprintf(str,"error  num =  %d\n",ret);
	     eag_cli_send(sockfd,str);
	}
	
        	free(parameter);
	printf("%s,%d\n",__func__,__LINE__);
	return 0;
}


struct user_list
{
   // unsigned int num;
    uint32_t index;
	uint32_t user_ip;
	uint8_t usermac[PKT_ETH_ALEN];
	//char essid[MAX_ESSID_LENGTH];
	//char intf[MAX_IF_NAME_LEN];
	char username[USERNAMESIZE];
	uint32_t session_time;
	//char passwd[USERNAMESIZE];
	//uint8_t challenge[PORTAL_CHALLEN];
	//uint16_t chapid;
	//uint8_t chappasswd[PORTAL_CHALLEN];
	//char sessionid[MAX_SESSION_ID_LEN];
	//char nasid[RADIUS_MAX_NASID_LEN];
	//char nas_port_id[MAX_NASPORTID_LEN];
	uint64_t input_octets;
	//uint32_t input_packets;
	uint64_t output_octets;
	//uint32_t output_packets;

};

int show_usr_list(int sockfd)
{
	int ret =0;
	unsigned int num = 0;
	appconn_db_t *appdb = NULL;
	struct app_conn_t *appconn = NULL;
	struct list_head *head = NULL;
	char buf[4096] = {0};
	//char test[5]={0};
	struct timeval tv = {0};
	struct user_list user = {0};
	struct sockaddr_un sock_address;
	socklen_t  address_len=0;

	sock_address.sun_family = AF_UNIX;
	strcpy(sock_address.sun_path,CLI_PATH);
	address_len = sizeof(sock_address);

            appdb = (appconn_db_t *)eagins->appdb;
             if (NULL == appdb)
             {
                    eag_log_err("eag_dbus_method_show_user_all user_data error!");
                      ret = EAG_ERR_UNKNOWN;
		    return ret;
               }
	

	eag_time_gettimeofday(&tv, NULL);
            flush_all_appconn_flux_immediate(appdb);
           head = appconn_db_get_head(appdb);
	num = appconn_count_authed(appdb);
          sprintf(buf,"%d",num);
	//memcpy(buf,(char *)test,sizeof(num));
	eag_cli_send(sockfd,buf);
	
	list_for_each_entry(appconn, head, node)
	{

	  user.index= appconn->session.index;
             user.user_ip = appconn->session.user_ip;
	// strcpy(user.essid,appconn->session.essid);

	      memcpy(user.usermac,appconn->session.usermac,PKT_ETH_ALEN);
                strcpy(user.username,appconn->session.username);
	      user.session_time = tv.tv_sec - appconn->session.session_start_time;
                user.input_octets= appconn->session.input_octets;
	     user.output_octets= appconn->session.output_octets;

	
	    if (sendto(sockfd, &user, sizeof(user), 0,(struct sockaddr *)&sock_address,address_len) < 0) {
		printf("%s,%d,%s\n",__func__,__LINE__,safe_strerror(errno));
		return NULL;
	    }
		
	}
           

	return ret;

}

 int eag_cli_cmd_show(int sockfd,char *cmd)
{
	 struct cli_parameter *parameter= NULL;
	int ret = -1;
	char str[1024]={0};
	if (cmd == NULL) {
		printf("  the cmd is NULL.\n");
		return -1;
	}
            parameter = eag_cli_get_parameter(cmd);
	if(parameter == NULL)
		return -1;

	if((0 == strcmp(parameter->argv[0],"list")) || (0 == strcmp(parameter->argv[0],"list")))
	{

                ret = show_usr_list(sockfd);
	}
	else if(0 == strcmp(parameter->argv[0],"ip"))
	{
		

	}
	else if (0 == strcmp(parameter->argv[0],"index"))
	{
	}
	else if (0 == strcmp(parameter->argv[0],"mac"))
	{
	}
	else if(0 == strcmp(parameter->argv[0],"username"))
	{
	}

        	free(parameter);
	return 0;
}


struct eag_cli_cmd {
	const char *cmd;
	int (*handler)(int sockfd,char *cmd);
};

static struct eag_cli_cmd eag_cli_commands[] = {
		{ "add portal_server", eag_cli_cmd_add_portal_server },
		{ "del portal_server", eag_cli_cmd_del_portal_server },
		{ "modify portal_server", eag_cli_cmd_modify_portal_server },
		{ "add captive_interface", eag_cli_cmd_add_captive_interface },
		{ "del captive_interface", eag_cli_cmd_del_captive_interface },
		{"set nasip",eag_cli_cmd_set_nasip},
		{"set local_database",eag_cli_set_local_database_switch},
		{"add white-list ip",eag_cli_cmd_add_white_list},
		{"delete white-list ip",eag_cli_cmd_delete_white_list},
		{ "service", eag_cli_cmd_service_status},
		{ "show user", eag_cli_cmd_show },
		{NULL,NULL}

};

typedef enum {
	EAG_CLI_READ,
} eag_cli_event_t;

static int
cli_receive(eag_thread_t *thread)
{
	struct eag_cli *cli = NULL;
	socklen_t len = 0;
	ssize_t nbyte = 0;
	char buf[4096]={0};
	struct sockaddr_un from;
	socklen_t fromlen;
	int buf_len =0;
	int cmd_len =0;

	struct eag_cli_cmd *match;
	        printf("%s,%d\n",__func__,__LINE__);

	if (NULL == thread) {
		eag_log_err("cli_receive input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	cli = eag_thread_get_arg(thread);	
	if (NULL == cli) {
		eag_log_err("cli_receive cli null");
		return EAG_ERR_NULL_POINTER;
	}

	nbyte = recvfrom(cli->sockfd, buf, sizeof(buf), 0,(struct sockaddr *) &from, &fromlen);
	if (nbyte < 0) {
		eag_log_err("cli_receive recvfrom failed: %s, fd(%d)",
			safe_strerror(errno), cli->sockfd);
		return EAG_ERR_SOCKET_RECV_FAILED;
	}
	char  cmd[4096] = {0};	
	
	eag_log_info("cli fd(%d) receive %s  from sockpath(%s)",cli->sockfd,buf,from.sun_path);
	match = eag_cli_commands;
	while(match->cmd)
	{
               if(0 == strncmp(buf,match->cmd,strlen(match->cmd)))
                {
		    buf_len = strlen(buf);
		    cmd_len = strlen(match->cmd);
		    memcpy(cmd,&buf[cmd_len+1],buf_len-cmd_len-1);
	              printf("cmd:%s \n",cmd);
                        match->handler(cli->sockfd,cmd);
		    break;
	       }
	        match++;
	}
	
	


	return EAG_RETURN_OK;
}

void
eag_cli_set_thread_master(struct eag_cli*cli,
		eag_thread_master_t *master)
{
	if (NULL == cli ||NULL == master) {
		eag_log_err("eag_cli_set_thread_master input error");
		return;
	}
	cli->master = master;
}

static void
eag_cli_event(eag_cli_event_t event,
		struct eag_cli* cli)
{
	        printf("%s,%d\n",__func__,__LINE__);

	if (NULL == cli) {
		eag_log_err("eag_cli_event input error");
		return;
	}
        printf("%s,%d\n",__func__,__LINE__);
	switch (event) {
	case EAG_CLI_READ:
		cli->t_read =
		    eag_thread_add_read(cli->master, cli_receive,
					cli, cli->sockfd);
		break;
	default:
		break;
	}
}

int  eag_cli_start(struct eag_cli *cli)
{
	struct sockaddr_un sock_address;
	int address_len=0;
	cli->sockfd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (cli->sockfd < 0)
	{
                printf("create socket fail.\n");
	      return -1;
	}
	
	sock_address.sun_family = AF_UNIX;
	strcpy(sock_address.sun_path,cli->sockpath);
	address_len = sizeof(sock_address);
	printf("%s\n",sock_address.sun_path);

	unlink(sock_address.sun_path);
	if(bind(cli->sockfd,(struct sockaddr *)&sock_address,address_len) < 0)
	{
                   close(cli->sockfd);
	        unlink(sock_address.sun_path);
	        printf("socket bind fail.\n");
	        return -1; 
	}
	      printf("%s,%d\n",__func__,__LINE__);

        	eag_cli_event(EAG_CLI_READ,cli);

	return EAG_RETURN_OK;

}
int  eag_cli_stop(struct eag_cli *cli)
{
	
	if (NULL == cli) {
		eag_log_err("eag_cli_stop input error");
		return EAG_ERR_NULL_POINTER;
	}

	eag_log_info("cli(%s) fd(%d) stop ok",
			cli->sockpath,
			cli->sockfd);
		
	 if (NULL != cli->t_read) {
		eag_thread_cancel(cli->t_read);
		cli->t_read = NULL;
	}
	if (cli->sockfd >= 0)
	{
		close(cli->sockfd );
		cli->sockfd  = -1;
	}
	unlink(EAG_PATH);
	return EAG_RETURN_OK;
}

struct eag_cli* eag_cli_new()
{
	struct eag_cli *cli = NULL;

	cli = eag_malloc(sizeof(*cli));
	if (NULL == cli) {
		eag_log_err("eag_cli_new eag_malloc failed");
		return NULL;
	}

	memset(cli, 0, sizeof(*cli));
	cli->sockfd = -1;
	strcpy(cli->sockpath,EAG_PATH);
	
	eag_log_info( "cli new ok, sockpath=%s",
			cli->sockpath);
	return cli;

}

int
eag_cli_free(struct eag_cli *cli)
{
	if (NULL == cli) {
		eag_log_err("eag_stamsg_free input error");
		return -1;
	}

	if (cli->sockfd >= 0) {
		close(cli->sockfd);
		cli->sockfd = -1;
	}
	eag_free(cli);

	eag_log_info( "cli free ok");
	return 0;
}

eag_ins_t *eag_ins_new()
{
	eag_ins_t *eagins = NULL;
	char buf[64] = "";
	uint32_t local_ip = 0;
	int ret = EAG_RETURN_OK;
            eag_log_info("%s,%d\n",__func__,__LINE__);
	eagins = eag_malloc(sizeof(*eagins));
	if (NULL == eagins) {
		eag_log_err("eag_ins_new eag_malloc failed");
		goto failed_0;
	}

	memset(eagins, 0, sizeof(*eagins));
	/* thread_master */
	eagins->master = eag_thread_master_new();
	if (NULL == eagins->master) {
		eag_log_err("eag_ins_new eag_thread_master_new failed");
		goto failed_1;
	}

	/*redir*/
	eagins->redir = eag_redir_new();
	if (NULL == eagins->redir) {
		eag_log_err("eag_ins_new eag_redir_new failed");
		goto failed_4;
	}
	/*portal*/
	eagins->portal = eag_portal_new();
	if (NULL == eagins->portal) {
		eag_log_err("eag_ins_new eag_portal_new failed");
		goto failed_5;
		return NULL;
	}

	/*radius*/
	eagins->radius = eag_radius_new();
	if (NULL == eagins->radius) {
		eag_log_err("eag_ins_new eag_radius_new failed");
		goto failed_6;
	}
	/*captive*/
	eagins->captive = eag_captive_new();
	if (NULL == eagins->captive) {
		eag_log_err("eag_ins_new eag_captive_new failed");
		goto failed_7;
	}
	/*appdb*/
	eagins->appdb = appconn_db_create(EAG_APPCONN_DB_HASHSIZE);
	if (NULL == eagins->appdb) {
		eag_log_err("eag_ins_new appconn_db_create failed");
		goto failed_8;
	}
	eagins->stamsg = eag_stamsg_new();
	if (NULL == eagins->stamsg) {
		eag_log_err("eag_ins_new eag_stamsg_new failed");
		goto failed_9;
	}
	eagins->coa = eag_coa_new();
	if (NULL == eagins->coa) {
		eag_log_err("eag_ins_new eag_coa_new failed");
		goto failed_10;
	}
	eagins->eagstat = eag_statistics_create(EAG_BSS_STAT_DB_HASHSIZE);
	if (NULL == eagins->eagstat) {
		eag_log_err("eag_ins_new eag_statistics_create failed");
		goto failed_11;
	}
	/*fastfwd*/
	#if 0
	eagins->fastfwd = eag_fastfwd_new(hansitype, insid);
	if (NULL == eagins->fastfwd) {
		eag_log_err("eag_eagins_new eag_fastfwd_new failed");
		goto failed_12;
	}
	#endif
	/* macauth */
	eagins->macauth = eag_macauth_new();
	if (NULL == eagins->macauth) {
		eag_log_err("eag_ins_new eag_macauth_new failed");
		goto failed_13;
	}
	/* arplisten */
	eagins->arp = eag_arp_new();
	if (NULL == eagins->macauth) {
		eag_log_err("eag_ins_new eag_arp_new failed");
		goto failed_14;
	}
	eagins->cli = eag_cli_new();
	if (NULL == eagins->cli) {
		eag_log_err("eag_ins_new eag_cli_new failed");
		goto failed_15;
	}
	
	eagins->flux_interval = DEFAULT_FLUX_INTERVAL;
	eagins->flux_from = FLUX_FROM_IPTABLES;
	//eagins->threshold_onlineusernum = EAG_DEFAULT_ONLINEUSERNUM_THRESHOLD;
	
	/* hansi */
	//eag_hansi_set_backup_port(eagins->eaghansi, EAG_HANSI_BACKUP_PORT);
		
	/* redir */
	eag_redir_set_thread_master(eagins->redir, eagins->master);
	eag_redir_set_appdb(eagins->redir, eagins->appdb);
	eag_redir_set_portal(eagins->redir, eagins->portal);
	eag_redir_set_eagins(eagins->redir, eagins);
	eag_redir_set_portal_conf(eagins->redir, &(eagins->portalconf));
	eag_redir_set_eagstat(eagins->redir, eagins->eagstat);
	eag_redir_set_stamsg(eagins->redir, eagins->stamsg);
	//eag_redir_set_eagdbus(eagins->redir, eagins->eagdbus);
	/* portal */
	eag_portal_set_thread_master(eagins->portal, eagins->master);
	//eag_portal_set_slot_id(eagins->portal, eagins->slot_id);
	eag_portal_set_eagins(eagins->portal, eagins);
	eag_portal_set_appdb(eagins->portal, eagins->appdb);
	eag_portal_set_radius(eagins->portal, eagins->radius);
	eag_portal_set_captive(eagins->portal, eagins->captive);
	eag_portal_set_coa(eagins->portal, eagins->coa);
	eag_portal_set_portal_conf(eagins->portal, &(eagins->portalconf));
	eag_portal_set_radius_conf(eagins->portal, &(eagins->radiusconf));
	//eag_portal_set_eag_dbus(eagins->portal, eagins->eagdbus);
	eag_portal_set_stamsg(eagins->portal, eagins->stamsg);
	eag_portal_set_eagstat(eagins->portal, eagins->eagstat);
	eag_portal_set_fastfwd(eagins->portal, eagins->fastfwd);
	eag_portal_set_macauth(eagins->portal, eagins->macauth);
	/* radius */
	eag_radius_set_thread_master(eagins->radius, eagins->master);
	eag_radius_set_eagins(eagins->radius, eagins);
	eag_radius_set_appdb(eagins->radius, eagins->appdb);
	eag_radius_set_portal(eagins->radius, eagins->portal);
	eag_radius_set_radius_conf(eagins->radius, &(eagins->radiusconf));
	eag_radius_set_eagstat(eagins->radius, eagins->eagstat);
	eag_radius_set_captive(eagins->radius, eagins->captive);
//	eag_radius_set_eag_dbus(eagins->radius, eagins->eagdbus);
	eag_radius_set_coa(eagins->radius, eagins->coa);
	eag_radius_set_stamsg(eagins->radius, eagins->stamsg);
	eag_radius_set_fastfwd(eagins->radius, eagins->fastfwd);
	eag_radius_set_macauth(eagins->radius, eagins->macauth);
	/* captive */
	eag_authorize_iptables_auth_init(eagins->captive,
				 eagins->appdb);
	/*eag_authorize_ipset_auth_init(eagins->captive,
				NULL);*/
	eag_authorize_tag_auth_init(eagins->captive,
				 NULL);
	/* appdb */
	appconn_db_set_eagins(eagins->appdb, eagins);
	appconn_db_set_nasid_conf(eagins->appdb, &(eagins->nasidconf));
	appconn_db_set_nasportid_conf(eagins->appdb, &(eagins->nasportidconf));
	appconn_db_set_portal_conf(eagins->appdb, &(eagins->portalconf));
	//appconn_db_set_eag_dbus(eagins->appdb, eagins->eagdbus);
	/* stamsg */
	eag_stamsg_set_thread_master(eagins->stamsg, eagins->master);
	eag_stamsg_set_eagins(eagins->stamsg, eagins);
	eag_stamsg_set_portal(eagins->stamsg, eagins->portal);
	eag_stamsg_set_radius(eagins->stamsg, eagins->radius);
	//eag_stamsg_set_eagdbus(eagins->stamsg, eagins->eagdbus);
	eag_stamsg_set_appdb(eagins->stamsg, eagins->appdb);
	eag_stamsg_set_captive(eagins->stamsg, eagins->captive);
	eag_stamsg_set_portal_conf(eagins->stamsg, &(eagins->portalconf));
	eag_stamsg_set_nasid_conf(eagins->stamsg, &(eagins->nasidconf));
	eag_stamsg_set_nasportid_conf(eagins->stamsg, &(eagins->nasportidconf));
	eag_stamsg_set_eagstat(eagins->stamsg, eagins->eagstat);
	//eag_stamsg_set_eaghansi(eagins->stamsg, eagins->eaghansi);
	eag_stamsg_set_macauth(eagins->stamsg, eagins->macauth);
	/* coa */
	eag_coa_set_thread_master(eagins->coa, eagins->master);
	eag_coa_set_portal(eagins->coa, eagins->portal);
	eag_coa_set_radius(eagins->coa, eagins->radius);
	eag_coa_set_appdb(eagins->coa, eagins->appdb);
	eag_coa_set_eagins(eagins->coa, eagins);
	eag_coa_set_radius_conf(eagins->coa, &(eagins->radiusconf));
	eag_coa_set_captive(eagins->coa, eagins->captive);
	//eag_coa_set_eag_dbus(eagins->coa, eagins->eagdbus);
	eag_coa_set_stamsg(eagins->coa, eagins->stamsg);
	//eag_coa_set_fastfwd(eagins->coa, eagins->fastfwd);
	/* statistics */
	eag_statistics_set_appdb(eagins->eagstat, eagins->appdb);
	/* fastfwd */
	#if 0
	eag_fastfwd_set_slot_id(eagins->fastfwd, eagins->slot_id);
	eag_fastfwd_set_thread_master(eagins->fastfwd, eagins->master);
	eag_fastfwd_set_appdb(eagins->fastfwd, eagins->appdb);
	eag_fastfwd_set_macauth(eagins->fastfwd, eagins->macauth);
	#endif
	/* macauth */
	eag_macauth_set_thread_master(eagins->macauth, eagins->master);
	eag_macauth_set_eagins(eagins->macauth, eagins);
	//eag_macauth_set_eagdbus(eagins->macauth, eagins->eagdbus);
	eag_macauth_set_appdb(eagins->macauth, eagins->appdb);
	eag_macauth_set_captive(eagins->macauth, eagins->captive);
	//eag_macauth_set_fastfwd(eagins->macauth, eagins->fastfwd);
	eag_macauth_set_portal(eagins->macauth, eagins->portal);
	eag_macauth_set_portal_conf(eagins->macauth, &(eagins->portalconf));
	eag_macauth_set_radius(eagins->macauth, eagins->radius);
	eag_macauth_set_radius_conf(eagins->macauth, &(eagins->radiusconf));
	/* arplisten */
	eag_arp_set_thread_master(eagins->arp, eagins->master);
	eag_arp_set_eagins(eagins->arp, eagins);
	eag_arp_set_appdb(eagins->arp, eagins->appdb);
	eag_arp_set_portal(eagins->arp, eagins->portal);
	eag_arp_set_macauth(eagins->arp, eagins->macauth);
	/* trap */
	//eag_trap_set_eagdbus(eagins->eagdbus);
	/* local addr */
	eag_cli_set_thread_master(eagins->cli, eagins->master);

	#if 0
	if (HANSI_LOCAL == eagins->hansi_type) {
		local_ip = SLOT_IPV4_BASE + 100 + insid;
		eag_redir_set_local_addr(eagins->redir, local_ip,
				EAG_REDIR_LISTEN_PORT_BASE + insid);
		eag_portal_set_local_addr(eagins->portal, local_ip,
					EAG_PORTAL_PORT_BASE + insid);
		eag_coa_set_local_addr(eagins->coa, local_ip,
					EAG_RADIUS_COA_PORT_BASE + insid);
	}
	else {
		local_ip = SLOT_IPV4_BASE + eagins->slot_id;
		eag_redir_set_local_addr(eagins->redir, local_ip, 
				EAG_REDIR_LISTEN_PORT_BASE + MAX_HANSI_ID + insid);
		eag_portal_set_local_addr(eagins->portal, local_ip, 
				EAG_PORTAL_PORT_BASE + MAX_HANSI_ID + insid);
		eag_coa_set_local_addr(eagins->coa, local_ip, 
				EAG_RADIUS_COA_PORT_BASE + MAX_HANSI_ID + insid);
	}
	eag_radius_set_local_ip(eagins->radius, local_ip);
	//eagins_register_all_dbus_method(eagins);
    #endif
	ret = eag_stamsg_start(eagins->stamsg);
	if (EAG_RETURN_OK != ret) {
		eag_log_err("eag_ins_new eag_stamsg_start failed");
		goto failed_15;
	}
    
	ret = eag_cli_start(eagins->cli);
	if (EAG_RETURN_OK != ret) {
		eag_log_err("eag_ins_new eag_cli_start failed");
		goto failed_15;
	}
	
	return eagins;
failed_15:
	eag_arp_free(eagins->arp);
	eagins->arp = NULL;
failed_14:
	eag_macauth_free(eagins->macauth);
	eagins->macauth = NULL;
failed_13:
	eag_statistics_destroy(eagins->eagstat);
	eagins->eagstat = NULL;
failed_11:
	eag_coa_free(eagins->coa);
	eagins->coa = NULL;
failed_10:
	eag_stamsg_free(eagins->stamsg);
	eagins->stamsg = NULL;
failed_9:
	appconn_db_destroy(eagins->appdb);
	eagins->appdb = NULL;
failed_8:
	eag_captive_free(eagins->captive);
failed_7:
	eag_radius_free(eagins->radius);
	eagins->radius = NULL;
failed_6:
	eag_portal_free(eagins->portal);
	eagins->portal = NULL;
failed_5:
	eag_redir_free(eagins->redir);
	eagins->redir = NULL;
failed_4:
	eag_thread_master_free(eagins->master);
	eagins->master = NULL;
failed_1:
	eag_free(eagins);
	eagins = NULL;
failed_0:
	return NULL;
}

int
eag_ins_free(eag_ins_t *eagins)
{
	if (NULL == eagins) {
		eag_log_err("eag_ins_free input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if (NULL != eagins->redir) {
		eag_redir_free(eagins->redir);
		eagins->redir = NULL;
	}
	
	if (NULL != eagins->portal) {
		eag_portal_free(eagins->portal);
		eagins->portal = NULL;
	}
	
	if (NULL != eagins->radius) {
		eag_radius_free(eagins->radius);
		eagins->radius = NULL;
	}
	
	if (NULL != eagins->captive) {
		eag_captive_free(eagins->captive);
		eagins->captive = NULL;
	}
	
	if (NULL != eagins->appdb) {
		appconn_db_destroy(eagins->appdb);
		eagins->appdb = NULL;
	}
	
	eag_stamsg_stop(eagins->stamsg);
	if (NULL != eagins->stamsg) {
		eag_stamsg_free(eagins->stamsg);
		eagins->stamsg = NULL;
	}
         eag_cli_stop(eagins->cli);
	if (NULL != eagins->cli) {
		eag_cli_free(eagins->cli);
		eagins->cli = NULL;
	}
	
	if (NULL != eagins->coa) {
		eag_coa_free(eagins->coa);
		eagins->coa = NULL;
	}

	if (NULL != eagins->macauth) {
		eag_macauth_free(eagins->macauth);
		eagins->macauth = NULL;
	}
		
	if (NULL != eagins->master) {
		eag_thread_master_free(eagins->master);
		eagins->master = NULL;
	}
	if (NULL != eagins->eagstat) {
		eag_statistics_destroy(eagins->eagstat);
		eagins->eagstat = NULL;
	}
	
	if (NULL != eagins->arp) {
		eag_arp_free(eagins->arp);
		eagins->arp = NULL;
	}


	eag_free(eagins);
	
	return EAG_RETURN_OK;
}

int
eag_ins_start(eag_ins_t *eagins)
{
	int ret = 0;
	
	if (NULL == eagins) {
		eag_log_err("eag_ins_start input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	if (1 == eagins->status) {
		eag_log_err("eag_ins_start service already enable");
		return EAG_ERR_EAGINS_SERVICE_ALREADY_ENABLE;
	}

	if (0 == eagins->nasip) {
		eag_log_warning("eag_ins_start nasip is 0");
		return EAG_ERR_EAGINS_NASIP_IS_EMPTY;
	}
		eag_captive_set_redir_srv( eagins->captive, eagins->nasip,
				EAG_REDIR_LISTEN_PORT);

	
	/*if (EAG_RETURN_OK != eag_hansi_start(eagins->eaghansi)) {
		eag_log_err("eag_ins_start eag_hansi_start failed");
	}*/

	extern int if_has_ipaddr( unsigned long ipaddr );
	/*if(eag_hansi_is_master(eagins->eaghansi)
		|| (if_has_ipaddr(eagins->nasip)
			&& !eag_hansi_is_enable(eagins->eaghansi)))*/
	
		eag_log_info("eag_ins_start before starting all module");
		ret = eag_redir_start(eagins->redir);
		if (EAG_RETURN_OK != ret) {
			eag_log_err("eag_ins_start eag_redir_start failed");
			goto failed_0;
		}

		ret = eag_portal_start(eagins->portal);
		if (EAG_RETURN_OK != ret) {
			eag_log_err("eag_ins_start eag_portal_start failed");
			goto failed_1;
		}

		ret = eag_radius_start(eagins->radius);
		if (EAG_RETURN_OK != ret) {
			eag_log_err("eag_ins_start eag_radius_start failed");
			goto failed_2;
		}

		ret = eag_coa_start(eagins->coa);
		if (EAG_RETURN_OK != ret) {
			eag_log_err("eag_ins_start eag_coa_start failed");
			goto failed_3;
		}
		
		ret = eag_captive_start(eagins->captive);
		if (EAG_RETURN_OK != ret) {
			eag_log_err("eag_ins_start eag_captive_start failed");
			goto failed_4;
		}
		#if 0
		ret = eag_fastfwd_start(eagins->fastfwd);
		if( EAG_RETURN_OK != ret ){
			eag_log_err("eag_ins_start eag_fastfwd_start failed");
			goto failed_5;
		}
		#endif
		if(eag_macauth_get_macauth_switch(eagins->macauth)) {
			ret = eag_macauth_start(eagins->macauth);
			if (EAG_RETURN_OK != ret) {
				eag_log_err("eag_ins_start eag_macauth_start failed");
				goto failed_6;
			}
		}
		ret = eag_arp_start(eagins->arp);
		if( EAG_RETURN_OK != ret ){
			eag_log_err("eag_ins_start eag_arp_start failed");
			goto failed_7;
		}
	
	/*else {
		eag_log_info("eag_ins_start just need start "
					"captive and fastfwd modules for backup instance");
		ret = eag_captive_start(eagins->captive);
		if (EAG_RETURN_OK != ret) {
			eag_log_err("eag_ins_start eag_captive_start failed");
			return ret;
		}
		ret = eag_fastfwd_start(eagins->fastfwd);
		if( EAG_RETURN_OK != ret ){
			eag_captive_stop(eagins->captive);
			eag_log_err("eag_ins_start eag_fastfwd_start failed");
			return ret;
		}
	}*/

	eagins_read_file_switch();
	
	eagins->status = 1;
	if (l2super_vlan_switch_t) {
    	eag_set_l2super_vlan(eagins, l2super_vlan_switch_t);
    }
	return EAG_RETURN_OK;
failed_7:
	eag_macauth_stop(eagins->macauth);
failed_6:
	eag_captive_stop(eagins->captive);
failed_4:
	eag_coa_stop(eagins->coa);
failed_3:
	eag_radius_stop(eagins->radius);
failed_2:
	eag_portal_stop(eagins->portal);
failed_1:
	eag_redir_stop(eagins->redir);
failed_0:
	return ret;
}

int
eag_ins_stop(eag_ins_t *eagins)
{
	if (NULL == eagins) {
		eag_log_err("eag_ins_stop input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	if (0 == eagins->status) {
		eag_log_warning("eag_ins_stop service is already disable");
		return EAG_ERR_EAGINS_SERVICE_IS_DISABLE;
	}
	eag_redir_stop(eagins->redir);
	eag_coa_stop(eagins->coa);
	eag_captive_stop(eagins->captive);
	if (eag_macauth_get_macauth_switch(eagins->macauth)) {
		eag_macauth_stop(eagins->macauth);
	}
	terminate_appconn_all(eagins);
	
	//eag_fastfwd_stop(eagins->fastfwd);
	eag_arp_stop(eagins->arp);

	/*if (EAG_RETURN_OK != eag_hansi_stop(eagins->eaghansi)) {
		eag_log_err("eag_ins_stop eag_hansi_stop failed");
	}*/
	eag_portal_stop(eagins->portal);
	eag_radius_stop(eagins->radius);
	eag_statistics_clear(eagins->eagstat);

	eagins->status = 0;
	if (l2super_vlan_switch_t) {
    	eag_set_l2super_vlan(eagins, 0);
    }
	return EAG_RETURN_OK;
}
#if 0
static void
eag_log_debug_heart_beat(void)
{
	static time_t prevheart = 0;
	time_t current = 0;
	struct timeval tv = {0};
	
	eag_time_gettimeofday(&tv, NULL);
	current = tv.tv_sec;
	if (current - prevheart >= EAG_HEART_BEAT_INTERVAL) {
		eag_log_debug("heartbeat",
				"eag heartbeat current eag_time is %lu second", current);
		prevheart = current;
	}
}
#endif
int
eag_get_debug_filter_key(char *session_filter_prefix, int size, const char *ip_str,
					const char *mac_str, const char *username)
{
	if (NULL == ip_str) {
		return -1;
	}
	snprintf(session_filter_prefix,size-1,"USERLOG: %s", ip_str);
	if (NULL != mac_str && 0 != strcmp(mac_str,"")) {
		strncat(session_filter_prefix, ": ", size-strlen(session_filter_prefix)-1);
		strncat(session_filter_prefix, mac_str, size-strlen(session_filter_prefix)-1);
	}
	if (NULL != username && 0 != strcmp(username,"")) {
		strncat(session_filter_prefix, ": ", size-strlen(session_filter_prefix)-1);
		strncat(session_filter_prefix, username, size-strlen(session_filter_prefix)-1);
	}
	strncat(session_filter_prefix, ":", size-strlen(session_filter_prefix)-1);

	return 0;
}


static void
eag_ins_session_interval(struct app_conn_t *appconn,
								eag_ins_t *eagins)
{
	appconn_db_t *appdb = NULL;
	time_t timenow = 0;
	struct timeval tv = {0};
	unsigned long session_time = 0;
	unsigned long idle_time = 0;
	unsigned long acct_time = 0;
	char ipstr[32] = "";
	char macstr[32] = "";
	const char *userintf = "";
	unsigned long idle_timeout = 0;
	uint64_t idle_flow = 0;
	
	if (NULL == appconn || NULL == eagins) {
		eag_log_err("eag_ins_session_interval input error");
		return;
	}

	appdb = eagins->appdb;
	appconn_db_get_idle_params(appdb, &idle_timeout, &idle_flow);
	ip2str(appconn->session.user_ip, ipstr, sizeof(ipstr));
	mac2str(appconn->session.usermac, macstr, sizeof(macstr)-1, '-');
	userintf = appconn->session.intf;
	
	eag_time_gettimeofday(&tv, NULL);
	timenow = tv.tv_sec;

	if (APPCONN_STATUS_NONE == appconn->session.state) {
		log_app_debug(appconn,
			"userip %s usermac %s interface %s last_active_time=%lu timenow=%lu",
			ipstr, macstr, userintf, 
			appconn->last_active_time, timenow);
		idle_time = timenow - appconn->last_active_time;
		if (idle_time >= idle_timeout) {
			log_app_debug(appconn,
				"userip %s usermac %s interface %s not authed and idle timeout, "
				"idle_time is %lu, idle_timeout is %lu, del from appdb",
				ipstr, macstr, userintf, idle_time, idle_timeout);
			appconn_del_from_db(appconn);
			appconn_free(appconn);
		} else {
			log_app_debug(appconn,
				"user ip %s mac %s interface %s not authed, "
				"idle_time is %lu, idle_timeout is %lu",
				ipstr, macstr, userintf, idle_time, idle_timeout);
		}
		return;
	}

	log_app_debug(appconn,
			"userip %s usermac %s username %s interface %s, session_start_time=%lu, "
			"last_acct_time=%lu, last_flux_time=%lu, timenow=%lu,",
			ipstr, macstr, userintf, appconn->session.username,
			appconn->session.session_start_time,
			appconn->session.last_acct_time,
			appconn->session.last_flux_time, timenow);

	if (0 == appconn->session.last_flux_time) {
		appconn->session.last_flux_time = timenow;
	}
	session_time = timenow - appconn->session.session_start_time;
	idle_time = timenow - appconn->session.last_flux_time;
	acct_time = timenow - appconn->session.last_acct_time;

	log_app_debug(appconn,
		"user ip %s mac %s session_time=%lu, idle_time=%lu, acct_time=%lu",
		ipstr, macstr, session_time, idle_time, acct_time);

	if ( (FLUX_FROM_FASTFWD == eagins->flux_from 
			|| FLUX_FROM_FASTFWD_IPTABLES == eagins->flux_from)
		&& (timenow - appconn->session.last_fastfwd_flow_time > eagins->flux_interval
			|| timenow < appconn->session.last_fastfwd_flow_time))
	{
		appconn->session.last_fastfwd_flow_time = timenow;
	}
	
	if (!appconn->on_ntf_logout
		&& appconn->session.sessiontimeout > 0
		&& session_time >= appconn->session.sessiontimeout)
	{
		log_app_debug(appconn,
			"user ip %s mac %s interface %s session timeout and will offline,"
			"session_time=%lu, session_timeout=%lu",
			ipstr, macstr, userintf, session_time,
			appconn->session.sessiontimeout);
		eag_portal_notify_logout(eagins->portal, appconn,
				  RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
		appconn->on_ntf_logout = 1;
		appconn->session.session_stop_time = timenow;
	} else if (!appconn->on_ntf_logout 
		&& appconn->session.sessionterminatetime > 0
		&& timenow >= appconn->session.sessionterminatetime) 
	{
		log_app_debug(appconn,
			"user ip %s mac %s interface %s session upto terminate time "
			"and will offline, timenow=%lu, sessionterminatetime=%lu",
			ipstr, macstr, userintf, timenow,
			appconn->session.sessionterminatetime);
		eag_portal_notify_logout(eagins->portal, appconn,
				  RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
		appconn->on_ntf_logout = 1;
		appconn->session.session_stop_time = timenow;
	} else if (!appconn->on_ntf_logout && appconn->session.idle_check  
			&& appconn->session.idle_timeout > 0
			&& idle_time >= appconn->session.idle_timeout)
	{
		log_app_debug(appconn,
			"user ip %s mac %s interface %s idle timeout "
			"and will offline, timenow=%lu, idletimeout=%lu,"
			"sta_state=%d, leave_reason=%d", ipstr, macstr, userintf,
			idle_time, appconn->session.idle_timeout, appconn->session.sta_state,
			appconn->session.leave_reason);
		if (SESSION_STA_STATUS_UNCONNECT == appconn->session.sta_state &&
			SESSION_STA_LEAVE_NORMAL == appconn->session.leave_reason) {
			eag_portal_notify_logout(eagins->portal, appconn,
				RADIUS_TERMINATE_CAUSE_LOST_CARRIER);
		} else {
			eag_portal_notify_logout(eagins->portal, appconn,
				RADIUS_TERMINATE_CAUSE_IDLE_TIMEOUT);
		}

		appconn->on_ntf_logout = 1;
		appconn->session.session_stop_time = timenow;
	} else if (!appconn->on_ntf_logout
		&& appconn->session.maxinputoctets > 0 
		&& appconn->session.input_octets > 
					appconn->session.maxinputoctets)
	{
		log_app_debug(appconn,
			"user ip %s mac %s interface %s input flux reach limit "
			"and will offline, input_octets=%llu, maxinputoctets=%llu",
			ipstr, macstr, userintf, appconn->session.input_octets,
			appconn->session.maxinputoctets);
		eag_portal_notify_logout(eagins->portal, appconn,
				  RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
		appconn->on_ntf_logout = 1;
		appconn->session.session_stop_time = timenow;
	} else if (!appconn->on_ntf_logout
		&& appconn->session.maxoutputoctets > 0
		&& appconn->session.output_octets >
		       		appconn->session.maxoutputoctets)
	{
		log_app_debug(appconn,
			"user ip %s mac %s interface %s output flux reach limit "
			"and will offline, input_octets=%llu, maxinputoctets=%llu",
			ipstr, macstr, userintf, appconn->session.output_octets,
			appconn->session.maxoutputoctets);
		eag_portal_notify_logout(eagins->portal, appconn,
						  RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
		appconn->on_ntf_logout = 1;
		appconn->session.session_stop_time = timenow;
	} else if (!appconn->on_ntf_logout
		&& appconn->session.maxtotaloctets > 0
		&& appconn->session.input_octets +
				appconn->session.output_octets >
				    appconn->session.maxtotaloctets)
	{
		log_app_debug(appconn,
			"user ip %s mac %s interface %s total flux reach limit "
			"and will offline, input_octets=%llu, input_octets=%llu,"
			" maxinputoctets=%llu",
			ipstr, macstr, userintf, 
			appconn->session.output_octets,
			appconn->session.output_octets,
			appconn->session.maxtotaloctets);
		eag_portal_notify_logout(eagins->portal, appconn,
				  RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
		appconn->on_ntf_logout = 1;
		appconn->session.session_stop_time = timenow;
	} else if (local_database_switch == 0 && !appconn->on_ntf_logout
			&& appconn->session.interim_interval > 0
			&& acct_time >= appconn->session.interim_interval)
	{
		log_app_debug(appconn,
			"user ip %s mac %s username %s interface %s interim account "
			"acct_time=%lu, interim_interval=%lu",
			ipstr, macstr, appconn->session.username, userintf,
			acct_time, appconn->session.interim_interval);

#define USER_TOO_TIME 60*60*6	/* six hour */
    
		int online_time = appconn->session.last_flux_time -
						    appconn->session.session_start_time;
		if (online_time > USER_TOO_TIME) {
			admin_log_notice("PortalUserTooTime___UserName:%s,UserIP:%s,UserMAC:%s,Onlinetime:%d",
				appconn->session.username, ipstr, macstr, online_time);
		}
		
		appconn->session.last_acct_time = timenow;
	        
		    radius_acct(eagins->radius, appconn,
				RADIUS_STATUS_TYPE_INTERIM_UPDATE);

		//eag_ins_syn_user(eagins, appconn);
	}
}

static int
eag_ins_appconn_check(eag_ins_t *eagins)
{
	struct timeval tv={0};
	static time_t prev_check_time = 0;
	static time_t prev_flux_time = 0;
	struct app_conn_t *appconn = NULL;
	struct app_conn_t *next = NULL;
	struct list_head *head = NULL;
	
	eag_time_gettimeofday(&tv, NULL);
	head = appconn_db_get_head(eagins->appdb);

	if (tv.tv_sec - prev_flux_time >= eagins->flux_interval) {
		flush_all_appconn_flux_immediate(eagins->appdb);
		prev_flux_time = tv.tv_sec;
	}
	
	if (tv.tv_sec - prev_check_time >= 1) {
		list_for_each_entry_safe(appconn, next, head, node) {
				eag_ins_session_interval(appconn, eagins);
		}

		prev_check_time = tv.tv_sec;
	}

	return EAG_RETURN_OK;
}
#if 0
static void
eag_ins_syn_time(eag_ins_t *eagins)
{
	static time_t prevheart = 0;
	time_t current = 0;
	struct timeval tv = {0};
	
	eag_time_gettimeofday(&tv, NULL);
	current = tv.tv_sec;
	if (current - prevheart >= EAG_SYN_TIME_INTERVAL) {
		eag_hansi_syn_time(eagins->eaghansi);
		prevheart = current;
	}
}
#endif
int 
eag_ins_dispatch(eag_ins_t *eagins)
{
	struct timeval timer_wait = {0};

	if (NULL == eagins)
	{
		eag_log_err("eag_ins_dispatch input error");
		return -1;
	}
	
	timer_wait.tv_sec = 0;
	timer_wait.tv_usec = 10000;
	eag_thread_dispatch(eagins->master, &timer_wait);
	//eag_dbus_dispach(eagins->eagdbus, 0);

	//eag_log_debug_heart_beat();
		
	//eag_hansi_check_connect_state(eagins->eaghansi);

	if (1 == eagins->status) {
			eag_ins_appconn_check(eagins);
			if (eag_macauth_get_macauth_switch(eagins->macauth)) {
				eag_macauth_preauth_check(eagins->macauth);
		
	    }
	}
        #if 0 /* syn for timer in hansi */
	if (eag_hansi_is_master(eagins->eaghansi))
	{
		eag_ins_syn_time(eagins);
	}
#endif
	return 0;
}

int
eag_ins_is_running(eag_ins_t *eagins)
{
	if (NULL == eagins) {
		eag_log_err("eag_ins_is_running input error");
		return 0;
	}

	return eagins->status;
}

int
eag_ins_set_nasip(eag_ins_t *eagins,
		uint32_t nasip)
{
	char ipstr[32] = "";
	
	if (NULL == eagins) {
		eag_log_err("eag_ins_set_nasip input error");
		return -1;
	}
	ip2str(nasip, ipstr, sizeof(ipstr));

	if (eag_ins_is_running(eagins)) {
		eag_log_warning("eag_ins_set_nasip eagins already started");
		return EAG_ERR_EAGINS_SERVICE_ALREADY_ENABLE;
	}
	
	eagins->nasip = nasip;

	eag_log_info("eagins set nasip %s", ipstr);
	return EAG_RETURN_OK;
}

uint32_t
eag_ins_get_nasip(eag_ins_t *eagins)
{
	return eagins->nasip;
}

/*
int
eag_ins_set_distributed(eag_ins_t *eagins,
		int is_distributed)
{
	if (NULL == eagins) {
		eag_log_err("eag_ins_set_distributed input error");
		return -1;
	}

	if (eag_ins_is_running(eagins)) {
		eag_log_warning("eag_ins_set_distributed eagins already started");
		return EAG_ERR_EAGINS_SERVICE_ALREADY_ENABLE;
	}
	
	eagins->is_distributed = is_distributed;

	eag_log_info("eagins set distributed %d", is_distributed);
	return EAG_RETURN_OK;
}
*/

#if 0
int
eag_ins_set_rdc_distributed(eag_ins_t *eagins,
		int rdc_distributed)
{
	if (NULL == eagins) {
		eag_log_err("eag_ins_set_rdc_distributed input error");
		return -1;
	}

	if (eag_ins_is_running(eagins)) {
		eag_log_warning("eag_ins_set_rdc_distributed eagins already started");
		return EAG_ERR_EAGINS_SERVICE_ALREADY_ENABLE;
	}
	
	eagins->rdc_distributed = rdc_distributed;

	eag_log_info("eagins set rdc distributed %d", rdc_distributed);
	return EAG_RETURN_OK;
}

int
eag_ins_set_pdc_distributed(eag_ins_t *eagins,
		int pdc_distributed)
{
	if (NULL == eagins) {
		eag_log_err("eag_ins_set_pdc_distributed input error");
		return -1;
	}

	if (eag_ins_is_running(eagins)) {
		eag_log_warning("eag_ins_set_pdc_distributed eagins already started");
		return EAG_ERR_EAGINS_SERVICE_ALREADY_ENABLE;
	}
	
	eagins->pdc_distributed = pdc_distributed;

	eag_log_info("eagins set pdc distributed %d", pdc_distributed);
	return EAG_RETURN_OK;
}

/*
int
eag_ins_get_distributed(eag_ins_t *eagins)
{
	return eagins->is_distributed;
}
*/
#endif

int
eag_ins_set_flux_from(eag_ins_t *eagins,
		int flux_from)
{
	if (NULL == eagins) {
		eag_log_err("eag_ins_set_flux_from input error");
		return -1;
	}

	if (eag_ins_is_running(eagins)) {
		eag_log_warning("eag_ins_set_flux_from eagins already started");
		return EAG_ERR_EAGINS_SERVICE_ALREADY_ENABLE;
	}
	
	eagins->flux_from = flux_from;

	eag_log_info("eagins set flux_from %d", flux_from);
	return EAG_RETURN_OK;
}

int
eag_ins_get_flux_from(eag_ins_t *eagins)
{
	return eagins->flux_from;
}

#if 0
int
eag_ins_get_trap_online_user_num_params(
										eag_ins_t *eagins, 
										int *trap_onlineusernum_switch,
										int *threshold_onlineusernum)
{
	*trap_onlineusernum_switch = eagins->trap_onlineusernum_switch;
	*threshold_onlineusernum = eagins->threshold_onlineusernum;

	return 0;
}

DBusMessage *
eag_dbus_method_set_nasip(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data)
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	uint32_t nasip = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_nasip "
			"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_set_nasip user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &nasip,
								DBUS_TYPE_INVALID)))
	{
		eag_log_err("eag_dbus_method_set_nasip unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_nasip %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = eag_ins_set_nasip(eagins, nasip);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

/*
DBusMessage *
eag_dbus_method_set_distributed(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int distributed = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_distributed "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_set_distributed "
					"user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyy;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &distributed,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_distributed "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_distributed %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyy;
	}
	
	ret = eag_ins_set_distributed(eagins, distributed);

replyy:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}
*/

DBusMessage *
eag_dbus_method_set_rdc_distributed(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int rdc_distributed = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_rdc_distributed "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_set_rdc_distributed "
					"user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyy;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &rdc_distributed,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_rdc_distributed "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_rdc_distributed %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyy;
	}
	
	ret = eag_ins_set_rdc_distributed(eagins, rdc_distributed);

replyy:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_pdc_distributed(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int pdc_distributed = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_pdc_distributed "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_set_pdc_distributed "
					"user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyy;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &pdc_distributed,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_pdc_distributed "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_pdc_distributed %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyy;
	}
	
	ret = eag_ins_set_pdc_distributed(eagins, pdc_distributed);

replyy:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

/*
DBusMessage *
eag_dbus_method_set_rdcpdc_ins(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int slotid = 0;
	int insid = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_rdcpdc_ins "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_set_rdcpdc_ins "
					"user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyy;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg, &err,
								DBUS_TYPE_INT32, &slotid,
								DBUS_TYPE_INT32, &insid,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_rdcpdc_ins "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_rdcpdc_ins %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyy;
	}
	
	eag_log_info("eag rdcpdc_ins set to %d-%d", slotid, insid);
	rdc_set_server_hansi(slotid, insid);
	pdc_set_server_hansi(slotid, insid);

replyy:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}
*/

DBusMessage *
eag_dbus_method_set_rdc_ins(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int slotid = 0;
	int insid = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_rdc_ins "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_set_rdc_ins "
					"user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyy;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg, &err,
								DBUS_TYPE_INT32, &slotid,
								DBUS_TYPE_INT32, &insid,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_rdc_ins "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_rdc_ins %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyy;
	}
	
	eag_log_info("eag rdc_ins set to %d-%d", slotid, insid);
	rdc_set_server_hansi(slotid, insid);

replyy:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_pdc_ins(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int slotid = 0;
	int insid = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_pdc_ins "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_set_pdc_ins "
					"user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyy;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg, &err,
								DBUS_TYPE_INT32, &slotid,
								DBUS_TYPE_INT32, &insid,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_pdc_ins "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_pdc_ins %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyy;
	}
	
	eag_log_info("eag pdc_ins set to %d-%d", slotid, insid);
	pdc_set_server_hansi(slotid, insid);

replyy:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_portal_port(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_portal_t *portal = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	uint16_t port = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_portal_port "
					"DBUS new reply message error");
		return NULL;
	}

	portal = (eag_portal_t *)user_data;
	if (NULL == portal) {
		eag_log_err("eag_dbus_method_set_portal_port "
					"user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyy;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT16, &port,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_portal_port "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_portal_port %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyy;
	}

	ret = eag_portal_set_portal_port(portal, port);

replyy:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_portal_retry_params(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_portal_t *portal = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	int retry_interval = 0;
	int retry_times = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_portal_retry_params "
					"DBUS new reply message error");
		return NULL;
	}

	portal = (eag_portal_t *)user_data;
	if (NULL == portal) {
		eag_log_err("eag_dbus_method_set_portal_retry_params user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &retry_interval,
								DBUS_TYPE_INT32, &retry_times,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_portal_retry_params "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_portal_retry_params %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	ret = eag_portal_set_retry_params(portal, retry_interval, retry_times);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_auto_session(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_portal_t *portal = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int auto_session = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_auto_session "
					"DBUS new reply message error");
		return NULL;
	}

	portal = (eag_portal_t *)user_data;
	if (NULL == portal) {
		eag_log_err("eag_dbus_method_set_auto_session user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &auto_session,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_auto_session "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_auto_session %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = eag_portal_set_auto_session(portal, auto_session);
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_radius_acct_interval(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_radius_t *radius = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	int acct_interval = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_radius_acct_interval "
					"DBUS new reply message error");
		return NULL;
	}

	radius = (eag_radius_t *)user_data;
	if (NULL == radius) {
		eag_log_err("eag_dbus_method_set_radius_acct_interval user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &acct_interval,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_radius_acct_interval "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_radius_acct_interval %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	ret = eag_radius_set_acct_interval(radius, acct_interval);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_radius_retry_params(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_radius_t *radius = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	int retry_times = 0;
	int vice_retry_times = 0;
	int retry_interval = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_radius_retry_params "
					"DBUS new reply message error");
		return NULL;
	}

	radius = (eag_radius_t *)user_data;
	if (NULL == radius) {
		eag_log_err("eag_dbus_method_set_radius_retry_params user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &retry_interval,
								DBUS_TYPE_INT32, &retry_times,
								DBUS_TYPE_INT32, &vice_retry_times,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_radius_rety_params "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_radius_retry_params %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	ret = eag_radius_set_retry_params(radius,
			retry_interval, retry_times, vice_retry_times);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_max_redir_times(
				DBusConnection *conn,
				DBusMessage *msg,
				void *user_data)
{
	eag_redir_t *redir = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int max_redir_times = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_max_http_request "
					"DBUS new reply message error");
		return NULL;
	}
	
	redir = (eag_redir_t *)user_data;
	if (NULL == redir) {
		eag_log_err("eag_dbus_method_set_max_http_request user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &max_redir_times,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_max_http_request "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_max_http_request %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = eag_redir_set_max_redir_times(redir, max_redir_times);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_force_dhcplease(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_redir_t *redir = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int force_dhcplease = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_force_dhcplease "
					"DBUS new reply message error");
		return NULL;
	}

	redir = (eag_redir_t *)user_data;
	if (NULL == redir) {
		eag_log_err("eag_dbus_method_set_force_dhcplease user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &force_dhcplease,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_force_dhcplease "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_force_dhcplease %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = eag_redir_set_force_dhcplease(redir, force_dhcplease);
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_check_errid(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_portal_t *portal = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int check_errid = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_check_errid "
					"DBUS new reply message error");
		return NULL;
	}

	portal = (eag_portal_t *)user_data;
	if (NULL == portal) {
		eag_log_err("eag_dbus_method_set_check_errid user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &check_errid,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_check_errid "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_check_errid %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = eag_portal_set_check_errid(portal, check_errid);
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_idle_params(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	appconn_db_t *appdb = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	uint64_t idle_flow = 0;
	unsigned long idle_timeout = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_idle_params "
					"DBUS new reply message error");
		return NULL;
	}
	
	appdb = (appconn_db_t *)user_data;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_set_idle_params user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32,&idle_timeout,
								DBUS_TYPE_UINT64, &idle_flow,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_idle_params "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_idle_params %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = appconn_db_set_idle_params(appdb, idle_timeout, idle_flow);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	
	return reply;
}

DBusMessage *
eag_dbus_method_set_force_wireless(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	appconn_db_t *appdb = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int force_wireless = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_force_wireless "
					"DBUS new reply message error");
		return NULL;
	}

	appdb = (appconn_db_t *)user_data;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_set_force_wireless user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &force_wireless,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_force_wireless "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_force_wireless %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = appconn_db_set_force_wireless(appdb, force_wireless);
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_flux_from(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	int ret = EAG_RETURN_OK;
	int flux_from = 0;
	reply = dbus_message_new_method_return(msg);
	
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_flux_from "\
					"DBUS new reply message error!\n");
		return NULL;
	}
	eagins = (eag_ins_t *)user_data;
	if ( NULL == eagins ){
		eag_log_err("eag_dbus_method_set_flux_from user_data eagins error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &flux_from,		
								DBUS_TYPE_INVALID)))
	{							
		eag_log_err("eag_dbus_method_set_flux_from "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_flux_from %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	eagins->flux_from  = flux_from;
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_flux_interval(
				DBusConnection *conn,
				DBusMessage *msg,
				void *user_data)
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int flux_interval = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_flux_interval "
					"DBUS new reply message error");
		return NULL;
	}
	
	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_set_flux_interval user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &flux_interval,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_flux_interval "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_flux_interval %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	eagins->flux_interval = flux_interval;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_ipset_auth(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_captive_t *cap = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int ipset_auth = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_ipset_auth "
					"DBUS new reply message error");
		return NULL;
	}

	cap = (eag_captive_t *)user_data;
	if (NULL == cap) {
		eag_log_err("eag_dbus_method_set_ipset_auth user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &ipset_auth,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_ipset_auth "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_ipset_auth %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = eag_captive_set_ipset(cap, ipset_auth);
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_check_nasportid(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	appconn_db_t *appdb = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int check_nasportid = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_check_nasportid "
					"DBUS new reply message error");
		return NULL;
	}

	appdb = (appconn_db_t *)user_data;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_set_check_nasportid user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &check_nasportid,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_check_nasportid "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_check_nasportid %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = appconn_db_set_check_nasportid(appdb, check_nasportid);
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_trap_onlineusernum_switch(
											DBusConnection *conn, 
											DBusMessage *msg, 
											void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	int ret = EAG_RETURN_OK;
	int switch_t = 0;
	reply = dbus_message_new_method_return(msg);
	
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_trap_onlineusernum_switch "\
					"DBUS new reply message error!\n");
		return NULL;
	}
	eagins = (eag_ins_t *)user_data;
	if ( NULL == eagins ){
		eag_log_err("eag_dbus_method_set_trap_onlineusernum_switch user_data eagins error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	dbus_error_init(&err);
	
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &switch_t,		
								DBUS_TYPE_INVALID)))
	{							
		eag_log_err("eag_dbus_method_set_trap_onlineusernum_switch "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_trap_onlineusernum_switch %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	eagins->trap_onlineusernum_switch = switch_t;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	
	return reply;
}

DBusMessage *
eag_dbus_method_set_threshold_onlineusernum(
											DBusConnection *conn, 
											DBusMessage *msg, 
											void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	int ret = EAG_RETURN_OK;
	int num = 0;
	reply = dbus_message_new_method_return(msg);
	
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_threshold_onlineusernum "\
					"DBUS new reply message error!\n");
		return NULL;
	}
	eagins = (eag_ins_t *)user_data;
	if ( NULL == eagins ){
		eag_log_err("eag_dbus_method_set_threshold_onlineusernum user_data eagins error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	dbus_error_init(&err);
	
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &num,		
								DBUS_TYPE_INVALID)))
	{							
		eag_log_err("eag_dbus_method_set_threshold_onlineusernum "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_threshold_onlineusernum %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	eagins->threshold_onlineusernum = num;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	
	return reply;
}

DBusMessage *
eag_dbus_method_set_octets_correct_factor(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	appconn_db_t *appdb = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	uint32_t input_correct_factor = 0;
	uint32_t output_correct_factor = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_octets_correct_factor "
					"DBUS new reply message error");
		return NULL;
	}
	
	appdb = (appconn_db_t *)user_data;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_set_octets_correct_factor user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &input_correct_factor,
								DBUS_TYPE_UINT32, &output_correct_factor,
								DBUS_TYPE_INVALID)))
	{							
		eag_log_err("eag_dbus_method_set_octets_correct_factor "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_octets_correct_factor %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	ret = appconn_db_set_correct_factor(appdb, 
			input_correct_factor, output_correct_factor);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	
	return reply;
}

DBusMessage *
eag_dbus_method_set_service_status(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	int status = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_service_status "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_set_service_status user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &status,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_service_status "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_service_status %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	if (1 == status) {
		ret = eag_ins_start(eagins);
	} else {
		ret = eag_ins_stop(eagins);
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_check_status(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	//int status = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_check_state "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_check_state user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	//status = eagins->status;
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_UINT32, &ret);
	/*
	if (EAG_RETURN_OK == ret) {
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &status);
	}
	*/
	return reply;
}

DBusMessage *
eag_dbus_method_get_base_conf(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	//int rdcpdc_slotid = 0;
	//int rdcpdc_insid = 0;
	int rdc_slotid = 0;
	int rdc_insid = 0;
	int pdc_slotid = 0;
	int pdc_insid = 0;
	uint16_t portal_port = 0;
	int portal_retry_times = 0;
	int portal_retry_interval = 0;
	int auto_session = 0;
	
	int acct_interval = 0;
	int retry_interval = 0;
	int retry_times = 0;
	int vice_retry_times = 0;
	
	int max_redir_times = 0;
	int force_dhcplease = 0;
	int check_errid = 0;
	
	unsigned long idle_timeout = 0;
	uint64_t idle_flow = 0;
	int force_wireless = 0;
	uint32_t input_correct_factor = 0;
	uint32_t output_correct_factor = 0;
	int ipset_auth = 0;
	int check_nasportid = 0;
	int trap_onlineusernum_switch = 0;
	int threshold_onlineusernum = 0;
	int portal_protocol = 0;
	int macauth_switch = 0;
	int macauth_type = 0;
	int macauth_ipset_auth = 0;
	int macauth_flux_from = 0;
	int macauth_flux_interval = 0;
	int macauth_flux_threshold = 0;
    int macauth_check_interval = 0;
	int notice_bindserver = 0;
	int autelan_log = 0;
	int henan_log = 0;
	int username_check = 0;
	int l2super_vlan = 0;
	int telecom_idletime_check = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_get_base_conf "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_get_base_conf user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	if (EAG_RETURN_OK == ret) {
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &(eagins->status));
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_UINT32, &(eagins->nasip));
		/* dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &(eagins->is_distributed)); */
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &(eagins->rdc_distributed));
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &(eagins->pdc_distributed));
        rdc_get_server_hansi(&rdc_slotid, &rdc_insid);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &rdc_slotid);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &rdc_insid);
		pdc_get_server_hansi(&pdc_slotid, &pdc_insid);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &pdc_slotid);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &pdc_insid);
		/* pdc_get_server_hansi(&rdcpdc_slotid, &rdcpdc_insid);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &rdcpdc_slotid);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &rdcpdc_insid); */
		
		portal_port = eag_portal_get_portal_port(eagins->portal);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_UINT16, &portal_port);
		eag_portal_get_retry_params(eagins->portal, &portal_retry_interval,
							&portal_retry_times);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &portal_retry_times);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &portal_retry_interval);
		auto_session = eag_portal_get_auto_session(eagins->portal);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &auto_session);

		acct_interval = eag_radius_get_acct_interval(eagins->radius);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &acct_interval);
		eag_radius_get_retry_params(eagins->radius, &retry_interval,
				&retry_times, &vice_retry_times);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &retry_interval);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &retry_times);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &vice_retry_times);

		eag_redir_get_max_redir_times(eagins->redir, &max_redir_times);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &max_redir_times);
		force_dhcplease = eag_redir_get_force_dhcplease(eagins->redir);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &force_dhcplease);
		check_errid = eag_portal_get_check_errid(eagins->portal);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &check_errid);
		
		appconn_db_get_idle_params(eagins->appdb, &idle_timeout, &idle_flow);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_UINT32, &idle_timeout);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_UINT64, &idle_flow);
		force_wireless = appconn_db_get_force_wireless(eagins->appdb);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &force_wireless);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &(eagins->flux_from));
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &(eagins->flux_interval));
		appconn_db_get_correct_factor(eagins->appdb, &input_correct_factor, 
					&output_correct_factor);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_UINT32, &input_correct_factor);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_UINT32, &output_correct_factor);

		ipset_auth = eag_captive_get_ipset(eagins->captive);
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &ipset_auth);
		check_nasportid = appconn_db_get_check_nasportid(eagins->appdb);
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &check_nasportid);
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &(eagins->trap_switch_abnormal_logoff));
		trap_onlineusernum_switch = eagins->trap_onlineusernum_switch;
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &trap_onlineusernum_switch);
		threshold_onlineusernum = eagins->threshold_onlineusernum;
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &threshold_onlineusernum);
		portal_protocol = portal_get_protocol_type();
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &portal_protocol);
		macauth_switch = eag_macauth_get_macauth_switch(eagins->macauth);
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &macauth_switch);
		macauth_type = eag_macauth_type;
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &macauth_type);
		macauth_ipset_auth = eag_captive_get_macauth_ipset(eagins->captive);
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &macauth_ipset_auth);
		macauth_flux_from = eag_macauth_get_flux_from(eagins->macauth);
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &macauth_flux_from);
		macauth_flux_interval = eag_macauth_get_flux_interval(eagins->macauth);
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &macauth_flux_interval);
		macauth_flux_threshold = eag_macauth_get_flux_threshold(eagins->macauth);
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &macauth_flux_threshold);
        macauth_check_interval = eag_macauth_get_check_interval(eagins->macauth);
        dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &macauth_check_interval);
		notice_bindserver = notice_to_bindserver;
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &notice_bindserver);
		autelan_log = autelan_log_switch;
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &autelan_log);
		henan_log = henan_log_switch;
		dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &henan_log);
		username_check = username_check_switch;
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &username_check);
		l2super_vlan= l2super_vlan_switch_t;
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &l2super_vlan);
		telecom_idletime_check = idletime_valuecheck;
		dbus_message_iter_append_basic(&iter, 
								DBUS_TYPE_INT32, &telecom_idletime_check);
	}
	
	return reply;
}

DBusMessage *
eag_dbus_method_show_relative_time(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	struct timeval tv_now = {0};
	unsigned long timenow = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_show_relative_time "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_show_relative_time user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	if (EAG_RETURN_OK == ret) {
		eag_time_gettimeofday(&tv_now, NULL);
		timenow = tv_now.tv_sec;
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &timenow);
	}
	
	return reply;
}
#if 0
DBusMessage *
eag_dbus_method_add_nasid(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	struct nasid_conf *nasidconf = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long keytype = 0;
	unsigned long keywd_1 = 0;
	unsigned long keywd_2 = 0;
	char        *keystr = NULL;
	char 	*nasid = NULL;
	unsigned long conid = 0;
	
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_add_nasid "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	nasidconf = (struct nasid_conf *)user_data;
	if( NULL == nasidconf ){
		eag_log_err("eag_dbus_method_add_nasid user_data error!");
		//return reply;
		ret = EAG_ERR_NULL_POINTER;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
									DBUS_TYPE_UINT32, &keywd_1,
									DBUS_TYPE_UINT32, &keywd_2,
									DBUS_TYPE_STRING, &keystr,
								DBUS_TYPE_STRING, &nasid,
								DBUS_TYPE_UINT32, &conid,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_add_nasid "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_add_nasid %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	switch(keytype){
		case NASID_KEYTYPE_WLANID:
			ret=nasid_conf_add_map(nasidconf, keytype, &keywd_1, nasid, conid);
			break;
		case NASID_KEYTYPE_VLANID:
			ret=nasid_conf_add_map(nasidconf, keytype, &keywd_1, nasid, conid);
			break;
		case NASID_KEYTYPE_WTPID:
			ret=nasid_conf_add_map(nasidconf, keytype, &keywd_1, nasid, conid);
			break;
		case NASID_KEYTYPE_IPRANGE:
			{
				struct iprange_t iprange;
				memset (&iprange, 0 , sizeof(struct iprange_t));
				iprange.ip_begin = keywd_1;
				iprange.ip_end = keywd_2;
				ret=nasid_conf_add_map(nasidconf, keytype, &iprange, nasid, conid);
			}
			break;
		case NASID_KEYTYPE_INTF:
			ret=nasid_conf_add_map(nasidconf, keytype, keystr, nasid, conid);
			break;
		default:
			eag_log_err("eag_dbus_method_add_nasid: keytype error!");
			ret=EAG_ERR_UNKNOWN;
			break;
	}

	if (EAG_RETURN_OK!=ret){
		eag_log_err("eag_dbus_method_add_nasid: "
							"nasid_conf_add_map error return %d\n",ret);
	}
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_get_nasid(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	struct nasid_conf *nasidconf=NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusMessageIter iter_array = {0};
	DBusError		err = {0};
	
	unsigned long num = 0;
	unsigned int i=0;
	unsigned long placeholder_int=0;
	char *placeholder_str="";	//dbus placeholder must not be NULL
	char *nasid=NULL;
	char *keystr=NULL;
	
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_get_nasid "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	nasidconf = (struct nasid_conf *)user_data;
	if( NULL == nasidconf ){
		eag_log_err("eag_dbus_method_get_nasid user_data error!");
		ret = EAG_ERR_NULL_POINTER;
		goto replyx;
	}
	
	dbus_error_init(&err);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32, &(nasidconf->current_num));

	num = nasidconf->current_num;
	if (0==num){
		goto out;
	}

	dbus_message_iter_open_container (&iter,
									   DBUS_TYPE_ARRAY,
									   DBUS_STRUCT_BEGIN_CHAR_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
												DBUS_TYPE_UINT32_AS_STRING
												DBUS_TYPE_UINT32_AS_STRING
												DBUS_TYPE_STRING_AS_STRING
											DBUS_TYPE_STRING_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
									   DBUS_STRUCT_END_CHAR_AS_STRING,
									   &iter_array);
	DBusMessageIter iter_struct;
	for( i=0; i<num; i++ ){
		dbus_message_iter_open_container (&iter_array,
										DBUS_TYPE_STRUCT,
										NULL,
										&iter_struct);
			
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key_type);
			switch(nasidconf->nasid_map[i].key_type){						
				case NASID_KEYTYPE_WLANID:
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.wlanid);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &placeholder_int);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &placeholder_str);
					break;
				case NASID_KEYTYPE_VLANID:
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.vlanid);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &placeholder_int);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &placeholder_str);
					break;
				case NASID_KEYTYPE_WTPID:
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.wtpid);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &placeholder_int);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &placeholder_str);
					break;
				case NASID_KEYTYPE_IPRANGE:
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.iprange.ip_begin);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.iprange.ip_end);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &placeholder_str);
					break;
				case NASID_KEYTYPE_INTF:
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &placeholder_int);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &placeholder_int);
					keystr=nasidconf->nasid_map[i].key.intf;
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &keystr);
					break;
				default:
					eag_log_err("eag_dbus_method_get_nasid nasid_type error!\n");
					ret = EAG_ERR_UNKNOWN;
					goto error_1;
					break;
				}
			nasid=nasidconf->nasid_map[i].nasid;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &nasid);

			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].conid);			

			dbus_message_iter_close_container (&iter_array, &iter_struct);

		}
	dbus_message_iter_close_container (&iter, &iter_array);
	
out:
	return reply;

error_1:
	dbus_message_iter_close_container (&iter_array, &iter_struct);
	dbus_message_iter_close_container (&iter, &iter_array);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);

	return reply;	
}

DBusMessage *
eag_dbus_method_del_nasid(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	struct nasid_conf *nasidconf=NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long keytype=0;
	unsigned long keywd_1=0;
	unsigned long keywd_2=0;
	char		*keystr=NULL;
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_add_nasid "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	nasidconf = (struct nasid_conf *)user_data;
	if( NULL == nasidconf ){
		eag_log_err("eag_dbus_method_add_nasid user_data error!");
		//return reply;
		ret = EAG_ERR_NULL_POINTER;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
									DBUS_TYPE_UINT32, &keywd_1,
									DBUS_TYPE_UINT32, &keywd_2,
									DBUS_TYPE_STRING, &keystr,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_add_nasid "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_add_nasid %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	switch(keytype){
		case NASID_KEYTYPE_WLANID:
			ret = nasid_conf_del_map(nasidconf, keytype, &keywd_1);
			break;
		case NASID_KEYTYPE_VLANID:
			ret = nasid_conf_del_map(nasidconf, keytype, &keywd_1);
			break;
		case NASID_KEYTYPE_WTPID:
			ret = nasid_conf_del_map(nasidconf, keytype, &keywd_1);
			break;
		case NASID_KEYTYPE_IPRANGE:
			{
				struct iprange_t iprange;
				memset (&iprange, 0 , sizeof(struct iprange_t));
				iprange.ip_begin = keywd_1;
				iprange.ip_end = keywd_2;
				ret = nasid_conf_del_map(nasidconf, keytype, &iprange);
			}
			break;
		case NASID_KEYTYPE_INTF:
			ret = nasid_conf_del_map(nasidconf, keytype, keystr);
			break;
		default:
			eag_log_err("eag_dbus_method_del_nasid error unknown keytype!");
			ret=EAG_ERR_UNKNOWN;
			goto replyx;
			break;
	}

	if (EAG_RETURN_OK!=ret){
		eag_log_err("eag_dbus_method_del_nasid: "
							"nasid_conf_del_map error return %d\n",ret);
	}

	replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;

}
#endif

 /* nasid config for wlan range */
DBusMessage *
eag_dbus_method_add_nasid(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	struct nasid_conf *nasidconf=NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long keytype=0;
	unsigned long keywd_1=0;
	unsigned long keywd_2=0;
	char        *keystr=NULL;
	char 	*nasid=NULL;
	unsigned long conid=0;
	
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_add_nasid "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	nasidconf = (struct nasid_conf *)user_data;
	if( NULL == nasidconf ){
		eag_log_err("eag_dbus_method_add_nasid user_data error!");
		//return reply;
		ret = EAG_ERR_NULL_POINTER;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
									DBUS_TYPE_UINT32, &keywd_1,
									DBUS_TYPE_UINT32, &keywd_2,
									DBUS_TYPE_STRING, &keystr,
								DBUS_TYPE_STRING, &nasid,
								DBUS_TYPE_UINT32, &conid,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_add_nasid "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_add_nasid %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	switch(keytype){
		case NASID_KEYTYPE_WLANID:
			{
				struct idrange_t wlanid_range;
				memset (&wlanid_range, 0 , sizeof(struct idrange_t));
				wlanid_range.id_begin = keywd_1;
				wlanid_range.id_end = keywd_2;
				ret=nasid_conf_add_map(nasidconf, keytype, &wlanid_range, nasid, conid);
			}
			break;
		case NASID_KEYTYPE_VLANID:
			{
				struct idrange_t vlanid_range;
				memset (&vlanid_range, 0 , sizeof(struct idrange_t));
				vlanid_range.id_begin = keywd_1;
				vlanid_range.id_end = keywd_2;
				ret=nasid_conf_add_map(nasidconf, keytype, &vlanid_range, nasid, conid);
			}
			break;
		case NASID_KEYTYPE_WTPID:
			{
				struct idrange_t wtpid_range;
				memset (&wtpid_range, 0 , sizeof(struct idrange_t));
				wtpid_range.id_begin = keywd_1;
				wtpid_range.id_end = keywd_2;
				ret=nasid_conf_add_map(nasidconf, keytype, &wtpid_range, nasid, conid);
			}
			break;
		case NASID_KEYTYPE_IPRANGE:
			{
				struct iprange_t iprange;
				memset (&iprange, 0 , sizeof(struct iprange_t));
				iprange.ip_begin = keywd_1;
				iprange.ip_end = keywd_2;
				ret=nasid_conf_add_map(nasidconf, keytype, &iprange, nasid, conid);
			}
			break;
		case NASID_KEYTYPE_INTF:
			ret=nasid_conf_add_map(nasidconf, keytype, keystr, nasid, conid);
			break;
		default:
			eag_log_err("eag_dbus_method_add_nasid: keytype error!");
			ret=EAG_ERR_UNKNOWN;
			break;
	}

	if (EAG_RETURN_OK!=ret){
		eag_log_err("eag_dbus_method_add_nasid: "
							"nasid_conf_add_map error return %d\n",ret);
	}
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_modify_nasid(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	struct nasid_conf *nasidconf=NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long keytype=0;
	unsigned long keywd_1=0;
	unsigned long keywd_2=0;
	char        *keystr=NULL;
	char 	*nasid=NULL;
	unsigned long conid=0;
	
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_add_nasid "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	nasidconf = (struct nasid_conf *)user_data;
	if( NULL == nasidconf ){
		eag_log_err("eag_dbus_method_add_nasid user_data error!");
		//return reply;
		ret = EAG_ERR_NULL_POINTER;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keywd_1,
								DBUS_TYPE_UINT32, &keywd_2,
								DBUS_TYPE_STRING, &keystr,
								DBUS_TYPE_STRING, &nasid,
								DBUS_TYPE_UINT32, &conid,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_add_nasid "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_add_nasid %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	switch(keytype){
		case NASID_KEYTYPE_WLANID:
			{
				struct idrange_t wlanid_range;
				memset (&wlanid_range, 0 , sizeof(struct idrange_t));
				wlanid_range.id_begin = keywd_1;
				wlanid_range.id_end = keywd_2;
				ret=nasid_conf_modify_map(nasidconf, keytype, &wlanid_range, nasid, conid);
			}
			break;
		case NASID_KEYTYPE_VLANID:
			{
				struct idrange_t vlanid_range;
				memset (&vlanid_range, 0 , sizeof(struct idrange_t));
				vlanid_range.id_begin = keywd_1;
				vlanid_range.id_end = keywd_2;
				ret=nasid_conf_modify_map(nasidconf, keytype, &vlanid_range, nasid, conid);
			}
			break;
		case NASID_KEYTYPE_WTPID:
			{
				struct idrange_t wtpid_range;
				memset (&wtpid_range, 0 , sizeof(struct idrange_t));
				wtpid_range.id_begin = keywd_1;
				wtpid_range.id_end = keywd_2;
				ret=nasid_conf_modify_map(nasidconf, keytype, &wtpid_range, nasid, conid);
			}
			break;
		case NASID_KEYTYPE_IPRANGE:
			{
				struct iprange_t iprange;
				memset (&iprange, 0 , sizeof(struct iprange_t));
				iprange.ip_begin = keywd_1;
				iprange.ip_end = keywd_2;
				ret=nasid_conf_modify_map(nasidconf, keytype, &iprange, nasid, conid);
			}
			break;
		case NASID_KEYTYPE_INTF:
			ret=nasid_conf_modify_map(nasidconf, keytype, keystr, nasid, conid);
			break;
		default:
			eag_log_err("eag_dbus_method_add_nasid: keytype error!");
			ret=EAG_ERR_UNKNOWN;
			break;
	}

	if (EAG_RETURN_OK!=ret){
		eag_log_err("eag_dbus_method_add_nasid: "
							"nasid_conf_add_map error return %d\n",ret);
	}
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_get_nasid(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	struct nasid_conf *nasidconf=NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusMessageIter iter_array = {0};
	DBusError		err = {0};
	
	unsigned long num = 0;
	unsigned int i=0;
	unsigned long placeholder_int=0;
	char *placeholder_str="";	//dbus placeholder must not be NULL
	char *nasid=NULL;
	char *keystr=NULL;
	
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_get_nasid "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	nasidconf = (struct nasid_conf *)user_data;
	if( NULL == nasidconf ){
		eag_log_err("eag_dbus_method_get_nasid user_data error!");
		ret = EAG_ERR_NULL_POINTER;
		goto replyx;
	}
	
	dbus_error_init(&err);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32, &(nasidconf->current_num));

	num = nasidconf->current_num;
	if (0==num){
		goto out;
	}

	dbus_message_iter_open_container (&iter,
									   DBUS_TYPE_ARRAY,
									   DBUS_STRUCT_BEGIN_CHAR_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
												DBUS_TYPE_UINT32_AS_STRING
												DBUS_TYPE_UINT32_AS_STRING
												DBUS_TYPE_STRING_AS_STRING
											DBUS_TYPE_STRING_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
									   DBUS_STRUCT_END_CHAR_AS_STRING,
									   &iter_array);
	DBusMessageIter iter_struct;
	for( i=0; i<num; i++ ){
		dbus_message_iter_open_container (&iter_array,
										DBUS_TYPE_STRUCT,
										NULL,
										&iter_struct);
			
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key_type);
			switch(nasidconf->nasid_map[i].key_type){						
				case NASID_KEYTYPE_WLANID:
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.wlanidrange.id_begin);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.wlanidrange.id_end);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &placeholder_str);
					break;
				case NASID_KEYTYPE_VLANID:
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.vlanidrange.id_begin);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.vlanidrange.id_end);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &placeholder_str);
					break;
				case NASID_KEYTYPE_WTPID:
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.wtpidrange.id_begin);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.wtpidrange.id_end);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &placeholder_str);
					break;
				case NASID_KEYTYPE_IPRANGE:
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.iprange.ip_begin);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].key.iprange.ip_end);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &placeholder_str);
					break;
				case NASID_KEYTYPE_INTF:
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &placeholder_int);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_UINT32, &placeholder_int);
					keystr=nasidconf->nasid_map[i].key.intf;
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &keystr);
					break;
				default:
					eag_log_err("eag_dbus_method_get_nasid nasid_type error!\n");
					ret = EAG_ERR_UNKNOWN;
					goto error_1;
					break;
				}
			nasid=nasidconf->nasid_map[i].nasid;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &nasid);

			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &nasidconf->nasid_map[i].conid);			

			dbus_message_iter_close_container (&iter_array, &iter_struct);

		}
	dbus_message_iter_close_container (&iter, &iter_array);
	
out:
	return reply;

error_1:
	dbus_message_iter_close_container (&iter_array, &iter_struct);
	dbus_message_iter_close_container (&iter, &iter_array);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);

	return reply;	
}


DBusMessage *
eag_dbus_method_del_nasid(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	struct nasid_conf *nasidconf=NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long keytype=0;
	unsigned long keywd_1=0;
	unsigned long keywd_2=0;
	char		*keystr=NULL;
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_add_nasid "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	nasidconf = (struct nasid_conf *)user_data;
	if( NULL == nasidconf ){
		eag_log_err("eag_dbus_method_add_nasid user_data error!");
		//return reply;
		ret = EAG_ERR_NULL_POINTER;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
									DBUS_TYPE_UINT32, &keywd_1,
									DBUS_TYPE_UINT32, &keywd_2,
									DBUS_TYPE_STRING, &keystr,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_add_nasid "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_add_nasid %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	switch(keytype){
		case NASID_KEYTYPE_WLANID:
			{
				struct idrange_t wlanid_range;
				memset (&wlanid_range, 0 , sizeof(struct idrange_t));
				wlanid_range.id_begin = keywd_1;
				wlanid_range.id_end = keywd_2;
				ret=nasid_conf_del_map(nasidconf, keytype, &wlanid_range);
			}
			break;
		case NASID_KEYTYPE_VLANID:
			{
				struct idrange_t vlanid_range;
				memset (&vlanid_range, 0 , sizeof(struct idrange_t));
				vlanid_range.id_begin = keywd_1;
				vlanid_range.id_end = keywd_2;
				ret=nasid_conf_del_map(nasidconf, keytype, &vlanid_range);
			}
			break;
		case NASID_KEYTYPE_WTPID:
			{
				struct idrange_t wtpid_range;
				memset (&wtpid_range, 0 , sizeof(struct idrange_t));
				wtpid_range.id_begin = keywd_1;
				wtpid_range.id_end = keywd_2;
				ret=nasid_conf_del_map(nasidconf, keytype, &wtpid_range);
			}
			break;
		case NASID_KEYTYPE_IPRANGE:
			{
				struct iprange_t iprange;
				memset (&iprange, 0 , sizeof(struct iprange_t));
				iprange.ip_begin = keywd_1;
				iprange.ip_end = keywd_2;
				ret = nasid_conf_del_map(nasidconf, keytype, &iprange);
			}
			break;
		case NASID_KEYTYPE_INTF:
			ret = nasid_conf_del_map(nasidconf, keytype, keystr);
			break;
		default:
			eag_log_err("eag_dbus_method_del_nasid error unknown keytype!");
			ret=EAG_ERR_UNKNOWN;
			goto replyx;
			break;
	}

	if (EAG_RETURN_OK!=ret){
		eag_log_err("eag_dbus_method_del_nasid: "
							"nasid_conf_del_map error return %d\n",ret);
	}

	replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;

}

DBusMessage *
eag_dbus_method_add_nasportid(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	struct nasportid_conf *nasportidconf=NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long wlanid_begin = 0;
	unsigned long wlanid_end = 0;
	unsigned long wtpid_begin = 0;
	unsigned long wtpid_end = 0;
	unsigned long vlanid_begin = 0;
	unsigned long vlanid_end = 0;
	unsigned long nasportid = 0;
	unsigned long key_type = 0;
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_add_nasportid "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	nasportidconf = (struct nasportid_conf *)user_data;
	if( NULL == nasportidconf ){
		eag_log_err("eag_dbus_method_add_nasportid user_data error!");
		//return reply;
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &wlanid_begin,
								DBUS_TYPE_UINT32, &wlanid_end,
								DBUS_TYPE_UINT32, &wtpid_begin,
								DBUS_TYPE_UINT32, &wtpid_end,
								DBUS_TYPE_UINT32, &vlanid_begin,
								DBUS_TYPE_UINT32, &vlanid_end,
								DBUS_TYPE_UINT32, &nasportid,
								DBUS_TYPE_UINT32, &key_type,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_add_nasportid "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_add_nasportid %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	switch(key_type) {
	case NASPORTID_KEYTYPE_WLAN_WTP:
		ret = nasportid_conf_add_map_by_wlan(nasportidconf, wlanid_begin, wlanid_end, wtpid_begin, wtpid_end, nasportid);
		break;
	case NASPORTID_KEYTYPE_VLAN:
		ret = nasportid_conf_add_map_by_vlan(nasportidconf, vlanid_begin, vlanid_end, nasportid);
		break;
	default:
		eag_log_warning("eag_dbus_method_add_nasportid: "
					"unknown nasportid type\n");
		break;
	}

	if (EAG_RETURN_OK != ret){
		eag_log_err("eag_dbus_method_add_nasportid: "
					"nasportid_conf_add_map_wlan error %d", ret);
	}
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;

}

DBusMessage *
eag_dbus_method_get_nasportid(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	struct nasportid_conf *nasportidconf=NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusMessageIter iter_array = {0};
	DBusError		err = {0};
	
	unsigned long num = 0;
	unsigned int i=0;
	
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_get_nasid "\
							"DBUS new reply message error!\n");
		return NULL;
	}

	nasportidconf = (struct nasportid_conf *)user_data;
	if( NULL == nasportidconf ){
		eag_log_err("eag_dbus_method_get_nasid user_data error!");
		//return reply;
		ret = EAG_ERR_NULL_POINTER;
		goto replyx;
	}
	
	dbus_error_init(&err);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32, &(nasportidconf->current_num));

	num=nasportidconf->current_num;
	if (0==num){
		goto out;
	}

	dbus_message_iter_open_container (&iter,
									   DBUS_TYPE_ARRAY,
									   DBUS_STRUCT_BEGIN_CHAR_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
									   DBUS_STRUCT_END_CHAR_AS_STRING,
									   &iter_array);
#if 1	
	for( i=0; i<num; i++ ){
		DBusMessageIter iter_struct;
		dbus_message_iter_open_container (&iter_array,
										DBUS_TYPE_STRUCT,
										NULL,
										&iter_struct);
			
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &nasportidconf->nasportid_map[i].key_type);

			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &nasportidconf->nasportid_map[i].key.wlan_wtp.wlanid_begin);

			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &nasportidconf->nasportid_map[i].key.wlan_wtp.wlanid_end);

			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &nasportidconf->nasportid_map[i].key.wlan_wtp.wtpid_begin);
			
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &nasportidconf->nasportid_map[i].key.wlan_wtp.wtpid_end);

			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &nasportidconf->nasportid_map[i].key.vlan.vlanid_begin);

			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &nasportidconf->nasportid_map[i].key.vlan.vlanid_end);
			
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &nasportidconf->nasportid_map[i].nasportid);

			dbus_message_iter_close_container (&iter_array, &iter_struct);

		}
#endif	
	dbus_message_iter_close_container (&iter, &iter_array);
	
out:
	return reply;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);

	return reply;
}

DBusMessage *
eag_dbus_method_del_nasportid(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	struct nasportid_conf *nasportidconf=NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long wlanid_begin = 0;
	unsigned long wlanid_end = 0;
	unsigned long wtpid_begin = 0;
	unsigned long wtpid_end = 0;
	unsigned long vlanid_begin = 0;
	unsigned long vlanid_end = 0;
	unsigned long nasportid = 0;
	unsigned long key_type = 0;
	
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_add_nasportid "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	nasportidconf = (struct nasportid_conf *)user_data;
	if( NULL == nasportidconf ){
		eag_log_err("eag_dbus_method_add_nasportid user_data error!");
		//return reply;
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &wlanid_begin,
								DBUS_TYPE_UINT32, &wlanid_end,
								DBUS_TYPE_UINT32, &wtpid_begin,
								DBUS_TYPE_UINT32, &wtpid_end,
								DBUS_TYPE_UINT32, &vlanid_begin,
								DBUS_TYPE_UINT32, &vlanid_end,
								DBUS_TYPE_UINT32, &nasportid,
								DBUS_TYPE_UINT32, &key_type,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_add_nasportid "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_add_nasportid %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	
	switch(key_type) {
		case NASPORTID_KEYTYPE_WLAN_WTP:
			ret = nasportid_conf_del_map_by_wlan(nasportidconf, wlanid_begin, wlanid_end, wtpid_begin, wtpid_end, nasportid);
			break;
		case NASPORTID_KEYTYPE_VLAN:
			ret = nasportid_conf_del_map_by_vlan(nasportidconf, vlanid_begin, vlanid_end, nasportid);
			break;
		default:
			eag_log_warning("eag_dbus_method_del_nasportid: "
						"unknown nasportid type\n");
			break;
		}


	if (EAG_RETURN_OK != ret){
		eag_log_err("eag_dbus_method_del_nasportid: "
							"nasportid_conf_del_map error %d",ret);
	}
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;

}

DBusMessage *
eag_dbus_method_add_captive_intf(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	char *intfs = NULL;
	int ret = -1;
	eag_log_info("eag_dbus_method_add_captive_intfs");

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_add_captive_intfs "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins 
		|| NULL == eagins->captive){
		eag_log_err("eag_dbus_method_add_captive_intfs user_data error!");
		//return reply;
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_STRING, &intfs,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_add_captive_intfs "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_add_captive_intfs %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	eag_log_info("eag add captive intf %s", intfs );
	ret = eag_captive_add_interface( eagins->captive, intfs );

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_del_captive_intf(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	char *intfs = NULL;
	int ret = -1;
	eag_log_info("eag_dbus_method_del_captive_intfs");
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_del_captive_intfs "\
					"DBUS new reply message error!\n");
		return NULL;
	}
	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins 
		|| NULL == eagins->captive){
		eag_log_err("eag_dbus_method_del_captive_intfs user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_STRING, &intfs,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_del_captive_intfs "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_del_captive_intfs %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	
	eag_log_info("eag del captive intf %s", intfs );
	ret = eag_captive_del_interface( eagins->captive, intfs );
	terminate_appconn_by_interface(eagins,intfs);
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_add_captive_tag(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	uint32_t tag = 0;
	int ret = -1;
	eag_log_info("eag_dbus_method_add_captive_tag");

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_add_captive_tag "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins 
		|| NULL == eagins->captive){
		eag_log_err("eag_dbus_method_add_captive_tag user_data error!");
		//return reply;
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &tag,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_add_captive_tag "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_add_captive_tag %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	eag_log_info("eag add captive tag %u", tag);
	ret = eag_captive_add_tag(eagins->captive, tag);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_del_captive_tag(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	uint32_t tag = 0;
	int ret = -1;
	eag_log_info("eag_dbus_method_del_captive_tag");
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_del_captive_tag "\
					"DBUS new reply message error!\n");
		return NULL;
	}
	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins 
		|| NULL == eagins->captive){
		eag_log_err("eag_dbus_method_del_captive_tag user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &tag,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_del_captive_tag "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_del_captive_tag %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	
	eag_log_info("eag del captive tag %u", tag);
	ret = eag_captive_del_tag(eagins->captive, tag);
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_add_portal(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long keytype = 0;
	unsigned long  keyid = 0;/*key 为wlanid等*/
	char *keystr = NULL;/*key 为ssid或者借口名等*/
	char *portal_url = NULL;
	unsigned short ntfport = 0;
	char *domain = NULL;
	uint32_t mac_server_ip = 0;
	uint16_t mac_server_port = 0;
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_add_portal "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins){
		eag_log_err("eag_dbus_method_add_portal user_data error!");
		//return reply;
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keystr,
								DBUS_TYPE_STRING, &portal_url,
								DBUS_TYPE_UINT16, &ntfport,
								DBUS_TYPE_STRING, &domain,
								DBUS_TYPE_UINT32, &mac_server_ip,
								DBUS_TYPE_UINT16, &mac_server_port,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_add_portal "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_add_portal %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	eag_log_debug("eag_portal", "keytype:%lu, keyid:%lu, keystr:%s, url:%s, port:%hu",
		keytype, keyid, keystr, portal_url, ntfport);		

	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		if( NULL != portal_srv_get_by_key(&(eagins->portalconf),keytype,keystr) ){
			ret = EAG_ERR_PORTAL_ADD_SRV_KEY_EXIST;
			goto replyx;
		}		
		ret = portal_conf_add_srv( &(eagins->portalconf),
						keytype,keystr,portal_url,ntfport,domain,
						mac_server_ip, mac_server_port);
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		if( NULL != portal_srv_get_by_key(&(eagins->portalconf),keytype,&keyid) ){
			ret = EAG_ERR_PORTAL_ADD_SRV_KEY_EXIST;
			goto replyx;
		}			
		ret = portal_conf_add_srv( &(eagins->portalconf),
						keytype,&keyid,portal_url,ntfport,domain,
						mac_server_ip, mac_server_port);
		break;
	default:
		ret = EAG_ERR_PORTAL_ADD_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_modify_portal(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long keytype;
	unsigned long  keyid;/*key 为wlanid等*/
	char          *keystr = NULL;/*key 为ssid或者借口名等*/
	char 		  *portal_url = NULL;
	unsigned short ntfport = 0;
	char		  *domain = NULL;
	uint32_t mac_server_ip = 0;
	uint16_t mac_server_port = 0;
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_modify_portal "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins ){
		eag_log_err("eag_dbus_method_modify_portal user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keystr,
								DBUS_TYPE_STRING, &portal_url,
								DBUS_TYPE_UINT16, &ntfport,
								DBUS_TYPE_STRING, &domain,
								DBUS_TYPE_UINT32, &mac_server_ip,
								DBUS_TYPE_UINT16, &mac_server_port,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_modify_portal "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_modify_portal %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	


	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		if( NULL == portal_srv_get_by_key(&(eagins->portalconf),keytype,keystr) ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}		
		ret = portal_conf_modify_srv( &(eagins->portalconf),
						keytype,keystr,portal_url,ntfport,domain,
						mac_server_ip, mac_server_port);
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		if( NULL == portal_srv_get_by_key(&(eagins->portalconf),keytype,&keyid) ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}			
		ret = portal_conf_modify_srv( &(eagins->portalconf),
						keytype,&keyid,portal_url,ntfport,domain,
						mac_server_ip, mac_server_port);		
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_del_portal(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long keytype;
	unsigned long  keyid;/*key 为wlanid等*/
	char *keystr = NULL;/*key 为ssid或者接口名等*/
	
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_del_portal "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins ){
		eag_log_err("eag_dbus_method_del_portal user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keystr,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_del_portal "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_del_portal %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		if( NULL == portal_srv_get_by_key(&(eagins->portalconf),keytype,keystr) ){
			ret = EAG_ERR_PORTAL_DEL_SRV_NOT_EXIST;
			goto replyx;
		}		
		ret = portal_conf_del_srv( &(eagins->portalconf),
						keytype,keystr );
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		if( NULL == portal_srv_get_by_key(&(eagins->portalconf),keytype,&keyid) ){
			ret = EAG_ERR_PORTAL_DEL_SRV_NOT_EXIST;
			goto replyx;
		}			
		ret = portal_conf_del_srv( &(eagins->portalconf),
						keytype,&keyid ); 	
		break;
	default:
		ret = EAG_ERR_PORTAL_DEL_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_get_portal_conf(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	struct portal_srv_t *portal_srv = NULL;
	unsigned long num = 0;	
	char key_tmp[128] = {0};
	memset(key_tmp, 0, 128);
	
	char *key = NULL;
	char *portal_url=NULL;
	char *domain=NULL;
	char *acname = NULL;
	int acip_to_url = 0;
	int usermac_to_url = 0;
	int clientmac_to_url = 0;
	int apmac_to_url = 0;
	int wlan_to_url = 0;
	int redirect_to_url = 0;
	int nasid_to_url = 0;
	int wlanparameter = 0;
	char *deskey = NULL;
	int wlanuserfirsturl = 0;
	char *url_suffix =NULL;
	char *secret = NULL;
	int wlanapmac = 0;
	int wlanusermac = 0;
	char *wlanusermac_deskey = NULL;
	int wisprlogin = 0;
	int mobile_urlparam = 0;
	int urlparam_add = 0;
	char *save_urlparam_config = NULL;
	char *macbind_server_domain = NULL;
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_get_portal_conf "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins ){
		eag_log_err("eag_dbus_method_get_portal_conf user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
		
	num = eagins->portalconf.current_num;	
	portal_srv = &(eagins->portalconf.portal_srv[0]);
	ret = EAG_RETURN_OK;
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);

	if( EAG_RETURN_OK == ret ){
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32, &num);
	}
	if( EAG_RETURN_OK == ret && num > 0 ){
		int i;
		DBusMessageIter  iter_array;
		dbus_message_iter_open_container (&iter,
									DBUS_TYPE_ARRAY,
									DBUS_STRUCT_BEGIN_CHAR_AS_STRING
									DBUS_TYPE_UINT32_AS_STRING/*key type*/
									DBUS_TYPE_STRING_AS_STRING/*key*/
									DBUS_TYPE_STRING_AS_STRING/*portal url*/
									DBUS_TYPE_UINT16_AS_STRING/*ntf port*/
									DBUS_TYPE_STRING_AS_STRING/*domain*/
									DBUS_TYPE_UINT32_AS_STRING/*ip*/
									DBUS_TYPE_STRING_AS_STRING/*acname*/
									DBUS_TYPE_INT32_AS_STRING/*ip_or_domain*/
									DBUS_TYPE_STRING_AS_STRING/*macbind_server_domain*/
									DBUS_TYPE_UINT32_AS_STRING/*mac bind server ip*/
									DBUS_TYPE_UINT16_AS_STRING/*mac bind server port*/
									DBUS_TYPE_INT32_AS_STRING/*acip to url*/			
        							DBUS_TYPE_INT32_AS_STRING/*usermac to url*/
									DBUS_TYPE_INT32_AS_STRING/*clientmac to url*/
									DBUS_TYPE_INT32_AS_STRING/*apmac to url*/
									DBUS_TYPE_INT32_AS_STRING/*wlan to url*/
									DBUS_TYPE_INT32_AS_STRING/*redirect to url*/
									DBUS_TYPE_INT32_AS_STRING/*nasid to url*/
									DBUS_TYPE_INT32_AS_STRING/*wlanparameter*/
									DBUS_TYPE_STRING_AS_STRING/*DES key*/
									DBUS_TYPE_INT32_AS_STRING/*wlanuserfirsturl*/
									DBUS_TYPE_STRING_AS_STRING/*url_suffix*/
									DBUS_TYPE_STRING_AS_STRING/*secret*/
									DBUS_TYPE_INT32_AS_STRING/*wlanapmac*/
									DBUS_TYPE_INT32_AS_STRING/*wlanusermac*/
									DBUS_TYPE_STRING_AS_STRING/*wlanusermac DES key*/
									DBUS_TYPE_INT32_AS_STRING/*wisprlogin 0(disable) 1(http) 2(https)*/
									DBUS_TYPE_INT32_AS_STRING/*mobile urlparam*/
									DBUS_TYPE_INT32_AS_STRING/*urlparam add*/
									DBUS_TYPE_STRING_AS_STRING/*save urlparam config*/
									DBUS_STRUCT_END_CHAR_AS_STRING,
									&iter_array);

		for( i=0; i<num; i++ ){
			DBusMessageIter iter_struct;
			dbus_message_iter_open_container (&iter_array,
										DBUS_TYPE_STRUCT,
										NULL,
										&iter_struct);
			
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &portal_srv[i].key_type);
			switch(portal_srv[i].key_type){						
				case PORTAL_KEYTYPE_ESSID:
					key = &(portal_srv[i].key.essid[0]);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &key);
					break;
				case PORTAL_KEYTYPE_WLANID:
					snprintf(key_tmp, sizeof(key_tmp)-1, "%u", portal_srv[i].key.wlanid);
					key = key_tmp;
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &key);
					break;
				case PORTAL_KEYTYPE_VLANID:
					snprintf(key_tmp, sizeof(key_tmp)-1, "%u", portal_srv[i].key.vlanid);
					key = key_tmp;
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &key);
					break;
				case PORTAL_KEYTYPE_WTPID:
					snprintf(key_tmp, sizeof(key_tmp)-1, "%u", portal_srv[i].key.wtpid);
					key = key_tmp;
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &key);
					break;
				case PORTAL_KEYTYPE_INTF:
					key = &(portal_srv[i].key.intf[0]);
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &key);
					break;
				default:
					key = "";
					dbus_message_iter_append_basic(&iter_struct, DBUS_TYPE_STRING, &key);
					break;
				}

			portal_url = portal_srv[i].portal_url;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &portal_url);

			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT16, &portal_srv[i].ntf_port);

			domain = portal_srv[i].domain;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &domain);			

			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &portal_srv[i].ip);

			acname = portal_srv[i].acname;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &acname);

			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &portal_srv[i].ip_or_domain);

			macbind_server_domain = portal_srv[i].macbind_server_domain;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &macbind_server_domain);

			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &portal_srv[i].mac_server_ip);

			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT16, &portal_srv[i].mac_server_port);

			acip_to_url = portal_srv[i].acip_to_url;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &acip_to_url);

			usermac_to_url = portal_srv[i].usermac_to_url;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &usermac_to_url);

			clientmac_to_url = portal_srv[i].clientmac_to_url;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &clientmac_to_url);
			
			apmac_to_url = portal_srv[i].apmac_to_url;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &apmac_to_url);
			
			wlan_to_url = portal_srv[i].wlan_to_url;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &wlan_to_url);
			
			redirect_to_url = portal_srv[i].redirect_to_url;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &redirect_to_url);

			nasid_to_url = portal_srv[i].nasid_to_url;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &nasid_to_url);

			wlanparameter = portal_srv[i].wlanparameter;
			deskey = portal_srv[i].deskey;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &wlanparameter);
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &deskey);

			wlanuserfirsturl = portal_srv[i].wlanuserfirsturl;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &wlanuserfirsturl);

			url_suffix = portal_srv[i].url_suffix;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &url_suffix);

			secret = portal_srv[i].secret;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &secret);

			wlanapmac = portal_srv[i].wlanapmac;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &wlanapmac);

			wlanusermac = portal_srv[i].wlanusermac;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &wlanusermac);
			wlanusermac_deskey = portal_srv[i].wlanusermac_deskey;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &wlanusermac_deskey);

			wisprlogin = portal_srv[i].wisprlogin;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &wisprlogin);

			mobile_urlparam = portal_srv[i].mobile_urlparam;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &mobile_urlparam);

			urlparam_add = portal_srv[i].urlparam_add;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &urlparam_add);

			save_urlparam_config = portal_srv[i].save_urlparam_config;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &save_urlparam_config);

			dbus_message_iter_close_container (&iter_array, &iter_struct);

		}
		dbus_message_iter_close_container (&iter, &iter_array);
	}
	
	return reply;
}

DBusMessage *
eag_dbus_method_set_macbind (
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int ip_or_domain = 0;
	char *domain = NULL;
	uint32_t macbind_server_ip = 0;
	uint16_t macbind_server_port = 0;
	struct portal_srv_t * portal_srv_t = NULL;
	struct in_addr addr = {0};
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_macbind "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_macbind user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32,  &ip_or_domain,
								DBUS_TYPE_STRING, &domain,
								DBUS_TYPE_UINT32, &macbind_server_ip,
								DBUS_TYPE_UINT16, &macbind_server_port,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_macbind "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_macbind %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype, keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype, &keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}			
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}

	if (MACBIND_SERVER_IP == ip_or_domain) {
	    portal_srv_t->mac_server_ip = macbind_server_ip;
	    portal_srv_t->mac_server_port = macbind_server_port;
	    portal_srv_t->ip_or_domain = MACBIND_SERVER_IP;
	} else if (MACBIND_SERVER_DOMAIN == ip_or_domain) {
	    portal_srv_t->mac_server_ip = macbind_server_ip;
	    portal_srv_t->mac_server_port = macbind_server_port;
	    portal_srv_t->ip_or_domain = MACBIND_SERVER_DOMAIN;
	    if (NULL != domain) {
	        strncpy(portal_srv_t->macbind_server_domain, domain, 
	                    sizeof(portal_srv_t->macbind_server_domain));
	    }
	} else {
		ret = EAG_ERR_UNKNOWN;
        goto replyx;
	}
	addr.s_addr = htonl(portal_srv_t->mac_server_ip);
	eag_log_info("set macbind server ip:%s, port:%u, domain:%s", 
					inet_ntoa(addr), 
					portal_srv_t->mac_server_port, 
					portal_srv_t->macbind_server_domain);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_acname(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	char		  *acname = NULL;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_acname "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_acname user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_STRING, &acname,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_acname "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_acname %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}		
		strncpy(portal_srv_t->acname, acname, MAX_MULTPORTAL_ACNAME_LEN-1);
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}			
		strncpy(portal_srv_t->acname, acname, MAX_MULTPORTAL_ACNAME_LEN-1);	
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_url_suffix(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	char		  *url_suffix = NULL;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_url_suffix "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_url_suffix user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_STRING, &url_suffix,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_url_suffix "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_url_suffix %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}		
		strncpy(portal_srv_t->url_suffix, url_suffix, MAX_PORTAL_URL_SUFFIX_LEN-1);
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}			
		strncpy(portal_srv_t->url_suffix, url_suffix, MAX_PORTAL_URL_SUFFIX_LEN-1);	
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_acip_to_url(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int acip_to_url = 0;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_acip_to_url "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_acip_to_url user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &acip_to_url,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_acip_to_url "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_acip_to_url %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}
		portal_srv_t->acip_to_url = acip_to_url;
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}	
		portal_srv_t->acip_to_url = acip_to_url;
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_nasid_to_url(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int nasid_to_url = 0;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_nasid_to_url "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_nasid_to_url user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &nasid_to_url,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_nasid_to_url "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_nasid_to_url %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}
		portal_srv_t->nasid_to_url = nasid_to_url;
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}	
		portal_srv_t->nasid_to_url = nasid_to_url;
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}


DBusMessage *
eag_dbus_method_set_wlanparameter(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int status = 0;
	char	*deskey = NULL;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_wlanparameter "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_wlanparameter user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &status,
								DBUS_TYPE_STRING, &deskey,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_wlanparameter "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_wlanparameter %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	if( NULL!=deskey && strlen(deskey)>MAX_DES_KEY_LEN ){
		ret = EAG_ERR_PORTAL_WLANPARAMTER_DESKEY_LEN_LIMITE;
		goto replyx;
	}

	if ( 1==status 
		 && (NULL==deskey || strlen(deskey)==0 ) )
	{
		ret = EAG_ERR_PORTAL_WLANPARAMTER_NOT_SET_DESKEY;
		goto replyx;
	}
	
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}

		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		goto replyx;
		break;
	}
	
	portal_srv_t->wlanparameter = status;
	memset( portal_srv_t->deskey, 0, sizeof(portal_srv_t->deskey));
	memcpy( portal_srv_t->deskey, deskey, 
					MIN(sizeof(portal_srv_t->deskey),strlen(deskey)));
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}


DBusMessage *
eag_dbus_method_set_wlanuserfirsturl(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int wlanuserfirsturl = 0;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_wlanuserfirsturl "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_wlanuserfirsturl user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &wlanuserfirsturl,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_wlanuserfirsturl "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_wlanuserfirsturl %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}
		portal_srv_t->wlanuserfirsturl = wlanuserfirsturl;
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}	
		portal_srv_t->wlanuserfirsturl = wlanuserfirsturl;
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_portal_secret(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	char		  *secret = NULL;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_portal_secret "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_portal_secret user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_STRING, &secret,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_portal_secret "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_portal_secret %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}
		memset(portal_srv_t->secret, 0, PORTAL_SECRETSIZE);
		strncpy(portal_srv_t->secret, secret, PORTAL_SECRETSIZE-1);
		portal_srv_t->secretlen = strlen(portal_srv_t->secret);
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}	
		memset(portal_srv_t->secret, 0, PORTAL_SECRETSIZE);
		strncpy(portal_srv_t->secret, secret, PORTAL_SECRETSIZE-1);
		portal_srv_t->secretlen = strlen(portal_srv_t->secret);	
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_wlanapmac(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int wlanapmac = 0;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_wlanapmac "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_wlanapmac user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &wlanapmac,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_wlanapmac "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_wlanapmac %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}
		portal_srv_t->wlanapmac = wlanapmac;
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}	
		portal_srv_t->wlanapmac = wlanapmac;
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_usermac_to_url(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int usermac_to_url = 0;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_acip_to_url "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_acip_to_url user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &usermac_to_url,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_acip_to_url "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_acip_to_url %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_DEL_SRV_NOT_EXIST;
			goto replyx;
		}
		portal_srv_t->usermac_to_url = usermac_to_url;
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}	
		portal_srv_t->usermac_to_url = usermac_to_url;
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_clientmac_to_url(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int clientmac_to_url = 0;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_clientmac_to_url "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_clientmac_to_url user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &clientmac_to_url,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_clientmac_to_url "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_clientmac_to_url %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_DEL_SRV_NOT_EXIST;
			goto replyx;
		}
		portal_srv_t->clientmac_to_url = clientmac_to_url;
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}	
		portal_srv_t->clientmac_to_url = clientmac_to_url;
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_apmac_to_url(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int apmac_to_url = 0;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_apmac_to_url "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_apmac_to_url user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &apmac_to_url,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_apmac_to_url "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_apmac_to_url %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_DEL_SRV_NOT_EXIST;
			goto replyx;
		}
		portal_srv_t->apmac_to_url = apmac_to_url;
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}	
		portal_srv_t->apmac_to_url = apmac_to_url;
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_wlan_to_url(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int wlan_to_url = 0;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_wlan_to_url "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_wlan_to_url user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &wlan_to_url,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_wlan_to_url "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_wlan_to_url %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_DEL_SRV_NOT_EXIST;
			goto replyx;
		}
		portal_srv_t->wlan_to_url = wlan_to_url;
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}	
		portal_srv_t->wlan_to_url = wlan_to_url;
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_redirect_to_url(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int redirect_to_url = 0;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_redirect_to_url "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_redirect_to_url user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &redirect_to_url,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_redirect_to_url "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_redirect_to_url %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_DEL_SRV_NOT_EXIST;
			goto replyx;
		}
		portal_srv_t->redirect_to_url = redirect_to_url;
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}	
		portal_srv_t->redirect_to_url = redirect_to_url;
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_wlanusermac(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int status = 0;
	char	*deskey = NULL;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_wlanusermac "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_wlanusermac user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &status,
								DBUS_TYPE_STRING, &deskey,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_wlanusermac "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_wlanusermac %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	if( NULL!=deskey && strlen(deskey)>MAX_DES_KEY_LEN ){
		ret = EAG_ERR_PORTAL_WLANPARAMTER_DESKEY_LEN_LIMITE;
		goto replyx;
	}

	if ( 1==status 
		 && (NULL==deskey || strlen(deskey)==0 ) )
	{
		ret = EAG_ERR_PORTAL_WLANPARAMTER_NOT_SET_DESKEY;
		goto replyx;
	}
	
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}

		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		goto replyx;
		break;
	}
	
	portal_srv_t->wlanusermac = status;
	memset( portal_srv_t->wlanusermac_deskey, 0, sizeof(portal_srv_t->wlanusermac_deskey));
	memcpy( portal_srv_t->wlanusermac_deskey, deskey, 
					MIN(sizeof(portal_srv_t->wlanusermac_deskey),strlen(deskey)));
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_wisprlogin(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int 		  status = 0;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_wisprlogin "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_wisprlogin user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &status,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_wisprlogin "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_wisprlogin %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	if (WISPR_URL_NO != status 
		&& WISPR_URL_HTTP != status
		&& WISPR_URL_HTTPS != status )
	{
		eag_log_err("eag_dbus_method_set_wisprlogin "\
					"error wispr url type!\n");	
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		goto replyx;
	}

	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_DEL_SRV_NOT_EXIST;
			goto replyx;
		}
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		goto replyx;
		break;
	}


	portal_srv_t->wisprlogin = status;


replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

/* url param begin*/
DBusMessage *
eag_dbus_method_set_mobile_urlparam(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int mobile_urlparam = 0;
	struct portal_srv_t * portal_srv_t = NULL;
	int ret = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_mobile_urlparam "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_mobile_urlparam user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INT32, &mobile_urlparam,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_mobile_urlparam "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_mobile_urlparam %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_DEL_SRV_NOT_EXIST;
			goto replyx;
		}
		portal_srv_t->mobile_urlparam = mobile_urlparam;
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}	
		portal_srv_t->mobile_urlparam = mobile_urlparam;
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		break;
	}
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

int
eag_urlparam_get_value( char *src, 
						char *name, 
						char *des, 
						int size )
{
	char *s = src;
	char *d = des;
	char *pos = NULL;
	int des_len = 0;
	
	if(des == NULL || src == NULL || name == NULL) {
		return 0;
	}
	memset(des, 0, size);
	pos = strstr(src, name);
	if (NULL == pos) {
		return 0;
	}

	for (s = pos + strlen(name); *s != ';' && '\0' != *s && '}' != *s; s++)
	{
		*d = *s;
		d++;
		des_len++;
		if (des_len+1 > size) {
            *d = '\0';
			break;
		}
	}
	*d = '\0';
	
	return 1;
}

/* like strcpy */
int
eag_urlparam_cover( char *des, 
					char *src )
{
	char *d = des;
	char *s = src;

	if(des == NULL || src == NULL) {
		return -1;
	}
	if(src != NULL && *src == '\0') {
		*d = '\0';
        return 0;
	}
	if(*src == ';') {
		s++;
	}
	if(*s == '\0') {
		*d = '\0';
        return 0;
	}
	while('\0' != *s) {
		*d = *s;
		d++;
		s++;
	}
	*d = '\0';
	
	return 0;
}

/* get value by name */
int
eag_urlparam_get_wispr_feature( struct urlparam_query_str_t *urlparam, 
								char *feature_str )
{
	char u_type[8] = "";
	char u_encode[8] = "";
	
	if (feature_str == NULL || urlparam == NULL) {
		return 0;
	}

	memset(u_type, 0, sizeof(u_type));
	memset(u_encode, 0, sizeof(u_encode));
    eag_log_debug("eag_urlparam", "eag_urlparam_get_wispr_feature begin:%s\n", feature_str);

	if (eag_urlparam_get_value(feature_str, "type=", u_type, sizeof(u_type))) {
		if (!strstr(u_type, "s")) { // https
			urlparam->wispr_type = UP_HTTP;
		} else {
			urlparam->wispr_type = UP_HTTPS;
		}
	}
	if (eag_urlparam_get_value(feature_str, "encode=", u_encode, sizeof(u_encode))) {
		if (strstr(u_encode, "off") || strstr(u_type, "dis")) { // off or disable
			urlparam->wispr_encode = UP_ENCODE_OFF;
		} else {
			urlparam->wispr_encode = UP_ENCODE_ON;
		}
	}
	eag_urlparam_get_value(feature_str, "value=",  urlparam->wispr_value, 
							sizeof(urlparam->wispr_value));
	eag_log_debug("eag_urlparam", "eag_urlparam_get_wispr_feature end:wispr_type:%d, wispr_encode:%d, wispr_value:%s", 
        	urlparam->wispr_type, urlparam->wispr_encode, urlparam->wispr_value);
	
	return 0;
}

/* get value by name */
int
eag_urlparam_get_feature( struct url_param_t *param, 
							char *feature_str )
{
	char u_type[8] = "";
	char u_encode[8] = "";
	char m_letter[8] = "";
	
	if (feature_str == NULL || param == NULL) {
		return -1;
	}
	
	memset(u_type, 0, sizeof(u_type));
	memset(u_encode, 0, sizeof(u_encode));
	memset(m_letter, 0, sizeof(m_letter));
    eag_log_debug("eag_urlparam", "eag_urlparam_get_feature begin:%s\n", feature_str);
	if (eag_urlparam_get_value(feature_str, "type=", u_type, sizeof(u_type))) {
		if (!strstr(u_type, "https")) { // https
			param->url_type = UP_HTTP;
		} else {
			param->url_type = UP_HTTPS;
		}
	}
	if (eag_urlparam_get_value(feature_str, "encode=", u_encode, sizeof(u_encode))) {
		if (strstr(u_encode, "off") || strstr(u_type, "dis")) { // off or disable
			param->url_encode = UP_ENCODE_OFF;
		} else {
			param->url_encode = UP_ENCODE_ON;
		}
	}
	if (eag_urlparam_get_value(feature_str, "letter=", m_letter, sizeof(m_letter))) {
		if (strstr(m_letter, "l") || strstr(u_type, "s")) { // lower or small
			param->letter_type = UP_LETTER_LOWER;
		} else {
			param->letter_type = UP_LETTER_UPPER;
		}
	}
	eag_urlparam_get_value(feature_str, "format=", param->mac_format, 
							sizeof(param->mac_format));

	eag_urlparam_get_value(feature_str, "deskey=", param->mac_deskey, 
							sizeof(param->mac_deskey));
	
	eag_urlparam_get_value(feature_str, "value=", param->param_value, 
							sizeof(param->param_value));
	eag_log_debug("eag_urlparam", "eag_urlparam_get_feature end:url_type:%d, url_encode:%d, letter_type:%d, mac_format:%s, mac_deskey:%s, param_value:%s", 
				param->url_type, param->url_encode, param->letter_type, param->mac_format, param->mac_deskey, param->param_value);
	return 0;
}

/* separate param name*/
int
eag_urlparam_get_namestr( char *srcstr, 
						char *name, 
						int name_size, 
						char *extra, 
						int extra_size )
{
	char *cmp = NULL;
	int len = 0;
	int name_len = 0;

	if (srcstr == NULL || strlen(srcstr) == 0 
		|| name == NULL || *srcstr != '{') {
		return -1;
	}
	for (cmp = srcstr+1; *cmp != '\0'; cmp++)
	{
		if (*cmp == ';' || *cmp == '}' || *cmp == '=') {
			*name = '\0';
			break;
		}
		*name = *cmp;
		name++;
		name_len++;
		if (name_len+1 > name_size) {
			*name = '\0';
			break;
		}
	}
	
	cmp++;
	if ('\0' == *cmp) {
		extra = NULL;
		return 0;
	}
	len = strlen(cmp) - 1;
	if (*(cmp+len) == '}') {
		*(cmp+len) = '\0';
	}
	if (extra != NULL) {
		strncpy(extra, cmp, extra_size-1);
	}
	
	return 0;
}

int
eag_urlparam_get_paramstr( char *srcstr, 
						char *param, 
						char *desstr, 
						int des_size )
{
	char *pos = NULL;
	char *cmp = NULL;
	char *des = desstr;
	int name_len = 0;
	int param_len = 0;
	int mark = 0;

	if (srcstr == NULL || param == NULL 
		|| strlen(srcstr) == 0 || strlen(param) == 0) {
		return -1;
	}
	
	pos = strstr(srcstr, param);
	if (pos == NULL) {
		return 0;
	}
	while (*pos != '{' && *pos != ';' && *pos != '\0') {
		name_len++;
		pos++;
	}
	for (cmp = pos; *cmp != '\0'; cmp++)
	{
		param_len++;
		if (*cmp == '{') {
			mark++;
		}
		if (*cmp == '}') {
			mark--;
		}
		if (desstr == NULL) {
		} else {
			*des = *cmp;
			des++;
			if (param_len+1 > des_size) {
                *des = '\0';
				return name_len+param_len;
			}
		}
		if (mark == 0 || *cmp == '\0') {
			break;
		}
	}
	if (desstr != NULL) {
		*des = '\0';
	}
	
	return name_len+param_len;
}

int
eag_urlparam_splice_single( struct url_param_t *param, 
							char *name, 
							char *query_str, 
							int query_size )
{
    char cmpbuf[URL_PARAM_VALUE_LEN*2] = "";
    
	if (param == NULL) {
		return -1;
	}
	
    memset(cmpbuf, 0, sizeof(cmpbuf));
    
    snprintf(cmpbuf, sizeof(cmpbuf)-1, "%s=${%s", name, param->param_name);
    
	if (strlen(param->param_value) > 0) {
	    strncat(cmpbuf, ";value=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	    strncat(cmpbuf, param->param_value, sizeof(cmpbuf)-strlen(cmpbuf)-1);
	}
	
	if (strlen(param->mac_deskey) > 0) {
	    strncat(cmpbuf, ";deskey=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	    strncat(cmpbuf, param->mac_deskey, sizeof(cmpbuf)-strlen(cmpbuf)-1);
	}
	
	if (strlen(param->mac_format) > 0) {
	    strncat(cmpbuf, ";format=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	    strncat(cmpbuf, param->mac_format, sizeof(cmpbuf)-strlen(cmpbuf)-1);
	}
	
    if (UP_LETTER_UPPER == param->letter_type) {
        strncat(cmpbuf, ";letter=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
    	strncat(cmpbuf, "upper", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	} else if (UP_LETTER_LOWER == param->letter_type) {
        strncat(cmpbuf, ";letter=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
    	strncat(cmpbuf, "lower", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	}
	
    if (UP_HTTPS == param->url_type) {
        strncat(cmpbuf, ";type=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
        strncat(cmpbuf, "https", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	} else if (UP_HTTP == param->url_type) {
        strncat(cmpbuf, ";type=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
        strncat(cmpbuf, "http", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	}

    if (UP_ENCODE_ON == param->url_encode) {
        strncat(cmpbuf, ";encode=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
        strncat(cmpbuf, "on", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	} else if (UP_ENCODE_OFF == param->url_encode) {
        strncat(cmpbuf, ";encode=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
        strncat(cmpbuf, "off", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	}
	
    strncat(cmpbuf, "};", sizeof(cmpbuf)-strlen(cmpbuf)-1);
    
    strncat(query_str, cmpbuf, query_size-strlen(query_str)-1);
    eag_log_debug("eag_urlparam", "eag_urlparam_splice_single:%s\n", query_str);

    return 0;
}

int
eag_urlparam_splice_param( struct url_param_t *param, 
							char *query_str, 
							int query_size )
{
	if (param == NULL || query_str == NULL) {
		return -1;
	}
	
	switch (param->param_type) {
		case URL_PARAM_NASIP:
		eag_urlparam_splice_single(param, "nasip", query_str, query_size);
	break;
		case URL_PARAM_USERIP:
		eag_urlparam_splice_single(param, "userip", query_str, query_size);
	break;
		case URL_PARAM_USERMAC:
		eag_urlparam_splice_single(param, "usermac", query_str, query_size);
	break;
		case URL_PARAM_APMAC:
		eag_urlparam_splice_single(param, "apmac", query_str, query_size);
	break;
		case URL_PARAM_APNAME:
		eag_urlparam_splice_single(param, "apname", query_str, query_size);
	break;
		case URL_PARAM_ESSID:
		eag_urlparam_splice_single(param, "essid", query_str, query_size);
	break;
		case URL_PARAM_NASID:
		eag_urlparam_splice_single(param, "nasid", query_str, query_size);
	break;
		case URL_PARAM_VLANID:
		eag_urlparam_splice_single(param, "vlanid", query_str, query_size);
	break;
	case URL_PARAM_ACNAME:
		eag_urlparam_splice_single(param, "acname", query_str, query_size);
		break;
	case URL_PARAM_FIRSTURL:
		eag_urlparam_splice_single(param, "firsturl", query_str, query_size);
		break;
	default:
		break;
	}

	return EAG_RETURN_OK;
}

int
eag_urlparam_splice_common( char *query_str, 
							int query_size, 
							struct urlparam_query_str_t *urlparam, 
							URLPARAM com_or_wis )
{
    struct url_param_t *param = NULL;
    int i = 0;
    
    if (urlparam == NULL) {
		return 0;
    }
	if (UP_COMMON == com_or_wis) {
	    for (i = 0; i < urlparam->common_param_num; i++) {
	    	param = &(urlparam->common_param[i]);

			eag_log_debug("eag_urlparam", "eag_urlparam_splice_common common:param_type:%d;name:%s;value:%s;mac_deskey:%s;mac_format:%s;letter_type:%d;url_type:%d;url_encode:%d\n", 
			param->param_type, param->param_name, param->param_value, param->mac_deskey,param->mac_format, param->letter_type,param->url_type, param->url_encode);

			eag_urlparam_splice_param(param, query_str, query_size);
		}
	} else if (UP_WISPR == com_or_wis) {
	    for (i = 0; i < urlparam->wispr_param_num; i++) {
	    	param = &(urlparam->wispr_param[i]);
			
			eag_log_debug("eag_urlparam", "eag_urlparam_splice_common wispr:param_type:%d;name:%s;value:%s;mac_deskey:%s;mac_format:%s;letter_type:%d;url_type:%d;url_encode:%d\n", 
			param->param_type, param->param_name, param->param_value, param->mac_deskey,param->mac_format, param->letter_type,param->url_type, param->url_encode);
			
			eag_urlparam_splice_param(param, query_str, query_size);
		}
	}

	return EAG_RETURN_OK;
}

int
eag_urlparam_splice_wispr( char *query_str, 
						int query_size, 
						struct urlparam_query_str_t *wispr )
{
	char cmpbuf[URL_PARAM_VALUE_LEN*2] = "";
    memset(cmpbuf, 0, sizeof(cmpbuf));

	snprintf(cmpbuf, sizeof(cmpbuf)-1, "wisprurl=${%s", wispr->wispr_name);

    if (UP_HTTPS == wispr->wispr_type) {
        strncat(cmpbuf, ";type=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
        strncat(cmpbuf, "https", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	} else if (UP_HTTP == wispr->wispr_type) {
        strncat(cmpbuf, ";type=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
        strncat(cmpbuf, "http", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	}
    if (UP_ENCODE_ON == wispr->wispr_encode) {
        strncat(cmpbuf, ";encode=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
        strncat(cmpbuf, "on", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	} else if (UP_ENCODE_OFF == wispr->wispr_encode) {
        strncat(cmpbuf, ";encode=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
        strncat(cmpbuf, "off", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	}
	
	if (strlen(wispr->wispr_value) > 0) {
	    strncat(cmpbuf, ";value=", sizeof(cmpbuf)-strlen(cmpbuf)-1);
	    strncat(cmpbuf, wispr->wispr_value, sizeof(cmpbuf)-strlen(cmpbuf)-1);
	}
	
    strncat(query_str, cmpbuf, query_size-strlen(query_str)-1);
    
	if (wispr->wispr_param_num > 0) {
	    strncat(query_str, ";", query_size-strlen(query_str)-1);
	    eag_urlparam_splice_common(query_str, query_size, wispr, UP_WISPR);
    }
	if(';' == query_str[strlen(query_str)-1]) {
		query_str[strlen(query_str)-1] = '}';
		query_str[strlen(query_str)] = '\0';
	} else {
		strncat(query_str, "}", query_size-strlen(query_str)-1);
	}
	eag_log_debug("eag_urlparam", "eag_urlparam_splice_wispr:%s\n", query_str);

	return EAG_RETURN_OK;
}

int
eag_urlparam_save_config( struct portal_srv_t *portal_srv )
{
	if (portal_srv == NULL) {
		return -1;
	}
	eag_log_debug("eag_urlparam", "eag_urlparam_save_config begin!\n");
	portal_srv->urlparam_add = 1;
	memset(portal_srv->save_urlparam_config, 0, sizeof(portal_srv->save_urlparam_config));

	if (portal_srv->urlparam_query_str.common_param_num > 0) {
		eag_urlparam_splice_common(portal_srv->save_urlparam_config, sizeof(portal_srv->save_urlparam_config), 
								&(portal_srv->urlparam_query_str), UP_COMMON);
	}
	if (portal_srv->urlparam_query_str.wispr_status > 0) {
		eag_urlparam_splice_wispr(portal_srv->save_urlparam_config, sizeof(portal_srv->save_urlparam_config), 
								&(portal_srv->urlparam_query_str));
	}

	if(';' == portal_srv->save_urlparam_config[strlen(portal_srv->save_urlparam_config)-1]) {
		portal_srv->save_urlparam_config[strlen(portal_srv->save_urlparam_config)-1] = '\0';
	}
    
	eag_log_debug("eag_urlparam", "eag_urlparam_save_config query str:%s\n", 
					portal_srv->save_urlparam_config);

	return EAG_RETURN_OK;
}

int
eag_urlparam_del_single( struct urlparam_query_str_t *urlparam, 
						URL_PARAM_TYPE param_type, 
						URLPARAM com_or_wis, 
						char *param_str )
{
	struct url_param_t *param = NULL;
	int i = 0;

	if (urlparam == NULL || param_str == NULL) {
		return -1;
	}
    
	if (UP_COMMON == com_or_wis) {
		for (i = 0; i < urlparam->common_param_num; i++) {
			param = &(urlparam->common_param[i]);
			if (param->param_type == param_type) {
				urlparam->common_param_num--;
				memcpy(param, param+1, sizeof(struct url_param_t)*(urlparam->common_param_num-i));
				break;
			}
		}
	} else if (UP_WISPR == com_or_wis) {
		for (i = 0; i < urlparam->wispr_param_num; i++) {
			param = &(urlparam->wispr_param[i]);
			if (param->param_type == param_type) {
				urlparam->wispr_param_num--;
				memcpy(param, param+1, sizeof(struct url_param_t)*(urlparam->wispr_param_num-i));
				break;
			}
		}
	}
	
    return EAG_RETURN_OK;
}

int
eag_urlparam_del_param( struct urlparam_query_str_t *urlparam, 
						char *param_str, 
						URLPARAM com_or_wis )
{
	if (urlparam == NULL || param_str == NULL) {
		return EAG_ERR_PORTAL_SET_URLPARAM_INPUT_ERR;
	}
	
	if (strstr(param_str, "nasip")) {
		eag_urlparam_del_single(urlparam, URL_PARAM_NASIP, com_or_wis, param_str);
	}
	if (strstr(param_str, "userip")) {
		eag_urlparam_del_single(urlparam, URL_PARAM_USERIP, com_or_wis, param_str);
	}
	if (strstr(param_str, "usermac")) {
		eag_urlparam_del_single(urlparam, URL_PARAM_USERMAC, com_or_wis, param_str);
	}
	if (strstr(param_str, "apmac")) {
		eag_urlparam_del_single(urlparam, URL_PARAM_APMAC, com_or_wis, param_str);
	}
	if (strstr(param_str, "apname")) {
		eag_urlparam_del_single(urlparam, URL_PARAM_APNAME, com_or_wis, param_str);
	}
	if (strstr(param_str, "essid")) {
		eag_urlparam_del_single(urlparam, URL_PARAM_ESSID, com_or_wis, param_str);
	}
	if (strstr(param_str, "nasid")) {
		eag_urlparam_del_single(urlparam, URL_PARAM_NASID, com_or_wis, param_str);
	}
	if (strstr(param_str, "vlanid")) {
		eag_urlparam_del_single(urlparam, URL_PARAM_VLANID, com_or_wis, param_str);
	}
	if (strstr(param_str, "acname")) {
		eag_urlparam_del_single(urlparam, URL_PARAM_ACNAME, com_or_wis, param_str);
	}
	if (strstr(param_str, "firsturl")) {
		eag_urlparam_del_single(urlparam, URL_PARAM_FIRSTURL, com_or_wis, param_str);
	}

	return EAG_RETURN_OK;
}

int
eag_urlparam_del_wispr( struct urlparam_query_str_t *urlparam_query_str, 
						char *param_str )
{
	char wispr_str[URL_PARAM_VALUE_LEN*2] = "";
	char *pos = NULL;
	char *wispr = "wispr";
	int wispr_len = 0;
	
	if (wispr == NULL || param_str == NULL) {
		return EAG_ERR_PORTAL_SET_URLPARAM_INPUT_ERR;
	}
	
	memset(wispr_str, 0, sizeof(wispr_str));
	
	wispr_len = eag_urlparam_get_paramstr(param_str, wispr, wispr_str, sizeof(wispr_str));
	if (wispr_len > 0) {
		eag_urlparam_del_param(urlparam_query_str, wispr_str, UP_WISPR);
		if (strlen(wispr_str) == 0) {
			memset(&(urlparam_query_str->wispr_param[0]), 0, 
					sizeof(struct url_param_t)*MAX_URL_PARAM_NUM);
			urlparam_query_str->wispr_status = 0;
			urlparam_query_str->wispr_param_num = 0;
		}
		pos = strstr(param_str, wispr);
		eag_urlparam_cover(pos, pos+wispr_len);
	}
	
	return EAG_RETURN_OK;
}

int
eag_urlparam_del_urlparam( struct urlparam_query_str_t *urlparam_query_str, 
							char *param_str )
{
	if (urlparam_query_str == NULL || param_str == NULL) {
		return EAG_ERR_PORTAL_SET_URLPARAM_INPUT_ERR;
	}
	
	if (strstr(param_str, "wispr")) {
		eag_urlparam_del_wispr(urlparam_query_str, param_str);
	}

	eag_urlparam_del_param(urlparam_query_str, param_str, UP_COMMON);
		
    return EAG_RETURN_OK;
}

int
eag_urlparam_add_param( char *url_param_str, 
						struct urlparam_query_str_t *urlparam, 
						URL_PARAM_TYPE param_type, 
						URLPARAM add_urlparam )
{
	char *namestr = NULL;
	char cmpbuf[URL_PARAM_VALUE_LEN*2] = "";
	char feature_str[URL_PARAM_VALUE_LEN*2] = "";
	struct url_param_t *param = NULL;
	int i = 0;
	int param_len = 0;
	char *pos = NULL;

	if (url_param_str == NULL || urlparam == NULL) {
		return EAG_ERR_PORTAL_SET_URLPARAM_INPUT_ERR;
	}

	memset(cmpbuf, 0, sizeof(cmpbuf));
	memset(feature_str, 0, sizeof(feature_str));

	switch (param_type) {
	case URL_PARAM_NASIP:
		namestr = "nasip=";
		break;
	case URL_PARAM_USERIP:
		namestr = "userip=";
		break;
	case URL_PARAM_USERMAC:
		namestr = "usermac=";
		break;
	case URL_PARAM_APMAC:
		namestr = "apmac=";
		break;
	case URL_PARAM_APNAME:
		namestr = "apname=";
		break;
	case URL_PARAM_ESSID:
		namestr = "essid=";
		break;
	case URL_PARAM_NASID:
		namestr = "nasid=";
		break;
	case URL_PARAM_VLANID:
		namestr = "vlanid=";
		break;
	case URL_PARAM_ACNAME:
		namestr = "acname=";
		break;
	case URL_PARAM_FIRSTURL:
		namestr = "firsturl=";
		break;
	default:
		return EAG_RETURN_OK;
	}
	
	param_len = eag_urlparam_get_paramstr(url_param_str, namestr, cmpbuf, sizeof(cmpbuf));
	if (param_len > 0) {
		if (UP_WISPR == add_urlparam) {
			for (i = 0; i < urlparam->wispr_param_num; i++) {
				param = &(urlparam->wispr_param[i]);
				if (param->param_type == param_type) {
					break;
				} else {
					param = NULL;
				}
			}
			if (param == NULL) {
				if (urlparam->wispr_param_num < MAX_URL_PARAM_NUM) {
					param = &(urlparam->wispr_param[urlparam->wispr_param_num]);
					urlparam->wispr_param_num++;
				} else {
					return EAG_ERR_PORTAL_SET_URLPARAM_MAX_NUM;
				}
			} else if (param != NULL) {
				memset(param, 0, sizeof(struct url_param_t));
			}
		} else if (UP_COMMON == add_urlparam) {
			for (i = 0; i < urlparam->common_param_num; i++) {
				param = &(urlparam->common_param[i]);
				if (param->param_type == param_type) {
					break;
				} else {
					param = NULL;
				}
			}
			if (param == NULL) {
				if (urlparam->common_param_num < MAX_URL_PARAM_NUM) {
					param = &(urlparam->common_param[urlparam->common_param_num]);
					urlparam->common_param_num++;
				} else {
					return EAG_ERR_PORTAL_SET_URLPARAM_MAX_NUM;
				}
		        } else if (param != NULL) {
		        	memset(param, 0, sizeof(struct url_param_t));
		        }
		}

		param->param_type = param_type;
		eag_urlparam_get_namestr(cmpbuf, param->param_name, sizeof(param->param_name), 
								feature_str, sizeof(feature_str));
		eag_log_debug("eag_urlparam", "eag_urlparam_add_param:name:%s, param:%s\n", 
						param->param_name, feature_str);
		eag_urlparam_get_feature(param, feature_str);

		pos = strstr(url_param_str, namestr);
		eag_urlparam_cover(pos, pos+param_len);
	} else if (-1 == param_len) {
		return EAG_ERR_PORTAL_SET_URLPARAM_INPUT_ERR;
	}
	
	return EAG_RETURN_OK;
}

int
eag_urlparam_add_common( char *url_param_buf, 
						struct urlparam_query_str_t *urlparam, 
						URLPARAM com_or_wis )
{
	if (url_param_buf == NULL || urlparam == NULL) {
		return EAG_ERR_PORTAL_SET_URLPARAM_INPUT_ERR;
	}
	eag_log_debug("eag_urlparam", "eag_urlparam_add_common %s begin:%s\n", 
				(UP_COMMON==com_or_wis)?"common":"wispr", url_param_buf);

	eag_urlparam_add_param(url_param_buf, urlparam, URL_PARAM_NASIP, com_or_wis);
	eag_urlparam_add_param(url_param_buf, urlparam, URL_PARAM_USERIP, com_or_wis);
	eag_urlparam_add_param(url_param_buf, urlparam, URL_PARAM_USERMAC, com_or_wis);
	eag_urlparam_add_param(url_param_buf, urlparam, URL_PARAM_APMAC, com_or_wis);
	eag_urlparam_add_param(url_param_buf, urlparam, URL_PARAM_APNAME, com_or_wis);

	eag_urlparam_add_param(url_param_buf, urlparam, URL_PARAM_ESSID, com_or_wis);
	eag_urlparam_add_param(url_param_buf, urlparam, URL_PARAM_NASID, com_or_wis);
	eag_urlparam_add_param(url_param_buf, urlparam, URL_PARAM_VLANID, com_or_wis);
	eag_urlparam_add_param(url_param_buf, urlparam, URL_PARAM_ACNAME, com_or_wis);
	eag_urlparam_add_param(url_param_buf, urlparam, URL_PARAM_FIRSTURL, com_or_wis);

	eag_log_debug("eag_urlparam", "eag_urlparam_add_common %s end:%s\n", 
				(UP_COMMON==com_or_wis)?"common":"wispr", url_param_buf);

	return EAG_RETURN_OK;
}

int
eag_urlparam_add_wispr( char *url_param_str, 
						struct urlparam_query_str_t *urlparam )
{
	int wispr_len = 0;
	char *pos = NULL;
	char *namestr = "wispr";
	char cmp_buf[URL_PARAM_WISPR_VALUE_LEN] = "";
	char wispr_buf[URL_PARAM_WISPR_VALUE_LEN] = "";

	if (url_param_str == NULL || urlparam == NULL) {
		return EAG_ERR_PORTAL_SET_URLPARAM_INPUT_ERR;
	}

	memset(cmp_buf, 0, sizeof(cmp_buf));

	eag_log_debug("eag_urlparam", "eag_urlparam_add_wispr begin:%s\n", url_param_str);
	wispr_len = eag_urlparam_get_paramstr(url_param_str, namestr, cmp_buf, sizeof(cmp_buf));
	if (wispr_len > 0) {
		memset(wispr_buf, 0, sizeof(wispr_buf));

		urlparam->wispr_status = UP_STATUS_ON;
		eag_urlparam_get_namestr(cmp_buf, urlparam->wispr_name, sizeof(urlparam->wispr_name), 
								wispr_buf, sizeof(wispr_buf));	
		eag_log_debug("eag_urlparam", "eag_urlparam_add_wispr name:%s, param:%s\n", urlparam->wispr_name, wispr_buf);

		eag_urlparam_add_common(wispr_buf, urlparam, UP_WISPR);

		if (strlen(wispr_buf) != 0) {
			/* other url param */
			eag_urlparam_get_wispr_feature(urlparam, wispr_buf);
		}

		pos = strstr(url_param_str, namestr);
		eag_urlparam_cover(pos, pos+wispr_len);
	} else if (-1 == wispr_len) {
		return EAG_ERR_PORTAL_SET_URLPARAM_INPUT_ERR;
	}
	eag_log_debug("eag_urlparam", "eag_urlparam_add_wispr end:%s\n", url_param_str);

	return EAG_RETURN_OK;
}

int
eag_urlparam_add_urlparam( struct urlparam_query_str_t *urlparam_query_str, 
							char *param_str )
{
	int ret = 0;

	if (urlparam_query_str == NULL || param_str == NULL) {
		return EAG_ERR_PORTAL_SET_URLPARAM_INPUT_ERR;
	}
	eag_log_debug("eag_urlparam", "eag_urlparam_add_urlparam begin:%s\n", param_str);
	/* wisprloginurl */
	ret = eag_urlparam_add_wispr(param_str, urlparam_query_str);
	if (EAG_RETURN_OK != ret) {
		return ret;
	}
	/* common param */
	ret = eag_urlparam_add_common(param_str, urlparam_query_str, UP_COMMON);
	if (EAG_RETURN_OK != ret) {
		return ret;
	}
	eag_log_debug("eag_urlparam", "eag_urlparam_add_urlparam end:%s\n", param_str);

	return EAG_RETURN_OK;
}

DBusMessage *
eag_dbus_method_set_urlparam(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	struct portal_srv_t * portal_srv_t = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	int				add_or_del = 0;
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	char		  *url_param = NULL;
	int				ret = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_urlparam "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_set_urlparam user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_UINT32, &add_or_del,
								DBUS_TYPE_STRING, &url_param,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_urlparam "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_urlparam %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	if (NULL == url_param || 0 == strlen(url_param)) {
		eag_log_err("eag_dbus_method_set_urlparam user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	if (strlen(url_param) >= URL_PARAM_QUERY_STR_LEN) {
		eag_log_err("eag_dbus_method_set_urlparam error args!\n");	
		ret =  EAG_ERR_PORTAL_SET_URLPARAM_LEN_LINITE;
		goto replyx;
	}
	
	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_DEL_SRV_NOT_EXIST;
			goto replyx;
		}
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		goto replyx;
		break;
	}

	if (1 == add_or_del) {
		ret = eag_urlparam_add_urlparam(&(portal_srv_t->urlparam_query_str), url_param);
		if (EAG_RETURN_OK != ret) {
			eag_log_err("eag_dbus_method_set_urlparam add urlparam error!");
			goto replyx;
		}
	} else if (0 == add_or_del) {
		ret = eag_urlparam_del_urlparam(&(portal_srv_t->urlparam_query_str), url_param);
		if (EAG_RETURN_OK != ret) {
			eag_log_err("eag_dbus_method_set_urlparam del urlparam error!");
			goto replyx;
		}
	} else {
		eag_log_err("eag_dbus_method_set_urlparam user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	ret = eag_urlparam_save_config(portal_srv_t);
	if (EAG_RETURN_OK != ret) {
		eag_log_err("eag_dbus_method_set_urlparam save config error!");
		goto replyx;
	}
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_show_urlparam(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	struct portal_conf *portal_conf = NULL;
	struct portal_srv_t * portal_srv_t = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned long  keytype = 0;
	unsigned long  keyid = 0;
	char		  *keyword = NULL;
	int				ret = 0;
	struct urlparam_query_str_t *urlparam = NULL;
	struct url_param_t *param = NULL;
	uint32_t num = 0;
	uint32_t param_type = 0;
	char *param_name = NULL;
	char *param_value = NULL;
	char *mac_deskey = NULL;
	char *mac_format = NULL;
	uint32_t url_type = 0;
	uint32_t url_encode = 0;
	uint32_t letter_type = 0;
	uint32_t wispr_status = 0;
	int i = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_show_urlparam "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	portal_conf = (struct portal_conf *)user_data;
	if( NULL == portal_conf){
		eag_log_err("eag_dbus_method_show_urlparam user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
						        DBUS_TYPE_UINT32, &keytype,
								DBUS_TYPE_UINT32, &keyid,
								DBUS_TYPE_STRING, &keyword,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_show_urlparam "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_show_urlparam %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	switch( keytype ){
	case PORTAL_KEYTYPE_ESSID:
	case PORTAL_KEYTYPE_INTF:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,keyword);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_DEL_SRV_NOT_EXIST;
			goto replyx;
		}
		break;
	case PORTAL_KEYTYPE_WLANID:
	case PORTAL_KEYTYPE_VLANID:
	case PORTAL_KEYTYPE_WTPID:
		portal_srv_t = portal_srv_get_by_key(portal_conf, keytype,&keyid);
		if( NULL == portal_srv_t ){
			ret = EAG_ERR_PORTAL_MODIFY_SRV_NOT_EXIST;
			goto replyx;
		}
		break;
	default:
		ret = EAG_ERR_PORTAL_MODIFY_SRV_ERR_TYPE;
		goto replyx;
		break;
	}

    dbus_error_init(&err);
    ret = EAG_RETURN_OK;
    
replyx:
    dbus_message_iter_init_append(reply, &iter);
    dbus_message_iter_append_basic(&iter,
                                    DBUS_TYPE_INT32, &ret);
    if (EAG_RETURN_OK == ret) {
    	urlparam = &(portal_srv_t->urlparam_query_str);
        num = urlparam->common_param_num;
        dbus_message_iter_append_basic(&iter,
                                    DBUS_TYPE_UINT32, &num);
		if (num > 0) {
	        DBusMessageIter iter_array = {0};
	        
	        dbus_message_iter_open_container (&iter,
	                                DBUS_TYPE_ARRAY,
	                                    DBUS_STRUCT_BEGIN_CHAR_AS_STRING
	                                        DBUS_TYPE_UINT32_AS_STRING
								            DBUS_TYPE_STRING_AS_STRING
								            DBUS_TYPE_STRING_AS_STRING
								            DBUS_TYPE_STRING_AS_STRING
								            DBUS_TYPE_STRING_AS_STRING
								            DBUS_TYPE_UINT32_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
								            DBUS_TYPE_UINT32_AS_STRING
	                                    DBUS_STRUCT_END_CHAR_AS_STRING,
	                                &iter_array);

	        for (i = 0; i < urlparam->common_param_num; i++) {
	        	param = &(urlparam->common_param[i]);
				DBusMessageIter iter_struct = {0};
	            dbus_message_iter_open_container (&iter_array,
	                                    DBUS_TYPE_STRUCT,
	                                    NULL,
	                                    &iter_struct);
				param_type = param->param_type;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_UINT32,
	                                &param_type);                           
	            param_name = param->param_name;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_STRING,
	                                &param_name);
				param_value = param->param_value;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_STRING,
	                                &param_value);
				mac_deskey = param->mac_deskey;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_STRING,
	                                &mac_deskey);
				mac_format = param->mac_format;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_STRING,
	                                &mac_format);
				letter_type = param->letter_type;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_UINT32,
	                                &letter_type);
				url_type = param->url_type;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_UINT32,
	                                &url_type);
				url_encode = param->url_encode;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_UINT32,
	                                &url_encode);
				dbus_message_iter_close_container (&iter_array, &iter_struct);
			}
			dbus_message_iter_close_container (&iter, &iter_array);
    	}
	
		wispr_status = urlparam->wispr_status;
        dbus_message_iter_append_basic(&iter,
                                    DBUS_TYPE_UINT32,
                                    &wispr_status);
		if (wispr_status == UP_STATUS_ON) {
			num = urlparam->wispr_param_num;
			dbus_message_iter_append_basic(&iter,
                                DBUS_TYPE_UINT32,
                                &num);
            param_name = urlparam->wispr_name;
            dbus_message_iter_append_basic(&iter,
                                DBUS_TYPE_STRING,
                                &param_name);
			param_value = urlparam->wispr_value;
            dbus_message_iter_append_basic(&iter,
                                DBUS_TYPE_STRING,
                                &param_value);
			url_type = urlparam->wispr_type;
            dbus_message_iter_append_basic(&iter,
                                DBUS_TYPE_UINT32,
                                &url_type);
			url_encode = urlparam->wispr_encode;
            dbus_message_iter_append_basic(&iter,
                                DBUS_TYPE_UINT32,
                                &url_encode);
        }
        
	    if (wispr_status == UP_STATUS_ON && num > 0) {
	        DBusMessageIter iter_array = {0};
	        dbus_message_iter_open_container (&iter,
	                                DBUS_TYPE_ARRAY,
	                                    DBUS_STRUCT_BEGIN_CHAR_AS_STRING
	                                        DBUS_TYPE_UINT32_AS_STRING
								            DBUS_TYPE_STRING_AS_STRING
								            DBUS_TYPE_STRING_AS_STRING
								            DBUS_TYPE_STRING_AS_STRING
								            DBUS_TYPE_STRING_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING
								            DBUS_TYPE_UINT32_AS_STRING
								            DBUS_TYPE_UINT32_AS_STRING
	                                    DBUS_STRUCT_END_CHAR_AS_STRING,
	                                &iter_array);

	        for(i = 0; i < urlparam->wispr_param_num; i++) {
	        	param = &(urlparam->wispr_param[i]);
				DBusMessageIter iter_struct = {0};
	            dbus_message_iter_open_container (&iter_array,
	                                    DBUS_TYPE_STRUCT,
	                                    NULL,
	                                    &iter_struct);
				param_type = param->param_type;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_UINT32,
	                                &param_type);                           
	            param_name = param->param_name;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_STRING,
	                                &param_name);
				param_value = param->param_value;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_STRING,
	                                &param_value);
				mac_deskey = param->mac_deskey;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_STRING,
	                                &mac_deskey);
				mac_format = param->mac_format;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_STRING,
	                                &mac_format);
				letter_type = param->letter_type;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_UINT32,
	                                &letter_type);
				url_type = param->url_type;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_UINT32,
	                                &url_type);
				url_encode = param->url_encode;
	            dbus_message_iter_append_basic(&iter_struct,
	                                DBUS_TYPE_UINT32,
	                                &url_encode);
	            dbus_message_iter_close_container (&iter_array, &iter_struct);
	        }
	        dbus_message_iter_close_container (&iter, &iter_array);
	    }
	}
	
	return reply;
}
/* url param end*/

DBusMessage *
eag_dbus_method_add_radius(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	struct radius_srv_t *radius_srv = NULL;
	
	char *domain=NULL;
	unsigned long auth_ip=0;
	unsigned short auth_port=0;
	char *auth_secret=NULL;
	unsigned long acct_ip=0;
	unsigned short acct_port=0;
	char *acct_secret=NULL;
	unsigned long backup_auth_ip=0;
	unsigned short backup_auth_port=0;
	char *backup_auth_secret=NULL;
	unsigned long backup_acct_ip=0;
	unsigned short backup_acct_port=0;
	char *backup_acct_secret=NULL;
	
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_portal_port "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins ){
		eag_log_err("eag_dbus_method_add_radius user_data error!");
		//return reply;
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_STRING, &domain,
								DBUS_TYPE_UINT32, &auth_ip,
								DBUS_TYPE_UINT16, &auth_port,
								DBUS_TYPE_STRING, &auth_secret,
								DBUS_TYPE_UINT32, &acct_ip,
								DBUS_TYPE_UINT16, &acct_port,
								DBUS_TYPE_STRING, &acct_secret,
								DBUS_TYPE_UINT32, &backup_auth_ip,
								DBUS_TYPE_UINT16, &backup_auth_port,
								DBUS_TYPE_STRING, &backup_auth_secret,
								DBUS_TYPE_UINT32, &backup_acct_ip,
								DBUS_TYPE_UINT16, &backup_acct_port,
								DBUS_TYPE_STRING, &backup_acct_secret,								
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_portal_port "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_portal_port %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	radius_srv = radius_srv_get_by_domain(&(eagins->radiusconf),domain);
	if( NULL != radius_srv ){
		ret = EAG_ERR_RADIUS_DOAMIN_AREADY_EXIST;
		eag_log_err("eag_dbus_method_add_radius domain already exist!");
	}else if( MAX_RADIUS_SRV_NUM == eagins->radiusconf.current_num ){
		ret = EAG_ERR_RADIUS_MAX_NUM_LIMITE;
		eag_log_err("eag_dbus_method_add_radius failed because max num limite!");
	}else{
		radius_srv = radius_conf_and_domain(&(eagins->radiusconf),domain);
		radius_srv_set_auth(radius_srv,auth_ip,auth_port,
							auth_secret,strlen(auth_secret));
		radius_srv_set_acct(radius_srv,acct_ip,acct_port,
							acct_secret,strlen(acct_secret));
		radius_srv_set_backauth(radius_srv,backup_auth_ip,backup_auth_port,
								backup_auth_secret,strlen(backup_auth_secret));
		radius_srv_set_backacct(radius_srv,backup_acct_ip,backup_acct_port,
								backup_acct_secret,strlen(backup_acct_secret));
		ret = EAG_RETURN_OK;
	}


replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}



DBusMessage *
eag_dbus_method_modify_radius(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	struct radius_srv_t *radius_srv = NULL;
	
	char *domain=NULL;
	unsigned long auth_ip=0;
	unsigned short auth_port=0;
	char *auth_secret=NULL;
	unsigned long acct_ip=0;
	unsigned short acct_port=0;
	char *acct_secret=NULL;
	unsigned long backup_auth_ip=0;
	unsigned short backup_auth_port=0;
	char *backup_auth_secret=NULL;
	unsigned long backup_acct_ip=0;
	unsigned short backup_acct_port=0;
	char *backup_acct_secret=NULL;
	
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_portal_port "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins ){
		eag_log_err("eag_dbus_method_add_radius user_data error!");
		//return reply;
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_STRING, &domain,
								DBUS_TYPE_UINT32, &auth_ip,
								DBUS_TYPE_UINT16, &auth_port,
								DBUS_TYPE_STRING, &auth_secret,
								DBUS_TYPE_UINT32, &acct_ip,
								DBUS_TYPE_UINT16, &acct_port,
								DBUS_TYPE_STRING, &acct_secret,
								DBUS_TYPE_UINT32, &backup_auth_ip,
								DBUS_TYPE_UINT16, &backup_auth_port,
								DBUS_TYPE_STRING, &backup_auth_secret,
								DBUS_TYPE_UINT32, &backup_acct_ip,
								DBUS_TYPE_UINT16, &backup_acct_port,
								DBUS_TYPE_STRING, &backup_acct_secret,								
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_modify_radius "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_modify_radius %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	radius_srv = radius_srv_get_by_domain(&(eagins->radiusconf),domain);
	if( NULL == radius_srv ){
		ret = EAG_ERR_RADIUS_DOAMIN_NOT_EXIST;
		eag_log_err("eag_dbus_method_modify_radius domain not exist!");
	}else{
		radius_srv_set_auth(radius_srv,auth_ip,auth_port,
							auth_secret,strlen(auth_secret));
		radius_srv_set_acct(radius_srv,acct_ip,acct_port,
							acct_secret,strlen(acct_secret));
		radius_srv_set_backauth(radius_srv,backup_auth_ip,backup_auth_port,
								backup_auth_secret,strlen(backup_auth_secret));
		radius_srv_set_backacct(radius_srv,backup_acct_ip,backup_acct_port,
								backup_acct_secret,strlen(backup_acct_secret));
		ret = EAG_RETURN_OK;
	}


replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}


DBusMessage *
eag_dbus_method_del_radius(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	struct radius_srv_t *radius_srv = NULL;
	
	char *domain=NULL;
	
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_portal_port "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins ){
		eag_log_err("eag_dbus_method_add_radius user_data error!");
		//return reply;
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_STRING, &domain,						
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_del_radius "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_del_radius %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	radius_srv = radius_srv_get_by_domain(&(eagins->radiusconf),domain);
	if( NULL == radius_srv ){
		ret = EAG_ERR_RADIUS_DOAMIN_NOT_EXIST;
		eag_log_err("eag_dbus_method_del_radius domain not exist!");
	}else{
		ret = radius_conf_del_domain( &(eagins->radiusconf),domain);
	}


replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_remove_domain_switch(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	struct radius_srv_t *radius_srv = NULL;
	
	char *domain = NULL;
	int remove_domain_switch = 1;
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_remove_domain_switch "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins ){
		eag_log_err("eag_dbus_method_set_remove_domain_switch user_data error!");
		//return reply;
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_STRING, &domain,
								DBUS_TYPE_INT32, &remove_domain_switch,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_remove_domain_switch "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_remove_domain_switch %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	radius_srv = radius_srv_get_by_domain(&(eagins->radiusconf), domain);
	if (NULL == radius_srv) {
		ret = EAG_ERR_RADIUS_DOAMIN_NOT_EXIST;
		eag_log_err("eag_dbus_method_set_remove_domain_switch domain not exist!");
	} else {
		radius_srv->remove_domain_name = remove_domain_switch;
		ret = EAG_RETURN_OK;
	}


replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_class_to_bandwidth_switch(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	struct radius_srv_t *radius_srv = NULL;
	char *domain = NULL;
	int class_to_bandwidth = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_class_to_bandwidth_switch "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_set_class_to_bandwidth_switch user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_STRING, &domain,
								DBUS_TYPE_INT32, &class_to_bandwidth,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_class_to_bandwidth_switch "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_class_to_bandwidth_switch %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	radius_srv = radius_srv_get_by_domain(&(eagins->radiusconf), domain);
	if (NULL == radius_srv) {
		ret = EAG_ERR_RADIUS_DOAMIN_NOT_EXIST;
		eag_log_err("eag_dbus_method_set_class_to_bandwidth_switch domain not exist!");
	} else {
		radius_srv->class_to_bandwidth = class_to_bandwidth;
		ret = EAG_RETURN_OK;
	}
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_get_radius_conf(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	struct radius_srv_t *radius_srv = NULL;
	unsigned long num;
	
	char *domain=NULL;
	char *auth_secret=NULL;
	char *acct_secret=NULL;
	char *backup_auth_secret=NULL;
	char *backup_acct_secret=NULL;
	
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_get_radius_conf "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if( NULL == eagins ){
		eag_log_err("eag_dbus_method_get_radius_conf user_data error!");
		//return reply;
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_STRING, &domain,						
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_get_radius_conf "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_get_radius_conf %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	eag_log_info("eag_dbus_method_get_radius_conf domain=%s", domain );
	if( strlen(domain) == 0 ){
		//get all
		num = eagins->radiusconf.current_num;
		ret = EAG_RETURN_OK;
		radius_srv = &(eagins->radiusconf.radius_srv[0]);
	}else{
		radius_srv = radius_srv_get_by_domain(&(eagins->radiusconf),domain);
		if( NULL == radius_srv ){
			eag_log_err("eag_dbus_method_get_radius_conf domain %s not exist!", domain );
			ret = EAG_ERR_RADIUS_DOAMIN_NOT_EXIST;
			num = 0;
		}else{
			num = 1;
			ret = EAG_RETURN_OK;
		}
	}

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);

	if( EAG_RETURN_OK == ret ){
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32, &num);
	}
	if( EAG_RETURN_OK == ret && num > 0 ){
		int i;
		DBusMessageIter  iter_array;
		
		dbus_message_iter_open_container (&iter,
									DBUS_TYPE_ARRAY,
										DBUS_STRUCT_BEGIN_CHAR_AS_STRING
											DBUS_TYPE_STRING_AS_STRING
											DBUS_TYPE_INT32_AS_STRING
											DBUS_TYPE_INT32_AS_STRING
											 DBUS_TYPE_UINT32_AS_STRING	
											 DBUS_TYPE_UINT16_AS_STRING
											 DBUS_TYPE_STRING_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING	
											DBUS_TYPE_UINT16_AS_STRING
											DBUS_TYPE_STRING_AS_STRING
											 DBUS_TYPE_UINT32_AS_STRING	
											 DBUS_TYPE_UINT16_AS_STRING
											 DBUS_TYPE_STRING_AS_STRING
											DBUS_TYPE_UINT32_AS_STRING	
											DBUS_TYPE_UINT16_AS_STRING
											DBUS_TYPE_STRING_AS_STRING										
										DBUS_STRUCT_END_CHAR_AS_STRING,
									&iter_array);

		for( i=0; i<num; i++ ){
			DBusMessageIter iter_struct;
			dbus_message_iter_open_container (&iter_array,
										DBUS_TYPE_STRUCT,
										NULL,
										&iter_struct);
			domain = radius_srv[i].domain;
			eag_log_info("eag_dbus_method_get_radius_conf add domain %s", domain );
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &domain);
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &radius_srv[i].remove_domain_name);
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_INT32, &radius_srv[i].class_to_bandwidth);
			/*auth*/
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &radius_srv[i].auth_ip);			
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT16, &radius_srv[i].auth_port);
			auth_secret = radius_srv[i].auth_secret;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &auth_secret);
			/*acct*/
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &radius_srv[i].acct_ip);			
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT16, &radius_srv[i].acct_port);
			acct_secret = radius_srv[i].acct_secret;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &acct_secret);
			/*backup auth*/
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &radius_srv[i].backup_auth_ip);			
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT16, &radius_srv[i].backup_auth_port);
			backup_auth_secret = radius_srv[i].backup_auth_secret;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &backup_auth_secret);
			/*bakcup acct*/
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT32, &radius_srv[i].backup_acct_ip);			
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_UINT16, &radius_srv[i].backup_acct_port);
			backup_acct_secret = radius_srv[i].backup_acct_secret;
			dbus_message_iter_append_basic(&iter_struct,
											DBUS_TYPE_STRING, &backup_acct_secret);	

			dbus_message_iter_close_container (&iter_array, &iter_struct);

		}
		dbus_message_iter_close_container (&iter, &iter_array);
	}
	
	return reply;
}

DBusMessage *
eag_dbus_method_get_eag_statistics(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_statistics_t *eagstat = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = 0;
	struct eag_stat_data stat_data;
	struct eag_ap_statistics *ap_stat = NULL;
	struct eag_bss_statistics *bss_stat = NULL;
	struct list_head *ap_head = NULL;

	struct timeval time_begin = {0};
	struct timeval time_end = {0};
	struct timeval time_res = {0};
	

	gettimeofday(&time_begin, NULL);
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_get_bss_statistics "
			" DBUS new reply message error");
		return NULL;
	}
	
	eagstat = (eag_statistics_t *)user_data;
	if (NULL == eagstat) {
		eag_log_err("eag_dbus_method_get_bss_statistics user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	ap_head = eag_statistics_get_ap_head(eagstat);
	memset(&stat_data, 0, sizeof(struct eag_stat_data));
	
	dbus_error_init(&err);
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);
	if (EAG_RETURN_OK == ret) {
		eag_statistics_count_online_user_info(eagstat);
		stat_data.ap_num= eag_ap_statistics_count(eagstat);
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &stat_data.ap_num);
	}

	if (EAG_RETURN_OK == ret) {
		list_for_each_entry(ap_stat, ap_head, ap_node) {
			list_for_each_entry(bss_stat, &(ap_stat->bss_head), bss_node) {
				stat_data.online_user_num += bss_stat->data.online_user_num;
				stat_data.user_connect_total_time+= bss_stat->data.user_connected_total_time
									+ bss_stat->data.user_connecting_total_time;
				stat_data.macauth_online_user_num += bss_stat->data.macauth_online_user_num;
				stat_data.macauth_user_connect_total_time += bss_stat->data.macauth_user_connected_total_time
									+ bss_stat->data.macauth_user_connecting_total_time;
				#if 1
				stat_data.http_redir_request_count += bss_stat->data.http_redir_request_count;
				stat_data.http_redir_success_count += bss_stat->data.http_redir_success_count;
				#endif
				stat_data.challenge_req_count += bss_stat->data.challenge_req_count;
				stat_data.challenge_ack_0_count += bss_stat->data.challenge_ack_0_count;
				stat_data.challenge_ack_1_count += bss_stat->data.challenge_ack_1_count;
				stat_data.challenge_ack_2_count += bss_stat->data.challenge_ack_2_count;
				stat_data.challenge_ack_3_count += bss_stat->data.challenge_ack_3_count;
				stat_data.challenge_ack_4_count += bss_stat->data.challenge_ack_4_count;

				stat_data.auth_req_count += bss_stat->data.auth_req_count;
				stat_data.auth_ack_0_count += bss_stat->data.auth_ack_0_count;
				stat_data.auth_ack_1_count += bss_stat->data.auth_ack_1_count;
				stat_data.auth_ack_2_count += bss_stat->data.auth_ack_2_count;
				stat_data.auth_ack_3_count += bss_stat->data.auth_ack_3_count;
				stat_data.auth_ack_4_count += bss_stat->data.auth_ack_4_count;

				stat_data.macauth_req_count += bss_stat->data.macauth_req_count;
				stat_data.macauth_ack_0_count += bss_stat->data.macauth_ack_0_count;
				stat_data.macauth_ack_1_count += bss_stat->data.macauth_ack_1_count;
				stat_data.macauth_ack_2_count += bss_stat->data.macauth_ack_2_count;
				stat_data.macauth_ack_3_count += bss_stat->data.macauth_ack_3_count;
				stat_data.macauth_ack_4_count += bss_stat->data.macauth_ack_4_count;
				#if 0
				stat_data.logout_req_0_count += bss_stat->data.logout_req_0_count;
				stat_data.logout_req_1_count += bss_stat->data.logout_req_1_count;
				stat_data.logout_ack_0_count += bss_stat->data.logout_ack_0_count;
				stat_data.logout_ack_1_count += bss_stat->data.logout_ack_1_count;
				stat_data.logout_ack_2_count += bss_stat->data.logout_ack_2_count;
				stat_data.ntf_logout_count += bss_stat->data.ntf_logout_count;
				#endif
				stat_data.normal_logoff_count += bss_stat->data.normal_logoff_count;
				stat_data.abnormal_logoff_count += bss_stat->data.abnormal_logoff_count;
				stat_data.macauth_abnormal_logoff_count += bss_stat->data.macauth_abnormal_logoff_count;

				stat_data.challenge_timeout_count += bss_stat->data.challenge_timeout_count;
				stat_data.challenge_busy_count += bss_stat->data.challenge_busy_count;

				stat_data.req_auth_password_missing_count += bss_stat->data.req_auth_password_missing_count;
				stat_data.req_auth_unknown_type_count += bss_stat->data.req_auth_unknown_type_count;
				stat_data.ack_auth_busy_count += bss_stat->data.ack_auth_busy_count;
				stat_data.auth_disorder_count += bss_stat->data.auth_disorder_count;

				stat_data.access_request_count += bss_stat->data.access_request_count;
				stat_data.access_request_retry_count += bss_stat->data.access_request_retry_count;
				stat_data.access_request_timeout_count += bss_stat->data.access_request_timeout_count;
				stat_data.access_accept_count += bss_stat->data.access_accept_count;
				stat_data.access_reject_count += bss_stat->data.access_reject_count;

				stat_data.acct_request_start_count += bss_stat->data.acct_request_start_count;
				stat_data.acct_request_start_retry_count += bss_stat->data.acct_request_start_retry_count;
				stat_data.acct_response_start_count += bss_stat->data.acct_response_start_count;

				stat_data.acct_request_update_count += bss_stat->data.acct_request_update_count;
				stat_data.acct_request_update_retry_count += bss_stat->data.acct_request_update_retry_count;
				stat_data.acct_response_update_count += bss_stat->data.acct_response_update_count;

				stat_data.acct_request_stop_count += bss_stat->data.acct_request_stop_count;
				stat_data.acct_request_stop_retry_count += bss_stat->data.acct_request_stop_retry_count;
				stat_data.acct_response_stop_count += bss_stat->data.acct_response_stop_count;
			}
		}
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.online_user_num));
		dbus_message_iter_append_basic (&iter,
									DBUS_TYPE_UINT32,
									&(stat_data.user_connect_total_time));			
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.macauth_online_user_num));
		dbus_message_iter_append_basic (&iter,
									DBUS_TYPE_UINT32,
									&(stat_data.macauth_user_connect_total_time));									
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.http_redir_request_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.http_redir_success_count));			
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.challenge_req_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.challenge_ack_0_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.challenge_ack_1_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.challenge_ack_2_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.challenge_ack_3_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.challenge_ack_4_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.auth_req_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.auth_ack_0_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.auth_ack_1_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.auth_ack_2_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.auth_ack_3_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.auth_ack_4_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.macauth_req_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.macauth_ack_0_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.macauth_ack_1_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.macauth_ack_2_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.macauth_ack_3_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.macauth_ack_4_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.normal_logoff_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.abnormal_logoff_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.macauth_abnormal_logoff_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.challenge_timeout_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.challenge_busy_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.req_auth_password_missing_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.req_auth_unknown_type_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.ack_auth_busy_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.auth_disorder_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.access_request_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.access_request_retry_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.access_request_timeout_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.access_accept_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.access_reject_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.acct_request_start_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.acct_request_start_retry_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.acct_response_start_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.acct_request_update_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								 	&(stat_data.acct_request_update_retry_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.acct_response_update_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.acct_request_stop_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.acct_request_stop_retry_count));
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32,
								  	&(stat_data.acct_response_stop_count));
	}

	gettimeofday(&time_end, NULL);
	timersub(&time_end, &time_begin, &time_res);

	eag_log_info("eag_dbus_method_get_eag_statistics use time %ds%dus", time_res.tv_sec, time_res.tv_usec);

	return reply;
}


DBusMessage *
eag_dbus_method_get_ap_statistics(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_statistics_t *eagstat = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = 0;
	int num = 0;
	struct eag_ap_stat_data ap_stat_data;
	struct eag_ap_statistics *ap_stat = NULL;
	struct eag_bss_statistics *bss_stat = NULL;
	struct list_head *ap_head = NULL;
	uint32_t user_connect_total_time = 0;
	uint32_t macauth_user_connect_total_time = 0;
	struct app_conn_t *appconn = NULL;
	struct list_head *head = NULL;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32] = "";
	int total_appconn_num = 0;
	int connected_authed_num= 0;
	int unconnect_authed_num= 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_get_bss_statistics "
			" DBUS new reply message error");
		return NULL;
	}
	
	eagstat = (eag_statistics_t *)user_data;
	if (NULL == eagstat) {
		eag_log_err("eag_dbus_method_get_bss_statistics user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	ap_head = eag_statistics_get_ap_head(eagstat);
	
	dbus_error_init(&err);
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);
	if (EAG_RETURN_OK == ret) {
		eag_statistics_count_online_user_info(eagstat);
		num = eag_ap_statistics_count(eagstat);
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &num);
	}

    /*for onlinebug933 debug*/
	if (EAG_RETURN_OK == ret && num > 0) {
		if( EAG_TRUE == eag_log_is_filter_register("onlinebug933") ) {
            head = eag_statistics_get_appconn_head(eagstat);
			list_for_each_entry(appconn, head, node) {
				mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr), '-');
				mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr), '-');
				ip2str(appconn->session.user_ip, user_ipstr, sizeof (user_ipstr));
				if (APPCONN_STATUS_AUTHED == appconn->session.state) {
					total_appconn_num ++;
					if (SESSION_STA_STATUS_CONNECT == appconn->session.sta_state) {
						eag_log_debug("onlinebug933","Sta_state=Connected(0),State=Authed(1),apmac=%s,usermac=%s,userip=%s,username=%s", 
							ap_macstr,user_macstr,user_ipstr,appconn->session.username);
						connected_authed_num ++;
					} else if(SESSION_STA_STATUS_UNCONNECT== appconn->session.sta_state) {
                        eag_log_debug("onlinebug933","Sta_state=Unconnect(1),State=Authed(1),apmac=%s,usermac=%s,userip=%s,username=%s", 
                            ap_macstr,user_macstr,user_ipstr,appconn->session.username);
                        unconnect_authed_num ++;
					}
				}
			}
			if (0 < total_appconn_num) {
				eag_log_debug("onlinebug933","Total-appconn-num:%d, Connected-Authed-num:%d, Unconnect-Authed-num:%d",
					total_appconn_num, connected_authed_num, unconnect_authed_num);
			}
		}
	}
	
	if (EAG_RETURN_OK == ret && num > 0) {
		DBusMessageIter iter_array = {0};
		
		dbus_message_iter_open_container(&iter,
								DBUS_TYPE_ARRAY,
									DBUS_STRUCT_BEGIN_CHAR_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
									DBUS_STRUCT_END_CHAR_AS_STRING,
								&iter_array);

		list_for_each_entry(ap_stat, ap_head, ap_node) {
			memset(&ap_stat_data, 0, sizeof(struct eag_ap_stat_data));
			memcpy(ap_stat_data.apmac, ap_stat->ap_mac, 6);
			list_for_each_entry(bss_stat, &(ap_stat->bss_head), bss_node) {
				ap_stat_data.online_user_num += bss_stat->data.online_user_num;
				ap_stat_data.user_connected_total_time += bss_stat->data.user_connected_total_time;
				ap_stat_data.user_connecting_total_time += bss_stat->data.user_connecting_total_time;

				ap_stat_data.macauth_online_user_num += bss_stat->data.macauth_online_user_num;
				ap_stat_data.macauth_user_connected_total_time += bss_stat->data.macauth_user_connected_total_time;
				ap_stat_data.macauth_user_connecting_total_time += bss_stat->data.macauth_user_connecting_total_time;
				#if 1
				ap_stat_data.http_redir_request_count += bss_stat->data.http_redir_request_count;
				ap_stat_data.http_redir_success_count += bss_stat->data.http_redir_success_count;
				#endif
				ap_stat_data.challenge_req_count += bss_stat->data.challenge_req_count;
				ap_stat_data.challenge_ack_0_count += bss_stat->data.challenge_ack_0_count;
				ap_stat_data.challenge_ack_1_count += bss_stat->data.challenge_ack_1_count;
				ap_stat_data.challenge_ack_2_count += bss_stat->data.challenge_ack_2_count;
				ap_stat_data.challenge_ack_3_count += bss_stat->data.challenge_ack_3_count;
				ap_stat_data.challenge_ack_4_count += bss_stat->data.challenge_ack_4_count;

				ap_stat_data.auth_req_count += bss_stat->data.auth_req_count;
				ap_stat_data.auth_ack_0_count += bss_stat->data.auth_ack_0_count;
				ap_stat_data.auth_ack_1_count += bss_stat->data.auth_ack_1_count;
				ap_stat_data.auth_ack_2_count += bss_stat->data.auth_ack_2_count;
				ap_stat_data.auth_ack_3_count += bss_stat->data.auth_ack_3_count;
				ap_stat_data.auth_ack_4_count += bss_stat->data.auth_ack_4_count;

				ap_stat_data.macauth_req_count += bss_stat->data.macauth_req_count;
				ap_stat_data.macauth_ack_0_count += bss_stat->data.macauth_ack_0_count;
				ap_stat_data.macauth_ack_1_count += bss_stat->data.macauth_ack_1_count;
				ap_stat_data.macauth_ack_2_count += bss_stat->data.macauth_ack_2_count;
				ap_stat_data.macauth_ack_3_count += bss_stat->data.macauth_ack_3_count;
				ap_stat_data.macauth_ack_4_count += bss_stat->data.macauth_ack_4_count;
				#if 0
				ap_stat_data.logout_req_0_count += bss_stat->data.logout_req_0_count;
				ap_stat_data.logout_req_1_count += bss_stat->data.logout_req_1_count;
				ap_stat_data.logout_ack_0_count += bss_stat->data.logout_ack_0_count;
				ap_stat_data.logout_ack_1_count += bss_stat->data.logout_ack_1_count;
				ap_stat_data.logout_ack_2_count += bss_stat->data.logout_ack_2_count;
				ap_stat_data.ntf_logout_count += bss_stat->data.ntf_logout_count;
				#endif
				ap_stat_data.normal_logoff_count += bss_stat->data.normal_logoff_count;
				ap_stat_data.abnormal_logoff_count += bss_stat->data.abnormal_logoff_count;
				ap_stat_data.macauth_abnormal_logoff_count += bss_stat->data.macauth_abnormal_logoff_count;

				ap_stat_data.challenge_timeout_count += bss_stat->data.challenge_timeout_count;
				ap_stat_data.challenge_busy_count += bss_stat->data.challenge_busy_count;

				ap_stat_data.req_auth_password_missing_count += bss_stat->data.req_auth_password_missing_count;
				ap_stat_data.req_auth_unknown_type_count += bss_stat->data.req_auth_unknown_type_count;
				ap_stat_data.ack_auth_busy_count += bss_stat->data.ack_auth_busy_count;
				ap_stat_data.auth_disorder_count += bss_stat->data.auth_disorder_count;

				ap_stat_data.access_request_count += bss_stat->data.access_request_count;
				ap_stat_data.access_request_retry_count += bss_stat->data.access_request_retry_count;
				ap_stat_data.access_request_timeout_count += bss_stat->data.access_request_timeout_count;
				ap_stat_data.access_accept_count += bss_stat->data.access_accept_count;
				ap_stat_data.access_reject_count += bss_stat->data.access_reject_count;

				ap_stat_data.acct_request_start_count += bss_stat->data.acct_request_start_count;
				ap_stat_data.acct_request_start_retry_count += bss_stat->data.acct_request_start_retry_count;
				ap_stat_data.acct_response_start_count += bss_stat->data.acct_response_start_count;

				ap_stat_data.acct_request_update_count += bss_stat->data.acct_request_update_count;
				ap_stat_data.acct_request_update_retry_count += bss_stat->data.acct_request_update_retry_count;
				ap_stat_data.acct_response_update_count += bss_stat->data.acct_response_update_count;

				ap_stat_data.acct_request_stop_count += bss_stat->data.acct_request_stop_count;
				ap_stat_data.acct_request_stop_retry_count += bss_stat->data.acct_request_stop_retry_count;
				ap_stat_data.acct_response_stop_count += bss_stat->data.acct_response_stop_count;
			}
			DBusMessageIter iter_struct = {0};
		
			dbus_message_iter_open_container(&iter_array,
											DBUS_TYPE_STRUCT,
											NULL,
											&iter_struct);
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_BYTE,
										&(ap_stat_data.apmac[0]));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_BYTE,
										&(ap_stat_data.apmac[1]));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_BYTE,
										&(ap_stat_data.apmac[2]));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_BYTE,
										&(ap_stat_data.apmac[3]));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_BYTE,
										&(ap_stat_data.apmac[4]));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_BYTE,
									 	&(ap_stat_data.apmac[5]));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.online_user_num));
			user_connect_total_time = ap_stat_data.user_connected_total_time 
						+ ap_stat_data.user_connecting_total_time;
			dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
										&user_connect_total_time);			
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.macauth_online_user_num));
			macauth_user_connect_total_time = ap_stat_data.macauth_user_connected_total_time 
						+ ap_stat_data.macauth_user_connecting_total_time;
			dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
										&macauth_user_connect_total_time);	
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.http_redir_request_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.http_redir_success_count));			
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.challenge_req_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.challenge_ack_0_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.challenge_ack_1_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.challenge_ack_2_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.challenge_ack_3_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.challenge_ack_4_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.auth_req_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.auth_ack_0_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.auth_ack_1_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.auth_ack_2_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.auth_ack_3_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.auth_ack_4_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.macauth_req_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.macauth_ack_0_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.macauth_ack_1_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.macauth_ack_2_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.macauth_ack_3_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.macauth_ack_4_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.normal_logoff_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.abnormal_logoff_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.macauth_abnormal_logoff_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.challenge_timeout_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.challenge_busy_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.req_auth_password_missing_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.req_auth_unknown_type_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.ack_auth_busy_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.auth_disorder_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.access_request_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.access_request_retry_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.access_request_timeout_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.access_accept_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.access_reject_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.acct_request_start_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.acct_request_start_retry_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.acct_response_start_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.acct_request_update_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									 	&(ap_stat_data.acct_request_update_retry_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.acct_response_update_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.acct_request_stop_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.acct_request_stop_retry_count));
			dbus_message_iter_append_basic(&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(ap_stat_data.acct_response_stop_count));
			dbus_message_iter_close_container (&iter_array, &iter_struct);
		}
		dbus_message_iter_close_container (&iter, &iter_array);
	}

	return reply;
}


DBusMessage *
eag_dbus_method_get_bss_statistics(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_statistics_t *eagstat = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = 0;
	int num = 0;
	struct eag_ap_statistics *ap_stat = NULL;
	struct eag_bss_statistics *bss_stat = NULL;
	struct list_head *ap_head = NULL;
	uint32_t user_connect_total_time = 0;
	uint32_t macauth_user_connect_total_time = 0;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_get_bss_statistics "
			" DBUS new reply message error");
		return NULL;
	}
	
	eagstat = (eag_statistics_t *)user_data;
	if (NULL == eagstat) {
		eag_log_err("eag_dbus_method_get_bss_statistics user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	ap_head = eag_statistics_get_ap_head(eagstat);
	
	dbus_error_init(&err);
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	if (EAG_RETURN_OK == ret) {
		eag_statistics_count_online_user_info(eagstat);
		num = eag_bss_statistics_count(eagstat);
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32, &num);
	}

	if (EAG_RETURN_OK == ret && num > 0) {
		DBusMessageIter iter_array = {0};
		
		dbus_message_iter_open_container (&iter,
								DBUS_TYPE_ARRAY,
									DBUS_STRUCT_BEGIN_CHAR_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING /* wlanid */
										DBUS_TYPE_BYTE_AS_STRING /* radioid */
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
									DBUS_STRUCT_END_CHAR_AS_STRING,
								&iter_array);
		list_for_each_entry(ap_stat, ap_head, ap_node) {
			list_for_each_entry(bss_stat, &(ap_stat->bss_head), bss_node) {
				DBusMessageIter iter_struct = {0};
		
				dbus_message_iter_open_container (&iter_array,
											DBUS_TYPE_STRUCT,
											NULL,
											&iter_struct);
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_BYTE,
										&(bss_stat->data.apmac[0]));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_BYTE,
										&(bss_stat->data.apmac[1]));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_BYTE,
										&(bss_stat->data.apmac[2]));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_BYTE,
										&(bss_stat->data.apmac[3]));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_BYTE,
										&(bss_stat->data.apmac[4]));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_BYTE,
									 	&(bss_stat->data.apmac[5]));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_BYTE,
										&(bss_stat->data.wlanid));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_BYTE,
									  	&(bss_stat->data.radioid));
		
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.online_user_num));
				user_connect_total_time = bss_stat->data.user_connected_total_time 
							+ bss_stat->data.user_connecting_total_time;
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&user_connect_total_time);
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.macauth_online_user_num));
				macauth_user_connect_total_time = bss_stat->data.macauth_user_connected_total_time 
							+ bss_stat->data.macauth_user_connecting_total_time;
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&macauth_user_connect_total_time);
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.http_redir_request_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.http_redir_success_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.challenge_req_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.challenge_ack_0_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.challenge_ack_1_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.challenge_ack_2_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.challenge_ack_3_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.challenge_ack_4_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.auth_req_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.auth_ack_0_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.auth_ack_1_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.auth_ack_2_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.auth_ack_3_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.auth_ack_4_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.macauth_req_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.macauth_ack_0_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.macauth_ack_1_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.macauth_ack_2_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.macauth_ack_3_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.macauth_ack_4_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.normal_logoff_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.abnormal_logoff_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.macauth_abnormal_logoff_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.challenge_timeout_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.challenge_busy_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.req_auth_password_missing_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.req_auth_unknown_type_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.ack_auth_busy_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.auth_disorder_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.access_request_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.access_request_retry_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.access_request_timeout_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.access_accept_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.access_reject_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.acct_request_start_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.acct_request_start_retry_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.acct_response_start_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.acct_request_update_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									 	&(bss_stat->data.acct_request_update_retry_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.acct_response_update_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.acct_request_stop_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.acct_request_stop_retry_count));
				dbus_message_iter_append_basic (&iter_struct,
										DBUS_TYPE_UINT32,
									  	&(bss_stat->data.acct_response_stop_count));
			dbus_message_iter_close_container (&iter_array, &iter_struct);
			}
		}
		dbus_message_iter_close_container (&iter, &iter_array);
	}
	return reply;
}

static DBusMessage *
eag_dbus_method_show_user_all(
				DBusConnection *conn,
				DBusMessage *msg,
				void *user_data )
{
	appconn_db_t *appdb = NULL;
	struct app_conn_t *appconn = NULL;
	eag_ins_t *eagins = NULL;
	struct list_head *head = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	int num = 0;
	const char *username = NULL;
	uint32_t session_time = 0;
	struct timeval tv = {0};
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32] = "";
	int total_appconn_num = 0;
	int connected_authed_num = 0;
	int unconnect_authed_num = 0;

	eag_time_gettimeofday(&tv, NULL);
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_show_user_all "
					"DBUS new reply message error!");
		return NULL;
	}

	appdb = (appconn_db_t *)user_data;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_show_user_all user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	eagins = appconn_db_get_eagins(appdb);
	if (!eag_hansi_is_enable(eagins->eaghansi)
		||eag_hansi_is_master(eagins->eaghansi)) {	
		flush_all_appconn_flux_immediate(appdb);
	}
	head = appconn_db_get_head(appdb);
	
	dbus_error_init(&err);
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	if (EAG_RETURN_OK == ret) {
		num = appconn_count_authed(appdb);
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32, &num);
	}
	if (EAG_RETURN_OK == ret && num > 0) {
		DBusMessageIter iter_array = {0};
		
		dbus_message_iter_open_container (&iter,
								DBUS_TYPE_ARRAY,
									DBUS_STRUCT_BEGIN_CHAR_AS_STRING
										DBUS_TYPE_STRING_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_INT32_AS_STRING	//accurate_start_time
										DBUS_TYPE_UINT64_AS_STRING
										DBUS_TYPE_UINT64_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_INT32_AS_STRING
									DBUS_STRUCT_END_CHAR_AS_STRING,
								&iter_array);

		list_for_each_entry(appconn, head, node) {
			/*for onlinebug933 debug*/
			mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr), '-');
			mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr), '-');
			ip2str(appconn->session.user_ip, user_ipstr, sizeof (user_ipstr));
            if (APPCONN_STATUS_AUTHED == appconn->session.state) {
				total_appconn_num ++;
				if (SESSION_STA_STATUS_CONNECT == appconn->session.sta_state) {
					eag_log_debug("onlinebug933","Sta_state=Connected(0),State=Authed(1),apmac=%s,usermac=%s,userip=%s,username=%s", 
						ap_macstr,user_macstr,user_ipstr,appconn->session.username);
					connected_authed_num ++;
				} else if (SESSION_STA_STATUS_UNCONNECT== appconn->session.sta_state) {
					eag_log_debug("onlinebug933","Sta_state=Unconnect(1),State=Authed(1),apmac=%s,usermac=%s,userip=%s,username=%s", 
						ap_macstr,user_macstr,user_ipstr,appconn->session.username);
					unconnect_authed_num ++;
				}
			}
	
			if (APPCONN_STATUS_AUTHED == appconn->session.state) {
				DBusMessageIter iter_struct = {0};

				dbus_message_iter_open_container (&iter_array,
										DBUS_TYPE_STRUCT,
										NULL,
										&iter_struct);
				username = appconn->session.username;
				dbus_message_iter_append_basic(&iter_struct,
									DBUS_TYPE_STRING,
									&username);
				dbus_message_iter_append_basic(&iter_struct,
									DBUS_TYPE_UINT32, 
									&(appconn->session.user_ip));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[0]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[1]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[2]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[3]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[4]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[5]));
				session_time = tv.tv_sec - appconn->session.session_start_time;
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&session_time);
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_INT32,
									&(appconn->session.accurate_start_time));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT64,
									&(appconn->session.input_octets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT64,
									&(appconn->session.output_octets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.input_packets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.output_packets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[0]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[1]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[2]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[3]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[4]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[5]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.vlanid));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_INT32,
									&(appconn->session.sta_state));
				dbus_message_iter_close_container (&iter_array, &iter_struct);
			}
		}
		dbus_message_iter_close_container (&iter, &iter_array);
		
		eag_log_debug("onlinebug933","Total-appconn-num:%d, Connected-Authed-num:%d, Unconnect-Authed-num:%d",
			total_appconn_num, connected_authed_num, unconnect_authed_num);
	}
	
	return reply;
}

static DBusMessage *
eag_dbus_method_show_user_by_username(
				DBusConnection *conn,
				DBusMessage *msg,
				void *user_data )
{
	appconn_db_t *appdb = NULL;
	struct app_conn_t *appconn = NULL;
	eag_ins_t *eagins = NULL;
	struct list_head *head = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	int num = 0;
	const char *username = NULL;
	uint32_t session_time = 0;
	struct timeval tv = {0};
	
	eag_time_gettimeofday(&tv, NULL);
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_show_user_by_username "
					"DBUS new reply message error!");
		return NULL;
	}

	appdb = (appconn_db_t *)user_data;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_show_user_by_username user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	eagins = appconn_db_get_eagins(appdb);
	if (!eag_hansi_is_enable(eagins->eaghansi)
		||eag_hansi_is_master(eagins->eaghansi)) {	
		flush_all_appconn_flux_immediate(appdb);
	}
	head = appconn_db_get_head(appdb);
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg, &err,
								DBUS_TYPE_STRING, &username,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_show_user_by_username "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_show_user_by_username %s raised:%s",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	if (EAG_RETURN_OK == ret) {
		num = appconn_count_by_username(appdb, username);
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32, &(num));
	}
	if (EAG_RETURN_OK == ret && num > 0) {
		DBusMessageIter iter_array = {0};
		
		dbus_message_iter_open_container (&iter,
								DBUS_TYPE_ARRAY,
									DBUS_STRUCT_BEGIN_CHAR_AS_STRING
										DBUS_TYPE_STRING_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT64_AS_STRING
										DBUS_TYPE_UINT64_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
									DBUS_STRUCT_END_CHAR_AS_STRING,
								&iter_array);

		list_for_each_entry(appconn, head, node) {
			if (APPCONN_STATUS_AUTHED == appconn->session.state
				&& strcmp(username, appconn->session.username) == 0) {
				DBusMessageIter iter_struct = {0};

				dbus_message_iter_open_container (&iter_array,
										DBUS_TYPE_STRUCT,
										NULL,
										&iter_struct);
				dbus_message_iter_append_basic(&iter_struct,
									DBUS_TYPE_STRING,
									&username);
				dbus_message_iter_append_basic(&iter_struct,
									DBUS_TYPE_UINT32, 
									&(appconn->session.user_ip));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[0]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[1]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[2]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[3]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[4]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[5]));
				session_time = tv.tv_sec - appconn->session.session_start_time;
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&session_time);
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT64,
									&(appconn->session.input_octets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT64,
									&(appconn->session.output_octets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.input_packets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.output_packets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[0]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[1]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[2]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[3]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[4]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[5]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.auth_tag));
				dbus_message_iter_close_container (&iter_array, &iter_struct);
			}
		}
		dbus_message_iter_close_container (&iter, &iter_array);
	}
	
	return reply;
}

static DBusMessage *
eag_dbus_method_show_user_by_userip(
				DBusConnection *conn,
				DBusMessage *msg,
				void *user_data )
{
	appconn_db_t *appdb = NULL;
	struct app_conn_t *appconn = NULL;
	eag_ins_t *eagins = NULL;
	struct list_head *head = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	int num = 0;
	const char *username = NULL;
	uint32_t session_time = 0;
	struct timeval tv = {0};
	uint32_t userip = 0;

	eag_time_gettimeofday(&tv, NULL);
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_show_user_by_userip "
					"DBUS new reply message error!");
		return NULL;
	}

	appdb = (appconn_db_t *)user_data;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_show_user_by_userip user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	eagins = appconn_db_get_eagins(appdb);
	if (!eag_hansi_is_enable(eagins->eaghansi)
		||eag_hansi_is_master(eagins->eaghansi)) {	
		flush_all_appconn_flux_immediate(appdb);
	}
	head = appconn_db_get_head(appdb);
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg, &err,
								DBUS_TYPE_UINT32, &userip,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_show_user_by_userip "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_show_user_by_userip %s raised:%s",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	if (EAG_RETURN_OK == ret) {
		num = appconn_count_by_userip(appdb, userip);
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32, &(num));
	}
	if (EAG_RETURN_OK == ret && num > 0) {
		DBusMessageIter iter_array = {0};
		
		dbus_message_iter_open_container (&iter,
								DBUS_TYPE_ARRAY,
									DBUS_STRUCT_BEGIN_CHAR_AS_STRING
										DBUS_TYPE_STRING_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT64_AS_STRING
										DBUS_TYPE_UINT64_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
									DBUS_STRUCT_END_CHAR_AS_STRING,
								&iter_array);

		list_for_each_entry(appconn, head, node) {
			if (APPCONN_STATUS_AUTHED == appconn->session.state
				&& userip == appconn->session.user_ip) {
				DBusMessageIter iter_struct = {0};

				dbus_message_iter_open_container (&iter_array,
										DBUS_TYPE_STRUCT,
										NULL,
										&iter_struct);
				username = appconn->session.username;
				dbus_message_iter_append_basic(&iter_struct,
									DBUS_TYPE_STRING,
									&username);
				dbus_message_iter_append_basic(&iter_struct,
									DBUS_TYPE_UINT32, 
									&(appconn->session.user_ip));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[0]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[1]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[2]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[3]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[4]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[5]));
				session_time = tv.tv_sec - appconn->session.session_start_time;
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&session_time);
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT64,
									&(appconn->session.input_octets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT64,
									&(appconn->session.output_octets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.input_packets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.output_packets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[0]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[1]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[2]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[3]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[4]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[5]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.auth_tag));
				dbus_message_iter_close_container (&iter_array, &iter_struct);
			}
		}
		dbus_message_iter_close_container (&iter, &iter_array);
	}
	
	return reply;
}

static DBusMessage *
eag_dbus_method_show_user_by_usermac(
				DBusConnection *conn,
				DBusMessage *msg,
				void *user_data )
{
	appconn_db_t *appdb = NULL;
	struct app_conn_t *appconn = NULL;
	eag_ins_t *eagins = NULL;
	struct list_head *head = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	int num = 0;
	const char *username = NULL;
	uint32_t session_time = 0;
	struct timeval tv = {0};
	uint8_t usermac[6] = {0};

	eag_time_gettimeofday(&tv, NULL);
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_show_user_by_usermac "
					"DBUS new reply message error!");
		return NULL;
	}

	appdb = (appconn_db_t *)user_data;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_show_user_by_usermac user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	eagins = appconn_db_get_eagins(appdb);
	if (!eag_hansi_is_enable(eagins->eaghansi)
		||eag_hansi_is_master(eagins->eaghansi)) {	
		flush_all_appconn_flux_immediate(appdb);
	}
	head = appconn_db_get_head(appdb);
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg, &err,
								DBUS_TYPE_BYTE, &usermac[0],
								DBUS_TYPE_BYTE, &usermac[1],
								DBUS_TYPE_BYTE, &usermac[2],
								DBUS_TYPE_BYTE, &usermac[3],
								DBUS_TYPE_BYTE, &usermac[4],
								DBUS_TYPE_BYTE, &usermac[5],
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_show_user_by_usermac "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_show_user_by_usermac %s raised:%s",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	if (EAG_RETURN_OK == ret) {
		num = appconn_count_by_usermac(appdb, usermac);
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32, &(num));
	}
	if (EAG_RETURN_OK == ret && num > 0) {
		DBusMessageIter iter_array = {0};
		
		dbus_message_iter_open_container (&iter,
								DBUS_TYPE_ARRAY,
									DBUS_STRUCT_BEGIN_CHAR_AS_STRING
										DBUS_TYPE_STRING_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT64_AS_STRING
										DBUS_TYPE_UINT64_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
									DBUS_STRUCT_END_CHAR_AS_STRING,
								&iter_array);

		list_for_each_entry(appconn, head, node) {
			if (APPCONN_STATUS_AUTHED == appconn->session.state
				&& memcmp(usermac, appconn->session.usermac, 6) == 0 ) {
				DBusMessageIter iter_struct = {0};

				dbus_message_iter_open_container (&iter_array,
										DBUS_TYPE_STRUCT,
										NULL,
										&iter_struct);
				username = appconn->session.username;
				dbus_message_iter_append_basic(&iter_struct,
									DBUS_TYPE_STRING,
									&username);
				dbus_message_iter_append_basic(&iter_struct,
									DBUS_TYPE_UINT32, 
									&(appconn->session.user_ip));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[0]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[1]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[2]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[3]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[4]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[5]));
				session_time = tv.tv_sec - appconn->session.session_start_time;
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&session_time);
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT64,
									&(appconn->session.input_octets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT64,
									&(appconn->session.output_octets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.input_packets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.output_packets));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[0]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[1]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[2]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[3]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[4]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[5]));
				dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.auth_tag));
				dbus_message_iter_close_container (&iter_array, &iter_struct);
			}
		}
		dbus_message_iter_close_container (&iter, &iter_array);
	}
	
	return reply;
}

static DBusMessage *
eag_dbus_method_show_user_by_index(
				DBusConnection *conn,
				DBusMessage *msg,
				void *user_data )
{
	appconn_db_t *appdb = NULL;
	struct app_conn_t *appconn = NULL;
	eag_ins_t *eagins = NULL;
	struct list_head *head = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	int num = 0;
	const char *username = NULL;
	uint32_t session_time = 0;
	struct timeval tv = {0};
	uint32_t total = 0;
	uint32_t index = 0;
	int i = 0;

	eag_time_gettimeofday(&tv, NULL);
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_show_user_by_index "
					"DBUS new reply message error!");
		return NULL;
	}

	appdb = (appconn_db_t *)user_data;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_show_user_by_index user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	eagins = appconn_db_get_eagins(appdb);
	if (!eag_hansi_is_enable(eagins->eaghansi)
		||eag_hansi_is_master(eagins->eaghansi)) {	
		flush_all_appconn_flux_immediate(appdb);
	}
	head = appconn_db_get_head(appdb);
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg, &err,
								DBUS_TYPE_UINT32, &index,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_show_user_by_index "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_show_user_by_index %s raised:%s",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	if (EAG_RETURN_OK == ret) {
		total = appconn_count_authed(appdb);
		num = (index <= total) ? 1 : 0; 
		dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_UINT32, &(num));
	}
	if (EAG_RETURN_OK == ret && num > 0) {
		DBusMessageIter iter_array = {0};
		
		dbus_message_iter_open_container (&iter,
								DBUS_TYPE_ARRAY,
									DBUS_STRUCT_BEGIN_CHAR_AS_STRING
										DBUS_TYPE_STRING_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT64_AS_STRING
										DBUS_TYPE_UINT64_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_BYTE_AS_STRING
										DBUS_TYPE_UINT32_AS_STRING
									DBUS_STRUCT_END_CHAR_AS_STRING,
								&iter_array);

		list_for_each_entry(appconn, head, node) {
			if (APPCONN_STATUS_AUTHED == appconn->session.state) {
				i++;
				if (i == index) {
					DBusMessageIter iter_struct = {0};

					dbus_message_iter_open_container (&iter_array,
										DBUS_TYPE_STRUCT,
										NULL,
										&iter_struct);
					username = appconn->session.username;
					dbus_message_iter_append_basic(&iter_struct,
									DBUS_TYPE_STRING,
									&username);
					dbus_message_iter_append_basic(&iter_struct,
									DBUS_TYPE_UINT32, 
									&(appconn->session.user_ip));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[0]));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[1]));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[2]));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[3]));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[4]));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.usermac[5]));
					session_time = tv.tv_sec - appconn->session.session_start_time;
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&session_time);
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT64,
									&(appconn->session.input_octets));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT64,
									&(appconn->session.output_octets));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.input_packets));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.output_packets));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[0]));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[1]));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[2]));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[3]));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[4]));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_BYTE,
									&(appconn->session.apmac[5]));
					dbus_message_iter_append_basic (&iter_struct,
									DBUS_TYPE_UINT32,
									&(appconn->session.auth_tag));
					dbus_message_iter_close_container (&iter_array, &iter_struct);
					break;
				}
			}
		}
		dbus_message_iter_close_container (&iter, &iter_array);
	}
	
	return reply;
}

static DBusMessage *
eag_dbus_method_kick_user_by_username(
				DBusConnection *conn,
				DBusMessage *msg,
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	appconn_db_t *appdb = NULL;
	struct app_conn_t *appconn = NULL;
	struct app_conn_t *next = NULL;
	struct list_head *head = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	const char *username = NULL;
	int ret = EAG_RETURN_OK;
	int num = 0;
	time_t timenow = 0;
	struct timeval tv = {0};

	eag_time_gettimeofday(&tv, NULL);
	timenow = tv.tv_sec;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_kick_user_by_username "
					"DBUS new reply message error!");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_kick_user_by_username user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg, &err,
								DBUS_TYPE_STRING, &username,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_kick_user_by_username "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_kick_user_by_username %s raised:%s",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	appdb = eagins->appdb;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_kick_user_by_username appdb null");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	head = appconn_db_get_head(appdb);

	if (eag_hansi_is_backup(eagins->eaghansi)) {
		eag_log_warning("kick_user_by_username not allow, for hansi is backup");
		ret = EAG_ERR_HANSI_IS_BACKUP;
		goto replyx;
	}
	num = appconn_count_by_username(appdb, username);
	if (num <= 0) {
		eag_log_err("eag_dbus_method_kick_user_by_username num <= 0");
		ret = EAG_ERR_APPCONN_DELAPP_NOT_INDB;
		goto replyx;
	}
	
	list_for_each_entry_safe(appconn, next, head, node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state
			&& strcmp(username, appconn->session.username) == 0
			&& !appconn->on_ntf_logout) {
			eag_portal_notify_logout(eagins->portal, appconn,
					RADIUS_TERMINATE_CAUSE_NAS_REQUEST);
			appconn->on_ntf_logout = 1;
			appconn->session.session_stop_time = timenow;
		}
	}
	ret = EAG_RETURN_OK;
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	
	return reply;
}

static DBusMessage *
eag_dbus_method_kick_user_by_userip(
				DBusConnection *conn,
				DBusMessage *msg,
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	appconn_db_t *appdb = NULL;
	struct app_conn_t *appconn = NULL;
	struct app_conn_t *next = NULL;
	struct list_head *head = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	uint32_t userip = 0;
	int ret = EAG_RETURN_OK;
	int num = 0;
	time_t timenow = 0;
	struct timeval tv = {0};

	eag_time_gettimeofday(&tv, NULL);
	timenow = tv.tv_sec;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_kick_user_by_userip "
					"DBUS new reply message error!");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_kick_user_by_userip user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg, &err,
								DBUS_TYPE_UINT32, &userip,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_kick_user_by_userip "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_kick_user_by_userip %s raised:%s",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	appdb = eagins->appdb;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_kick_user_by_userip appdb null");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	head = appconn_db_get_head(appdb);
	
	if (eag_hansi_is_backup(eagins->eaghansi)) {
		eag_log_warning("kick_user_by_username not allow, for hansi is backup");
		ret = EAG_ERR_HANSI_IS_BACKUP;
		goto replyx;
	}
	num = appconn_count_by_userip(appdb, userip);
	if (num <= 0) {
		eag_log_err("eag_dbus_method_kick_user_by_userip num <= 0");
		ret = EAG_ERR_APPCONN_DELAPP_NOT_INDB;
		goto replyx;
	}
	
	list_for_each_entry_safe(appconn, next, head, node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state
			&& userip == appconn->session.user_ip) {
			eag_portal_notify_logout(eagins->portal, appconn,
					RADIUS_TERMINATE_CAUSE_NAS_REQUEST);
			appconn->on_ntf_logout = 1;
			appconn->session.session_stop_time = timenow;
		}
	}
	ret = EAG_RETURN_OK;
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	
	return reply;
}

static DBusMessage *
eag_dbus_method_kick_user_by_usermac(
				DBusConnection *conn,
				DBusMessage *msg,
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	appconn_db_t *appdb = NULL;
	struct app_conn_t *appconn = NULL;
	struct app_conn_t *next = NULL;
	struct list_head *head = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	uint8_t usermac[6] = {0};
	int ret = EAG_RETURN_OK;
	int num = 0;
	time_t timenow = 0;
	struct timeval tv = {0};

	eag_time_gettimeofday(&tv, NULL);
	timenow = tv.tv_sec;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_kick_user_by_usermac "
					"DBUS new reply message error!");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_kick_user_by_usermac user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg, &err,
								DBUS_TYPE_BYTE, &usermac[0],
								DBUS_TYPE_BYTE, &usermac[1],
								DBUS_TYPE_BYTE, &usermac[2],
								DBUS_TYPE_BYTE, &usermac[3],
								DBUS_TYPE_BYTE, &usermac[4],
								DBUS_TYPE_BYTE, &usermac[5],
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_kick_user_by_usermac "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_kick_user_by_usermac %s raised:%s",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	appdb = eagins->appdb;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_kick_user_by_usermac appdb null");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	head = appconn_db_get_head(appdb);
	
	if (eag_hansi_is_backup(eagins->eaghansi)) {
		eag_log_warning("kick_user_by_username not allow, for hansi is backup");
		ret = EAG_ERR_HANSI_IS_BACKUP;
		goto replyx;
	}
	num = appconn_count_by_usermac(appdb, usermac);
	if (num <= 0) {
		eag_log_err("eag_dbus_method_kick_user_by_usermac num <= 0");
		ret = EAG_ERR_APPCONN_DELAPP_NOT_INDB;
		goto replyx;
	}
	
	list_for_each_entry_safe(appconn, next, head, node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state
			&& memcmp(usermac, appconn->session.usermac, 6) == 0 ) {
			eag_portal_notify_logout(eagins->portal, appconn,
					RADIUS_TERMINATE_CAUSE_NAS_REQUEST);
			appconn->on_ntf_logout = 1;
			appconn->session.session_stop_time = timenow;
		}
	}
	ret = EAG_RETURN_OK;
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	
	return reply;
}

static DBusMessage *
eag_dbus_method_kick_user_by_index(
				DBusConnection *conn,
				DBusMessage *msg,
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	appconn_db_t *appdb = NULL;
	struct app_conn_t *appconn = NULL;
	struct app_conn_t *next = NULL;
	struct list_head *head = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	uint32_t index = 0;
	uint32_t total = 0;
	int i = 0;
	int ret = EAG_RETURN_OK;
	time_t timenow = 0;
	struct timeval tv = {0};

	eag_time_gettimeofday(&tv, NULL);
	timenow = tv.tv_sec;
	
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_kick_user_by_index "
					"DBUS new reply message error!");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_kick_user_by_index user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg, &err,
								DBUS_TYPE_UINT32, &index,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_kick_user_by_index "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_kick_user_by_index %s raised:%s",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	appdb = eagins->appdb;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_kick_user_by_index appdb null");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	head = appconn_db_get_head(appdb);
	
	if (eag_hansi_is_backup(eagins->eaghansi)) {
		eag_log_warning("kick_user_by_username not allow, for hansi is backup");
		ret = EAG_ERR_HANSI_IS_BACKUP;
		goto replyx;
	}
	total = appconn_count_authed(appdb);
	if (index > total) {
		eag_log_warning("eag_dbus_method_kick_user_by_index index %u > total %u",
				index, total);
		ret = EAG_ERR_APPCONN_DELAPP_NOT_INDB;
		goto replyx;
	}
	
	list_for_each_entry_safe(appconn, next, head, node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			i++;
			if (i == index) {
				eag_portal_notify_logout(eagins->portal, appconn,
					RADIUS_TERMINATE_CAUSE_NAS_REQUEST);
				appconn->on_ntf_logout = 1;
				appconn->session.session_stop_time = timenow;
				break;
			}
		}
	}
	ret = EAG_RETURN_OK;
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	
	return reply;
}

DBusMessage *
eag_dbus_method_set_l2super_vlan_switch(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int l2super_vlan_switch = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_l2super_vlan_switch "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_set_l2super_vlan_switch user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &l2super_vlan_switch,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_l2super_vlan_switch "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_l2super_vlan_switch %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	ret = eag_set_l2super_vlan_status(l2super_vlan_switch);
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_macauth_switch(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_macauth_t *macauth = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int macauth_switch = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_macauth_switch "
					"DBUS new reply message error");
		return NULL;
	}

	macauth = (eag_macauth_t *)user_data;
	if (NULL == macauth) {
		eag_log_err("eag_dbus_method_set_macauth_switch user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &macauth_switch,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_macauth_switch "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_macauth_switch %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = eag_macauth_set_macauth_switch(macauth, macauth_switch);
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_macauth_type(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_macauth_t *macauth = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int macauth_type = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_macauth_type "
					"DBUS new reply message error");
		return NULL;
	}

	macauth = (eag_macauth_t *)user_data;
	if (NULL == macauth) {
		eag_log_err("eag_dbus_method_set_macauth_type user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &macauth_type,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_macauth_type "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_macauth_type %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = eag_macauth_set_macauth_type(macauth_type);
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_macauth_ipset_auth(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_captive_t *cap = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int ipset_auth = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_macauth_ipset_auth "
					"DBUS new reply message error");
		return NULL;
	}

	cap = (eag_captive_t *)user_data;
	if (NULL == cap) {
		eag_log_err("eag_dbus_method_set_macauth_ipset_auth user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &ipset_auth,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_macauth_ipset_auth "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_macauth_ipset_auth %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = eag_captive_set_macauth_ipset(cap, ipset_auth);
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_macauth_flux_from(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_macauth_t *macauth = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	int ret = EAG_RETURN_OK;
	int flux_from = 0;
	reply = dbus_message_new_method_return(msg);
	
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_macauth_flux_from "\
					"DBUS new reply message error!\n");
		return NULL;
	}
	
	macauth = (eag_macauth_t *)user_data;
	if ( NULL == macauth ){
		eag_log_err("eag_dbus_method_set_macauth_flux_from user_data error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &flux_from,		
								DBUS_TYPE_INVALID)))
	{							
		eag_log_err("eag_dbus_method_set_macauth_flux_from "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_macauth_flux_from %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = eag_macauth_set_flux_from(macauth, flux_from);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_macauth_flux_interval(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_macauth_t *macauth = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int flux_interval = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_macauth_flux_interval "
					"DBUS new reply message error");
		return NULL;
	}

	macauth = (eag_macauth_t *)user_data;
	if (NULL == macauth) {
		eag_log_err("eag_dbus_method_set_macauth_flux_interval user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &flux_interval,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_macauth_flux_interval "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_macauth_flux_interval %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = eag_macauth_set_flux_interval(macauth, flux_interval);
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_macauth_flux_threshold(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_macauth_t *macauth = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int flux_threshold = 0;
    int check_interval = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_macauth_flux_threshold "
					"DBUS new reply message error");
		return NULL;
	}

	macauth = (eag_macauth_t *)user_data;
	if (NULL == macauth) {
		eag_log_err("eag_dbus_method_set_macauth_flux_threshold user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &flux_threshold,
								DBUS_TYPE_INT32, &check_interval, 
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_macauth_flux_threshold "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_macauth_flux_threshold %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	
	ret = eag_macauth_set_flux_threshold(macauth, flux_threshold, check_interval);
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_macauth_notice_bindserver(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int notice_bindserver = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_macauth_notice_bindserver "
					"DBUS new reply message error");
		return NULL;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &notice_bindserver,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_macauth_notice_bindserver "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_macauth_notice_bindserver %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	notice_to_bindserver = notice_bindserver;
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_trap_switch_abnormal_logoff(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = EAG_RETURN_OK;
	int trap_switch = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_trap_switch_abnormal_logoff "
					"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_set_trap_switch_abnormal_logoff user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &trap_switch,
								DBUS_TYPE_INVALID))) {
		eag_log_err("eag_dbus_method_set_trap_switch_abnormal_logoff "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_trap_switch_abnormal_logoff %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}

	eagins->trap_switch_abnormal_logoff = trap_switch;
	
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_portal_protocol(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	int ret = EAG_RETURN_OK;
	int protocol_type = PORTAL_PROTOCOL_MOBILE;
	reply = dbus_message_new_method_return(msg);
	
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_portal_protocol "\
					"DBUS new reply message error!\n");
		return NULL;
	}
	eagins = (eag_ins_t *)user_data;
	if ( NULL == eagins ){
		eag_log_err("eag_dbus_method_set_portal_protocol user_data eagins error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &protocol_type,		
								DBUS_TYPE_INVALID)))
	{							
		eag_log_err("eag_dbus_method_set_portal_protocol "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_portal_protocol %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	portal_set_protocol_type(protocol_type);
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_telecom_idletime_valuecheck(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	int ret = EAG_RETURN_OK;
	int value_check = 0;
	reply = dbus_message_new_method_return(msg);
	
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_telecom_idletime_valuecheck "\
					"DBUS new reply message error!\n");
		return NULL;
	}
	eagins = (eag_ins_t *)user_data;
	if ( NULL == eagins ){
		eag_log_err("eag_dbus_method_set_telecom_idletime_valuecheck user_data eagins error!");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &value_check,		
								DBUS_TYPE_INVALID)))
	{							
		eag_log_err("eag_dbus_method_set_telecom_idletime_valuecheck "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_telecom_idletime_valuecheck %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}
	eag_set_idletime_valuecheck(value_check);
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_add_debug_filter(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	char *filter;
	
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_add_debug_filter "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_STRING, &filter,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_add_debug_filter "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_add_debug_filter %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	eag_log_add_filter(filter);
	ret = EAG_RETURN_OK;
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}



DBusMessage *
eag_dbus_method_del_debug_filter(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	char *filter;
	
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_add_debug_filter "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_STRING, &filter,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_add_debug_filter "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_add_debug_filter %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	eag_log_del_filter(filter);
	ret = EAG_RETURN_OK;
replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_log_all_appconn(
			    DBusConnection *conn, 
			    DBusMessage *msg, 
			    void *user_data )
{
	appconn_db_t *appdb = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_log_all_appconn "
			"DBUS new reply message error");
		return NULL;
	}

	appdb = (appconn_db_t *)user_data;
	if (NULL == appdb) {
		eag_log_err("eag_dbus_method_log_all_appconn user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	appdb_log_all_appconn(appdb);
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_log_all_redirconn(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_redir_t *redir = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_log_all_redirconn "
			"DBUS new reply message error");
		return NULL;
	}

	redir = (eag_redir_t *)user_data;
	if (NULL == redir) {
		eag_log_err("eag_dbus_method_log_all_redirconn user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	eag_redir_log_all_redirconn(redir);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_log_all_portalsess(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_portal_t *portal = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_log_all_portalsess "
			"DBUS new reply message error");
		return NULL;
	}

	portal = (eag_portal_t *)user_data;
	if (NULL == portal) {
		eag_log_err("eag_dbus_method_log_all_portalsess user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	eag_portal_log_all_portalsess(portal);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_log_all_sockradius(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_radius_t *radius = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_log_all_sockradius "
			"DBUS new reply message error");
		return NULL;
	}

	radius = (eag_radius_t *)user_data;
	if (NULL == radius) {
		eag_log_err("eag_dbus_method_log_all_sockradius user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}
	
	eag_radius_log_all_sockradius(radius);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_log_all_thread(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_log_all_thread "
			"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_log_all_thread user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	eag_thread_log_all_thread(eagins->master);
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_log_all_blkmem(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_ins_t *eagins = NULL;
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_log_all_blkmem "
			"DBUS new reply message error");
		return NULL;
	}

	eagins = (eag_ins_t *)user_data;
	if (NULL == eagins) {
		eag_log_err("eag_dbus_method_log_all_blkmem user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	eag_blkmem_log_all_blkmem(NULL);
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_log_all_mac_preauth(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	eag_macauth_t *macauth = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	int ret = EAG_RETURN_OK;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_log_all_mac_preauth "
			"DBUS new reply message error");
		return NULL;
	}

	macauth = (eag_macauth_t *)user_data;
	if (NULL == macauth) {
		eag_log_err("eag_dbus_method_log_all_mac_preauth user_data error");
		ret = EAG_ERR_UNKNOWN;
		goto replyx;
	}

	eag_macauth_log_all_preauth(macauth);

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_user_log_status(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	int status = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_user_log_status "
					"DBUS new reply message error");
		return NULL;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &status,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_user_log_status "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_user_log_status %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	eag_set_user_log(status);
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);

	return reply;
}

DBusMessage *
eag_dbus_method_set_log_format_status(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	int status = 0;
	int key = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_log_format_status "
					"DBUS new reply message error");
		return NULL;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &key,
								DBUS_TYPE_INT32, &status,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_log_format_status "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_log_format_status %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	eag_set_log_format(key, status);
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);

	return reply;
}

DBusMessage *
eag_dbus_method_set_username_check_status(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter = {0};
	DBusError err = {0};
	int ret = -1;
	int status = 0;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_username_check_status "
					"DBUS new reply message error");
		return NULL;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &status,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_username_check_status "
					"unable to get input args");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_username_check_status %s raised:%s",
						err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	username_check_switch = status;
	ret = EAG_RETURN_OK;

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);

	return reply;
}

DBusMessage *
eag_dbus_method_log_debug_on(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned int debug = 0;
	
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_log_debug_on "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &debug,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_log_debug_on "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_log_debug_on %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	

	if (EAG_RETURN_OK != (ret = eag_log_set_debug_value(debug))){
		openlog(STR_EAG, LOG_ODELAY, LOG_DAEMON); 
		eag_daemon_log_open = EAG_DAEMON_LOG_OPEN;
		ret = EAG_RETURN_OK;
	}

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);

	eag_log_notice("log open\n");
	return reply;
}

DBusMessage *
eag_dbus_method_log_debug_off(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	unsigned int debug  = 0;
	
	int ret = -1;

	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_log_debug_off "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	dbus_error_init(&err);
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_UINT32, &debug,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_log_debug_off "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_log_debug_off %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyx;
	}	
	eag_log_notice("log close\n");

	if (EAG_RETURN_OK != (ret = eag_log_set_no_debug_value(debug))){
		openlog(STR_EAG, LOG_ODELAY, LOG_DAEMON); 
		eag_daemon_log_open = EAG_DAEMON_LOG_CLOSE;
		ret = EAG_RETURN_OK;
	}

replyx:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
								DBUS_TYPE_INT32, &ret);

	return reply;
}

DBusMessage *
eag_dbus_method_set_pdc_client_log(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	int status = 0;
	int ret = EAG_RETURN_OK;
	eag_log_info("eag_dbus_method_set_rdc_socketclient_log");
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_rdc_socketclient_log "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	dbus_error_init(&err);
	
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &status,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_rdc_socketclient_log "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_rdc_socketclient_log %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyy;
	}	
	eag_log_info("eag rdc client socket pkg log set to %d", status);
	pdc_set_log_packet_switch(status);

replyy:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}

DBusMessage *
eag_dbus_method_set_rdc_client_log(
				DBusConnection *conn, 
				DBusMessage *msg, 
				void *user_data )
{
	DBusMessage* reply = NULL;
	DBusMessageIter iter = {0};
	DBusError		err = {0};
	int status = 0;
	int ret = EAG_RETURN_OK;
	eag_log_info("eag_dbus_method_set_rdc_socketclient_log");
	reply = dbus_message_new_method_return(msg);
	if (NULL == reply) {
		eag_log_err("eag_dbus_method_set_rdc_socketclient_log "\
					"DBUS new reply message error!\n");
		return NULL;
	}

	dbus_error_init(&err);
	
	if (!(dbus_message_get_args(msg ,&err,
								DBUS_TYPE_INT32, &status,
								DBUS_TYPE_INVALID))){
		eag_log_err("eag_dbus_method_set_rdc_socketclient_log "\
					"unable to get input args\n");
		if (dbus_error_is_set(&err)) {
			eag_log_err("eag_dbus_method_set_rdc_socketclient_log %s raised:%s\n",
							err.name, err.message);
			dbus_error_free(&err);
		}
		ret = EAG_ERR_DBUS_FAILED;
		goto replyy;
	}	
	eag_log_info("eag rdc client socket pkg log set to %d", status);
	rdc_set_log_packet_switch(status);

replyy:
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter,
									DBUS_TYPE_INT32, &ret);
	return reply;
}
#endif
#if 0
static void
eagins_register_all_dbus_method(eag_ins_t *eagins)
{
	/* base conf */
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_nasip, eagins);
	/* eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_distributed, eagins); */
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_rdc_distributed, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_pdc_distributed, eagins);
	/*eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_rdcpdc_ins, eagins); */
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_rdc_ins, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_pdc_ins, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_portal_port, eagins->portal);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_portal_retry_params, eagins->portal);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_auto_session, eagins->portal);

	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_radius_acct_interval, eagins->radius);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_radius_retry_params, eagins->radius);

	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_max_redir_times, eagins->redir);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_force_dhcplease, eagins->redir);
	eag_dbus_register_method(eagins->eagdbus,
			EAG_DBUS_INTERFACE, eag_dbus_method_set_check_errid, eagins->portal);

	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_idle_params, eagins->appdb);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_force_wireless, eagins->appdb);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_flux_from, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_flux_interval, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_ipset_auth, eagins->captive);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE,eag_dbus_method_set_trap_onlineusernum_switch, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE,eag_dbus_method_set_threshold_onlineusernum, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_check_nasportid, eagins->appdb);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_octets_correct_factor, eagins->appdb);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_trap_switch_abnormal_logoff, eagins);
	
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_service_status, eagins);
	eag_dbus_register_method(eagins->eagdbus,
			EAG_DBUS_INTERFACE, eag_dbus_method_check_status, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_get_base_conf, eagins);
		eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_show_relative_time, eagins);
	
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_portal_protocol, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_telecom_idletime_valuecheck, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_l2super_vlan_switch, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_macauth_switch, eagins->macauth);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_macauth_type, eagins->macauth);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_macauth_ipset_auth, eagins->captive);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_macauth_flux_from, eagins->macauth);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_macauth_flux_interval, eagins->macauth);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_macauth_flux_threshold, eagins->macauth);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_macauth_notice_bindserver, eagins->macauth);
	/* nasid */
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_add_nasid, &eagins->nasidconf);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_modify_nasid, &eagins->nasidconf);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_get_nasid, &eagins->nasidconf);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_del_nasid, &eagins->nasidconf);
	
	/* nasportid */			
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_add_nasportid, &eagins->nasportidconf);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_get_nasportid, &eagins->nasportidconf);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_del_nasportid, &eagins->nasportidconf);
	
	/*captive*/
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_add_captive_intf, eagins);	
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_del_captive_intf, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_add_captive_tag, eagins);	
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_del_captive_tag, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_conf_captive_list, eagins->captive);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_show_captive_intfs, eagins->captive);	
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_show_captive_tag, eagins->captive);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_show_white_list, eagins->captive);	
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_show_black_list, eagins->captive);	

	/* portal conf */
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_add_portal, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_modify_portal, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_del_portal, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_get_portal_conf, eagins);		
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_macbind, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_acname, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_acip_to_url, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_nasid_to_url, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_wlanparameter, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_wlanuserfirsturl, &(eagins->portalconf));	
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_url_suffix, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_portal_secret, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_wlanapmac, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_usermac_to_url, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_clientmac_to_url, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_apmac_to_url, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_wlan_to_url, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_redirect_to_url, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_wlanusermac, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_wisprlogin, &(eagins->portalconf));	
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_show_urlparam, &(eagins->portalconf));	
    eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_urlparam, &(eagins->portalconf));
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_mobile_urlparam, &(eagins->portalconf));

	/*radius conf */
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_add_radius, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_modify_radius, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_del_radius, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_remove_domain_switch, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_class_to_bandwidth_switch, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_get_radius_conf, eagins);
	
	/* vrrp */
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_hansi_dbus_vrrp_state_change_func, eagins->eaghansi);
	/*hmd*/
	/*
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_hansi_dbus_hmd_state_change_func, eagins->eaghansi);
	*/
	/* bss statistics */
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_get_bss_statistics, eagins->eagstat);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_get_ap_statistics, eagins->eagstat);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_get_eag_statistics, eagins->eagstat);
	/* online user */
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_show_user_all, eagins->appdb);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_show_user_by_username, eagins->appdb);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_show_user_by_userip, eagins->appdb);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_show_user_by_usermac, eagins->appdb);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_show_user_by_index, eagins->appdb);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_kick_user_by_username, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_kick_user_by_userip, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_kick_user_by_usermac, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_kick_user_by_index, eagins);
	
	/* debug */
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_add_debug_filter, NULL);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_del_debug_filter, NULL);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_log_all_appconn, eagins->appdb);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_log_all_redirconn, eagins->redir);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_log_all_portalsess, eagins->portal);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_log_all_sockradius, eagins->radius);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_log_all_thread, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_log_all_blkmem, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_log_all_mac_preauth, eagins->macauth);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_user_log_status, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_log_format_status, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_username_check_status, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_log_debug_on, eagins);
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_log_debug_off, eagins);

	/*eag rdc client*/
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_rdc_client_log, NULL);
	/*eag pdc client*/
	eag_dbus_register_method(eagins->eagdbus,
		EAG_DBUS_INTERFACE, eag_dbus_method_set_pdc_client_log, NULL);

	return;
}
#endif

