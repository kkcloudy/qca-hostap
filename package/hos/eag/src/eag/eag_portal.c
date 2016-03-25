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
* eag_portal.c
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* eag portal
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
#include <time.h>

#include "nm_list.h"
#include "hashtable.h"
#include "eag_mem.h"
#include "eag_log.h"
#include "eag_blkmem.h"
#include "eag_thread.h"
#include "eag_conf.h"  //not need
#include "eag_time.h"
#include "eag_util.h"

#include "portal_packet.h"
#include "radius_packet.h"
//#include "pdc_handle.h"
#include "eag_radius.h"
#include "eag_portal.h"
#include "appconn.h"
#include "eag_statistics.h"
#include "eag_captive.h"
#include "eag_interface.h"
#include "eag_ins.h"
#include "eag_coa.h"
#include "eag_stamsg.h"
#include "eag_wireless.h"
//#include "eag_trap.h"
#include "eag_macauth.h"
#include "md5.h"

/* prime number */
#define EAG_PORTALSESS_HASHSIZE			101

#define EAG_PORTALSESS_BLKMEM_NAME 		"eag_portalsess_blkmem"
#define EAG_PORTALSESS_BLKMEM_ITEMNUM		64
#define EAG_PORTALSESS_BLKMEM_MAXNUM		128

#define ADDRESS_NOT_ALLOCATE		1       /* 地址没有分配*/
#define ADDRESS_ALLOCATE			2       /* 地址分配出*/
#define ADDRESS_EXPIRED				3      /*   地址已分配，并且租约过期*/

#define ADDRESS_IN_POOL				1   /* 是地址池中地址*/
#define ADDRESS_OUT_POOL			0	/*不是地址池中地址*/


#define PORTAL_ERR_REASON_USER_NAME_WRONG	"Username length is too long or too short."
#define PORTAL_ERR_REASON_USER_NAME_EXIT	"Username is already exit."
#define PORTAL_ERR_REASON_USER_PASSWD_WRONG	"User password is wrong."
#define PORTAL_ERR_REASON_USER_STATE_WRONG	"User session state is wrong."
#define PORTAL_ERR_REASON_APPCONN_FAILED	"This is a wired user or user has no redir."
#define PORTAL_ERR_REASON_SESSION_FAILED	"Create portal session failed."
#define PORTAL_ERR_REASON_NO_FIND_SERVER	"Can not find portal or radius server."
#define PORTAL_ERR_REASON_DHCP_ALLOC		"Ip is not dhcp alloced."
#define PORTAL_ERR_REASON_DHCP_EXPIRED		"Dhcp lease expired."
#define PORTAL_ERR_REASON_NO_CHELLENGED		"Chap auth type but not challenged."
#define PORTAL_ERR_REASON_PACKET_WRONG		"Packet format is wrong."
#define PORTAL_ERR_REASON_PACKET_TIMEOUT	"Radius packet is timeout."
#define PORTAL_ERR_REASON_UNKNOWN_ERR		"Other reason."

int notice_to_bindserver  = 1; 	/* 默认为 浙江MAC认证 */
int username_check_switch = 1; /*默认为 印尼Telkom*/

typedef struct portal_sess portal_sess_t;

extern int cmtest_no_notice_to_pdc;
extern int local_database_switch ;
struct eag_portal {
	int sockfd;
	uint16_t portal_port;
	uint32_t local_ip;
	uint16_t local_port;
	
	
	eag_thread_t *t_read;
	eag_thread_master_t *master;
	struct list_head sess_head;
	hashtable *htable;
	eag_blk_mem_t *sess_blkmem;
	
	int auto_session;
	int retry_times;
	int retry_interval;
	int check_errid;

	int macbound_timeout;
	int challenged_timeout;
	int logout_wait_timeout;

	eag_ins_t *eagins;
	appconn_db_t *appdb;
	eag_radius_t *radius;
	eag_captive_t *cap;
	eag_coa_t *coa;
	eag_stamsg_t *stamsg;
	//eag_dbus_t *eagdbus;
	eag_statistics_t *eagstat;
	eag_fastfwd_t *fastfwd;
	eag_macauth_t *macauth;
	struct portal_conf *portalconf;
	struct radius_conf *radiusconf;
};

typedef enum {
	SESS_STATUS_NONE = 0,
	SESS_STATUS_ON_MACBIND,
	SESS_STATUS_MACBOUND,
	SESS_STATUS_CHALLENGED,
	SESS_STATUS_ON_CHAPAUTH,
	SESS_STATUS_ON_PAPAUTH,
	SESS_STATUS_AFF_WAIT,
	SESS_STATUS_LOGOUT_WAIT,
	SESS_STATUS_NTF_LOGOUT_WAIT
} SESS_STATUS;

struct portal_sess {
	struct list_head node;
	struct hlist_node hnode;
	uint32_t userip;
	SESS_STATUS status;
	eag_portal_t *portal;
	eag_thread_master_t *master;
	eag_thread_t *t_timeout;
	int timeout;
	int retry_count;
		
	//uint16_t sn;
	uint16_t reqid;
	uint8_t challenge[CHALLENGESIZE];
	uint32_t portal_ip;
	uint16_t portal_port;
	struct portal_packet_t rcvpkt;
	char secret[PORTAL_SECRETSIZE];
	uint32_t secretlen;
	int terminate_cause;
	char username[USERNAMESIZE];
	
	int is_dm_logout;
	uint32_t radius_ip;
	uint16_t radius_port;
	uint8_t dm_id;
};

typedef enum {
	EAG_PORTAL_READ,
} eag_portal_event_t;

typedef enum {
	SESS_ONMACBIND_TIMEOUT,
	SESS_MACBOUND_TIMEOUT,
	SESS_CHALLENGED_TIMEOUT,
	SESS_ONAUTH_TIMEOUT,
	SESS_AFF_WAIT_TIMEOUT,
	SESS_LOGOUT_WAIT_TIMEOUT,
	SESS_NTF_LOGOUT_WAIT_TIMEOUT,
} portal_sess_event_t;

static void
eag_portal_event(eag_portal_event_t event,
		eag_portal_t *portal);

static void
portal_sess_event(eag_portal_event_t event,
		portal_sess_t *portalsess);


const char *
sess_status2str(int status)
{
	switch (status) {
	case SESS_STATUS_NONE:
		return "NONE";
	case SESS_STATUS_ON_MACBIND:
		return "ON_MACBIND";
	case SESS_STATUS_MACBOUND:
		return "MACBOUND";
	case SESS_STATUS_CHALLENGED:
		return "CHALLENGED";
	case SESS_STATUS_ON_CHAPAUTH:
		return "ON_CHAPAUTH";
	case SESS_STATUS_ON_PAPAUTH:
		return "ON_PAPAUTH";
	case SESS_STATUS_AFF_WAIT:
		return "AFF_WAIT";
	case SESS_STATUS_LOGOUT_WAIT:
		return "LOGOUT_WAIT";
	case SESS_STATUS_NTF_LOGOUT_WAIT:
		return "NTF_LOGOUT_WAIT";
	default:
		return "unknow";
	}
}

static int
sess_status_is_valid(portal_sess_t *portalsess,
		struct app_conn_t *appconn)
{
	if (NULL == portalsess || NULL == appconn) {
		eag_log_err("sess_status_is_valid input error");
		return 0;
	}
	
	if ((SESS_STATUS_ON_MACBIND == portalsess->status
			|| SESS_STATUS_MACBOUND == portalsess->status
			|| SESS_STATUS_CHALLENGED == portalsess->status
			|| SESS_STATUS_ON_CHAPAUTH == portalsess->status
			|| SESS_STATUS_ON_PAPAUTH == portalsess->status
			|| SESS_STATUS_LOGOUT_WAIT == portalsess->status)
		&& APPCONN_STATUS_AUTHED == appconn->session.state)
	{
		return 0;
	}

	if ((SESS_STATUS_AFF_WAIT == portalsess->status
			|| SESS_STATUS_NTF_LOGOUT_WAIT == portalsess->status)
		&& APPCONN_STATUS_NONE == appconn->session.state)
	{
		return 0;
	}

	return 1;
}

static portal_sess_t *
portal_sess_new(eag_portal_t *portal,
		uint32_t userip)
{
	portal_sess_t *portalsess = NULL;

	portalsess = eag_blkmem_malloc_item(portal->sess_blkmem);
	if (NULL == portalsess) {
		eag_log_err("portal_sess_new blkmem_malloc_item failed");
		return NULL;
	}
	
	memset(portalsess, 0, sizeof(struct portal_sess));
	portalsess->userip = userip;
	portalsess->status = SESS_STATUS_NONE;
	portalsess->portal = portal;
	portalsess->master = portal->master;
	list_add(&(portalsess->node), &(portal->sess_head));
	hashtable_check_add_node(portal->htable, &userip, sizeof(userip), 
						&(portalsess->hnode));

	eag_log_debug("eag_portal", "portal_sess_new userip=%#x", userip);
	return portalsess;
}

static int
portal_sess_free(portal_sess_t *portalsess)
{
	eag_portal_t *portal = NULL;

	if (NULL == portalsess) {
		eag_log_err("portal_sess_free input error");
		return -1;
	}
	portal = portalsess->portal;

	eag_log_debug("eag_portal", "portal_sess_free userip=%#x",
			portalsess->userip);
	
	list_del(&(portalsess->node));
	hlist_del(&(portalsess->hnode));
	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}
	eag_blkmem_free_item(portal->sess_blkmem, portalsess);
	
	return EAG_RETURN_OK;
}

static portal_sess_t *
portal_sess_find_by_userip(eag_portal_t *portal,
		uint32_t userip)
{
	portal_sess_t *portalsess = NULL;
	struct hlist_head *head = NULL;
	struct hlist_node *node = NULL;

	head = hashtable_get_hash_list(portal->htable, &userip, sizeof(userip));
	if (NULL == head) {
		eag_log_err("portal_sess_find_by_userip head is null");
		return NULL;
	}
	
	hlist_for_each_entry(portalsess, node, head, hnode) {
		if (userip == portalsess->userip) {
			eag_log_debug("eag_portal", "found portal sess by userip %#x",
				userip);
			return portalsess;
		}
	}

	eag_log_debug("eag_portal", "not found portal sess by userip %#x",
				userip);
	return NULL;
}

static int
reqid_is_used(eag_portal_t *portal, uint16_t reqid)
{
	portal_sess_t *sess = NULL;
	//int is_distributed = 0;
	//int pdc_distributed = 0;

	//is_distributed = eag_ins_get_distributed(portal->eagins);
	
		list_for_each_entry(sess, &(portal->sess_head), node) {
			if ((SESS_STATUS_CHALLENGED == sess->status
				|| SESS_STATUS_ON_CHAPAUTH == sess->status)
				&& reqid == sess->reqid) {
				eag_log_debug("eag_portal", "reqid %#x is used", reqid);
				return EAG_TRUE;
			}
		}
	
	
	eag_log_debug("eag_portal", "reqid %x is not used", reqid);
	return EAG_FALSE;
}

static uint16_t
portal_detect_unique_reqid(eag_portal_t *portal)
{
	uint16_t reqid = 0;
	static uint16_t prev_reqid = 0;
	int found = 0;
	//uint16_t hansi_id = portal->hansi_id;
	//int is_distributed = 0;
	//int pdc_distributed = 0;

	eag_log_debug("eag_portal","portal_detect_unique_reqid begin, prev_reqid=%#x", prev_reqid);
	//is_distributed = eag_ins_get_distributed(portal->eagins);
	/* (A % 0X1000) == (A & 0XFFF) */
	
		for (reqid = prev_reqid + 1; reqid != prev_reqid; reqid++) {
			if (0 != reqid && !reqid_is_used(portal, reqid)) {
				found = 1;
				eag_log_debug("eag_portal",
					"portal_detect_unique_reqid found free reqid %#x", reqid);
				break;
			}
		}
		if (!found) {
			if (0 == ++reqid) reqid++;
			eag_log_debug("eag_portal", "portal_detect_unique_reqid "
				"not found free reqid, use next reqid %#x", reqid);
		}
		prev_reqid = reqid;
	

	eag_log_debug("eag_portal","portal_detect_unique_reqid reqid %#x", reqid);
	return reqid;
}

int
portal_packet_init_rsp(eag_portal_t *portal,
		struct portal_packet_t *rsppkt,
		const struct portal_packet_t *reqpkt)
{
	uint16_t reqid = 0;

	if (NULL == rsppkt || NULL == reqpkt) {
		eag_log_err("portal_packet_init_rsp input error");
		return -1;
	}

	memset(rsppkt, 0, sizeof(struct portal_packet_t));
	rsppkt->version = reqpkt->version;
	rsppkt->serial_no = reqpkt->serial_no;
	rsppkt->user_ip = reqpkt->user_ip;
	rsppkt->attr_num = 0;

	switch (reqpkt->type) {
	case REQ_CHALLENGE:
		rsppkt->type = ACK_CHALLENGE;
		reqid = portal_detect_unique_reqid(portal);
		rsppkt->req_id = htons(reqid);
		break;
	case REQ_AUTH:
		rsppkt->type = ACK_AUTH;
		rsppkt->req_id = reqpkt->req_id;
		break;
	case REQ_LOGOUT:
		rsppkt->type = ACK_LOGOUT;
		break;
	case REQ_INFO:
		rsppkt->type = ACK_INFO;
		break;
	default:
		eag_log_err("portal_packet_init_rsp unexpected type %u",
				reqpkt->type);
		break;
	}
	
	return 0;
}

int
eag_portal_send_packet(eag_portal_t *portal,
		uint32_t portal_ip,
		uint16_t portal_port,
		struct portal_packet_t *packet)
{
	size_t length = 0;
	struct sockaddr_in addr = {0};
	ssize_t nbyte = 0;
	char portal_ipstr[32] = "";
	//int is_distributed = 0;
	//int pdc_distributed = 0;
	
	if (NULL == portal || NULL == packet) {
		eag_log_err("eag_portal_send_packet input error");
		return -1;
	}
	
	//is_distributed = eag_ins_get_distributed(portal->eagins);
	length = portal_packet_get_length(packet);

	ip2str(portal_ip, portal_ipstr, sizeof(portal_ipstr));
	eag_log_debug("eag_portal",
		"portal send packet %d bytes, fd %d, portal server %s:%u, type %x",
		length, portal->sockfd,
		portal_ipstr, portal_port, packet->type);
	
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(portal_ip);
	addr.sin_port = htons(portal_port);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif

	//portal_packet_hton(packet);

		nbyte = sendto(portal->sockfd, packet, length, 0,
					(struct sockaddr *)&addr, sizeof(addr));
		if (nbyte < 0) {
			eag_log_err("eag_portal_send_packet failed fd(%d): %s",
				portal->sockfd, safe_strerror(errno));
			return -1;
		}
	
	
	return EAG_RETURN_OK;
}

uint16_t
rand_serialNo(void)
{
	uint16_t serial_no = 0;

	rand_buff((uint8_t *)&serial_no, sizeof(serial_no));

	return serial_no;
}

static int
portal_add_macbind_req_attr(struct portal_packet_t *packet,
		struct app_conn_t *appconn,
		eag_portal_t *portal)
{
	uint32_t nasip = 0;
	
	if (NULL == packet || NULL == appconn) {
		eag_log_err("portal_add_macbind_req_attr input error");
		return -1;
	}

	portal_packet_add_attr(packet, ATTR_USERMAC, appconn->session.usermac,
		sizeof(appconn->session.usermac));

	nasip = eag_ins_get_nasip(portal->eagins);
	nasip = htonl(nasip);
	portal_packet_add_attr(packet, ATTR_BASIP, &nasip, sizeof(nasip));
	
	portal_packet_add_attr(packet, ATTR_NASID, appconn->session.nasid,
		strlen(appconn->session.nasid));

	return 0;
}

eag_portal_t *eag_portal_new()
{
	eag_portal_t *portal = NULL;

	portal = eag_malloc(sizeof(*portal));
	if (NULL == portal) {
		eag_log_err("eag_portal_new eag_malloc failed");
		goto failed_0;
	}

	memset(portal, 0, sizeof(*portal));
	if (EAG_RETURN_OK != eag_blkmem_create(&(portal->sess_blkmem),
						EAG_PORTALSESS_BLKMEM_NAME,
						sizeof(portal_sess_t),
						EAG_PORTALSESS_BLKMEM_ITEMNUM,
						EAG_PORTALSESS_BLKMEM_MAXNUM)) {
		eag_log_err("eag_portal_new blkmem_create failed");
		goto failed_1;
	}
	if (EAG_RETURN_OK != hashtable_create_table(&(portal->htable),
							EAG_PORTALSESS_HASHSIZE)) {
		eag_log_err("eag_portal_new hashtable_create failed");
		goto failed_2;
	}
	INIT_LIST_HEAD(&(portal->sess_head));
	portal->sockfd = -1;
	portal->portal_port = PORTAL_PORT_DEFAULT;
	portal->auto_session = 1;
	portal->retry_times = 0;
	portal->retry_interval = 2;
	portal->check_errid = 0;
	portal->macbound_timeout = 5;
	portal->challenged_timeout = 15;
	portal->logout_wait_timeout = 10;
	
	eag_log_info("portal new ok");
	return portal;
	
failed_2:
	eag_blkmem_destroy(&(portal->sess_blkmem));
failed_1:
	eag_free(portal);
failed_0:
	return NULL;
}

int
eag_portal_free(eag_portal_t *portal)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_free input error");
		return -1;
	}

	if (NULL != portal->sess_blkmem) {
		eag_blkmem_destroy(&(portal->sess_blkmem));
	}
	if (NULL != portal->htable) {
		hashtable_destroy_table(&(portal->htable));
	}
	eag_free(portal);

	eag_log_info("portal free ok");
	return 0;
}

int
eag_portal_start(eag_portal_t *portal)
{
	int ret = 0;
	struct sockaddr_in addr = {0};
	char ipstr[32] = "";
	uint32_t nasip = 0;
	//int is_distributed = 0;
	int pdc_distributed = 0;
	
	if (NULL == portal) {
		eag_log_err("eag_portal_start input error");
		return -1;
	}

	if (portal->sockfd >= 0) {
		eag_log_err("eag_portal_start already start fd(%d)", 
			portal->sockfd);
		return EAG_RETURN_OK;
	}
	
	//is_distributed = eag_ins_get_distributed(portal->eagins);
	nasip = eag_ins_get_nasip(portal->eagins);
	portal->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (portal->sockfd  < 0) {
		eag_log_err("Can't create portal dgram socket: %s",
			safe_strerror(errno));
		portal->sockfd = -1;
		return EAG_ERR_SOCKET_FAILED;
	}

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(nasip);
	addr.sin_port = htons(portal->portal_port);
	
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	#if 0
	ret = setsockopt(portal->sockfd, SOL_SOCKET, SO_REUSEADDR,
					&opt, sizeof(opt));
	if (0 != ret) {
		eag_log_err("Can't set REUSEADDR to portal socket(%d): %s",
			portal->sockfd, safe_strerror(errno));
	}
	#endif
	ret  = bind(portal->sockfd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		eag_log_err("Can't bind to portal socket(%d): %s",
			portal->sockfd, safe_strerror(errno));
		close(portal->sockfd);
		portal->sockfd = -1;
		return EAG_ERR_PORTAL_SOCKET_BIND_FAILED;
	}

	eag_portal_event(EAG_PORTAL_READ, portal);

		eag_log_info("portal(%s:%u) fd(%d) start ok", 
			ip2str(nasip, ipstr, sizeof(ipstr)),
			portal->portal_port,
			portal->sockfd);
	
	return EAG_RETURN_OK;
}

int
eag_portal_stop(eag_portal_t *portal)
{
	portal_sess_t *portalsess = NULL;
	portal_sess_t *next = NULL;
	char ipstr[32] = "";
	uint32_t nasip = 0;
	//int is_distributed = 0;
	//int pdc_distributed = 0;
	
	if (NULL == portal) {
		eag_log_err("eag_portal_stop input error");
		return -1;
	}

	//is_distributed = eag_ins_get_distributed(portal->eagins);
	nasip = eag_ins_get_nasip(portal->eagins);
	if (NULL != portal->t_read) {
		eag_thread_cancel(portal->t_read);
		portal->t_read = NULL;
	}
	if (portal->sockfd >= 0) {
		close(portal->sockfd);
		portal->sockfd = -1;
	}
	list_for_each_entry_safe(portalsess, next, &(portal->sess_head), node) {
		portal_sess_free(portalsess);
	}
	
		eag_log_info("portal(%s:%u) stop ok",
			ip2str(nasip, ipstr, sizeof(ipstr)),
			portal->portal_port);
	

	return EAG_RETURN_OK;

}

static int
eag_portal_onmacbind_timeout(eag_thread_t *thread)
{
	portal_sess_t *portalsess = NULL;
	eag_portal_t *portal = NULL;
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	struct app_conn_t *appconn = NULL;
	struct portal_packet_t req_packet = {0};

	if (NULL == thread) {
		eag_log_err("eag_portal_onmacbind_timeout input error");
		return -1;
	}
	portalsess = eag_thread_get_arg(thread);
	if (NULL == portalsess) {
		eag_log_err("eag_portal_onmacbind_timeout portalsess null");
		return -1;
	}
	
	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}

	portal = portalsess->portal;
	userip = portalsess->userip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL == appconn) {
		eag_log_warning("portal_onmacbind_timeout not found appconn userip=%s",
			user_ipstr);
		eag_del_mac_preauth(portal->macauth, userip);
		portal_sess_free(portalsess);
		return -1;
	}
	
	eag_log_debug("eag_portal", "portalsess onmacbind timeout userip=%s", user_ipstr);
	if (portalsess->retry_count < portal->retry_times) {
		/* retry macbind req  */
		portal_packet_init(&req_packet, REQ_MACBINDING_INFO, userip);
		req_packet.serial_no = rand_serialNo();

		portal_add_macbind_req_attr(&req_packet, appconn, portal);

		eag_log_debug("eag_portal", "portal_macbind_req userip %s, "
			"send req_macbind_info, errcode=%u", user_ipstr, req_packet.err_code);
		admin_log_notice("PortalReqMacBindInfo___UserIP:%s", user_ipstr);
		eag_log_filter(user_ipstr,"PortalReqMacBindInfo___UserIP:%s", user_ipstr);
		eag_portal_send_packet(portal, 
			appconn->portal_srv.mac_server_ip,
			appconn->portal_srv.mac_server_port, &req_packet);
		portalsess->retry_count++;
		portalsess->timeout = portal->retry_interval;
		portal_sess_event(SESS_ONMACBIND_TIMEOUT, portalsess);
	} else {
		/*  del mac pre_auth */
		eag_del_mac_preauth(portal->macauth, userip);
		portal_sess_free(portalsess);
	}

	return EAG_RETURN_OK;
}

static int
eag_portal_macbound_timeout(eag_thread_t *thread)
{
	portal_sess_t *portalsess = NULL;
	eag_portal_t *portal = NULL;
	uint32_t userip = 0;
	char user_ipstr[32] = "";

	if (NULL == thread) {
		eag_log_err("eag_portal_macbound_timeout input error");
		return -1;
	}
	portalsess = eag_thread_get_arg(thread);
	if (NULL == portalsess) {
		eag_log_err("eag_portal_macbound_timeout portalsess null");
		return -1;
	}

	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}
	
	portal = portalsess->portal;
	userip = portalsess->userip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	
	eag_log_debug("eag_portal", "macbound timeout userip %s, "
		"ack_macbind received, but no req_auth or req_challenge received",
		user_ipstr);
	/* del mac pre_auth */
	eag_del_mac_preauth(portal->macauth, userip);
	portal_sess_free(portalsess);

	return EAG_RETURN_OK;
}

static int
eag_portal_challenged_timeout(eag_thread_t *thread)
{
	portal_sess_t *portalsess = NULL;
	eag_portal_t *portal = NULL;
	uint32_t userip = 0;
	char user_ipstr[32] = "";

	if (NULL == thread) {
		eag_log_err("eag_portal_challenged_timeout input error");
		return -1;
	}
	portalsess = eag_thread_get_arg(thread);
	if (NULL == portalsess) {
		eag_log_err("eag_portal_challenged_timeout portalsess null");
		return -1;
	}
	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}
	
	portal = portalsess->portal;
	userip = portalsess->userip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	
	eag_log_info("portalsess challenged timeout userip=%s", user_ipstr);
	if (eag_macauth_get_macauth_switch(portal->macauth))
	{
		/* del mac pre_auth */
		eag_del_mac_preauth(portal->macauth, userip);
	}
	portal_sess_free(portalsess);

	return EAG_RETURN_OK;
}

static int
eag_portal_onauth_timeout(eag_thread_t *thread)
{
	portal_sess_t *portalsess = NULL;
	eag_portal_t *portal = NULL;
	struct portal_packet_t rsppkt = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	struct app_conn_t *appconn = NULL;
	char *err_reason = "";
	
	if (NULL == thread) {
		eag_log_err("eag_portal_onauth_timeout input error");
		return -1;
	}
	portalsess = eag_thread_get_arg(thread);
	if (NULL == portalsess) {
		eag_log_err("eag_portal_onauth_timeout portalsess null");
		return -1;
	}

	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}
	
	portal = portalsess->portal;
	userip = portalsess->userip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));

	eag_log_debug("eag_portal","portalsess onauth timeout userip=%s", user_ipstr);
	portal_packet_init_rsp(portal, &rsppkt, &(portalsess->rcvpkt));
	rsppkt.err_code = PORTAL_AUTH_REJECT;
	err_reason = PORTAL_ERR_REASON_PACKET_TIMEOUT;

	if (portal->check_errid
		&& PORTAL_PROTOCOL_MOBILE == portal_get_protocol_type())
	{
		const char *errid = ERRID_AC201;
		portal_packet_add_attr(&rsppkt, ATTR_ERRID, errid, strlen(errid));
	}
	
	eag_log_debug("eag_portal","eag_portal_onauth_timeout userip %s, "
		"send ack_auth, errcode=%u", user_ipstr, rsppkt.err_code);
	
	portal_resp_authenticator(&rsppkt, &(portalsess->rcvpkt), portalsess->secret, 
				portalsess->secretlen);
	eag_portal_send_packet(portal, portalsess->portal_ip,
			portalsess->portal_port, &rsppkt);

	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL != appconn) {
		appconn->on_auth = 0;
	}
	
	if (NULL == appconn) {
		eag_log_filter(user_ipstr,"PortalAckAuth___UserIP:%s,Username:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, portalsess->username, rsppkt.err_code, err_reason);
		admin_log_notice("PortalAckAuth___UserIP:%s,Username:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, portalsess->username, rsppkt.err_code, err_reason);
		eag_henan_log_warning("PORTAL_USER_LOGON_FAIL:-UserName=%s-IPAddr=%s-Reason=%s: %d; User failed to get online.",
			portalsess->username, user_ipstr, err_reason, rsppkt.err_code);
	} else {
		mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
		ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
		ip2str(portalsess->portal_ip, portal_ipstr, sizeof(portal_ipstr));
		log_app_filter(appconn,"PortalAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, user_macstr, portalsess->username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, rsppkt.err_code, err_reason);	
		admin_log_notice("PortalAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, user_macstr, portalsess->username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, rsppkt.err_code, err_reason);
		eag_henan_log_warning("PORTAL_USER_LOGON_FAIL:-UserName=%s-IPAddr=%s-IfName=%s-VlanID=%u"
			"-MACAddr=%s-Reason=%s: %d; User failed to get online.", portalsess->username, user_ipstr, 
			appconn->session.intf, appconn->session.vlanid, user_macstr, err_reason, rsppkt.err_code);
	}
	eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_1_COUNT, 1);
	/* del mac pre_auth */
	if (eag_macauth_get_macauth_switch(portal->macauth)) {
		eag_del_mac_preauth(portal->macauth, userip);
	}
	portal_sess_free(portalsess);

	return EAG_RETURN_OK;
}

static int
eag_portal_aff_wait_timeout(eag_thread_t * thread)
{
	portal_sess_t *portalsess = NULL;
	eag_portal_t *portal = NULL;
	struct portal_packet_t rsppkt = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	struct app_conn_t *appconn = NULL;
	char *err_reason = "";

	if (NULL == thread) {
		eag_log_err("eag_portal_aff_wait_timeout input error");
		return -1;
	}
	portalsess = eag_thread_get_arg(thread);
	if (NULL == portalsess) {
		eag_log_err("eag_portal_aff_wait_timeout portalsess null");
		return -1;
	}
	
	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}
	
	portal = portalsess->portal;
	userip = portalsess->userip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	
	eag_log_debug("eag_portal","eag_portal_aff_wait_timeout "
		"userip=%s, retry_count=%d, retry_times=%d",
		user_ipstr, portalsess->retry_count, portal->retry_times);
	
	if (portalsess->retry_count < portal->retry_times) {
		eag_log_debug("eag_portal",
				"eag_portal_aff_wait_timeout resend ack_auth");
		portal_packet_init_rsp(portal, &rsppkt, &(portalsess->rcvpkt));

		eag_log_debug("eag_portal","eag_portal_aff_wait_timeout userip %s, "
			"send ack_auth, errcode=%u", user_ipstr, rsppkt.err_code);

		appconn = appconn_find_by_userip(portal->appdb, userip);
		if (NULL == appconn) {
			eag_log_filter(user_ipstr,"PortalAckAuth___UserIP:%s,Username:%s,ErrCode:%d,ErrReason:%s",
				user_ipstr, portalsess->username, rsppkt.err_code, err_reason);
			admin_log_notice("PortalAckAuth___UserIP:%s,Username:%s,ErrCode:%d,ErrReason:%s",
				user_ipstr, portalsess->username, rsppkt.err_code, err_reason);
		} else {
			mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
			mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
			ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
			ip2str(portalsess->portal_ip, portal_ipstr, sizeof(portal_ipstr));
			log_app_filter(appconn,"PortalAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%d,ErrReason:%s",
				user_ipstr, user_macstr, portalsess->username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, rsppkt.err_code, err_reason);
			admin_log_notice("PortalAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%d,ErrReason:%s",
				user_ipstr, user_macstr, portalsess->username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, rsppkt.err_code, err_reason);
		}
		portal_resp_authenticator(&rsppkt, &(portalsess->rcvpkt), portalsess->secret, 
				portalsess->secretlen);
		eag_portal_send_packet(portal, portalsess->portal_ip,
				portalsess->portal_port, &rsppkt);
		portalsess->retry_count++;
		
		portalsess->timeout = portal->retry_interval;
		portal_sess_event(SESS_AFF_WAIT_TIMEOUT, portalsess);
	} else {
		eag_log_debug("eag_portal", "eag_portal_aff_wait_timeout "
				"userip=%s, portal_sess_free", user_ipstr);
		portal_sess_free(portalsess);
	}

	return EAG_RETURN_OK;
}

static int
eag_portal_logout_wait_timeout(eag_thread_t * thread)
{
	portal_sess_t *portalsess = NULL;

	if (NULL == thread) {
		eag_log_err("eag_portal_logout_wait_timeout input error");
		return -1;
	}
	portalsess = eag_thread_get_arg(thread);
	if (NULL == portalsess) {
		eag_log_err("eag_portal_logout_wait_timeout portalsess null");
		return -1;
	}

	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}

	portal_sess_free(portalsess);

	return EAG_RETURN_OK;
}

static int
eag_portal_ntf_logout_wait_timeout(eag_thread_t * thread)
{
	portal_sess_t *portalsess = NULL;
	eag_portal_t *portal = NULL;
	struct portal_packet_t ntfpkt = {0};
	struct app_conn_t *appconn = NULL;
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";

	if (NULL == thread) {
		eag_log_err("eag_portal_ntf_logout_wait_timeout input error");
		return -1;
	}
	portalsess = eag_thread_get_arg(thread);
	if (NULL == portalsess) {
		eag_log_err("eag_portal_ntf_logout_wait_timeout portalsess null");
		return -1;
	}

	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}
	
	portal = portalsess->portal;
	userip = portalsess->userip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	
	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL == appconn) {
		eag_log_err("eag_portal_ntf_logout_wait_timeout "
			"not found appconn by userip %s", user_ipstr);
		portal_sess_free(portalsess);
		return -1;
	}

	eag_log_debug("eag_portal", "eag_portal_ntf_logout_wait_timeout "
		"userip=%s, retry_count=%d, retry_times=%d",
		user_ipstr, portalsess->retry_count, portal->retry_times);
		
	if (portalsess->retry_count < portal->retry_times) {
		portal_packet_init(&ntfpkt, NTF_LOGOUT, userip);

		eag_log_debug("eag_portal","ntf_logout_wait_timeout userip %s resend ntf_logout",
				user_ipstr);
		mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
		ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
		ip2str(portalsess->portal_ip, portal_ipstr, sizeof(portal_ipstr));
		portal_req_authenticator(&ntfpkt, appconn->portal_srv.secret,
				appconn->portal_srv.secretlen);
		admin_log_notice("PortalNtfLogout___UserIP:%s,UserMAC:%s,UserName:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s",
			user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, 
			nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
		log_app_filter(appconn,"PortalNtfLogout___UserIP:%s,UserMAC:%s,UserName:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s",
			user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, 
			nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
		eag_portal_send_packet(portal, portalsess->portal_ip,
				portalsess->portal_port, &(ntfpkt));
		portalsess->retry_count++;
		portalsess->timeout = portal->retry_interval;
		portal_sess_event(SESS_NTF_LOGOUT_WAIT_TIMEOUT, portalsess);
	} else {
		if (portalsess->is_dm_logout) {
			eag_log_debug("eag_portal","ntf_logout_wait_timeout userip %s is dm logout, "
				"coa response to radius", user_ipstr);
			admin_log_notice("RadiusDisconnectACK___UserName:%s,UserIP:%s,ErrorCause:%d",
				portalsess->username, user_ipstr, RADIUS_ERROR_CAUSE_201);
			log_app_filter(appconn,"RadiusDisconnectACK___UserName:%s,UserIP:%s,ErrorCause:%d",
				portalsess->username, user_ipstr, RADIUS_ERROR_CAUSE_201);
			eag_coa_ack_logout_proc(portal->coa, portalsess->radius_ip,
				portalsess->radius_port, portalsess->dm_id);
		}
		appconn->on_ntf_logout = 0;
		terminate_appconn(appconn, portal->eagins,
					portalsess->terminate_cause);
		portal_sess_free(portalsess);
	}

	return EAG_RETURN_OK;
}

int
eag_portal_challenge_proc(eag_portal_t *portal,
		uint32_t portal_ip,
		uint16_t portal_port,
		struct portal_packet_t *reqpkt)
{
	struct app_conn_t *appconn = NULL;
	portal_sess_t *portalsess = NULL;
	struct portal_packet_t rsppkt = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
//	DBusConnection *dbus_conn = NULL;
	unsigned int addr_in_pool_flag = 0;
	unsigned int addr_lease_status = 0;
	int dhcp_op_ret = 0;
	int app_check_ret = 0;
	struct app_conn_t *tmp_appconn = NULL;
	struct appsession tmpsession = {0};
	char *err_reason = "";

	if (NULL == portal || NULL == reqpkt) {
		eag_log_err("eag_portal_challenge_proc input error");
		return -1;
	}

	userip = ntohl(reqpkt->user_ip);
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	portal_packet_init_rsp(portal, &rsppkt, reqpkt);

	/*dbus_conn = eag_dbus_get_dbus_conn(portal->eagdbus);
	if (portal->check_errid
		&& PORTAL_PROTOCOL_MOBILE == portal_get_protocol_type())
	{
		dhcp_op_ret = eag_get_sta_dhcplease_info(dbus_conn, userip, 
				&addr_in_pool_flag, &addr_lease_status);
		if (0 != dhcp_op_ret || ADDRESS_OUT_POOL == addr_in_pool_flag
			|| ADDRESS_ALLOCATE != addr_lease_status)
		{
			eag_log_err("portal_challenge_proc dhcplease check failed, "
				"userip=%s, dhcp_op_ret=%d, in_pool_flag=%d, lease_status=%d",
				user_ipstr, dhcp_op_ret, addr_in_pool_flag, addr_lease_status);
			rsppkt.err_code = CHALLENGE_REJECT;
			err_reason = PORTAL_ERR_REASON_DHCP_ALLOC;
			goto send;
		}
	}*/
	
	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL == appconn && portal->auto_session) {
		eag_log_debug("eag_portal", "eag_portal_challenge_proc userip %s, "
			"appconn is null, auto_session is enable", user_ipstr);
		app_check_ret = appconn_check_is_conflict(userip, portal->appdb, &tmpsession, &tmp_appconn);
		appconn = appconn_create_no_arp(portal->appdb, &tmpsession);	
	}
	if (NULL == appconn || EAG_RETURN_OK != app_check_ret) {
		eag_log_warning("eag_portal_challenge_proc userip %s, "
			"appconn is null", user_ipstr);
		if (PORTAL_PROTOCOL_TELECOM == portal_get_protocol_type()) {
			goto check_appconn;
		}
		rsppkt.err_code = CHALLENGE_REJECT;
		err_reason = PORTAL_ERR_REASON_APPCONN_FAILED;
		eag_log_filter(user_ipstr,"PortalReqChallenge___UserIP:%s",
			user_ipstr);
		admin_log_notice("PortalReqChallenge___UserIP:%s",
				user_ipstr);
		goto send;
	}

	if (0 != portal_request_check(reqpkt, appconn->portal_srv.secret,
				appconn->portal_srv.secretlen))
	{
		eag_log_warning("portal_challenge_proc authenticator not match secret=%s userip=%s",
			appconn->portal_srv.secret, user_ipstr);
		return -1;
	}
	
	mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
	mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
    appconn->session.nasip = eag_ins_get_nasip(portal->eagins);
	ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
	ip2str(portal_ip, portal_ipstr, sizeof(portal_ipstr));
	log_app_filter(appconn,"PortalReqChallenge___UserIP:%s,UserMAC:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s",
			user_ipstr, user_macstr, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
	admin_log_notice("PortalReqChallenge___UserIP:%s,UserMAC:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s",
			user_ipstr, user_macstr, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);

	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL == portalsess) {
		eag_log_debug("eag_portal", "eag_portal_challenge_proc "
			"not found portal_sess by userip %s, new one",
			user_ipstr);
		portalsess = portal_sess_new(portal, userip);
	}
	if (NULL == portalsess) {
		eag_log_err("eag_portal_challenge_proc userip %s, "
			"portal_sess_new failed", user_ipstr);
		rsppkt.err_code = CHALLENGE_REJECT;
		err_reason = PORTAL_ERR_REASON_SESSION_FAILED;
		goto send;
	}
	
	if (0 != reqpkt->rsv) {
		rsppkt.err_code = CHALLENGE_FAILED;
		err_reason = PORTAL_ERR_REASON_PACKET_WRONG;
		eag_log_warning("eag_portal_challenge_proc "
				"userip %s, rsv %d, return errcode=%d",
				user_ipstr, reqpkt->rsv, rsppkt.err_code);
		goto send;
	}

	eag_log_debug("eag_portal", "eag_portal_challenge_proc "
			"userip %s, sess_status %u, user_state %d",
			user_ipstr, portalsess->status, appconn->session.state);
	
	if (!sess_status_is_valid(portalsess, appconn)) {
		eag_log_err("eag_portal_challenge_proc "
			"userip %s, sess_status %s not match user_state %d",
			user_ipstr, sess_status2str(portalsess->status),
			appconn->session.state);
	}
	
	switch (portalsess->status) {
	case SESS_STATUS_ON_MACBIND:
	case SESS_STATUS_LOGOUT_WAIT:
		eag_log_warning("eag_portal_challenge_proc "
				"userip %s, portalsess status %s",
				user_ipstr, sess_status2str(portalsess->status));
	case SESS_STATUS_MACBOUND:
	case SESS_STATUS_NONE:
		if (NULL != portalsess->t_timeout) {
			eag_thread_cancel(portalsess->t_timeout);
			portalsess->t_timeout = NULL;
		}
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			rsppkt.err_code = CHALLENGE_CONNECTED;
			err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		} else {
			portalsess->status = SESS_STATUS_CHALLENGED;
			rand_buff(portalsess->challenge, sizeof(portalsess->challenge));
			portalsess->reqid = ntohs(rsppkt.req_id);
			portal_packet_add_attr(&rsppkt, ATTR_CHALLENGE,
						portalsess->challenge, CHALLENGESIZE);
			
			portalsess->timeout = portal->challenged_timeout;
			portal_sess_event(SESS_CHALLENGED_TIMEOUT, portalsess);
		}
		break;
	case SESS_STATUS_CHALLENGED:
		rsppkt.req_id = htons(portalsess->reqid);
		portal_packet_add_attr(&rsppkt, ATTR_CHALLENGE,
				portalsess->challenge, CHALLENGESIZE);
		break;
	case SESS_STATUS_ON_PAPAUTH:
		eag_log_warning("eag_portal_challenge_proc "
				"userip %s, sess_status is ON_PAPAUTH", user_ipstr);
	case SESS_STATUS_ON_CHAPAUTH:
		rsppkt.err_code = CHALLENGE_ONAUTH;
		err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		break;
	case SESS_STATUS_AFF_WAIT:
	case SESS_STATUS_NTF_LOGOUT_WAIT:
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			rsppkt.err_code = CHALLENGE_CONNECTED;
			err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		} else {
			eag_log_err("eag_portal_challenge_proc "
				"portal sess is %s, but user %s is not authed",
				sess_status2str(portalsess->status), user_ipstr);
			rsppkt.err_code = CHALLENGE_REJECT;
			err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		}
		break;
	default:
		eag_log_err("eag_portal_challenge_proc unknown portalsess status:%d",
			portalsess->status);
		rsppkt.err_code = CHALLENGE_REJECT;
		err_reason = PORTAL_ERR_REASON_UNKNOWN_ERR;
		break;
	}

send:
	if (eag_macauth_get_macauth_switch(portal->macauth)
			&& CHALLENGE_SUCCESS != rsppkt.err_code)
	{
		/* del mac pre_auth */
		eag_del_mac_preauth(portal->macauth, userip);
	}
	if (portal->check_errid
		&& PORTAL_PROTOCOL_MOBILE == portal_get_protocol_type()
		&& CHALLENGE_SUCCESS != rsppkt.err_code)
	{
		const char *errid = ERRID_AC999;
		if (0 != dhcp_op_ret)
		{
			errid = ERRID_AC999;
		}
		else if (ADDRESS_IN_POOL == addr_in_pool_flag 
			&& CHALLENGE_CONNECTED == rsppkt.err_code)
		{
			errid = ERRID_AC101;
		}
		else if (ADDRESS_OUT_POOL == addr_in_pool_flag)
		{
			errid = ERRID_AC102;
		}
		else if (ADDRESS_IN_POOL == addr_in_pool_flag
			&& ADDRESS_ALLOCATE != addr_lease_status)
		{
			errid = ERRID_AC103;
		}
		eag_log_debug("eag_portal","eag_portal_challenge_proc  errid = %s", errid);
		portal_packet_add_attr(&rsppkt, ATTR_ERRID, errid, strlen(errid));
	}
	eag_log_debug("eag_portal","portal_challenge_proc userip %s, "
		"send ack_challenge, errcode=%u", user_ipstr, rsppkt.err_code);
	if (NULL == appconn) {
		eag_log_filter(user_ipstr, "PortalAckChallenge___UserIP:%s,ErrCode:%u,ErrReason:%s",
								user_ipstr, rsppkt.err_code, err_reason);
		admin_log_notice("PortalAckChallenge___UserIP:%s,ErrCode:%u,ErrReason:%s",
			user_ipstr, rsppkt.err_code, err_reason);
	} else {
		log_app_filter(appconn,"PortalAckChallenge___UserIP:%s,UserMAC:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ErrCode:%u,ErrReason:%s",
			user_ipstr, user_macstr, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid, rsppkt.err_code, err_reason);
		admin_log_notice("PortalAckChallenge___UserIP:%s,UserMAC:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ErrCode:%u,ErrReason:%s",
			user_ipstr, user_macstr, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid, rsppkt.err_code, err_reason);
	}
	eag_bss_message_count(portal->eagstat, appconn, BSS_CHALLENGE_REQ_COUNT, 1);
	if (NULL != appconn) {
		portal_resp_authenticator(&rsppkt, reqpkt, appconn->portal_srv.secret, 
				appconn->portal_srv.secretlen);
	}
	eag_portal_send_packet(portal, portal_ip, portal_port, &rsppkt);

	switch (rsppkt.err_code) {
	case CHALLENGE_SUCCESS:
		eag_bss_message_count(portal->eagstat, appconn, BSS_CHALLENGE_ACK_0_COUNT, 1);
		break;
	case CHALLENGE_REJECT:
		eag_bss_message_count(portal->eagstat, appconn, BSS_CHALLENGE_ACK_1_COUNT, 1);
		break;
	case CHALLENGE_CONNECTED:
		eag_bss_message_count(portal->eagstat, appconn, BSS_CHALLENGE_ACK_2_COUNT, 1);
		break;
	case CHALLENGE_ONAUTH:
		eag_bss_message_count(portal->eagstat, appconn, BSS_CHALLENGE_ACK_3_COUNT, 1);
		break;
	case CHALLENGE_FAILED:
	default:
		eag_bss_message_count(portal->eagstat, appconn, BSS_CHALLENGE_ACK_4_COUNT, 1);
		break;
	}
check_appconn:
	if (EAG_ERR_APPCONN_APP_IS_CONFLICT == app_check_ret && NULL != tmp_appconn) {
		if (APPCONN_STATUS_AUTHED == tmp_appconn->session.state) {
			terminate_appconn_nowait(tmp_appconn, portal->eagins, RADIUS_TERMINATE_CAUSE_LOST_CARRIER);
		} else {
			appconn_del_from_db(tmp_appconn);
			appconn_free(tmp_appconn);
		}
		tmp_appconn = NULL;
	}

	return EAG_RETURN_OK;
}

char *get_passwd_from_datebase(char *name,char *path)
{
	FILE *fp = NULL;
	char buf[256];
	char username[64];
	char *passwd;
	//char group_name[64];

	if ((NULL == name) ||(NULL == path)) {
		eag_log_err("read_file input error");
		return NULL;
	}

	passwd = (char *)malloc(128);
	if(NULL == passwd)
		return NULL;
	memset(passwd,0,128);
	if ( (fp = fopen(path, "r")) == NULL) {
		eag_log_err("get_passwd_from_datebase %s open failed, %s", 
			path, safe_strerror(errno));
		return NULL;
	}
        while (!feof(fp)) {
		memset(buf, 0, 256);
            	if (fgets(buf, sizeof(buf), fp) == NULL) {
            		eag_log_err("get_passwd_from_datebase %s get failed, %s", 
            			path, safe_strerror(errno));
            		fclose(fp);
            		return NULL;
            	}
		printf("buf %s\n",buf);
		sscanf(buf,"%s %s ",username,passwd);
		printf("username: %s,name: %s,%d\n",username,name,strlen(name));
               	if(0== memcmp(name,username,strlen(name)))
               	{
			printf("chenjun passwd : %s\n",passwd);
			fclose(fp);
			return passwd;
               	}
        }
	fclose(fp);
	return NULL;

}

int
database_passwd_check(struct appsession  *portalsession,uint8_t *chappasswd,char *passwd)
{
	uint8_t auth[PORTAL_AUTHLEN] = {0};
	MD5_CTX context;


	MD5Init(&context);
           MD5Update(&context, (uint8_t *)&(portalsession->chapid), 1);
           MD5Update(&context, (uint8_t *)passwd, strlen(passwd));
           MD5Update(&context,  (uint8_t *)portalsession->challenge, PORTAL_AUTHLEN);
	MD5Final(auth, &context);
	printf("chip: %d,passwd:%s,challenge:value %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", \
		portalsession->chapid,passwd,portalsession->challenge[0],portalsession->challenge[1],portalsession->challenge[2],portalsession->challenge[3],\
		portalsession->challenge[4],portalsession->challenge[5],portalsession->challenge[6],portalsession->challenge[7],portalsession->challenge[8],\
		portalsession->challenge[9],portalsession->challenge[10],portalsession->challenge[11],portalsession->challenge[12],portalsession->challenge[13],portalsession->challenge[14],portalsession->challenge[15]);
           printf("chappasswd: value %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x  	auth:value %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", \
		   	chappasswd[0],chappasswd[1],chappasswd[2],chappasswd[3],chappasswd[4],chappasswd[5],\
		   	chappasswd[6],chappasswd[7],chappasswd[8],chappasswd[9],chappasswd[10],chappasswd[11],chappasswd[12],chappasswd[13],chappasswd[14],chappasswd[15],\
		   	auth[0],auth[1],auth[2],auth[3],auth[4],auth[5],auth[6],auth[7],auth[8],auth[9],auth[10],auth[11],auth[12],auth[13],auth[14],auth[15]);
	return memcmp(chappasswd, auth,PORTAL_AUTHLEN);
}

int
eag_portal_chapauth_proc(eag_portal_t *portal,
		uint32_t portal_ip,
		uint16_t portal_port,
		struct portal_packet_t *reqpkt)
{
	struct app_conn_t *appconn = NULL;
	portal_sess_t *portalsess = NULL;
	struct portal_packet_t rsppkt = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32]= "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	struct portal_packet_attr *attr = NULL;
	int ret = 0;
	int retry_interval = 0;
	int retry_times = 0;
	int vice_retry_times = 0;
	char username[USERNAMESIZE] = "";
	struct timeval tv = {0};
	int app_check_ret = 0;
	struct app_conn_t *tmp_appconn = NULL;
	struct appsession tmpsession = {0};
	char *err_reason = "";
	char session_filter_prefix[512] = ""; /* add for debug-filter */
	struct app_conn_t *appconn_by_name = NULL;
	
	if (NULL == portal || NULL == reqpkt) {
		eag_log_err("eag_portal_chapauth_proc input error");
		return -1;
	}

	userip = ntohl(reqpkt->user_ip);
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	portal_packet_init_rsp(portal, &rsppkt, reqpkt);

	attr = portal_packet_get_attr(reqpkt, ATTR_USERNAME);
	if (NULL == attr) {
		eag_log_err("eag_portal_chapauth_proc userip %s "
			" not get username attr in req_auth", user_ipstr);
		memset(username, 0, sizeof(username));
	} else {
		memset(username, 0, sizeof(username));
		memcpy(username, attr->value, attr->len - 2);
	}

	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL == appconn && portal->auto_session) {
		eag_log_debug("eag_portal", "eag_portal_chapauth_proc userip %s, "
			"appconn is null, auto_session is enable", user_ipstr);
		app_check_ret = appconn_check_is_conflict(userip, portal->appdb, &tmpsession, &tmp_appconn);
		appconn = appconn_create_no_arp(portal->appdb, &tmpsession);
	}
	if (NULL == appconn || EAG_RETURN_OK != app_check_ret) {
		eag_log_warning("eag_portal_chapauth_proc userip %s, "
			"appconn is null", user_ipstr);
		if (PORTAL_PROTOCOL_TELECOM == portal_get_protocol_type()) {
			goto check_appconn;
		}
		rsppkt.err_code = PORTAL_AUTH_REJECT;
		err_reason = PORTAL_ERR_REASON_APPCONN_FAILED;
		eag_log_filter(user_ipstr,"PortalReqAuth___UserIP:%s,UserName:%s,ChapAuth",
			user_ipstr, username);
		admin_log_notice("PortalReqAuth___UserIP:%s,UserName:%s,ChapAuth",
			user_ipstr, username);
		goto send;
	}

	if (0 != portal_request_check(reqpkt, appconn->portal_srv.secret,
				appconn->portal_srv.secretlen))
	{
		eag_log_warning("portal_chapauth_proc authenticator not match secret=%s userip=%s",
			appconn->portal_srv.secret, user_ipstr);
		return -1;
	}
	/* add username to session_filter_prefix */
	mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
	mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
    appconn->session.nasip = eag_ins_get_nasip(portal->eagins);
	ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
	ip2str(portal_ip, portal_ipstr, sizeof(portal_ipstr));
	
    eag_get_debug_filter_key(session_filter_prefix, sizeof(session_filter_prefix),
		user_ipstr, user_macstr, username);
	eag_log_filter(session_filter_prefix,"PortalReqAuth___UserIP:%s,UserMAC:%s,UserName:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ChapAuth",
		user_ipstr, user_macstr, username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
	admin_log_notice("PortalReqAuth___UserIP:%s,UserMAC:%s,UserName:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ChapAuth",
		user_ipstr, user_macstr, username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
	
	eag_time_gettimeofday(&tv, NULL);
	appconn->last_active_time = tv.tv_sec;
	
	if (EAG_RETURN_OK != appconn_config_portalsrv(appconn, portal->portalconf)) {
		eag_log_warning("eag_portal_chapauth_proc userip %s, "
			"appconn config portal srv failed", user_ipstr);
		rsppkt.err_code = PORTAL_AUTH_REJECT;
		err_reason = PORTAL_ERR_REASON_NO_FIND_SERVER;
		goto send;
	}
	if (portal_ip == appconn->portal_srv.mac_server_ip) {
		appconn->session.server_auth_type = EAG_AUTH_TYPE_MAC;
	} else {
		appconn->session.server_auth_type = EAG_AUTH_TYPE_PORTAL;
	}

	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL == portalsess) {
		eag_log_debug("eag_portal", "eag_portal_chapauth_proc "
			"not found portal_sess by userip %s, new one",
			user_ipstr);
		portalsess = portal_sess_new(portal, userip);
	}
	if (NULL == portalsess) {
		eag_log_err("eag_portal_chapauth_proc userip %s, "
			"portal_sess_new failed", user_ipstr);
		rsppkt.err_code = PORTAL_AUTH_REJECT;
		err_reason = PORTAL_ERR_REASON_SESSION_FAILED;
		goto send;
	}
	strncpy(portalsess->username, username, sizeof(portalsess->username));
	
	eag_log_debug("eag_portal", "eag_portal_chapauth_proc "
			"userip %s, sess_status %u, user_state %d",
			user_ipstr, portalsess->status, appconn->session.state);
	
	if (!sess_status_is_valid(portalsess, appconn)) {
		eag_log_err("eag_portal_chapauth_proc "
			"userip %s, sess_status %s not match user_state %d",
			user_ipstr, sess_status2str(portalsess->status),
			appconn->session.state);
	}
	
	switch (portalsess->status) {
	case SESS_STATUS_NONE:
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			rsppkt.err_code = PORTAL_AUTH_CONNECTED;
			err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		} else {
			rsppkt.err_code = PORTAL_AUTH_REJECT;
			err_reason = PORTAL_ERR_REASON_NO_CHELLENGED;
		}
		portal_sess_free(portalsess);
		break;
	case SESS_STATUS_ON_MACBIND:
	case SESS_STATUS_MACBOUND:
	case SESS_STATUS_LOGOUT_WAIT:
		eag_log_warning("eag_portal_chapauth_proc "
				"userip %s, on invalid portalsess %s",
				user_ipstr, sess_status2str(portalsess->status));
		rsppkt.err_code = PORTAL_AUTH_REJECT;
		err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		break;
	case SESS_STATUS_CHALLENGED:
		if (NULL != portalsess->t_timeout) {
			eag_thread_cancel(portalsess->t_timeout);
			portalsess->t_timeout = NULL;
		}
		if (ntohs(reqpkt->req_id) != portalsess->reqid) {
			eag_log_warning("eag_portal_chapauth_proc userip %s, "
				"req_auth reqid(%u) not equal to portalsess reqid(%u)",
				user_ipstr, reqpkt->req_id, portalsess->reqid);
			portal_sess_free(portalsess);
			rsppkt.err_code = PORTAL_AUTH_REJECT;
			err_reason = PORTAL_ERR_REASON_PACKET_WRONG;
			break;
		}

		memset(appconn->session.username, 0,
				sizeof(appconn->session.username));
		strncpy(appconn->session.username, username,
				sizeof(appconn->session.username));
        appconn_set_filter_prefix(appconn);

		if (PORTAL_PROTOCOL_TELECOM == portal_get_protocol_type()
			&& strlen(username) > PORTAL_TELECOM_USERNAME_LEN)
		{
			eag_log_err("eag_portal_chapauth_proc userip %s, "
				"username length %d > max %d", 
				user_ipstr, strlen(username), PORTAL_TELECOM_USERNAME_LEN);
			portal_sess_free(portalsess);
			rsppkt.err_code = PORTAL_AUTH_REJECT;
			err_reason = PORTAL_ERR_REASON_USER_NAME_WRONG;
			break;
		}
		
		div_username_and_domain(appconn->session.username,
								appconn->session.domain_name,
								sizeof(appconn->session.domain_name),
								portal->radiusconf);

		if (0 == strlen(appconn->session.username)) {
			eag_log_err("eag_portal_chapauth_proc userip %s, "
				"username length is 0", user_ipstr);
			portal_sess_free(portalsess);
			rsppkt.err_code = PORTAL_AUTH_REJECT;
			err_reason = PORTAL_ERR_REASON_USER_NAME_WRONG;
			break;
		}

		if (1 == username_check_switch) {
			appconn_by_name = appconn_find_by_username(portal->appdb, appconn->session.username);
	    
			if (NULL != appconn_by_name) {
		        eag_log_warning("eag_portal_chapauth_proc userip %s username %s has already authed",
					user_ipstr, appconn->session.username);
		        portal_sess_free(portalsess);
		        rsppkt.err_code = PORTAL_AUTH_REJECT;
		        err_reason = PORTAL_ERR_REASON_USER_NAME_EXIT;
		       break;
		    }
		}
                    if( 0==local_database_switch)
                    {
            		ret = appconn_config_radiussrv_by_domain(appconn, portal->radiusconf);
            		if (EAG_RETURN_OK != ret) {
            			eag_log_err("eag_portal_chapauth_proc userip %s, "
            					"appconn config radiussrv by domain failed", user_ipstr);
            			portal_sess_free(portalsess);
            			rsppkt.err_code = PORTAL_AUTH_REJECT;
            			err_reason = PORTAL_ERR_REASON_NO_FIND_SERVER;
            			break;
            		}
                    }
		
		attr = portal_packet_get_attr(reqpkt, ATTR_CHAPPASSWORD);
		if (NULL == attr) {
			eag_log_err("eag_portal_chapauth_proc userip %s, "
				"not get chappassword attr in req_auth", user_ipstr);
			eag_bss_message_count(portal->eagstat, appconn, BSS_REQ_AUTH_PASSWORD_MISSING_COUNT, 1);
			portal_sess_free(portalsess);
			rsppkt.err_code = PORTAL_AUTH_REJECT;
			err_reason = PORTAL_ERR_REASON_USER_PASSWD_WRONG;
			break;
		}
		
		if (attr->len != RADIUS_PASSWORD_LEN + 2) {
			eag_log_err("eag_portal_chapauth_proc userip %s, "
				"wrong chappasswd length %u", user_ipstr, attr->len);
			portal_sess_free(portalsess);
			rsppkt.err_code = PORTAL_AUTH_REJECT;
			err_reason = PORTAL_ERR_REASON_USER_PASSWD_WRONG;
			break;
		}
        if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_REQ_COUNT, 1);
        } else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_REQ_COUNT, 1);
        }

		memcpy(appconn->session.chappasswd, attr->value, RADIUS_PASSWORD_LEN);

		appconn->session.chapid = (uint8_t)(portalsess->reqid);
		memcpy(appconn->session.challenge, portalsess->challenge,
					CHALLENGESIZE);
		appconn->on_auth = 1;
		appconn->session.nasip = eag_ins_get_nasip(portal->eagins);
		appconn->portal_srv.ip = portal_ip;
		portalsess->portal_ip = portal_ip;
		portalsess->portal_port = portal_port;
		memcpy(&(portalsess->rcvpkt), reqpkt, sizeof(portalsess->rcvpkt));
		memcpy(portalsess->secret, appconn->portal_srv.secret, PORTAL_SECRETSIZE);
		portalsess->secretlen = appconn->portal_srv.secretlen;
		portalsess->status = SESS_STATUS_ON_CHAPAUTH;
		strncpy(portalsess->username, username, sizeof(portalsess->username));
		if(local_database_switch == 0)
		{
		           radius_auth(portal->radius, appconn, AUTH_CHAP);
			  eag_radius_get_retry_params(portal->radius, 
            				&retry_interval, &retry_times, &vice_retry_times);
            		portalsess->timeout = 
            				retry_interval * (retry_times + vice_retry_times + 1);
            		portal_sess_event(SESS_ONAUTH_TIMEOUT, portalsess);
		}
		else if (local_database_switch == 1)
		{
			char * passwd = get_passwd_from_datebase(appconn->session.username,EMPLOYEE_DATABASE_PATH);
			if(passwd == NULL)
				passwd = get_passwd_from_datebase(appconn->session.username,GUEST_DATABASE_PATH);
				
			if ((NULL != passwd) && (database_passwd_check(&(appconn->session),appconn->session.chappasswd,passwd) == 0))
			{
                                    printf("chenjun##########\n");
			    eag_portal_auth_success(portal,appconn);
			}
			else
			{
				eag_portal_auth_failure(portal, portalsess->userip, PORTAL_AUTH_REJECT,"user or passwd error");
			}
			free(passwd);

		}
				
		return EAG_RETURN_OK;
		/* break; */
	case SESS_STATUS_ON_PAPAUTH:
		eag_log_err("eag_portal_chapauth_proc userip %s, "
				"portalsess status is ON_PAPAUTH", user_ipstr);
	case SESS_STATUS_ON_CHAPAUTH:
		rsppkt.err_code = PORTAL_AUTH_ONAUTH;
		err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		break;
	case SESS_STATUS_AFF_WAIT:
		break;
	case SESS_STATUS_NTF_LOGOUT_WAIT:
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			rsppkt.err_code = PORTAL_AUTH_CONNECTED;
			err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		} else {
			eag_log_err("eag_portal_chapauth_proc userip %s "
				"portalsess NTF_LOGOUT_WAIT, but user not authed", user_ipstr);
			rsppkt.err_code = PORTAL_AUTH_REJECT;
			err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		}
		break;
	default:
		eag_log_err("eag_portal_chapauth_proc unknown portalsess status:%d",
			portalsess->status);
		portal_sess_free(portalsess);
		rsppkt.err_code = PORTAL_AUTH_REJECT;
		err_reason = PORTAL_ERR_REASON_UNKNOWN_ERR;
		break;
	}

send:
	if (eag_macauth_get_macauth_switch(portal->macauth)
			&& PORTAL_AUTH_SUCCESS != rsppkt.err_code)
	{
		/* del mac pre_auth */
		eag_del_mac_preauth(portal->macauth, userip);
	}
	if (portal->check_errid
		&& PORTAL_PROTOCOL_MOBILE == portal_get_protocol_type()
		&& PORTAL_AUTH_SUCCESS != rsppkt.err_code)
	{
		const char *errid = ERRID_AC999;
		portal_packet_add_attr(&rsppkt, ATTR_ERRID, errid, strlen(errid));
	}
	eag_log_debug("eag_portal","portal_chapauth_proc userip %s, "
		"send ack_auth, errcode=%u", user_ipstr, rsppkt.err_code);
	if (NULL == appconn) {
		eag_log_filter(user_ipstr,"PortalAckAuth___UserIP:%s,Username:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, username, rsppkt.err_code, err_reason);
		admin_log_notice("PortalAckAuth___UserIP:%s,Username:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, username, rsppkt.err_code, err_reason);
	} else {
		eag_log_filter(session_filter_prefix,"PortalAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, user_macstr, username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid, rsppkt.err_code, err_reason);
		admin_log_notice("PortalAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, user_macstr, username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid, rsppkt.err_code, err_reason);
	}
	if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
		eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_REQ_COUNT, 1);
	} else {
		eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_REQ_COUNT, 1);
	}

	if (NULL != appconn) {
		portal_resp_authenticator(&rsppkt, reqpkt, appconn->portal_srv.secret, 
				appconn->portal_srv.secretlen);
	}
	eag_portal_send_packet(portal, portal_ip, portal_port, &(rsppkt));
	switch (rsppkt.err_code) {
	case PORTAL_AUTH_SUCCESS:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_0_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_0_COUNT, 1);
		}
		break;
	case PORTAL_AUTH_REJECT:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_1_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_1_COUNT, 1);
		}
		break;
	case PORTAL_AUTH_CONNECTED:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_2_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_2_COUNT, 1);
		}
		break;
	case PORTAL_AUTH_ONAUTH:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_3_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_3_COUNT, 1);
		}
		break;
	case PORTAL_AUTH_FAILED:
	default:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_4_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_4_COUNT, 1);
		}
		break;
	}

check_appconn:
	if (EAG_ERR_APPCONN_APP_IS_CONFLICT == app_check_ret && NULL != tmp_appconn) {
		if (APPCONN_STATUS_AUTHED == tmp_appconn->session.state) {
			terminate_appconn_nowait(tmp_appconn, portal->eagins, RADIUS_TERMINATE_CAUSE_LOST_CARRIER);
		} else {
			appconn_del_from_db(tmp_appconn);
			appconn_free(tmp_appconn);
		}
		tmp_appconn = NULL;
	}

	return EAG_RETURN_OK;
}

int
eag_portal_papauth_proc(eag_portal_t *portal,
		uint32_t portal_ip,
		uint16_t portal_port,
		struct portal_packet_t *reqpkt)
{
	struct app_conn_t *appconn = NULL;
	portal_sess_t *portalsess = NULL;
	struct portal_packet_t rsppkt = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	eag_radius_t *radius = NULL;
	struct portal_packet_attr *attr = NULL;
	int ret = 0;
	int retry_interval = 0;
	int retry_times = 0;
	int vice_retry_times = 0;
	char username[USERNAMESIZE] = "";
	struct timeval tv = {0};
	int app_check_ret = 0;
	struct app_conn_t *tmp_appconn = NULL;
	struct appsession tmpsession = {0};
	char *err_reason = "";
	char session_filter_prefix[512] = ""; /* add for debug-filter */
    struct app_conn_t *appconn_by_name = NULL;

	if (NULL == portal || NULL == reqpkt) {
		eag_log_err("eag_portal_papauth_proc input error");
		return -1;
	}

	userip = ntohl(reqpkt->user_ip);
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	radius = portal->radius;
	portal_packet_init_rsp(portal, &rsppkt, reqpkt);

	attr = portal_packet_get_attr(reqpkt, ATTR_USERNAME);
	if (NULL == attr) {
		eag_log_err("eag_portal_papauth_proc userip %s "
			" not get username attr in req_auth", user_ipstr);
		memset(username, 0, sizeof(username));
	} else {
		memset(username, 0, sizeof(username));
		memcpy(username, attr->value, attr->len - 2);
	}
	
	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL == appconn && portal->auto_session) {
		eag_log_debug("eag_portal", "eag_portal_papauth_proc userip %s, "
			"appconn is null, auto_session is enable", user_ipstr);
		app_check_ret = appconn_check_is_conflict(userip, portal->appdb, &tmpsession, &tmp_appconn);
		appconn = appconn_create_no_arp(portal->appdb, &tmpsession);
	}
	if (NULL == appconn || EAG_RETURN_OK != app_check_ret) {
		eag_log_warning("eag_portal_papauth_proc userip %s, "
			"appconn is null", user_ipstr);
		if (PORTAL_PROTOCOL_TELECOM == portal_get_protocol_type()) {
			goto check_appconn;
		}
		rsppkt.err_code = PORTAL_AUTH_REJECT;
		err_reason = PORTAL_ERR_REASON_APPCONN_FAILED;
		admin_log_notice("PortalReqAuth___UserIP:%s,UserName:%s,PapAuth",
			user_ipstr, username);
		eag_log_filter(user_ipstr,"PortalReqAuth___UserIP:%s,UserName:%s,PapAuth",
			user_ipstr, username);
		goto send;
	}

	if (0 != portal_request_check(reqpkt, appconn->portal_srv.secret,
				appconn->portal_srv.secretlen))
	{
		eag_log_warning("portal_papauth_proc authenticator not match secret=%s userip=%s",
			appconn->portal_srv.secret, user_ipstr);
		return -1;
	}
	/* add username to session_filter_prefix */
	mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
	mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
	ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
	ip2str(portal_ip, portal_ipstr, sizeof(portal_ipstr));
	
    eag_get_debug_filter_key(session_filter_prefix, sizeof(session_filter_prefix),
		user_ipstr, user_macstr, username);
	eag_log_filter(session_filter_prefix,"PortalReqAuth___UserIP:%s,UserMAC:%s,UserName:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,PapAuth",
		user_ipstr, user_macstr, username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
	admin_log_notice("PortalReqAuth___UserIP:%s,UserMAC:%s,UserName:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,PapAuth",
		user_ipstr, user_macstr, username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
	
	eag_time_gettimeofday(&tv, NULL);
	appconn->last_active_time = tv.tv_sec;

	if (EAG_RETURN_OK != appconn_config_portalsrv(appconn, portal->portalconf)) {
		eag_log_warning("eag_portal_papauth_proc userip %s, "
			"appconn config portal srv failed", user_ipstr);
		rsppkt.err_code = PORTAL_AUTH_REJECT;
		err_reason = PORTAL_ERR_REASON_NO_FIND_SERVER;
		goto send;
	}
	if (portal_ip == appconn->portal_srv.mac_server_ip) {
		appconn->session.server_auth_type = EAG_AUTH_TYPE_MAC;
	} else {
		appconn->session.server_auth_type = EAG_AUTH_TYPE_PORTAL;
	}
	
	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL == portalsess) {
		eag_log_debug("eag_portal", "eag_portal_papauth_proc "
			"not found portal_sess by userip %s, new one",
			user_ipstr);
		portalsess = portal_sess_new(portal, userip);
	}
	if (NULL == portalsess) {
		eag_log_err("eag_portal_papauth_proc userip %s, "
			"portal_sess_new failed", user_ipstr);
		rsppkt.err_code = PORTAL_AUTH_REJECT;
		err_reason = PORTAL_ERR_REASON_SESSION_FAILED;
		goto send;
	}
	strncpy(portalsess->username, username, sizeof(portalsess->username));
	
	eag_log_debug("eag_portal", "eag_portal_papauth_proc "
			"userip %s, sess_status %u, user_state %d",
			user_ipstr, portalsess->status, appconn->session.state);
	
	if (!sess_status_is_valid(portalsess, appconn)) {
		eag_log_err("eag_portal_papauth_proc "
			"userip %s, sess_status %s not match user_state %d",
			user_ipstr, sess_status2str(portalsess->status),
			appconn->session.state);
	}
	
	switch (portalsess->status) {
	case SESS_STATUS_ON_MACBIND:
	case SESS_STATUS_CHALLENGED:
	case SESS_STATUS_LOGOUT_WAIT:
		eag_log_warning("eag_portal_papauth_proc userip %s, "
			"receive pap req_auth, on sess status %s",
			user_ipstr, sess_status2str(portalsess->status));
	case SESS_STATUS_MACBOUND:
		if (NULL != portalsess->t_timeout) {
			eag_thread_cancel(portalsess->t_timeout);
			portalsess->t_timeout = NULL;
		}
	case SESS_STATUS_NONE:
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			rsppkt.err_code = PORTAL_AUTH_CONNECTED;
			err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
			portal_sess_free(portalsess);
			goto send;
		}
		
		memset(appconn->session.username, 0,
				sizeof(appconn->session.username));
		strncpy(appconn->session.username, username,
				sizeof(appconn->session.username));
        appconn_set_filter_prefix(appconn);

		if (PORTAL_PROTOCOL_TELECOM == portal_get_protocol_type()
			&& strlen(username) > PORTAL_TELECOM_USERNAME_LEN)
		{
			eag_log_err("eag_portal_papauth_proc userip %s, "
				"username length %d > max %d", 
				user_ipstr, strlen(username), PORTAL_TELECOM_USERNAME_LEN);
			portal_sess_free(portalsess);
			rsppkt.err_code = PORTAL_AUTH_REJECT;
			err_reason = PORTAL_ERR_REASON_USER_NAME_WRONG;
			break;
		}
		
		div_username_and_domain(appconn->session.username,
								appconn->session.domain_name,
								sizeof(appconn->session.domain_name),
								portal->radiusconf);

		if (0 == strlen(appconn->session.username)) {
			eag_log_err("eag_portal_papauth_proc userip %s "
					"username length is 0", user_ipstr);
			portal_sess_free(portalsess);
			rsppkt.err_code = PORTAL_AUTH_REJECT;
			err_reason = PORTAL_ERR_REASON_USER_NAME_WRONG;
			break;
		}
		
		if (1 == username_check_switch) {
			appconn_by_name = appconn_find_by_username(portal->appdb, appconn->session.username);
	    
			if (NULL != appconn_by_name) {
		         eag_log_warning("eag_portal_chapauth_proc userip %s username %s has already authed",
					user_ipstr, appconn->session.username);
				portal_sess_free(portalsess);
				rsppkt.err_code = PORTAL_AUTH_REJECT;
		        err_reason = PORTAL_ERR_REASON_USER_NAME_EXIT;
		        break;
		    }
		}
	      if( 0==local_database_switch)
	      {
            		ret = appconn_config_radiussrv_by_domain(appconn,
            								portal->radiusconf);
            		if (EAG_RETURN_OK != ret) {
            			eag_log_err("eag_portal_papauth_proc userip %s "
            				"appconn config radiussrv by domain failed", user_ipstr);
            			portal_sess_free(portalsess);
            			rsppkt.err_code = PORTAL_AUTH_REJECT;
            			err_reason = PORTAL_ERR_REASON_NO_FIND_SERVER;
            			break;
            		}
	      }
		attr = portal_packet_get_attr(reqpkt, ATTR_PASSWORD);
		if (NULL == attr || attr->len < 3) {
			eag_log_err("eag_portal_papauth_proc userip %s "
				"not get password attr in pap req_auth", user_ipstr);
			eag_bss_message_count(portal->eagstat, appconn, BSS_REQ_AUTH_PASSWORD_MISSING_COUNT, 1);
			portal_sess_free(portalsess);
			rsppkt.err_code = PORTAL_AUTH_REJECT;
			err_reason = PORTAL_ERR_REASON_USER_PASSWD_WRONG;
			break;
		}
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_REQ_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_REQ_COUNT, 1);
		}
		memset(appconn->session.passwd, 0, sizeof(appconn->session.passwd));
		memcpy(appconn->session.passwd, attr->value, attr->len - 2);
		appconn->on_auth = 1;
		appconn->session.nasip = eag_ins_get_nasip(portal->eagins);
		appconn->portal_srv.ip = portal_ip;
		portalsess->portal_ip = portal_ip;
		portalsess->portal_port = portal_port;
		memcpy(&(portalsess->rcvpkt), reqpkt, sizeof(portalsess->rcvpkt));
		memcpy(portalsess->secret, appconn->portal_srv.secret, PORTAL_SECRETSIZE);
		portalsess->secretlen = appconn->portal_srv.secretlen;
		portalsess->status = SESS_STATUS_ON_PAPAUTH;
		strncpy(portalsess->username, username, sizeof(portalsess->username));
		if(0 == local_database_switch)
		{
            		radius_auth(portal->radius, appconn, AUTH_PAP);
            		eag_radius_get_retry_params(radius, 
            				&retry_interval, &retry_times, &vice_retry_times);
            		portalsess->timeout = 
            				retry_interval *(retry_times + vice_retry_times + 1);
            		portal_sess_event(SESS_ONAUTH_TIMEOUT, portalsess);
		}
		else if (local_database_switch == 1)
		{
			char * passwd = get_passwd_from_datebase(appconn->session.username,EMPLOYEE_DATABASE_PATH);
			if(passwd == NULL)
				passwd = get_passwd_from_datebase(appconn->session.username,GUEST_DATABASE_PATH);
			
			if ((NULL != passwd) && (memcmp(passwd,appconn->session.passwd,strlen(appconn->session.passwd)) == 0))
			{
                                    printf("chenjun##########1111\n");
			    eag_portal_auth_success(portal,appconn);
			}
			else
			{
				eag_portal_auth_failure(portal, portalsess->userip, PORTAL_AUTH_REJECT,"user or passwd error");
			}
			free(passwd);

		}
		return EAG_RETURN_OK;
		/* break; */
	case SESS_STATUS_ON_CHAPAUTH:
		eag_log_warning("eag_portal_papauth_proc userip %s "
				"portalsess status is ON_CHAPAUTH", user_ipstr);
	case SESS_STATUS_ON_PAPAUTH:
		rsppkt.err_code = PORTAL_AUTH_ONAUTH;
		err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		break;

	case SESS_STATUS_AFF_WAIT:
			break;
	case SESS_STATUS_NTF_LOGOUT_WAIT:
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			rsppkt.err_code = PORTAL_AUTH_CONNECTED;
			err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		} else {
			eag_log_err("eag_portal_papauth_proc userip %s "
				"portalsess NTF_LOGOUT_WAIT, but user not authed", user_ipstr);
			rsppkt.err_code = PORTAL_AUTH_REJECT;
			err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		}
		break;
	default:
		eag_log_err("eag_portal_papauth_proc unknown portalsess status:%d",
			portalsess->status);
		portal_sess_free(portalsess);
		rsppkt.err_code = PORTAL_AUTH_REJECT;
		err_reason = PORTAL_ERR_REASON_UNKNOWN_ERR;
		break;
	}

send:
	if (eag_macauth_get_macauth_switch(portal->macauth)
			&& PORTAL_AUTH_SUCCESS != rsppkt.err_code)
	{
		/* del mac pre_auth */
		eag_del_mac_preauth(portal->macauth, userip);
	}
	if (portal->check_errid
		&& PORTAL_PROTOCOL_MOBILE == portal_get_protocol_type()
		&& CHALLENGE_SUCCESS != rsppkt.err_code)
	{
		const char *errid = ERRID_AC999;
		portal_packet_add_attr(&rsppkt, ATTR_ERRID, errid, strlen(errid));
	}
	eag_log_debug("eag_portal","portal_papauth_proc userip %s, "
			"send ack_auth, errcode=%u", user_ipstr, rsppkt.err_code);
	if (NULL == appconn) {
		eag_log_filter(user_ipstr,"PortalAckAuth___UserIP:%s,Username:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, username, rsppkt.err_code, err_reason);
		admin_log_notice("PortalAckAuth___UserIP:%s,Username:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, username, rsppkt.err_code, err_reason);
	} else {
		eag_log_filter(session_filter_prefix,"PortalAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, user_macstr, username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid, rsppkt.err_code, err_reason);
		admin_log_notice("PortalAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, user_macstr, username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid, rsppkt.err_code, err_reason);
	}
	if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
		eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_REQ_COUNT, 1);
	} else {
		eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_REQ_COUNT, 1);
	}
	if (NULL != appconn) {
		portal_resp_authenticator(&rsppkt, reqpkt, appconn->portal_srv.secret, 
				appconn->portal_srv.secretlen);
	}
	eag_portal_send_packet(portal, portal_ip, portal_port, &(rsppkt));
	switch (rsppkt.err_code) {
	case PORTAL_AUTH_SUCCESS:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_0_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_0_COUNT, 1);
		}
		break;
	case PORTAL_AUTH_REJECT:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_1_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_1_COUNT, 1);
		}
		break;
	case PORTAL_AUTH_CONNECTED:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_2_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_2_COUNT, 1);
		}
		break;
	case PORTAL_AUTH_ONAUTH:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_3_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_3_COUNT, 1);
		}
		break;
	case PORTAL_AUTH_FAILED:
	default:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_4_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_4_COUNT, 1);
		}
		break;
	}

check_appconn:
	if (EAG_ERR_APPCONN_APP_IS_CONFLICT == app_check_ret && NULL != tmp_appconn) {
		if (APPCONN_STATUS_AUTHED == tmp_appconn->session.state) {
			terminate_appconn_nowait(tmp_appconn, portal->eagins, RADIUS_TERMINATE_CAUSE_LOST_CARRIER);
		} else {
			appconn_del_from_db(tmp_appconn);
			appconn_free(tmp_appconn);
		}
		tmp_appconn = NULL;
	}

	return EAG_RETURN_OK;
}

int
eag_portal_logout_proc(eag_portal_t *portal,
		uint32_t portal_ip,
		uint16_t portal_port,
		struct portal_packet_t *reqpkt)
{
	struct app_conn_t *appconn = NULL;
	portal_sess_t *portalsess = NULL;
	struct portal_packet_t rsppkt = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	struct timeval tv = {0};
	int app_check_ret = 0;
	struct app_conn_t *tmp_appconn = NULL;
	struct appsession tmpsession = {0};
	char *err_reason = "";

	if (NULL == portal || NULL == reqpkt) {
		eag_log_err("eag_portal_logout_proc input error");
		return -1;
	}

	userip = ntohl(reqpkt->user_ip);
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	portal_packet_init_rsp(portal, &rsppkt, reqpkt);

	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL == appconn) {
		app_check_ret = appconn_check_is_conflict(userip, portal->appdb, &tmpsession, &tmp_appconn);
		appconn = appconn_create_no_arp(portal->appdb, &tmpsession);
	}
	if (NULL == appconn || EAG_RETURN_OK != app_check_ret) {
		eag_log_warning("eag_portal_logout_proc userip %s, "
			"appconn is null", user_ipstr);
		if (PORTAL_PROTOCOL_TELECOM == portal_get_protocol_type()) {
			goto check_appconn;
		}
		admin_log_notice("PortalReqLogout___UserIP:%s,ErrCode:%u",
			user_ipstr, reqpkt->err_code);
		eag_log_filter(user_ipstr,"PortalReqLogout___UserIP:%s,ErrCode:%u",
			user_ipstr, reqpkt->err_code);
		rsppkt.err_code = EC_ACK_LOGOUT_REJECT;
		err_reason = PORTAL_ERR_REASON_APPCONN_FAILED;
		goto send;
	}

	if (0 != portal_request_check(reqpkt, appconn->portal_srv.secret,
				appconn->portal_srv.secretlen))
	{
		eag_log_warning("portal_logout_proc authenticator not match secret=%s userip=%s",
			appconn->portal_srv.secret, user_ipstr);
		return -1;
	}
	
	mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr), '-');
	mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
	ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
	ip2str(portal_ip, portal_ipstr, sizeof(portal_ipstr));
	if (APPCONN_STATUS_AUTHED == appconn->session.state) {
		admin_log_notice("PortalReqLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ErrCode:%u",
			user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid, reqpkt->err_code);
	} else {
		admin_log_notice("PortalReqLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ErrCode:%u",
			user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid, reqpkt->err_code);
	}
	log_app_filter(appconn,"PortalReqLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ErrCode:%u",
		user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid, reqpkt->err_code);
	
	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL == portalsess) {
		eag_log_debug("eag_portal", "eag_portal_logout_proc "
			"not found portal_sess by userip %s, new one",
			user_ipstr);
		portalsess = portal_sess_new(portal, userip);
	}
	if (NULL == portalsess) {
		eag_log_err("eag_portal_logout_proc userip %s, "
			"portal_sess_new failed", user_ipstr);
		rsppkt.err_code = EC_ACK_LOGOUT_REJECT;
		err_reason = PORTAL_ERR_REASON_SESSION_FAILED;
		goto send;
	}
	
	eag_log_debug("eag_portal", "eag_portal_logout_proc "
			"userip %s, sess_status %u, user_state %d",
			user_ipstr, portalsess->status, appconn->session.state);
	
	if (!sess_status_is_valid(portalsess, appconn)) {
		eag_log_err("eag_portal_logout_proc "
			"userip %s, sess_status %s not match user_state %d",
			user_ipstr, sess_status2str(portalsess->status),
			appconn->session.state);
	}

	if (0 != reqpkt->rsv) {
		reqpkt->err_code = EC_ACK_LOGOUT_FAILED;
		err_reason = PORTAL_ERR_REASON_PACKET_WRONG;
		eag_log_warning("eag_portal_logout_proc userip %s, "
					"req_logout rsv is %d, response ack_logout errcode=%d",
			user_ipstr, reqpkt->rsv, reqpkt->err_code);
		goto send;
	}
	
	switch (portalsess->status) {
	case SESS_STATUS_AFF_WAIT:
		if (NULL != portalsess->t_timeout) {
			eag_thread_cancel(portalsess->t_timeout);
			portalsess->t_timeout = NULL;
		}
		eag_log_warning("eag_portal_logout_proc userip %s, "
			"receive req_logout packet on portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		/* no break */
	case SESS_STATUS_NONE:
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			eag_time_gettimeofday(&tv, NULL);
			appconn->session.session_stop_time = tv.tv_sec;
			eag_log_debug("eag_portal","portal_logout_proc userip %s, send ack_logout,"
				"errcode=%u", user_ipstr, rsppkt.err_code);
			admin_log_notice("PortalAckLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ErrCode:%u",
				user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid, rsppkt.err_code);
			log_app_filter(appconn,"PortalAckLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s,ErrCode:%u",
				user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid, rsppkt.err_code);
			portal_resp_authenticator(&rsppkt, reqpkt, appconn->portal_srv.secret, 
					appconn->portal_srv.secretlen);
			eag_portal_send_packet(portal, portal_ip, portal_port, &(rsppkt));
			terminate_appconn(appconn, portal->eagins,
						RADIUS_TERMINATE_CAUSE_USER_REQUEST);
			portalsess->status = SESS_STATUS_LOGOUT_WAIT;
			portalsess->timeout = portal->logout_wait_timeout;
			portal_sess_event(SESS_LOGOUT_WAIT_TIMEOUT, portalsess);
			return EAG_RETURN_OK;
		} else {
			rsppkt.err_code = EC_ACK_LOGOUT_REJECT;
			err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
			portal_sess_free(portalsess);
		}
		break;
	case SESS_STATUS_LOGOUT_WAIT:
		portal_resp_authenticator(&rsppkt, reqpkt, appconn->portal_srv.secret, 
					appconn->portal_srv.secretlen);
		eag_portal_send_packet(portal, portal_ip, portal_port, &(rsppkt));
		admin_log_notice("PortalAckLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%u",
				user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, rsppkt.err_code);
		eag_log_filter(user_ipstr,"PortalAckLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%u",
				user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, rsppkt.err_code);
		eag_log_warning("eag_portal_logout_proc userip %s, "
			"receive req_logout packet on portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		return EAG_RETURN_OK;
	case SESS_STATUS_ON_MACBIND:
	case SESS_STATUS_MACBOUND:
	case SESS_STATUS_ON_CHAPAUTH:
	case SESS_STATUS_ON_PAPAUTH:
	case SESS_STATUS_NTF_LOGOUT_WAIT:
		eag_log_warning("eag_portal_logout_proc userip %s, "
			"receive req_logout packet on portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		rsppkt.err_code = EC_ACK_LOGOUT_REJECT;
		err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		break;
	case SESS_STATUS_CHALLENGED:
		eag_log_warning("eag_portal_logout_proc userip %s, "
			"receive req_logout packet on portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		rsppkt.err_code = EC_ACK_LOGOUT_FAILED; 
		err_reason = PORTAL_ERR_REASON_USER_STATE_WRONG;
		/*for china mobile test, best to delete this line after test. */ 
		break;
	default:
		eag_log_err("eag_portal_logout_proc userip %s, "
			"unknown portalsess status %d",
		     user_ipstr, portalsess->status);
		rsppkt.err_code = EC_ACK_LOGOUT_REJECT;
		err_reason = PORTAL_ERR_REASON_UNKNOWN_ERR;
		break;
	}
	
send:
	eag_log_debug("eag_portal","portal_logout_proc userip %s, "
			"send ack_logout, errcode=%u", user_ipstr, rsppkt.err_code);
	if (NULL == appconn) {
		eag_log_filter(user_ipstr,"PortalAckLogout___UserIP:%s,ErrCode:%u,ErrReason:%s",
				user_ipstr, rsppkt.err_code, err_reason);
		admin_log_notice("PortalAckLogout___UserIP:%s,ErrCode:%u,ErrReason:%s",
					user_ipstr, rsppkt.err_code, err_reason);
	} else {
		log_app_filter(appconn,"PortalAckLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%u,ErrReason:%s",
				user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, rsppkt.err_code, err_reason);
		admin_log_notice("PortalAckLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%u,ErrReason:%s",
					user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, rsppkt.err_code, err_reason);
	}
	if (NULL != appconn) {
		portal_resp_authenticator(&rsppkt, reqpkt, appconn->portal_srv.secret, 
					appconn->portal_srv.secretlen);
	}
	eag_portal_send_packet(portal, portal_ip, portal_port, &(rsppkt));

check_appconn:
	if (EAG_ERR_APPCONN_APP_IS_CONFLICT == app_check_ret && NULL != tmp_appconn) {
		if (APPCONN_STATUS_AUTHED == tmp_appconn->session.state) {
			terminate_appconn_nowait(tmp_appconn, portal->eagins, RADIUS_TERMINATE_CAUSE_LOST_CARRIER);
		} else {
			appconn_del_from_db(tmp_appconn);
			appconn_free(tmp_appconn);
		}
		tmp_appconn = NULL;
	}

	return EAG_RETURN_OK;
}

int
eag_portal_logout_errcode1_proc(eag_portal_t *portal,
		uint32_t portal_ip,
		uint16_t portal_port,
		struct portal_packet_t *reqpkt)
{
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	struct app_conn_t *appconn = NULL;

	if (NULL == portal || NULL == reqpkt) {
		eag_log_err("eag_portal_logout_errcode1_proc input error");
		return -1;
	}
	
	/* logout_errcode1_proc */
	userip = ntohl(reqpkt->user_ip);
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	
	appconn = appconn_find_by_userip(portal->appdb,userip);
	if (NULL == appconn) {
		eag_log_filter(user_ipstr,"PortalReqLogout___UserIP:%s,ErrCode:%u",
			user_ipstr, reqpkt->err_code);
		admin_log_notice("PortalReqLogout___UserIP:%s,ErrCode:%u",
				user_ipstr, reqpkt->err_code);
	} else {
		mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr), '-');
		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
		ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
		ip2str(portal_ip, portal_ipstr, sizeof(portal_ipstr));
		log_app_filter(appconn,"PortalReqLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%u",
			user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, reqpkt->err_code);
		admin_log_notice("PortalReqLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%u",
			user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, reqpkt->err_code);
	}
	
	return EAG_RETURN_OK;
}

int
eag_portal_ack_logout_proc(eag_portal_t *portal,
		uint32_t portal_ip,
		uint16_t portal_port,
		struct portal_packet_t *reqpkt)
{
	struct app_conn_t *appconn = NULL;
	portal_sess_t *portalsess = NULL;
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	struct timeval tv = {0};

	if (NULL == portal || NULL == reqpkt) {
		eag_log_err("eag_portal_ack_logout_proc input error");
		return -1;
	}

	userip = ntohl(reqpkt->user_ip);
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	
	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL == appconn) {
		eag_log_warning("eag_portal_ack_logout_proc "
			"not found appconn by userip %s", user_ipstr);
		eag_log_filter(user_ipstr,"PortalAckLogout___UserIP:%s,ErrCode:%u,Received",
				user_ipstr, reqpkt->err_code);
		admin_log_notice("PortalAckLogout___UserIP:%s,ErrCode:%u,Received",
					user_ipstr, reqpkt->err_code);
		return 0;
	} else {
		mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr), '-');
		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
		ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
		ip2str(portal_ip, portal_ipstr, sizeof(portal_ipstr));
		log_app_filter(appconn,"PortalAckLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%u,Received",
				user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, reqpkt->err_code);
		admin_log_notice("PortalAckLogout___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%u,Received",
				user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, reqpkt->err_code);
	}

	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL == portalsess) {
		eag_log_warning("eag_portal_logout_proc "
			"not found portal_sess by userip %s", user_ipstr);
		return 0;
	}
	
	eag_log_debug("eag_portal", "eag_portal_ack_logout_proc "
			"userip %s, sess_status %u, user_state %d",
			user_ipstr, portalsess->status, appconn->session.state);
	
	if (!sess_status_is_valid(portalsess, appconn)) {
		eag_log_err("eag_portal_ack_logout_proc "
			"userip %s, sess_status %s not match user_state %d",
			user_ipstr, sess_status2str(portalsess->status),
			appconn->session.state);
	}

	switch (portalsess->status) {
	case SESS_STATUS_NONE:
		eag_log_warning("eag_portal_ack_logout_proc userip %s, " 
			"receive ack_logout on portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		if (NULL != portalsess->t_timeout) {
			eag_thread_cancel(portalsess->t_timeout);
			portalsess->t_timeout = NULL;
		}
		portal_sess_free(portalsess);
		break;
	case SESS_STATUS_ON_MACBIND:
	case SESS_STATUS_MACBOUND:
	case SESS_STATUS_CHALLENGED:
	case SESS_STATUS_ON_CHAPAUTH:
	case SESS_STATUS_ON_PAPAUTH:
	case SESS_STATUS_AFF_WAIT:
	case SESS_STATUS_LOGOUT_WAIT:
		eag_log_warning("eag_portal_ack_logout_proc userip %s, " 
			"receive ack_logout on expected portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
	break;
	case SESS_STATUS_NTF_LOGOUT_WAIT:
		if (NULL != portalsess->t_timeout) {
			eag_thread_cancel(portalsess->t_timeout);
			portalsess->t_timeout = NULL;
		}
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			if (portalsess->is_dm_logout) {
				eag_log_debug("eag_portal","portal_ack_logout_proc userip %s, "
					"is dm logout, coa response to radius", user_ipstr);
				admin_log_notice("RadiusDisconnectACK___UserName:%s,UserIP:%s,ErrorCause:%d",
					portalsess->username, user_ipstr, RADIUS_ERROR_CAUSE_201);
				log_app_filter(appconn,"RadiusDisconnectACK___UserName:%s,UserIP:%s,ErrorCause:%d",
					portalsess->username, user_ipstr, RADIUS_ERROR_CAUSE_201);
				eag_coa_ack_logout_proc(portal->coa, portalsess->radius_ip,
					portalsess->radius_port, portalsess->dm_id);
			}
			eag_time_gettimeofday(&tv, NULL);
			appconn->session.session_stop_time = tv.tv_sec;
			appconn->on_ntf_logout = 0;
			terminate_appconn(appconn, portal->eagins,
				portalsess->terminate_cause);
		} else {
			eag_log_err("eag_portal_ack_logout_proc userip %s, "
				"receive ack_logout on portalsess %s, but user not authed",
				user_ipstr, sess_status2str(portalsess->status));
		}
		portal_sess_free(portalsess);
		break;
	default:
		eag_log_err("eag_portal_ack_logout_proc userip %s, "
			"unknown portalsess status %d",
			user_ipstr, portalsess->status);
		break;
	}
	
	return EAG_RETURN_OK;
}

static int
eag_portal_aff_ack_auth_proc(eag_portal_t *portal,
		uint32_t portal_ip,
		uint16_t portal_port,
		struct portal_packet_t *reqpkt)
{
	struct app_conn_t *appconn = NULL;
	portal_sess_t *portalsess = NULL;
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";

	if (NULL == portal || NULL == reqpkt) {
		eag_log_err("eag_portal_aff_ack_auth_proc input error");
		return -1;
	}

	userip = ntohl(reqpkt->user_ip);
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	
	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL == appconn) {
		eag_log_warning("eag_portal_aff_ack_auth_proc "
			"not found appconn by userip %s", user_ipstr);
		eag_log_filter(user_ipstr,"PortalAffAckAuth___UserIP:%s",
				user_ipstr);
		admin_log_notice("PortalAffAckAuth___UserIP:%s",
			user_ipstr);
		return 0;
	} else {
		mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr), '-');
		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
		ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
		ip2str(portal_ip, portal_ipstr, sizeof(portal_ipstr));
		log_app_filter(appconn,"PortalAffAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s",
						user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
		admin_log_notice("PortalAffAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s",
			user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
	}
	if (0 != portal_request_check(reqpkt, appconn->portal_srv.secret,
				appconn->portal_srv.secretlen))
	{
		eag_log_warning("portal_logout_proc authenticator not match secret=%s userip=%s",
			appconn->portal_srv.secret, user_ipstr);
		return -1;
	}

	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL == portalsess) {
		eag_log_warning("eag_portal_aff_ack_auth_proc "
			"not found portal_sess by userip %s", user_ipstr);
		return 0;
	}
	
	eag_log_debug("eag_portal", "eag_portal_aff_ack_auth_proc "
			"userip %s, sess_status %u, user_state %d",
			user_ipstr, portalsess->status, appconn->session.state);
	
	if (!sess_status_is_valid(portalsess, appconn)) {
		eag_log_err("eag_portal_aff_ack_auth_proc "
			"userip %s, sess_status %s not match user_state %d",
			user_ipstr, sess_status2str(portalsess->status),
			appconn->session.state);
	}

	switch (portalsess->status) {
	case SESS_STATUS_NONE:
		eag_log_warning("eag_portal_aff_ack_auth_proc userip %s, " 
			"receive aff_ack_auth on portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		if (NULL != portalsess->t_timeout) {
			eag_thread_cancel(portalsess->t_timeout);
			portalsess->t_timeout = NULL;
		}
		portal_sess_free(portalsess);
		break;
	case SESS_STATUS_AFF_WAIT:
		if (NULL != portalsess->t_timeout) {
			eag_thread_cancel(portalsess->t_timeout);
			portalsess->t_timeout = NULL;
		}
		portal_sess_free(portalsess);
		break;
	case SESS_STATUS_ON_MACBIND:
	case SESS_STATUS_MACBOUND:
	case SESS_STATUS_CHALLENGED:
	case SESS_STATUS_ON_CHAPAUTH:
	case SESS_STATUS_ON_PAPAUTH:
	case SESS_STATUS_LOGOUT_WAIT:
	case SESS_STATUS_NTF_LOGOUT_WAIT:
	eag_log_warning("eag_portal_aff_ack_auth_proc userip %s, "
		"receive aff_ack_auth on portalsess status %s",
		user_ipstr, sess_status2str(portalsess->status));
		break;
	default:
		eag_log_err("eag_portal_aff_ack_auth_proc userip %s, "
			"unknown portalsess status %d",
			user_ipstr, portalsess->status);
		portal_sess_free(portalsess);
		break;
	}

	return EAG_RETURN_OK;
}

int
eag_portal_reqinfo_proc(eag_portal_t *portal,
		uint32_t portal_ip,
		uint16_t portal_port,
		struct portal_packet_t *reqpkt)
{
	struct app_conn_t *appconn = NULL;
	struct portal_packet_t rsppkt = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	int app_check_ret = 0;
	struct app_conn_t *tmp_appconn = NULL;
	struct appsession tmpsession = {0};
	char *err_reason = "";

	if (NULL == portal || NULL == reqpkt) {
		eag_log_err("eag_portal_reqinfo_proc input error");
		return -1;
	}

	userip = ntohl(reqpkt->user_ip);
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	portal_packet_init_rsp(portal, &rsppkt, reqpkt);

	admin_log_notice("PortalReqInfo___UserIP:%s",
			user_ipstr);
	
	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL == appconn) {
		app_check_ret = appconn_check_is_conflict(userip, portal->appdb, &tmpsession, &tmp_appconn);
		appconn = appconn_create_no_arp(portal->appdb, &tmpsession);
	}
	if (NULL == appconn || EAG_RETURN_OK != app_check_ret) {
		eag_log_warning("eag_portal_reqinfo_proc "
			"not find appconn by userip %s, and create appconn failed",
			user_ipstr);
		if (PORTAL_PROTOCOL_TELECOM == portal_get_protocol_type()) {
			return -1;
		}
		rsppkt.err_code = EC_ACK_INFO_FAILED;
		err_reason = PORTAL_ERR_REASON_APPCONN_FAILED;
		goto send;
	}

	if (0 != portal_request_check(reqpkt, appconn->portal_srv.secret,
				appconn->portal_srv.secretlen))
	{
		eag_log_warning("portal_reqinfo_proc authenticator not match secret=%s userip=%s",
			appconn->portal_srv.secret, user_ipstr);
		return -1;
	}
	
	if (PORTAL_PROTOCOL_MOBILE == portal_get_protocol_type()) {
		portal_packet_add_attr(&rsppkt, ATTR_PORT_ID,
			appconn->session.nas_port_id, strlen(appconn->session.nas_port_id));
	} else {
		int find = 0;
		if ( NULL != portal_packet_get_attr(reqpkt, ATTR_PORT_ID)) {
			char hostname[128] = {0};
			char attr_port[64] = {0};
			int attrlen = 0;
			
			if (0 != gethostname(hostname, sizeof(hostname)-1)) {
				memset(hostname, 0, sizeof(hostname));
			}
			/* (HostName)-(SlotID)(subSlotID)(Port)(OuterVlan)0(InnerVlan) */
			snprintf(attr_port, sizeof(attr_port)-1, "%s-%02u%02u%04u0%04u",
				hostname, 0, /*portal->portal_port,*/ 0,
				0, appconn->session.vlanid);

			attrlen = strlen(attr_port);
			attrlen = (attrlen>35) ? 35 : attrlen;
			portal_packet_add_attr(&rsppkt, ATTR_PORT_ID, &attr_port, attrlen);
			find = 1;
		}
		
		if ( NULL != portal_packet_get_attr(reqpkt, ATTR_UPLINKFLUX)
			&& APPCONN_STATUS_AUTHED == appconn->session.state)
		{
			uint64_t uplinkflux = 0;
			
			uplinkflux = htonl64(appconn->session.output_octets/1024);
			portal_packet_add_attr(&rsppkt, ATTR_UPLINKFLUX, &uplinkflux, 8);
			find = 1;
		}
		
		if ( NULL != portal_packet_get_attr(reqpkt, ATTR_UPLINKFLUX)
			&& APPCONN_STATUS_AUTHED == appconn->session.state)
		{
			uint64_t downlinkflux = 0;
			
			downlinkflux = htonl64(appconn->session.input_octets/1024);
			portal_packet_add_attr(&rsppkt, ATTR_DOWNLINKFLUX, &downlinkflux, 8);
			find = 1;
		}
		if (!find) {
			eag_log_warning("portal_reqinfo_proc no any attr in req_info userip=%s",
				user_ipstr);
			rsppkt.err_code = EC_ACK_INFO_FAILED;
			err_reason = PORTAL_ERR_REASON_PACKET_WRONG;
			goto send;
		}
	}

send:
	eag_log_debug("eag_portal", "portal_reqinfo_proc userip %s, "
			"send ack_info, errcode=%u", user_ipstr, rsppkt.err_code);
	admin_log_notice("PortalAckInfo___UserIP:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, rsppkt.err_code, err_reason);
	if (NULL != appconn) {
		portal_resp_authenticator(&(rsppkt), reqpkt, appconn->portal_srv.secret,
		appconn->portal_srv.secretlen);
	}
	eag_portal_send_packet(portal, portal_ip, portal_port, &(rsppkt));
	
	return EAG_RETURN_OK;
}

int
eag_portal_ack_macbind_proc(eag_portal_t *portal,
		uint32_t portal_ip,
		uint16_t portal_port,
		struct portal_packet_t *reqpkt)
{
	struct app_conn_t *appconn = NULL;
	portal_sess_t *portalsess = NULL;
	uint32_t userip = 0;
	char user_ipstr[32] = "";

	if (NULL == portal || NULL == reqpkt) {
		eag_log_err("eag_portal_ack_macbind_proc input error");
		return -1;
	}

	userip = ntohl(reqpkt->user_ip);
	ip2str(userip, user_ipstr, sizeof(user_ipstr));

	admin_log_notice("PortalAckMacBindInfo___UserIP:%s,ErrCode:%u,%s",
			user_ipstr, reqpkt->err_code,
			(0x01 == reqpkt->err_code)?"NotBound":"Bound");
		
	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL == appconn) {
		eag_log_warning("eag_portal_ack_macbind_proc "
			"not found appconn by userip %s",
			user_ipstr);
		eag_log_filter(user_ipstr,"PortalAckMacBindInfo___UserIP:%s,ErrCode:%u,%s",
			user_ipstr, reqpkt->err_code,
			(0x01 == reqpkt->err_code)?"NotBound":"Bound");
		return 0;
	}
	log_app_filter(appconn, "PortalAckMacBindInfo___UserIP:%s,ErrCode:%u,%s",
			user_ipstr, reqpkt->err_code,
			(0x01 == reqpkt->err_code)?"NotBound":"Bound");
	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL == portalsess) {
		eag_log_warning("eag_portal_ack_macbind_proc "
			"not found portal_sess by userip %s", user_ipstr);
		return 0;
	}
	
	eag_log_debug("eag_portal", "eag_portal_ack_macbind_proc "
			"userip %s, sess_status %u, user_state %d",
			user_ipstr, portalsess->status, appconn->session.state);
	
	if (!sess_status_is_valid(portalsess, appconn)) {
		eag_log_err("eag_portal_ack_macbind_proc "
			"userip %s, sess_status %s not match user_state %d",
			user_ipstr, sess_status2str(portalsess->status),
			appconn->session.state);
	}

	switch (portalsess->status) {
	case SESS_STATUS_NONE:
		eag_log_warning("eag_portal_ack_macbind_proc userip %s, " 
			"receive ack_macbind on portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		if (NULL != portalsess->t_timeout) {
			eag_thread_cancel(portalsess->t_timeout);
			portalsess->t_timeout = NULL;
		}
		portal_sess_free(portalsess);
		break;
	case SESS_STATUS_MACBOUND:
	case SESS_STATUS_CHALLENGED:
	case SESS_STATUS_ON_CHAPAUTH:
	case SESS_STATUS_ON_PAPAUTH:
	case SESS_STATUS_AFF_WAIT:
	case SESS_STATUS_LOGOUT_WAIT:
	case SESS_STATUS_NTF_LOGOUT_WAIT:
	eag_log_warning("eag_portal_ack_macbind_proc userip %s, "
		"receive ack_macbind on portalsess status %s",
		user_ipstr, sess_status2str(portalsess->status));
		break;
	case SESS_STATUS_ON_MACBIND:
		if (NULL != portalsess->t_timeout) {
			eag_thread_cancel(portalsess->t_timeout);
			portalsess->t_timeout = NULL;
		}
		if (0x01 == reqpkt->err_code) {
			eag_del_mac_preauth(portal->macauth,userip);
			portal_sess_free(portalsess);
		} else {
			portalsess->status = SESS_STATUS_MACBOUND;
			portalsess->timeout = portal->macbound_timeout;
			portal_sess_event(SESS_MACBOUND_TIMEOUT, portalsess);
			eag_log_debug("eag_portal","portal ack_macbind proc userip %s "
				"come into MACBOUND status",
				user_ipstr);
		}
		break;
	default:
		eag_log_err("eag_portal_ack_macbind_proc userip %s, "
			"unknown portalsess status %d",
			user_ipstr, portalsess->status);
		portal_sess_free(portalsess);
		break;
	}

	return EAG_RETURN_OK;
}

int
eag_portal_user_offline_proc(eag_portal_t *portal,
		uint32_t portal_ip,
		uint16_t portal_port,
		struct portal_packet_t *reqpkt)
{
	struct app_conn_t *appconn = NULL;
	struct timeval tv = {0};
	time_t timenow = 0;
	uint32_t userip = 0;
	uint8_t usermac[6] = {0};
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char user_macstr_pack[32] = "";
	struct portal_packet_attr *attr = NULL;
	
	if (NULL == portal || NULL == reqpkt) {
		eag_log_err("eag_portal_user_offline_proc input error");
		return -1;
	}

	userip = ntohl(reqpkt->user_ip);
	ip2str(userip, user_ipstr, sizeof(user_ipstr));

	attr = portal_packet_get_attr(reqpkt, ATTR_USERMAC);
	if (NULL == attr || attr->len != 8) {
		eag_log_warning("eag_portal_user_offline_proc userip %s "
			"not get USERMAC attr in REQ_USER_OFFLINE", user_ipstr);
		return 0;
	}

	memcpy(usermac, attr->value, sizeof(usermac));
	mac2str(usermac, user_macstr_pack, sizeof(user_macstr_pack), '-');
	
	admin_log_notice("PortalReqUserOffline___UserIP:%s,UserMac:%s",
		user_ipstr, user_macstr_pack);
	
	eag_time_gettimeofday(&tv,NULL);
	timenow = tv.tv_sec;

	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL == appconn) {
		eag_log_warning("eag_portal_user_offline_proc userip %s, "
			"appconn is null", user_ipstr);
		eag_log_filter(user_ipstr,"PortalReqUserOffline___UserIP:%s,UserMac:%s",
			user_ipstr, user_macstr_pack);
		return 0;
	}
	log_app_filter(appconn,"PortalReqUserOffline___UserIP:%s,UserMac:%s",
		user_ipstr, user_macstr_pack);

	mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr), '-');
	if (0 != memcmp(appconn->session.usermac, usermac, 6)) {
		eag_log_warning("bind server cannot force user(%s) offline, "
			"user mac %s not match request packet %s",
			user_ipstr, user_macstr, user_macstr_pack);
		return 0;
	}
	
	if (APPCONN_STATUS_AUTHED == appconn->session.state) {
		appconn->session.session_stop_time = timenow;
		eag_portal_notify_logout_nowait(portal, appconn);
		terminate_appconn(appconn, portal->eagins,
				RADIUS_TERMINATE_CAUSE_ADMIN_RESET);
	} else {
		appconn_del_from_db(appconn);
		appconn_free(appconn);
	}

	return EAG_RETURN_OK;
}

static int
portal_proc_packet(eag_portal_t *portal,
		uint32_t portal_ip,
		uint16_t portal_port,
		struct portal_packet_t *reqpkt)
{
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	
	if (NULL == portal || NULL == reqpkt) {
		eag_log_err("portal_proc_packet input error");
		return -1;
	}

	userip = reqpkt->user_ip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));

	eag_log_info("Receive portal packet type=%x,userip=%#x,errcode=%u "
		" from portal server %#x:%u",
		reqpkt->type, reqpkt->user_ip, reqpkt->err_code,
		portal_ip, portal_port);
	
	switch (reqpkt->type) {
	case REQ_CHALLENGE:
		eag_portal_challenge_proc(portal, portal_ip, portal_port, reqpkt);
		break;
	case REQ_AUTH:
		if (AUTH_CHAP == reqpkt->auth_type) {
			eag_portal_chapauth_proc(portal, portal_ip, portal_port, reqpkt);
		} else if (AUTH_PAP == reqpkt->auth_type) {
			eag_portal_papauth_proc(portal, portal_ip, portal_port, reqpkt);
		} else {
			/* ins unknow auth type */
			eag_bss_message_count(portal->eagstat, NULL, BSS_REQ_AUTH_UNKNOWN_TYPE_COUNT, 1);
			eag_log_warning("portal proc packet userip %s, "
				"unknow auth type %u",
				user_ipstr, reqpkt->auth_type);
		}
		break;
	case REQ_LOGOUT:
		if (0 == reqpkt->err_code) {
			eag_portal_logout_proc(portal, portal_ip, portal_port, reqpkt);
		} else if (0x01 == reqpkt->err_code) {
			eag_portal_logout_errcode1_proc(portal, portal_ip, portal_port, reqpkt);
		} else {
			/* ins unknow packet type */
			eag_log_warning("portal proc packet userip %s, "
					"unknow packet type, type=REQ_LOGOUT, errcode=%u",
					user_ipstr, reqpkt->err_code);
		}
		break;
	case ACK_LOGOUT:
		eag_portal_ack_logout_proc(portal, portal_ip, portal_port, reqpkt);
		break;
	case AFF_ACK_AUTH:
		eag_portal_aff_ack_auth_proc(portal, portal_ip, portal_port, reqpkt);
		break;
	case REQ_INFO:
		eag_portal_reqinfo_proc(portal, portal_ip, portal_port, reqpkt);
		break;
	case ACK_MACBINDING_INFO:
		eag_portal_ack_macbind_proc(portal, portal_ip, portal_port, reqpkt);
		break;
	case REQ_USER_OFFLINE:
		eag_portal_user_offline_proc(portal, portal_ip, portal_port, reqpkt);
		break;
	default:
		eag_log_warning("portal proc packet userip %s, "
			"unexpected packet type:%u",
			user_ipstr, reqpkt->type);
		break;
	}

	return EAG_RETURN_OK;
}

static int
portal_receive(eag_thread_t *thread)
{
	eag_portal_t *portal = NULL;
	struct sockaddr_in addr = {0};
	socklen_t len = 0;
	ssize_t nbyte = 0;
	struct portal_packet_t reqpkt = {0};
	int packet_len = 0;
	char ipstr[32] = "";
	uint32_t portal_ip = 0;
	uint16_t portal_port = 0;
	//int is_distributed = 0;
	//int pdc_distributed = 0;
	int portal_minsize = 0;
	
	if (NULL == thread) {
		eag_log_err("portal_receive input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}

	portal = eag_thread_get_arg(thread);
	if (NULL == portal) {
		eag_log_err("portal_receive portal is null");
		return EAG_ERR_NULL_POINTER;
	}
	//is_distributed = eag_ins_get_distributed(portal->eagins);

	len = sizeof(addr);
	
		nbyte = recvfrom(portal->sockfd, &reqpkt, sizeof(reqpkt), 0,
						(struct sockaddr *)&addr, &len);
		if (nbyte < 0) {
			eag_log_err("portal_receive recvfrom failed: fd(%d) %s",
				portal->sockfd, safe_strerror(errno));
			return EAG_ERR_SOCKET_RECV_FAILED;
		}
	

	portal_ip = ntohl(addr.sin_addr.s_addr);
	portal_port = ntohs(addr.sin_port);
	eag_log_info( "portal fd(%d) receive %d bytes from %s:%u",
		portal->sockfd,
		nbyte,
		ip2str(portal_ip, ipstr, sizeof(ipstr)),
		portal_port);

	portal_minsize = portal_packet_minsize();
	if (nbyte < portal_minsize) {
		eag_log_warning("portal_receive packet size %d < min %d",
			nbyte, portal_minsize);
		return -1;
	}

	if (nbyte > PORTAL_PACKET_SIZE) {
		eag_log_warning("portal_receive packet size %d > max %d",
			nbyte, PORTAL_PACKET_SIZE);
		return -1;
	}

	//portal_packet_ntoh(&reqpkt);
	packet_len = portal_packet_get_length(&reqpkt);
	if (nbyte != packet_len) {
		eag_log_warning("portal_receive packet size %d != len %d",
			nbyte, packet_len);
		return -1;
	}

	if (REQ_CHALLENGE != reqpkt.type
		&& REQ_AUTH != reqpkt.type
		&& REQ_LOGOUT != reqpkt.type
		&& ACK_LOGOUT != reqpkt.type
		&& AFF_ACK_AUTH != reqpkt.type
		&& REQ_INFO != reqpkt.type
		&& ACK_MACBINDING_INFO != reqpkt.type
		&& REQ_USER_OFFLINE != reqpkt.type) {
		eag_log_warning("portal_receive unexpected packet type %d",
			reqpkt.type);
		return -1;
	}
	
	portal_proc_packet(portal, portal_ip, portal_port, &reqpkt);
	
	return EAG_RETURN_OK;
}

/* ack_auth failure may happen:
* 1. when receiving Req_Auth,
* 2. after receiving Access-Reject or Access-Accept,
* 3. auth timeout,
* this function is for the 2nd one. */
int
eag_portal_auth_failure(eag_portal_t *portal,
		uint32_t userip,
		uint8_t err_code,
		const char *err_id)
{
	portal_sess_t *portalsess = NULL;
	struct portal_packet_t rsppkt = {0};
	struct app_conn_t *appconn = NULL;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	const char *err_reason = "";

	if (NULL != err_id) {
		err_reason = err_id;
	}

	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	
	if (eag_macauth_get_macauth_switch(portal->macauth))
	{
		/* del mac pre_auth */
		eag_del_mac_preauth(portal->macauth, userip);
	}
	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL == portalsess) {
		eag_log_err("eag_portal_auth_failure "
			"portal_sess_find_by_userip %s failed", user_ipstr);
		return -1;
	}

	appconn = appconn_find_by_userip(portal->appdb, userip);
	if (NULL == appconn) {
		eag_log_warning("eag_portal_auth_failure "
			"not found appconn by userip %s", user_ipstr);
	} else {
		if (!sess_status_is_valid(portalsess, appconn)) {
			eag_log_err("eag_portal_auth_failure "
				"userip %s, sess_status %s not match user_state %d",
				user_ipstr, sess_status2str(portalsess->status),
				appconn->session.state);
		}
	}

	if (SESS_STATUS_ON_CHAPAUTH != portalsess->status
		&& SESS_STATUS_ON_PAPAUTH != portalsess->status) {
		eag_log_err("eag_portal_auth_failure userip %s, "
			"unexpected portalsess status %u", 
			user_ipstr, portalsess->status);
		return -1;
	}

	if (REQ_AUTH != portalsess->rcvpkt.type) {
		eag_log_err("eag_portal_auth_failure userip %s, "
			"unexpected rcvpkt type %u", 
			user_ipstr, portalsess->rcvpkt.type);
		return -1;
	}

	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}

	portal_packet_init_rsp(portal, &rsppkt, &(portalsess->rcvpkt));
	rsppkt.err_code = err_code;

	if (portal->check_errid && PORTAL_AUTH_SUCCESS != rsppkt.err_code) {
		if (PORTAL_PROTOCOL_MOBILE == portal_get_protocol_type())
		{
			char errid_str[256] = "";
			if (NULL != err_id) {
				strncpy(errid_str, err_id, sizeof(errid_str)-1);
			}
			portal_packet_add_attr(&rsppkt, ATTR_ERRID, errid_str, PORTAL_MOBILE_ERRID_LEN);
		}
		else if (PORTAL_PROTOCOL_TELECOM == portal_get_protocol_type()
			&& NULL != err_id)
		{
			char text_info[256] = "";
			int info_len = 0;
			strncpy(text_info, err_id, sizeof(text_info)-1);
			info_len = strlen(text_info);
			info_len = info_len < 1 ? 1:info_len;
			info_len = info_len > 253 ? 253:info_len;
			portal_packet_add_attr(&rsppkt, ATTR_ERRID, text_info, info_len);
		}
	}
	
	eag_log_debug("eag_portal","eag_portal_auth_failure userip %s, "
		"send ack_auth, errcode=%u", user_ipstr, rsppkt.err_code);
	if (NULL == appconn) {
		eag_log_filter(user_ipstr,"PortalAckAuth___UserIP:%s,Username:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, portalsess->username, rsppkt.err_code, err_reason);
		admin_log_notice("PortalAckAuth___UserIP:%s,Username:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, portalsess->username, rsppkt.err_code, err_reason);
		eag_henan_log_warning("PORTAL_USER_LOGON_FAIL:-UserName=%s-IPAddr=%s-Reason=%s: %d; User failed to get online.",
			portalsess->username, user_ipstr, err_reason, rsppkt.err_code);
	} else {
		mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
		ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
		ip2str(portalsess->portal_ip, portal_ipstr, sizeof(portal_ipstr));
		log_app_filter(appconn,"PortalAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, user_macstr, portalsess->username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, rsppkt.err_code, err_reason);
		admin_log_notice("PortalAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%d,ErrReason:%s",
			user_ipstr, user_macstr, portalsess->username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, rsppkt.err_code, err_reason);
		eag_henan_log_warning("PORTAL_USER_LOGON_FAIL:-UserName=%s-IPAddr=%s-IfName=%s-VlanID=%u"
			"-MACAddr=%s-Reason=%s: %d; User failed to get online.", portalsess->username, user_ipstr, 
			appconn->session.intf, appconn->session.vlanid, user_macstr, err_reason, rsppkt.err_code);
	}
	portal_resp_authenticator(&rsppkt, &(portalsess->rcvpkt), portalsess->secret, 
				portalsess->secretlen);
	eag_portal_send_packet(portal, portalsess->portal_ip,
			portalsess->portal_port, &rsppkt);
	switch (rsppkt.err_code) {
	case PORTAL_AUTH_SUCCESS:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_0_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_0_COUNT, 1);
		}
		break;
	case PORTAL_AUTH_REJECT:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_1_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_1_COUNT, 1);
		}
		break;
	case PORTAL_AUTH_CONNECTED:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_2_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_2_COUNT, 1);
		}
		break;
	case PORTAL_AUTH_ONAUTH:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_3_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_3_COUNT, 1);
		}
		break;
	case PORTAL_AUTH_FAILED:
	default:
		if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_4_COUNT, 1);
		} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_4_COUNT, 1);
		}
		break;
	}

	portal_sess_free(portalsess);

	return EAG_RETURN_OK;
}

int
eag_portal_auth_success(eag_portal_t *portal,
		struct app_conn_t *appconn)
{
	portal_sess_t *portalsess = NULL;
	struct portal_packet_t rsppkt = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	struct timeval tv = {0};
	time_t timenow = 0;
	//DBusConnection *dbus_conn = NULL;
	eag_ins_t *eagins = NULL;
	int flux_from = 0;
	int authed_user_num = 0;
	//int trap_onlineusernum_switch = 0;
	//int threshold_onlineusernum = 0;
	const char *err_reason = "";
	
	if (NULL == portal || NULL == appconn) {
		eag_log_err("eag_portal_auth_success input error");
		return -1;
	}
	
	userip = appconn->session.user_ip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
	eagins = portal->eagins;
	
	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL == portalsess) {
		eag_log_err("eag_portal_auth_success "
			"portal_sess_find_by_userip %s failed", user_ipstr);
		return -1;
	}

	if (!sess_status_is_valid(portalsess, appconn)) {
		eag_log_err("eag_portal_auth_success "
			"userip %s, sess_status %s not match user_state %d",
			user_ipstr, sess_status2str(portalsess->status),
			appconn->session.state);
	}

	/* Must not happen */
	if (SESS_STATUS_ON_CHAPAUTH != portalsess->status
		&& SESS_STATUS_ON_PAPAUTH != portalsess->status) {
		eag_log_err("eag_portal_auth_success userip %s, "
			"unexpected portalsess status %u", 
			user_ipstr, portalsess->status);
		return -1;
	}
	
	/* Must not happen */
	if (REQ_AUTH != portalsess->rcvpkt.type) {
		eag_log_err("eag_portal_auth_success userip %s, "
			"unexpected rcvpkt type %u", 
			user_ipstr, portalsess->rcvpkt.type);
		return -1;
	}

	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}

	eag_time_gettimeofday(&tv, NULL);
	timenow = tv.tv_sec;
	//dbus_conn = eag_dbus_get_dbus_conn(portal->eagdbus);

	/* authorize */
	eag_captive_authorize(portal->cap, &(appconn->session));
	appconn_update_name_htable(portal->appdb, appconn);
	
	mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
	ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
	ip2str(portalsess->portal_ip, portal_ipstr, sizeof(portal_ipstr));
	admin_log_notice("PortalUserOnline___UserName:%s,UserIP:%s,UserMAC:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s",
			appconn->session.username, user_ipstr, user_macstr, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
	eag_henan_log_notice("PORTAL_USER_LOGON_SUCCESS:-UserName=%s-IPAddr=%s-IfName=%s-VlanID=%u-MACAddr=%s; User got online successfully.",
			appconn->session.username, user_ipstr, appconn->session.intf, appconn->session.vlanid, user_macstr);
	log_app_filter(appconn,"PortalUserOnline___UserName:%s,UserIP:%s,UserMAC:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s",
		appconn->session.username, user_ipstr, user_macstr, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
	if ( EAG_AUTH_TYPE_MAC == appconn->session.server_auth_type)
	{
		eag_stamsg_send(portal->stamsg, &(appconn->session), EAG_MAC_AUTH);
	}
	else if (EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type)
	{
		eag_stamsg_send(portal->stamsg, &(appconn->session), EAG_AUTH);
	}
	if (eag_macauth_get_macauth_switch(portal->macauth))
	{
		/* del mac pre_auth */
		eag_del_mac_preauth(portal->macauth, userip);
	}

	/*flux */
	flux_from = eag_ins_get_flux_from(eagins);
	if (FLUX_FROM_WIRELESS == flux_from) {
		appconn_init_flux_from_wireless(appconn);
	} else if (FLUX_FROM_FASTFWD == flux_from
		|| FLUX_FROM_FASTFWD_IPTABLES == flux_from)
	{
		eag_log_debug("eag_portal","portal_auth_success fastfwd_send userip:%s online",
			user_ipstr);
		
		appconn->session.last_fastfwd_flow_time = timenow;
	}

	/* online user count++,add by zhangwl 2012-8-1 */
	authed_user_num = appdb_authed_user_num_increase(portal->appdb);
	#if 0
	eag_ins_get_trap_online_user_num_params(eagins, 
				&trap_onlineusernum_switch, &threshold_onlineusernum);
	if (1 == trap_onlineusernum_switch
		&& authed_user_num == threshold_onlineusernum + 1)
	{
		//int eag_trap=EAG_TRAP;
		int hansi_type = portal->hansi_type;
		int hansi_id = portal->hansi_id;
		/*eag_send_trap_signal(EAG_ONLINE_USER_NUM_THRESHOLD_SIGNAL, 
						DBUS_TYPE_INT32, &eag_trap,
						DBUS_TYPE_INT32, &hansi_type,
						DBUS_TYPE_INT32, &hansi_id,
						DBUS_TYPE_INT32, &threshold_onlineusernum,
						DBUS_TYPE_INVALID );
		
		eag_log_info("Eag send OnlineUserNumTrap: hansi_type(%d),ins_id(%d),"\
					"authed_user_num(%d),threshold(%d)", hansi_type, hansi_id, 
					authed_user_num, threshold_onlineusernum);*/
	}
	#endif
	eag_log_debug("eag_portal", "traffic limit userip %s, "
		"bandwidthmaxup=%u Kbps, bandwidthmaxdown=%u Kbps "
		"wlanid=%u, radio_id=%u",
		user_ipstr,
		appconn->session.bandwidthmaxup,
		appconn->session.bandwidthmaxdown,
		appconn->session.wlanid, appconn->session.radioid);
	if (appconn->session.bandwidthmaxup > 0) {
		/*eag_set_sta_up_traffic_limit(dbus_conn,
							portal->hansi_type, portal->hansi_id,
							appconn->session.usermac,
							appconn->session.g_radioid,
							appconn->session.wlanid,
							appconn->session.bandwidthmaxup);*/
	}
	if (appconn->session.bandwidthmaxdown > 0) {
		/*eag_set_sta_down_traffic_limit(dbus_conn,
							portal->hansi_type, portal->hansi_id,
							appconn->session.usermac,
							appconn->session.g_radioid,
							appconn->session.wlanid,
							appconn->session.bandwidthmaxdown);*/
	}

	/* ack_auth */
	portal_packet_init_rsp(portal, &rsppkt, &(portalsess->rcvpkt));
	eag_log_debug("eag_portal","eag_portal_auth_success userip %s, "
		"send ack_auth, errcode=%u", user_ipstr, rsppkt.err_code);
	admin_log_notice("PortalAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%d,ErrReason:%s",
		user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, rsppkt.err_code, err_reason);
	log_app_filter(appconn,"PortalAckAuth___UserIP:%s,UserMAC:%s,Username:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,ErrCode:%d,ErrReason:%s",
		user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, nas_ipstr, portal_ipstr, appconn->session.intf, rsppkt.err_code, err_reason);
	portal_resp_authenticator(&rsppkt, &(portalsess->rcvpkt), portalsess->secret, 
				portalsess->secretlen);
	eag_portal_send_packet(portal, portalsess->portal_ip,
			portalsess->portal_port, &rsppkt);
	if (NULL == appconn || EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
            eag_bss_message_count(portal->eagstat, appconn, BSS_AUTH_ACK_0_COUNT, 1);
	} else {
            eag_bss_message_count(portal->eagstat, appconn, BSS_MACAUTH_ACK_0_COUNT, 1);
	}
	
	portalsess->status = SESS_STATUS_AFF_WAIT;
	portalsess->retry_count = 0;
	portalsess->timeout = portal->retry_interval;
	portal_sess_event(SESS_AFF_WAIT_TIMEOUT, portalsess);

	appconn->portal_srv.ip = portalsess->portal_ip;
	appconn->session.state = APPCONN_STATUS_AUTHED;
	appconn->session.session_start_time = timenow;
	appconn->session.accurate_start_time = time(NULL);
	appconn->session.last_connect_ap_time = timenow;
	appconn->session.last_acct_time = timenow;
	appconn->session.last_flux_time = timenow;

	/* acct */
	if(local_database_switch == 0)
	    radius_acct(portal->radius, appconn, RADIUS_STATUS_TYPE_START);

	/* bind server */
	if (eag_macauth_get_macauth_switch(portal->macauth)
		&& appconn->session.wlanid > 0
		&& appconn->portal_srv.mac_server_ip != 0
		&& 1 == notice_to_bindserver)
	{
		eag_portal_ntf_user_logon(portal, appconn);
	}
	
	/* backup */
	//eag_ins_syn_user(eagins, appconn);

	return EAG_RETURN_OK;
}

int
eag_portal_notify_logout(eag_portal_t * portal,
						struct app_conn_t *appconn,
						int terminate_cause)
{
	portal_sess_t *portalsess = NULL;
	struct portal_packet_t ntfpkt = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	
	if (NULL == portal || NULL == appconn) {
		eag_log_err("eag_portal_notify_logout inpurt error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	
	memset(&ntfpkt, 0, sizeof(ntfpkt));
	userip = appconn->session.user_ip;
	ip2str(appconn->session.user_ip, user_ipstr, sizeof(user_ipstr));
	mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
	mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
	ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
	ip2str(appconn->portal_srv.ip, portal_ipstr, sizeof(portal_ipstr));
	
	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL == portalsess) {
		eag_log_debug("eag_portal", "eag_portal_notify_logout "
			"not found portalsess by userip %s, new portalsess",
			user_ipstr);
		portalsess = portal_sess_new(portal, userip);
		if (NULL == portalsess) {
			eag_log_err("eag_portal_notify_logout userip %s, "
				"portal_sess_new failed", user_ipstr);
			return EAG_ERR_PORTAL_CREATE_SESS_FAILED;
		}
	}

	if (!sess_status_is_valid(portalsess, appconn)) {
		eag_log_err("eag_portal_notify_logout "
			"userip %s, sess_status %s not match user_state %d",
			user_ipstr, sess_status2str(portalsess->status),
			appconn->session.state);
	}

	switch(portalsess->status) {
	case SESS_STATUS_ON_MACBIND:
	case SESS_STATUS_MACBOUND:
	case SESS_STATUS_CHALLENGED:
	case SESS_STATUS_ON_CHAPAUTH:
	case SESS_STATUS_ON_PAPAUTH:
	case SESS_STATUS_LOGOUT_WAIT:
		eag_log_err("eag_portal_notify_logout "
			"userip %s in wrong portalsess status %s", 
			user_ipstr, sess_status2str(portalsess->status));
		break;
	case SESS_STATUS_AFF_WAIT:
		eag_log_warning("eag_portal_notify_logout "
			"userip %s in special portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		break;
	case SESS_STATUS_NONE:
		eag_log_debug("eag_portal", "eag_portal_notify_logout "
			"userip %s in portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		break;
	case SESS_STATUS_NTF_LOGOUT_WAIT:
		eag_log_debug("eag_portal", "eag_portal_notify_logout "
			"userip %s in portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		return EAG_RETURN_OK;
	default:
		eag_log_err("eag_portal_notify_logout_nowait "
			"userip %s in unknown portalsess status %d", 
			user_ipstr, portalsess->status);
		break;
	}
	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}
	portalsess->terminate_cause = terminate_cause;
	portalsess->status = SESS_STATUS_NTF_LOGOUT_WAIT;
	portalsess->portal_ip = appconn->portal_srv.ip;
	portalsess->portal_port = appconn->portal_srv.ntf_port;
	portalsess->retry_count = 0;
	portalsess->timeout = portal->retry_interval;
	portal_sess_event(SESS_NTF_LOGOUT_WAIT_TIMEOUT, portalsess);

	portal_packet_init(&ntfpkt, NTF_LOGOUT, userip);

	eag_log_debug("eag_portal","portal_notify_logout userip %s, "
			"send ntf_logout, errcode=%u", user_ipstr, ntfpkt.err_code);
	admin_log_notice("PortalNtfLogout___UserIP:%s,UserMAC:%s,UserName:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s",
			user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, 
			nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
	log_app_filter(appconn,"PortalNtfLogout___UserIP:%s,UserMAC:%s,UserName:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s",
			user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, 
			nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
	portal_req_authenticator(&ntfpkt, appconn->portal_srv.secret,
		appconn->portal_srv.secretlen);
	eag_portal_send_packet(portal, portalsess->portal_ip,
			portalsess->portal_port, &(ntfpkt));
	
	return EAG_RETURN_OK;
}

int
eag_portal_notify_logout_nowait(eag_portal_t * portal,
		struct app_conn_t *appconn)
{
	portal_sess_t *portalsess = NULL;
	struct portal_packet_t ntfpkt = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	char ap_macstr[32]= "";
	char nas_ipstr[32]= "";
	char portal_ipstr[32]= "";
	
	if (NULL == portal || NULL == appconn) {
		eag_log_err("eag_portal_notify_logout_nowait inpurt error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	
	memset(&ntfpkt, 0, sizeof(ntfpkt));
	userip = appconn->session.user_ip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	mac2str(appconn->session.usermac, user_macstr, sizeof(user_macstr)-1, '-');
	mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr)-1, '-');
	ip2str(appconn->session.nasip, nas_ipstr, sizeof(nas_ipstr));
	ip2str(appconn->portal_srv.ip, portal_ipstr, sizeof(portal_ipstr));

	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL != portalsess) {
		eag_log_debug("eag_portal", "eag_portal_notify_logout_nowait "
			"found portalsess by userip %s, portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));

		if (!sess_status_is_valid(portalsess, appconn)) {
			eag_log_err("eag_portal_notify_logout_nowait "
				"userip %s, sess_status %s not match user_state %d",
				user_ipstr, sess_status2str(portalsess->status),
				appconn->session.state);
		}
		
		switch(portalsess->status) {
		case SESS_STATUS_ON_MACBIND:
		case SESS_STATUS_MACBOUND:
		case SESS_STATUS_CHALLENGED:
		case SESS_STATUS_ON_CHAPAUTH:
		case SESS_STATUS_ON_PAPAUTH:
		case SESS_STATUS_LOGOUT_WAIT:
			eag_log_err("eag_portal_notify_logout_nowait "
				"userip %s in wrong portalsess status %s", 
				user_ipstr, sess_status2str(portalsess->status));
			break;
		case SESS_STATUS_NONE:
		case SESS_STATUS_AFF_WAIT:
		case SESS_STATUS_NTF_LOGOUT_WAIT:
			eag_log_warning("eag_portal_notify_logout_nowait "
				"userip %s in special portalsess status %s",
				user_ipstr, sess_status2str(portalsess->status));
			break;
		default:
			eag_log_err("eag_portal_notify_logout_nowait "
				"userip %s in unknown portalsess status %d",
				user_ipstr, portalsess->status);
			break;
		}
		if (NULL != portalsess->t_timeout) {
			eag_thread_cancel(portalsess->t_timeout);
			portalsess->t_timeout = NULL;
		}
		portal_sess_free(portalsess);
	}
	
	portal_packet_init(&ntfpkt, NTF_LOGOUT, userip);

	admin_log_notice("PortalNtfLogout___UserIP:%s,UserMAC:%s,UserName:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s",
			user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, 
			nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
	log_app_filter(appconn,"PortalNtfLogout___UserIP:%s,UserMAC:%s,UserName:%s,ApMAC:%s,SSID:%s,NasIP:%s,PortalIP:%s,Interface:%s,NasID:%s",
			user_ipstr, user_macstr, appconn->session.username, ap_macstr, appconn->session.essid, 
			nas_ipstr, portal_ipstr, appconn->session.intf, appconn->session.nasid);
	portal_req_authenticator(&ntfpkt, appconn->portal_srv.secret,
		appconn->portal_srv.secretlen);
	eag_portal_send_packet(portal, appconn->portal_srv.ip,
			appconn->portal_srv.ntf_port, &(ntfpkt));
	
	return EAG_RETURN_OK;
}

int
eag_portal_proc_dm_request(eag_portal_t *portal,
		struct app_conn_t *appconn,
		uint32_t radius_ip, 
		uint16_t radius_port,
		uint8_t id)
{
	portal_sess_t *portalsess = NULL;
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	time_t timenow = 0;
	struct timeval tv = {0};

	eag_time_gettimeofday(&tv, NULL);
	timenow = tv.tv_sec;
	
	if (NULL == portal || NULL == appconn) {
		eag_log_err("eag_portal_proc_dm_request inpurt error");
		return -1;
	}

	userip = appconn->session.user_ip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	
	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL == portalsess) {
		eag_log_debug("eag_portal", "eag_portal_proc_dm_request "
			"not found portalsess by userip %s, new portalsess",
			user_ipstr);
		portalsess = portal_sess_new(portal, userip);
	}
	if (NULL == portalsess) {
		eag_log_err("eag_portal_proc_dm_request userip %s, "
			"portal_sess_new failed", user_ipstr);
		return -1;
	}

	if (!sess_status_is_valid(portalsess, appconn)) {
		eag_log_err("eag_portal_proc_dm_request "
			"userip %s, sess_status %s not match user_state %d",
			user_ipstr, sess_status2str(portalsess->status),
			appconn->session.state);
	}

	switch(portalsess->status) {
	case SESS_STATUS_ON_MACBIND:
	case SESS_STATUS_MACBOUND:
	case SESS_STATUS_CHALLENGED:
	case SESS_STATUS_ON_CHAPAUTH:
	case SESS_STATUS_ON_PAPAUTH:
	case SESS_STATUS_LOGOUT_WAIT:
		eag_log_err("eag_portal_proc_dm_request "
			"userip %s in wrong portalsess status %s", 
			user_ipstr, sess_status2str(portalsess->status));
		return -1;
		/* break; */
	case SESS_STATUS_AFF_WAIT:
		eag_log_warning("eag_portal_proc_dm_request "
			"userip %s in special portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		break;
	case SESS_STATUS_NONE:
		eag_log_debug("eag_portal", "eag_portal_proc_dm_request "
			"userip %s in portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		break;
	case SESS_STATUS_NTF_LOGOUT_WAIT:
		eag_log_warning("eag_portal_proc_dm_request "
			"userip %s in portalsess status %s",
			user_ipstr, sess_status2str(portalsess->status));
		return -1;
	default:
		eag_log_err("eag_portal_proc_dm_request "
			"userip %s in unknown portalsess status %d", 
			user_ipstr, portalsess->status);
		return -1;
	}
	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}

	portalsess->is_dm_logout = 1;
	portalsess->radius_ip = radius_ip;
	portalsess->radius_port = radius_port;
	portalsess->dm_id = id;

	appconn->on_ntf_logout = 1;
	appconn->session.session_stop_time = timenow;

	return eag_portal_notify_logout(portal, appconn,
			RADIUS_TERMINATE_CAUSE_ADMIN_RESET);
}

int
eag_portal_macbind_req(eag_portal_t *portal,
		struct app_conn_t *appconn)
{
	portal_sess_t *portalsess = NULL;
	struct portal_packet_t req_packet = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
		
	if (NULL == portal || NULL == appconn) {
		eag_log_err("eag_portal_macbind_req input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	
	memset(&req_packet, 0, sizeof(req_packet));
	userip = appconn->session.user_ip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	
	portalsess = portal_sess_find_by_userip(portal, userip);
	if (NULL == portalsess) {
		eag_log_debug("eag_portal", "eag_portal_macbind_req "
			"not found portalsess by userip %s, new portalsess",
			user_ipstr);
		portalsess = portal_sess_new(portal, userip);
		if (NULL == portalsess) {
			eag_log_err("eag_portal_macbind_req userip %s, "
				"portal_sess_new failed", user_ipstr);
			return EAG_ERR_PORTAL_CREATE_SESS_FAILED;
		}
	}

	if (!sess_status_is_valid(portalsess, appconn)) {
		eag_log_err("eag_portal_macbind_req "
			"userip %s, sess_status %s not match user_state %d",
			user_ipstr, sess_status2str(portalsess->status),
			appconn->session.state);
	}

	switch(portalsess->status) {
	case SESS_STATUS_ON_MACBIND:
	case SESS_STATUS_MACBOUND:
	case SESS_STATUS_CHALLENGED:
	case SESS_STATUS_ON_CHAPAUTH:
	case SESS_STATUS_ON_PAPAUTH:
	case SESS_STATUS_AFF_WAIT:
	case SESS_STATUS_NTF_LOGOUT_WAIT:
		eag_log_err("eag_portal_macbind_req "
			"userip %s in wrong portalsess status %s", 
			user_ipstr, sess_status2str(portalsess->status));
		return -1;
	case SESS_STATUS_NONE:
		eag_log_debug("eag_portal", "eag_portal_macbind_req "
			"userip %s in portalsess status %s", 
			user_ipstr, sess_status2str(portalsess->status));
		break;
	case SESS_STATUS_LOGOUT_WAIT:
		eag_log_warning("eag_portal_macbind_req "
			"userip %s in portalsess status %s", 
			user_ipstr, sess_status2str(portalsess->status));
		break;
	default:
		eag_log_err("eag_portal_macbind_req "
			"userip %s in unknown portalsess status %d", 
			user_ipstr, portalsess->status);
		return -1;
	}
	if (NULL != portalsess->t_timeout) {
		eag_thread_cancel(portalsess->t_timeout);
		portalsess->t_timeout = NULL;
	}
	
	portalsess->status = SESS_STATUS_ON_MACBIND;
	portalsess->retry_count = 0;
	portalsess->timeout = portal->retry_interval;
	portal_sess_event(SESS_ONMACBIND_TIMEOUT, portalsess);

	portal_packet_init(&req_packet, REQ_MACBINDING_INFO, userip);
	req_packet.serial_no = rand_serialNo();

	portal_add_macbind_req_attr(&req_packet, appconn, portal);

	eag_log_debug("eag_portal", "portal_macbind_req userip %s, "
			"send req_macbind_info, errcode=%u", user_ipstr, req_packet.err_code);
	admin_log_notice("PortalReqMacBindInfo___UserIP:%s",
			user_ipstr);
	log_app_filter(appconn,"PortalReqMacBindInfo___UserIP:%s",
			user_ipstr);
	eag_portal_send_packet(portal, 
		appconn->portal_srv.mac_server_ip,
		appconn->portal_srv.mac_server_port, &req_packet);
	
	return EAG_RETURN_OK;
}

int
eag_portal_ntf_user_logon(eag_portal_t *portal,
		struct app_conn_t *appconn)
{
	struct portal_packet_t req_packet = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	uint32_t nasip = 0;
	unsigned long starttime = 0;
	
	if (NULL == portal || NULL == appconn) {
		eag_log_err("eag_portal_ntf_user_logon input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	
	memset(&req_packet, 0, sizeof(req_packet));
	userip = appconn->session.user_ip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));

	portal_packet_init(&req_packet, NTF_USER_LOGON, userip);
	req_packet.serial_no = rand_serialNo();

	portal_packet_add_attr(&req_packet, ATTR_USERNAME, appconn->session.username,
		strlen(appconn->session.username));

	portal_packet_add_attr(&req_packet, ATTR_USERMAC, appconn->session.usermac,
		sizeof(appconn->session.usermac));

	nasip = eag_ins_get_nasip(portal->eagins);
	nasip = htonl(nasip);
	portal_packet_add_attr(&req_packet, ATTR_BASIP, &nasip, sizeof(nasip));
	
	portal_packet_add_attr(&req_packet, ATTR_NASID, appconn->session.nasid,
		strlen(appconn->session.nasid));
		
	starttime = htonl(time(NULL));
	portal_packet_add_attr(&req_packet, ATTR_SESS_START, &starttime, 4);

	if (0 != strcmp(appconn->user_agent, "")) {
		int length = strlen(appconn->user_agent);
		length = (length > 253)?253:length;
		portal_packet_add_attr(&req_packet, ATTR_USER_AGENT, appconn->user_agent, length);
	}

	if (EAG_AUTH_TYPE_MAC == appconn->session.server_auth_type) {
		req_packet.rsv = 0x01;
	} else {
		req_packet.rsv = 0;
	}
	
	eag_log_debug("eag_portal", "portal_ntf_user_logon userip %s, "
			"send ntf_user_logon, errcode=%u", user_ipstr, req_packet.err_code);
	admin_log_notice("PortalNtfUserLogon___UserIP:%s,UserName=%s",
			user_ipstr, appconn->session.username);
	log_app_filter(appconn,"PortalNtfUserLogon___UserIP:%s,UserName=%s",
			user_ipstr, appconn->session.username);

	eag_portal_send_packet(portal, 
		appconn->portal_srv.mac_server_ip,
		appconn->portal_srv.mac_server_port, &req_packet);
	
	return EAG_RETURN_OK;
}

int
eag_portal_ntf_user_logoff(eag_portal_t *portal,
		struct app_conn_t *appconn)
{
	struct portal_packet_t req_packet = {0};
	uint32_t userip = 0;
	char user_ipstr[32] = "";
	uint32_t nasip = 0;
	unsigned long stoptime = 0;
	struct timeval tv = {0};
	unsigned long timediff = 0;
	uint32_t input_octets = 0;
	uint32_t output_octets = 0;
	uint32_t input_packets = 0;
	uint32_t output_packets = 0;
	uint32_t input_gigawords = 0;
	uint32_t output_gigawords = 0;
	
	if (NULL == portal || NULL == appconn) {
		eag_log_err("eag_portal_ntf_user_logoff input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	
	memset(&req_packet, 0, sizeof(req_packet));
	userip = appconn->session.user_ip;
	ip2str(userip, user_ipstr, sizeof(user_ipstr));
	
	portal_packet_init(&req_packet, NTF_USER_LOGOUT, userip);
	req_packet.serial_no = rand_serialNo();

	portal_packet_add_attr(&req_packet, ATTR_USERNAME, appconn->session.username,
		strlen(appconn->session.username));

	portal_packet_add_attr(&req_packet, ATTR_USERMAC, appconn->session.usermac,
		sizeof(appconn->session.usermac));

	nasip = eag_ins_get_nasip(portal->eagins);
	nasip = htonl(nasip);
	portal_packet_add_attr(&req_packet, ATTR_BASIP, &nasip, sizeof(nasip));
	
	portal_packet_add_attr(&req_packet, ATTR_NASID, appconn->session.nasid,
		strlen(appconn->session.nasid));
		
	stoptime = htonl(time(NULL));
	portal_packet_add_attr(&req_packet, ATTR_SESS_STOP, &stoptime, 4);

	eag_time_gettimeofday(&tv, NULL);
	timediff = tv.tv_sec - appconn->session.session_start_time;
	timediff = htonl(timediff);
	portal_packet_add_attr(&req_packet, ATTR_SESS_TIME, &timediff, 4);

	output_octets = (uint32_t)(appconn->session.output_octets);
	output_octets = htonl(output_octets);
	portal_packet_add_attr(&req_packet, ATTR_INPUT_OCTETS, &output_octets, 4);
	
	input_octets = (uint32_t)(appconn->session.input_octets);
	input_octets = htonl(input_octets);
	portal_packet_add_attr(&req_packet, ATTR_OUTPUT_OCTETS, &input_octets, 4);
	
	output_packets = (uint32_t)(appconn->session.output_packets);
	output_packets = htonl(output_packets);
	portal_packet_add_attr(&req_packet, ATTR_INPUT_PACKETS, &output_packets, 4);

	input_packets = (uint32_t)(appconn->session.input_packets);
	input_packets = htonl(input_packets);
	portal_packet_add_attr(&req_packet, ATTR_OUTPUT_PACKETS, &input_packets, 4);

	output_gigawords = (uint32_t)(appconn->session.output_octets >> 32);
	output_gigawords = htonl(output_gigawords);
	portal_packet_add_attr(&req_packet, ATTR_INPUT_GIGAWORDS, &output_gigawords, 4);

	input_gigawords = (uint32_t)(appconn->session.input_octets >> 32);
	input_gigawords = htonl(input_gigawords);
	portal_packet_add_attr(&req_packet, ATTR_OUTPUT_GIGAWORDS, &input_gigawords, 4);

	eag_log_debug("eag_portal", "portal_ntf_user_logoff userip %s, "
			"send ntf_user_logoff, errcode=%u", user_ipstr, req_packet.err_code);
	admin_log_notice("PortalNtfUserLogout___UserIP:%s,UserName=%s",
			user_ipstr, appconn->session.username);
	log_app_filter(appconn,"PortalNtfUserLogout___UserIP:%s,UserName=%s",
			user_ipstr, appconn->session.username);

	eag_portal_send_packet(portal, 
		appconn->portal_srv.mac_server_ip,
		appconn->portal_srv.mac_server_port, &req_packet);
	
	return EAG_RETURN_OK;
}


int
eag_portal_set_portal_port(eag_portal_t *portal,
		uint16_t portal_port)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_portal_port input error");
		return -1;
	}

	if (eag_ins_is_running(portal->eagins)) {
		eag_log_warning("eag_portal_set_portal_port eag already started");
		return EAG_ERR_EAGINS_SERVICE_ALREADY_ENABLE;
	}
		
	portal->portal_port = portal_port;

	eag_log_debug("eag_portal","portal port is set to %u", portal_port);
	
	return 0;
}

uint16_t
eag_portal_get_portal_port(eag_portal_t *portal)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_get_portal_port input error");
		return 0;
	}

	return portal->portal_port;
}

int
eag_portal_set_local_addr(eag_portal_t *portal,
		uint32_t local_ip,
		uint16_t local_port)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_local_addr input error");
		return -1;
	}

	portal->local_ip = local_ip;
	portal->local_port = local_port;
	
	return 0;
}

int
eag_portal_set_slot_id(eag_portal_t *portal,
		uint8_t slot_id)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_slot_id input error");
		return -1;
	}


	return 0;
}

int
eag_portal_set_thread_master(eag_portal_t *portal,
		eag_thread_master_t *master)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_thread_master input error");
		return -1;
	}

	portal->master = master;

	return 0;
}

int
eag_portal_set_retry_params(eag_portal_t *portal,
		int retry_interval,
		int retry_times)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_retry_param input error");
		return -1;
	}

	portal->retry_interval = retry_interval;
	portal->retry_times = retry_times;

	return EAG_RETURN_OK;
}

int
eag_portal_get_retry_params(eag_portal_t *portal,
		int *retry_interval,
		int *retry_times)
{
	if (NULL == portal || NULL == retry_times 
		|| NULL == retry_interval) {
		eag_log_err("eag_portal_get_retry_params input error");
		return -1;
	}

	*retry_interval = portal->retry_interval;
	*retry_times = portal->retry_times;

	return EAG_RETURN_OK;
}

int
eag_portal_set_auto_session(eag_portal_t *portal,
		int auto_session)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_auto_session input error");
		return -1;
	}

	portal->auto_session = auto_session;

	return EAG_RETURN_OK;
}

int
eag_portal_get_auto_session(eag_portal_t *portal)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_get_auto_session input error");
		return 0;
	}

	return portal->auto_session;
}

int
eag_portal_set_check_errid(eag_portal_t *portal,
		int check_errid)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_check_errid input error");
		return -1;
	}

	portal->check_errid = check_errid;

	return EAG_RETURN_OK;
}

int
eag_portal_get_check_errid(eag_portal_t *portal)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_get_check_errid input error");
		return 0;
	}

	return portal->check_errid;
}

int
eag_portal_set_eagins(eag_portal_t *portal,
		eag_ins_t *eagins)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_eagins input error");
		return -1;
	}

	portal->eagins = eagins;

	return EAG_RETURN_OK;
}

int
eag_portal_set_appdb(eag_portal_t *portal,
		appconn_db_t *appdb)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_appdb input error");
		return -1;
	}

	portal->appdb = appdb;

	return EAG_RETURN_OK;
}

int
eag_portal_set_radius(eag_portal_t *portal,
		eag_radius_t *radius)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_radius input error");
		return -1;
	}

	portal->radius = radius;

	return EAG_RETURN_OK;
}

int
eag_portal_set_coa(eag_portal_t *portal,
		eag_coa_t *coa)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_coa input error");
		return -1;
	}

	portal->coa = coa;

	return EAG_RETURN_OK;
}

int
eag_portal_set_captive(eag_portal_t *portal,
		eag_captive_t *cap)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_captive input error");
		return -1;
	}

	portal->cap = cap;

	return EAG_RETURN_OK;
}

int
eag_portal_set_stamsg(eag_portal_t *portal,
		eag_stamsg_t *stamsg)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_stamsg input error");
		return -1;
	}

	portal->stamsg = stamsg;

	return EAG_RETURN_OK;
}

int
eag_portal_set_fastfwd(eag_portal_t *portal,
		eag_fastfwd_t	 *fastfwd)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_fastfwd input error");
		return -1;
	}

	portal->fastfwd = fastfwd;

	return EAG_RETURN_OK;
}

int
eag_portal_set_eagstat(eag_portal_t *portal,
		eag_statistics_t *eagstat)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_eagstat input error");
		return -1;
	}

	portal->eagstat = eagstat;
	
	return EAG_RETURN_OK;
}

int
eag_portal_set_portal_conf(eag_portal_t *portal,
		struct portal_conf *portalconf)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_portal_conf input error");
		return -1;
	}

	portal->portalconf = portalconf;

	return EAG_RETURN_OK;
}

int
eag_portal_set_radius_conf(eag_portal_t *portal,
		struct radius_conf *radiusconf)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_radius_conf input error");
		return -1;
	}

	portal->radiusconf = radiusconf;

	return EAG_RETURN_OK;
}
/*
int
eag_portal_set_eag_dbus(eag_portal_t *portal,
		eag_dbus_t *eagdbus)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_eag_dbus input error");
		return -1;
	}
	
	portal->eagdbus = eagdbus;
	return EAG_RETURN_OK;
}*/

int
eag_portal_log_all_portalsess(eag_portal_t *portal)
{
	portal_sess_t *portalsess = NULL;	
	char ipstr[32] = "";
	int num = 0;

	if (NULL == portal) {
		eag_log_err("eag_portal_log_all_portalsess input error");
		return -1;
	}

	eag_log_info( "-----log all portalsess begin-----");
	list_for_each_entry(portalsess, &(portal->sess_head), node) {
		num++;
		ip2str(portalsess->userip, ipstr, sizeof(ipstr));	
		eag_log_info("%-5d portalsess userip:%s sess_status:%s ",
			num, ipstr, sess_status2str(portalsess->status));
	}
	eag_log_info( "-----log all portalsess end, num: %d-----", num);

	return 0;

}
int
eag_portal_set_macauth(eag_portal_t *portal,
		eag_macauth_t *macauth)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_set_macauth input error");
		return -1;
	}

	portal->macauth = macauth;

	return EAG_RETURN_OK;
}

static void
eag_portal_event(eag_portal_event_t event,
		eag_portal_t *portal)
{
	if (NULL == portal) {
		eag_log_err("eag_portal_event input error");
		return;
	}
	
	switch (event) {
	case EAG_PORTAL_READ:
		portal->t_read =
		    eag_thread_add_read(portal->master, portal_receive,
					portal, portal->sockfd);
		if (NULL == portal->t_read) {
			eag_log_err("eag_portal_event thread_add_read failed");
		}
		break;
	default:
		break;
	}
}

static void
portal_sess_event(eag_portal_event_t event,
		portal_sess_t *portalsess)
{
	if (NULL == portalsess) {
		eag_log_err("portal_sess_event input error");
		return;
	}
	
	switch (event) {
	case SESS_ONMACBIND_TIMEOUT:
		portalsess->t_timeout =
		    eag_thread_add_timer(portalsess->master, 
		    			eag_portal_onmacbind_timeout,
						portalsess, portalsess->timeout);
		break;
	case SESS_MACBOUND_TIMEOUT:
		portalsess->t_timeout =
		    eag_thread_add_timer(portalsess->master, 
		    			eag_portal_macbound_timeout,
						portalsess, portalsess->timeout);
		break;
	case SESS_CHALLENGED_TIMEOUT:
		portalsess->t_timeout =
		    eag_thread_add_timer(portalsess->master, 
		    			eag_portal_challenged_timeout,
						portalsess, portalsess->timeout);
		break;
	case SESS_ONAUTH_TIMEOUT:
		portalsess->t_timeout =
		    eag_thread_add_timer(portalsess->master, 
		    			eag_portal_onauth_timeout,
						portalsess, portalsess->timeout);
		break;
	case SESS_AFF_WAIT_TIMEOUT:
		portalsess->t_timeout =
		    eag_thread_add_timer(portalsess->master,
		    			eag_portal_aff_wait_timeout,
						portalsess, portalsess->timeout);
		break;
	case SESS_LOGOUT_WAIT_TIMEOUT:
		portalsess->t_timeout =
		    eag_thread_add_timer(portalsess->master,
		    			eag_portal_logout_wait_timeout,
						portalsess, portalsess->timeout);
		break;
	case SESS_NTF_LOGOUT_WAIT_TIMEOUT:
		portalsess->t_timeout =
		    eag_thread_add_timer(portalsess->master,
		    			eag_portal_ntf_logout_wait_timeout,
						portalsess, portalsess->timeout);
		break;
	default:
		break;
	}
	if (NULL == portalsess->t_timeout) {
		eag_log_err("portal_sess_event thread_add_timer failed, event=%d",
			event);
	}
}

