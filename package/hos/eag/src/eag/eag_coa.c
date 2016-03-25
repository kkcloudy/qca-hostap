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
* eag_coa.c
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* Disconnect-Request
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
#include "portal_packet.h"
//#include "rdc_handle.h"
#include "eag_coa.h"
#include "eag_portal.h"
#include "eag_radius.h"
#include "appconn.h"
#include "eag_ins.h"
#include "eag_statistics.h"
#include "eag_captive.h"
#include "eag_stamsg.h"
#include "eag_wireless.h"
//#include "eag_trap.h"

#define EAG_COACONN_HASHSIZE			101

#define EAG_COACONN_BLKMEM_NAME 		"eag_coaconn_blkmem"
#define EAG_COACONN_BLKMEM_ITEMNUM		32
#define EAG_COACONN_BLKMEM_MAXNUM		32

extern int eag_macauth_type;

typedef struct eag_coaconn eag_coaconn_t;

struct eag_coa {
	int sockfd;
	uint16_t coa_port;
	uint32_t local_ip;
	uint16_t local_port;
	eag_thread_t *t_read;
	eag_thread_master_t *master;
	hashtable *htable;
	eag_blk_mem_t *conn_blkmem;
	
	struct radius_conf *radiusconf;
	eag_portal_t *portal;
	eag_radius_t *radius;
	appconn_db_t *appdb;
	eag_ins_t *eagins;
	eag_captive_t *cap;
	eag_stamsg_t *stamsg;

};

struct eag_coaconn {
	struct hlist_node hnode;
	eag_coa_t *coa;
	uint32_t ip;
	uint16_t port;
	uint8_t id;
	eag_thread_master_t *master;
	eag_thread_t *t_timeout;
	int timeout;
	char secret[RADIUS_SECRETSIZE];
	size_t secretlen;
	int on_proc;
	struct radius_packet_t rsppkt;
	uint8_t req_auth[RADIUS_AUTHLEN];
};

struct eag_coaconn_key {
	uint32_t ip;
	uint16_t port;
	uint8_t id;
} __attribute__ ((packed));

typedef enum {
	EAG_COA_READ,
} eag_coa_event_t;

typedef enum {
	EAG_COACONN_TIMEOUT,
} eag_coaconn_event_t;

static void
eag_coa_event(eag_coa_event_t event,
		eag_coa_t *coa);

static void
eag_coaconn_event(eag_coaconn_event_t event,
		eag_coaconn_t *coaconn);

static eag_coaconn_t *
eag_coaconn_new(eag_coa_t *coa,
		uint32_t ip,
		uint16_t port,
		uint8_t id)
{
	eag_coaconn_t *coaconn = NULL;
	char ipstr[32] = "";
	
	if (NULL == coa) {
		eag_log_err("eag_coaconn_new input error");
		return NULL;
	}

	coaconn = eag_blkmem_malloc_item(coa->conn_blkmem);
	if (NULL == coaconn) {
		eag_log_err("eag_coaconn_new blkmem_malloc_item failed");
		return NULL;
	}

	memset(coaconn, 0, sizeof(*coaconn));
	coaconn->coa = coa;
	coaconn->ip = ip;
	coaconn->port = port;
	coaconn->id = id;
	coaconn->master = coa->master;

	eag_log_debug("eag_coa", "coaconn(%s,%u,%u) new ok",
		ip2str(ip, ipstr, sizeof(ipstr)), 
		port, id);
	
	return coaconn;
}

static int
eag_coaconn_free(eag_coaconn_t *coaconn)
{
	eag_coa_t *coa = NULL;

	if (NULL == coaconn) {
		eag_log_err("eag_coaconn_free input error");
		return -1;
	}
	coa = coaconn->coa;
	if (NULL == coa) {
		eag_log_err("eag_coaconn_free coa null");
		return -1;
	}
	
	eag_blkmem_free_item(coa->conn_blkmem, coaconn);

	eag_log_debug("eag_coa", "coaconn free ok");
	return 0;
}

static int
eag_coaconn_add(eag_coa_t *coa,
		eag_coaconn_t *coaconn)
{
	struct eag_coaconn_key key = {0};
	char ipstr[32] = "";
	
	if (NULL == coa || NULL == coaconn)
	{
		eag_log_err("eag_coaconn_add input error");
		return -1;
	}

	key.ip = coaconn->ip;
	key.port = coaconn->port;
	key.id = coaconn->id;
	hashtable_check_add_node(coa->htable, &key, sizeof(key), 
						&(coaconn->hnode));

	eag_log_debug("eag_coa", "eag coaconn add (%s,%u,%u) ok",
		ip2str(key.ip, ipstr, sizeof(ipstr)), 
		key.port, key.id);
	
	return 0;
}

static int
eag_coaconn_del(eag_coa_t *coa,
		eag_coaconn_t *coaconn)

{
	char ipstr[32] = "";
	
	if (NULL == coa || NULL == coaconn)
	{
		eag_log_err("eag_coaconn_del input error");
		return -1;
	}

	hlist_del(&(coaconn->hnode));
	
	eag_log_debug("eag_coa", "eag coaconn del (%s,%u,%u) ok",
		ip2str(coaconn->ip, ipstr, sizeof(ipstr)), 
		coaconn->port, coaconn->id);
	
	return 0;
}

static eag_coaconn_t *
eag_coaconn_lookup(eag_coa_t *coa,
		uint32_t ip,
		uint16_t port,
		uint8_t id)
{
	struct eag_coaconn_key key = {ip, port, id};
	eag_coaconn_t *coaconn = NULL;
	struct hlist_head *head = NULL;
	struct hlist_node *node = NULL;
	char ipstr[32] = "";
	
	head = hashtable_get_hash_list(coa->htable, &key, sizeof(key));
	if (NULL == head) {
		eag_log_warning("eag_coaconn_lookup head is null");
		return NULL;
	}

	hlist_for_each_entry(coaconn, node, head, hnode) {
		if (key.ip == coaconn->ip
			&& key.port == coaconn->port
			&& key.id == coaconn->id) {
			eag_log_debug("eag_coa", "eag coaconn lookup, "
				"find coaconn %s,%u,%u ",
				ip2str(ip, ipstr, sizeof(ipstr)),
				port, id);
			return coaconn;
		}
	}

	eag_log_debug("eag_coa", "eag coaconn lookup, not find coaconn %s,%u,%u",
				ip2str(ip, ipstr, sizeof(ipstr)),
				port, id);
	
	return NULL;
}

static int
eag_coaconn_clear(eag_coa_t *coa)
{
	hashtable *htable = NULL;
	struct hlist_node *node = NULL;
	struct hlist_node *next = NULL;
	eag_coaconn_t *coaconn = NULL;
	int i = 0;

	if (NULL == coa) {
		eag_log_err("eag_coaconn_clear input error");
		return -1;
	}

	htable = coa->htable;
	if (NULL == htable) {
		eag_log_err("eag_coaconn_clear htable null");
		return -1;
	}

	for (i = 0; i < htable->hash_num; i++) {
		hlist_for_each_entry_safe(coaconn, node, next,
				&(htable->head_nodes[i]), hnode) {
			if (NULL != coaconn->t_timeout) {
				eag_thread_cancel(coaconn->t_timeout);
				coaconn->t_timeout = NULL;
			}
			hlist_del(&(coaconn->hnode));
			eag_coaconn_free(coaconn);
		}
	}
	
	eag_log_debug("eag_coa", "coaconn clear ok");
	return 0;
}

static int
eag_coaconn_timeout(eag_thread_t *thread)
{
	eag_coaconn_t *coaconn = NULL;
	char ipstr[32] = "";
	
	if (NULL == thread) {
		eag_log_err("eag_coaconn_timeout input error");
		return -1; 
	}
	
	coaconn = eag_thread_get_arg(thread);	
	if (NULL == coaconn) {
		eag_log_err("eag_coaconn_timeout coaconn null");
		return -1;
	}
	eag_log_debug("eag_coa", "coaconn %s,%u,%u timeout",
				ip2str(coaconn->ip, ipstr, sizeof(ipstr)),
				coaconn->port, coaconn->id);
	if (NULL != coaconn->t_timeout) {
		eag_thread_cancel(coaconn->t_timeout);
		coaconn->t_timeout = NULL;
	}

	if (NULL != coaconn->coa) {
		eag_coaconn_del(coaconn->coa, coaconn);
	}
	else {
		eag_log_warning("eag_coaconn_timeout coa null");
	}
	
	eag_coaconn_free(coaconn);
	
	return 0;
}

eag_coa_t *eag_coa_new()
{
	eag_coa_t *coa = NULL;

	coa = eag_malloc(sizeof(*coa));
	if (NULL == coa) {
		eag_log_err("eag_coa_new eag_malloc failed");
		goto failed_0;
	}

	memset(coa, 0, sizeof(*coa));
	if (EAG_RETURN_OK != hashtable_create_table(&(coa->htable),
							EAG_COACONN_HASHSIZE)) {
		eag_log_err("eag_coa_new hashtable_create failed");
		goto failed_1;
	}

	if (EAG_RETURN_OK != eag_blkmem_create(&(coa->conn_blkmem),
							EAG_COACONN_BLKMEM_NAME,
							sizeof(eag_coaconn_t),
							EAG_COACONN_BLKMEM_ITEMNUM, 
							EAG_COACONN_BLKMEM_MAXNUM)) {
		eag_log_err("eag_coa_new blkmem_create failed");
		goto failed_2;
	}

	coa->sockfd = -1;
	coa->coa_port = 3799;
	eag_log_info("coa new ok");
	return coa;

failed_2:
	hashtable_destroy_table(&(coa->htable));
failed_1:
	eag_free(coa);
failed_0:
	return NULL;
}

int
eag_coa_free(eag_coa_t *coa)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_free input error");
		return -1;
	}

	if (NULL != coa->t_read) {
		eag_thread_cancel(coa->t_read);
		coa->t_read = NULL;
	}
	if (coa->sockfd >= 0) {
		close(coa->sockfd);
		coa->sockfd = -1;
	}

	if (NULL != coa->conn_blkmem) {
		eag_blkmem_destroy(&(coa->conn_blkmem));
	}
	if (NULL != coa->htable) {
		hashtable_destroy_table(&(coa->htable));
	}
	
	eag_free(coa);

	eag_log_info("coa free ok");
	return 0;
}

int
eag_coa_start(eag_coa_t *coa)
{
	int ret = 0;
	struct sockaddr_in addr = {0};
	char ipstr[32] = "";
	uint32_t nasip = 0;
	//int is_distributed = 0;
	int rdc_distributed = 0;
	
	if (NULL == coa) {
		eag_log_err("eag_coa_start input error");
		return -1;
	}

	if (coa->sockfd >= 0) {
		eag_log_err("eag_coa_start already start fd(%d)", 
			coa->sockfd);
		return EAG_RETURN_OK;
	}

	nasip = eag_ins_get_nasip(coa->eagins);
	coa->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (coa->sockfd  < 0) {
		eag_log_err("Can't create coa dgram socket: %s",
			safe_strerror(errno));
		coa->sockfd = -1;
		return EAG_ERR_SOCKET_FAILED;
	}

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(nasip);
	addr.sin_port = htons(coa->coa_port);
	
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	#if 0
	ret = setsockopt(coa->sockfd, SOL_SOCKET, SO_REUSEADDR,
					&opt, sizeof(opt));
	if (0 != ret) {
		eag_log_err("Can't set REUSEADDR to coa socket(%d): %s",
			coa->sockfd, safe_strerror(errno));
	}
	#endif

	ret  = bind(coa->sockfd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		eag_log_err("Can't bind to coa socket(%d): %s",
			coa->sockfd, safe_strerror(errno));
		close(coa->sockfd);
		coa->sockfd = -1;
		return EAG_ERR_COA_SOCKET_BIND_FAILED;
	}

	eag_coa_event(EAG_COA_READ, coa);
	
	if (rdc_distributed) {
		eag_log_info("coa(%s:%u) fd(%d) start ok", 
			ip2str(coa->local_ip, ipstr, sizeof(ipstr)),
			coa->local_port,
			coa->sockfd);
	} else {
		eag_log_info("coa(%s:%u) fd(%d) start ok", 
			ip2str(nasip, ipstr, sizeof(ipstr)),
			coa->coa_port,
			coa->sockfd);
	}
	
	return EAG_RETURN_OK;
}

int
eag_coa_stop(eag_coa_t *coa)
{
	char ipstr[32] = "";
	uint32_t nasip = 0;
	//int is_distributed = 0;
	//int rdc_distributed = 0;

	if (NULL == coa) {
		eag_log_err("eag_coa_stop input error");
		return -1;
	}

	nasip = eag_ins_get_nasip(coa->eagins);

	if (NULL != coa->t_read) {
		eag_thread_cancel(coa->t_read);
		coa->t_read = NULL;
	}
	if (coa->sockfd >= 0)
	{
		close(coa->sockfd);
		coa->sockfd = -1;
	}
	eag_coaconn_clear(coa);
	eag_log_info("coa(%s:%u) stop ok",
			ip2str(nasip, ipstr, sizeof(ipstr)),
			coa->coa_port);
	

	return EAG_RETURN_OK;
}

static int
eag_coa_send_packet(eag_coa_t *coa,
		uint32_t radius_ip,
		uint16_t radius_port,
		struct radius_packet_t *packet)
{
	size_t length = 0;
	struct sockaddr_in addr = {0};
	ssize_t nbyte = 0;
	char ipstr[32] = "";
	//int is_distributed = 0;
	//int rdc_distributed = 0;
	
	if (NULL == coa || NULL == packet) {
		eag_log_err("eag_coa_send_packet input error");
		return -1;
	}
	ip2str(radius_ip, ipstr, sizeof(ipstr));
	length = ntohs(packet->length);
	
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(radius_ip);
	addr.sin_port = htons(radius_port);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif

	eag_log_debug("eag_coa",
		"eag_coa send packet %d bytes, fd %d, radius server %s:%u, code %u",
		length, coa->sockfd, ipstr, radius_port, packet->code);
	
	
		nbyte = sendto(coa->sockfd, packet, length, 0,
					(struct sockaddr *)&addr, sizeof(addr));
		if (nbyte < 0) {
			eag_log_err("eag_coa_send_packet failed fd(%d): %s",
				coa->sockfd, safe_strerror(errno));
			return -1;
		}
	

	return EAG_RETURN_OK;
}

static int
get_secret_by_radius_ip(struct radius_conf *radiusconf,
		uint32_t radius_ip, char *secret, size_t *secretlen)
{
	int i = 0;
	struct radius_srv_t *radius_srv = NULL;

	if (NULL == radiusconf || NULL == secret || 0 == secretlen) {
		eag_log_err("get_secret_by_radius_ip input error");
		return -1;
	}
	
	for (i = 0; i < radiusconf->current_num; i++) {
		radius_srv = &(radiusconf->radius_srv[i]);
		if (radius_ip == radius_srv->auth_ip) {
			strncpy(secret, radius_srv->auth_secret,
						sizeof(radius_srv->auth_secret)-1);
			*secretlen = radius_srv->auth_secretlen;
			return 0;
		}
		if (radius_ip == radius_srv->backup_auth_ip) {
			strncpy(secret, radius_srv->backup_auth_secret,
						sizeof(radius_srv->backup_auth_secret)-1);
			*secretlen = radius_srv->backup_auth_secretlen;
			return 0;
		}
		if (radius_ip == radius_srv->acct_ip) {
			strncpy(secret, radius_srv->acct_secret,
						sizeof(radius_srv->acct_secret)-1);
			*secretlen = radius_srv->acct_secretlen;
			return 0;
		}
		if (radius_ip == radius_srv->backup_acct_ip) {
			strncpy(secret, radius_srv->backup_acct_secret,
						sizeof(radius_srv->backup_acct_secret)-1);
			*secretlen = radius_srv->backup_acct_secretlen;
			return 0;
		}
	}

	return -1;
}

static void
config_coa_session(struct app_conn_t *appconn,
		struct radius_packet_t *pack)
{
	struct radius_attr_t *attr = NULL;

	/* Session timeout */
	if (!radius_getattr(pack, &attr, RADIUS_ATTR_SESSION_TIMEOUT, 0, 0, 0)) {
		appconn->session.sessiontimeout = ntohl(attr->v.i);
		eag_log_debug("eag_coa",
			"config_coa_session ip=%#x sessiontimeout=%lu",
			appconn->session.user_ip, appconn->session.sessiontimeout);
	}
	
    if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
            RADIUS_VENDOR_AUTELAN, 
            RADIUS_ATTR_AUTELAN_INPUT_AVERAGE_RATE, 0))
    {
		/*  v.i bytes / 1024 = ? KB for speed limit on AP */
        appconn->session.bandwidthmaxup = ntohl(attr->v.i) / 1024;
        eag_log_debug("eag_coa", "AUTELAN:bandwidthmaxup =%u",
            appconn->session.bandwidthmaxup);
    }

    if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
            RADIUS_VENDOR_AUTELAN, 
            RADIUS_ATTR_AUTELAN_OUTPUT_AVERAGE_RATE, 0))
    {
		/*  v.i bytes / 1024 = ? KB for speed limit on AP */
        appconn->session.bandwidthmaxdown = ntohl(attr->v.i) / 1024;
        eag_log_debug("eag_coa", "AUTELAN:bandwidthmaxdown =%u",
            appconn->session.bandwidthmaxdown);
    }

	if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
			RADIUS_VENDOR_AUTELAN, 
			RADIUS_ATTR_AUTELAN_BANDWIDTH_MAX_UP, 0))
	{
		/*  v.i KB for speed limit on AP */
		appconn->session.bandwidthmaxup = ntohl(attr->v.i);
		eag_log_debug("eag_coa", "AUTELAN:bandwidthmaxup =%u",
			appconn->session.bandwidthmaxup);
	}

	if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
			RADIUS_VENDOR_AUTELAN, 
			RADIUS_ATTR_AUTELAN_BANDWIDTH_MAX_DOWN, 0))
    {
        /*  v.i KB for speed limit on AP */
        appconn->session.bandwidthmaxdown = ntohl(attr->v.i);
        eag_log_debug("eag_coa", "AUTELAN:bandwidthmaxdown =%u",
            appconn->session.bandwidthmaxdown);
    }
    
	if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
			RADIUS_VENDOR_AUTELAN, 
			RADIUS_ATTR_AUTELAN_SESSION_FLOWOUT_KB, 0))
	{
		/*  v.i = ? KB, maxtotaloctets = ? bps  */
		appconn->session.maxtotaloctets = ntohl(attr->v.i) * 1024;
		eag_log_debug("eag_coa", "AUTELAN:maxtotaloctets=%llu",
			appconn->session.maxtotaloctets);
	}

	if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
			RADIUS_VENDOR_AUTELAN, 
			RADIUS_ATTR_AUTELAN_SESSION_FLOWOUT_MB, 0))
	{
		/*  v.i = ? MB, maxtotaloctets = ? bps  */
		appconn->session.maxtotaloctets = ntohl(attr->v.i) * 1024 * 1024;
		eag_log_debug("eag_coa", "AUTELAN:maxtotaloctets=%llu",
			appconn->session.maxtotaloctets);
	}
}

static void
get_coa_param(struct appsession *usrsession,
		struct radius_packet_t *pack)
{
	struct radius_attr_t *attr = NULL;
	char ipstr[32] = "";
	
	memset(usrsession, 0, sizeof(struct appsession));
	/* User-Name */
	if (!radius_getattr(pack, &attr, RADIUS_ATTR_USER_NAME, 0, 0, 0)) {
		memcpy(usrsession->username, attr->v.t, attr->l-2);
		eag_log_debug("eag_coa",
				"get_coa_param User-Name=%s, attr_len=%d",
				usrsession->username, attr->l-2);
	}

	/* Framed-IP-Address */
	if (!radius_getattr(pack, &attr, RADIUS_ATTR_FRAMED_IP_ADDRESS, 0, 0, 0)) {
		usrsession->user_ip = ntohl(attr->v.i);
		ip2str(usrsession->user_ip, ipstr, sizeof(ipstr));
		eag_log_debug("eag_coa",
				"get_coa_param Framed-IP-Address=%#X(%s)",
				usrsession->user_ip, ipstr);
	}

	/* Acct-Session-ID */
	if (!radius_getattr(pack, &attr, RADIUS_ATTR_ACCT_SESSION_ID, 0, 0, 0)) {
		memcpy(usrsession->sessionid, attr->v.t, attr->l-2);
		eag_log_debug("eag_coa",
				"get_coa_param Acct-Session-ID=%s, attr_len=%d",
				usrsession->sessionid, attr->l-2);
	}
}

static struct app_conn_t *
get_appconn_by_coa_param(appconn_db_t *appdb,
		struct appsession *session)
{
	struct app_conn_t *appconn = NULL;
	struct list_head *head = NULL;

	if (NULL == appdb || NULL == session) {
		eag_log_err("get_appconn_by_coa_param input error");
		return NULL;
	}
	head = appconn_db_get_head(appdb);
	
	if (0 == strlen(session->username)
		&& 0 == session->user_ip
		&& 0 == strlen(session->sessionid)) {
		eag_log_warning("get_appconn_by_coa_param, all of params is null");
		return NULL;
	}

	list_for_each_entry(appconn, head, node) {
		/* if (0 != strlen(session->username)
			&& 0 != strcmp(session->username, appconn->session.username)) {
			continue;
		} */
		
		if (0 != session->user_ip
			&& session->user_ip != appconn->session.user_ip) {
			continue;
		}
		
		if (0 != strlen(session->sessionid)
			&& 0 != strcmp(session->sessionid, 
						appconn->session.sessionid)) {
			continue;
		}

		eag_log_debug("eag_coa", "get appconn by coa_param, userip %#x",
			appconn->session.user_ip);
		
		return appconn;
	}

	eag_log_debug("eag_coa", "not get appconn by coa_param");
	
	return NULL;
}

static void
get_dm_param(struct appsession *usrsession,
		struct radius_packet_t *pack)
{
	struct radius_attr_t *attr = NULL;
	char ipstr[32] = "";
	
	memset(usrsession, 0, sizeof(struct appsession));
	/* User-Name */
	if (!radius_getattr(pack, &attr, RADIUS_ATTR_USER_NAME, 0, 0, 0)) {
		memcpy(usrsession->username, attr->v.t, attr->l-2);
		eag_log_debug("eag_coa",
				"get_dm_param User-Name=%s, attr_len=%d",
				usrsession->username, attr->l-2);
	}

	/* Framed-IP-Address */
	if (!radius_getattr(pack, &attr, RADIUS_ATTR_FRAMED_IP_ADDRESS, 0, 0, 0)) {
		usrsession->user_ip = ntohl(attr->v.i);
		ip2str(usrsession->user_ip, ipstr, sizeof(ipstr));
		eag_log_debug("eag_coa",
				"get_dm_param Framed-IP-Address=%#X(%s)",
				usrsession->user_ip, ipstr);
	}

	/* Acct-Session-ID */
	if (!radius_getattr(pack, &attr, RADIUS_ATTR_ACCT_SESSION_ID, 0, 0, 0)) {
		memcpy(usrsession->sessionid, attr->v.t, attr->l-2);
		eag_log_debug("eag_coa",
				"get_dm_param Acct-Session-ID=%s, attr_len=%d",
				usrsession->sessionid, attr->l-2);
	}
}

static struct app_conn_t *
get_appconn_by_dm_param(appconn_db_t *appdb,
		struct appsession *session)
{
	struct app_conn_t *appconn = NULL;
	struct list_head *head = NULL;

	if (NULL == appdb || NULL == session) {
		eag_log_err("get_appconn_by_dm_param input error");
		return NULL;
	}
	head = appconn_db_get_head(appdb);
	
	if (0 == strlen(session->username)
		&& 0 == session->user_ip
		&& 0 == strlen(session->sessionid)) {
		eag_log_warning("get_appconn_by_dm_param, all of params is null");
		return NULL;
	}

	list_for_each_entry(appconn, head, node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
			/* if (0 != strlen(session->username)
				&& 0 != strcmp(session->username, appconn->session.username)) {
				continue;
			} */
			
			if (0 != session->user_ip
				&& session->user_ip != appconn->session.user_ip) {
				continue;
			}
			
			if (0 != strlen(session->sessionid)
				&& 0 != strcmp(session->sessionid, 
							appconn->session.sessionid)) {
				continue;
			}

			eag_log_debug("eag_coa", "get appconn by dm_param, userip %#x",
				appconn->session.user_ip);
			
			return appconn;
		}
	}

	eag_log_debug("eag_coa", "not get appconn by dm_param");
	
	return NULL;
}

/* eag_coa_ack_logout_proc, 
* receive ack_logout, ack_logout timeout, receive req_logout after Disconnect request
*/
int
eag_coa_ack_logout_proc(eag_coa_t *coa,
		uint32_t radius_ip,
		uint16_t radius_port,
		uint8_t reqpkt_id)
{
	struct radius_packet_t rsppkt = {0};
	eag_coaconn_t *coaconn = NULL;
	uint32_t error_cause = RADIUS_ERROR_CAUSE_201;
	struct radius_attr_t *ma = NULL; /* Message authenticator */
	
	if (NULL == coa) {
		eag_log_err("eag_coa_ack_logout_proc input error");
		return -1;
	}

	coaconn = eag_coaconn_lookup(coa, radius_ip, radius_port, reqpkt_id);
	if (NULL == coaconn) {
		eag_log_warning("eag_coa_ack_logout_proc coaconn is null, "
			"maybe coaconn timeout is less than portalsess timeout");
		return -1;
	}

	coaconn->on_proc = 0;
	
	radius_packet_init(&rsppkt, RADIUS_CODE_DISCONNECT_ACK);
	rsppkt.id = coaconn->id;
	radius_addattr(&(rsppkt), RADIUS_ATTR_ERROR_CAUSE, 0, 0,
			error_cause, NULL, 0);
	
	/* Prepare for message authenticator TODO */
	memset(rsppkt.authenticator, 0, RADIUS_AUTHLEN);
	memcpy(rsppkt.authenticator, coaconn->req_auth, RADIUS_AUTHLEN);

	/* If packet contains message authenticator: Calculate it! */
	if (!radius_getattr(&(rsppkt), &ma,
				RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 0, 0, 0)) {
		radius_hmac_md5(&(rsppkt), coaconn->secret, 
				coaconn->secretlen, ma->v.t);
	}

	radius_authresp_authenticator(&(rsppkt), coaconn->req_auth,
		coaconn->secret, coaconn->secretlen);
	memcpy(&(coaconn->rsppkt), &(rsppkt), sizeof(coaconn->rsppkt));
	eag_coa_send_packet(coa, coaconn->ip, coaconn->port, &(rsppkt));

	return EAG_RETURN_OK;
}

static int
eag_coa_proc_accuris_disconnect_request(eag_coa_t *coa,
		eag_coaconn_t *coaconn,
		struct radius_packet_t *reqpkt)
{
	struct appsession session = {0};
	uint32_t error_cause = RADIUS_ERROR_CAUSE_503;
	struct radius_packet_t rsppkt = {0};
	struct radius_attr_t *ma = NULL; /* Message authenticator */
	struct app_conn_t *appconn = NULL;
	//int ret = 0;
	char user_ipstr[32] = "";
	struct timeval tv = {0};
	
	if (NULL == coa || NULL == coaconn || NULL == reqpkt) {
		eag_log_err("eag_coa_proc_disconnect_request input error");
		return -1;
	}

	get_dm_param(&session, reqpkt);
	if (0 == strlen(session.username)
		&& 0 == session.user_ip
		&& 0 == strlen(session.sessionid)) {
		error_cause = RADIUS_ERROR_CAUSE_402;
		admin_log_notice("RadiusDisconnectRequest___MissingAttribute");
		goto error;
	}
	
	ip2str(session.user_ip, user_ipstr, sizeof(user_ipstr));
	admin_log_notice("RadiusDisconnectRequest___UserName:%s,UserIP:%s,SessionID:%s",
		session.username, user_ipstr, session.sessionid);
	
	appconn = get_appconn_by_dm_param(coa->appdb, &session);
	if (NULL == appconn) {
		error_cause = RADIUS_ERROR_CAUSE_503;
		goto error;
	}

	if (APPCONN_STATUS_AUTHED == appconn->session.state
		&& appconn->session.auth_tag >= MIN_TAG_NUMBER
		&& appconn->session.auth_tag <= MAX_TAG_NUMBER) {
		eag_time_gettimeofday(&tv, NULL);
		appconn->session.session_stop_time = tv.tv_sec;
		terminate_appconn(appconn, coa->eagins, RADIUS_TERMINATE_CAUSE_ADMIN_RESET);

		eag_log_debug("eag_coa","eag_coa_proc_accuris_disconnect_request userip %s, "
			"is dm logout, coa response to radius", user_ipstr);
		eag_coa_ack_logout_proc(coa, coaconn->ip, coaconn->port, coaconn->id);
	} else {
		eag_log_err("eag_coa_proc_accuris_disconnect_request userip %s, "
			"receive ack_logout on appconn, but user not authed", user_ipstr);
	}

	return EAG_RETURN_OK;
error:
	radius_packet_init(&rsppkt, RADIUS_CODE_DISCONNECT_NAK);
	rsppkt.id = reqpkt->id;
	radius_addattr(&(rsppkt), RADIUS_ATTR_ERROR_CAUSE, 0, 0,
		       	error_cause, NULL, 0);
	
	/* Prepare for message authenticator TODO */
	memset(rsppkt.authenticator, 0, RADIUS_AUTHLEN);
	memcpy(rsppkt.authenticator, reqpkt->authenticator, RADIUS_AUTHLEN);

	/* If packet contains message authenticator: Calculate it! */
	if (!radius_getattr(&(rsppkt), &ma,
				RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 0, 0, 0)) {
		radius_hmac_md5(&(rsppkt), coaconn->secret, 
				coaconn->secretlen, ma->v.t);
	}

	radius_authresp_authenticator(&(rsppkt), reqpkt->authenticator,
		coaconn->secret, coaconn->secretlen);
	memcpy(&(coaconn->rsppkt), &(rsppkt), sizeof(coaconn->rsppkt));
	eag_coa_send_packet(coa, coaconn->ip, coaconn->port, &(rsppkt));

	if (RADIUS_ERROR_CAUSE_402 != error_cause) {
		admin_log_notice("RadiusDisconnectNAK___UserName:%s,UserIP:%s,SessionID:%s,ErrorCause:%d",
			session.username, user_ipstr, session.sessionid, error_cause);
	} else {
		admin_log_notice("RadiusDisconnectNAK,RADIUS_ERROR_CAUSE_402");
	}
	
	return EAG_RETURN_OK;
}

static int
eag_coa_proc_disconnect_request(eag_coa_t *coa,
		eag_coaconn_t *coaconn,
		struct radius_packet_t *reqpkt)
{
	struct appsession session = {0};
	uint32_t error_cause = RADIUS_ERROR_CAUSE_503;
	struct radius_packet_t rsppkt = {0};
	struct radius_attr_t *ma = NULL; /* Message authenticator */
	struct app_conn_t *appconn = NULL;
	int ret = 0;
	char user_ipstr[32] = "";
	
	if (NULL == coa || NULL == coaconn || NULL == reqpkt) {
		eag_log_err("eag_coa_proc_disconnect_request input error");
		return -1;
	}

	get_dm_param(&session, reqpkt);
	if (0 == strlen(session.username)
		&& 0 == session.user_ip
		&& 0 == strlen(session.sessionid)) {
		error_cause = RADIUS_ERROR_CAUSE_402;
		admin_log_notice("RadiusDisconnectRequest___MissingAttribute");
		goto error;
	}
	
	ip2str(session.user_ip, user_ipstr, sizeof(user_ipstr));
	admin_log_notice("RadiusDisconnectRequest___UserName:%s,UserIP:%s,SessionID:%s",
		session.username, user_ipstr, session.sessionid);
	
	appconn = get_appconn_by_dm_param(coa->appdb, &session);
	if (NULL == appconn || appconn->on_ntf_logout) {
		error_cause = RADIUS_ERROR_CAUSE_503;
		goto error;
	}

	ret = eag_portal_proc_dm_request(coa->portal, appconn,
				coaconn->ip, coaconn->port, coaconn->id);
	if (EAG_RETURN_OK != ret) {
		error_cause = RADIUS_ERROR_CAUSE_503;
		goto error;
	}

	coaconn->on_proc = 1;

	return EAG_RETURN_OK;
	
error:
	radius_packet_init(&rsppkt, RADIUS_CODE_DISCONNECT_NAK);
	rsppkt.id = reqpkt->id;
	radius_addattr(&(rsppkt), RADIUS_ATTR_ERROR_CAUSE, 0, 0,
		       	error_cause, NULL, 0);
	
	/* Prepare for message authenticator TODO */
	memset(rsppkt.authenticator, 0, RADIUS_AUTHLEN);
	memcpy(rsppkt.authenticator, reqpkt->authenticator, RADIUS_AUTHLEN);

	/* If packet contains message authenticator: Calculate it! */
	if (!radius_getattr(&(rsppkt), &ma,
				RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 0, 0, 0)) {
		radius_hmac_md5(&(rsppkt), coaconn->secret, 
				coaconn->secretlen, ma->v.t);
	}

	radius_authresp_authenticator(&(rsppkt), reqpkt->authenticator,
		coaconn->secret, coaconn->secretlen);
	memcpy(&(coaconn->rsppkt), &(rsppkt), sizeof(coaconn->rsppkt));
	eag_coa_send_packet(coa, coaconn->ip, coaconn->port, &(rsppkt));

	if (RADIUS_ERROR_CAUSE_402 != error_cause) {
		admin_log_notice("RadiusDisconnectNAK___UserName:%s,UserIP:%s,SessionID:%s,ErrorCause:%d",
			session.username, user_ipstr, session.sessionid, error_cause);
	} else {
		admin_log_notice("RadiusDisconnectNAK,RADIUS_ERROR_CAUSE_402");
	}
	
	return EAG_RETURN_OK;
}

static int
eag_coa_proc_coa_request(eag_coa_t *coa,
							eag_coaconn_t *coaconn,
							struct radius_packet_t *reqpkt)
{
    struct appsession session = {0};
    uint32_t error_cause = RADIUS_ERROR_CAUSE_503;
    struct radius_packet_t rsppkt = {0};
    struct radius_attr_t *ma = NULL; /* Message authenticator */
    struct app_conn_t *appconn = NULL;
	struct radius_attr_t *attr = NULL;
    int ret = 0;
    char user_ipstr[32] = "";
	char user_role[32] = "";
	int auth_tag = 0;
	//DBusConnection *dbus_conn = NULL;
	//char buff[256] = "";
	//int len = 0;
	
    if (NULL == coa || NULL == coaconn || NULL == reqpkt) {
        eag_log_err("eag_coa_proc_disconnect_request input error");
        return -1;
    }
    
	//dbus_conn = eag_dbus_get_dbus_conn(coa->eagdbus);
	
    get_coa_param(&session, reqpkt);
    if (0 == strlen(session.username)
        && 0 == session.user_ip
        && 0 == strlen(session.sessionid)) {
        error_cause = RADIUS_ERROR_CAUSE_402;
        admin_log_notice("RadiusCoaRequest___MissingAttribute");
        goto error;
    }
	
    ip2str(session.user_ip, user_ipstr, sizeof(user_ipstr));
    admin_log_notice("RadiusCoaRequest___UserName:%s,UserIP:%s,SessionID:%s",
        session.username, user_ipstr, session.sessionid);
    
    appconn = get_appconn_by_coa_param(coa->appdb, &session);
    if (NULL == appconn) {
        error_cause = RADIUS_ERROR_CAUSE_503;
        goto error;
    }

    config_coa_session(appconn, reqpkt);

	if (appconn->session.auth_tag >= MIN_TAG_NUMBER
		&& appconn->session.auth_tag <= MAX_TAG_NUMBER) {
	    eag_log_debug("eag_coa", "traffic limit userip %s, "
                "bandwidthmaxup=%u Kbps, bandwidthmaxdown=%u Kbps "
                "wlanid=%u, radio_id=%u",
                user_ipstr,
                appconn->session.bandwidthmaxup,
                appconn->session.bandwidthmaxdown,
                appconn->session.wlanid, appconn->session.radioid);
        if (appconn->session.bandwidthmaxup > 0) {
	#if 0
            eag_set_sta_up_traffic_limit(dbus_conn,
                                coa->hansi_type, coa->hansi_id,
                                appconn->session.usermac,
                                appconn->session.g_radioid,
                                appconn->session.wlanid,
                                appconn->session.bandwidthmaxup);
	#endif
        }
        if (appconn->session.bandwidthmaxdown > 0) {
	#if 0
            eag_set_sta_down_traffic_limit(dbus_conn,
                                coa->hansi_type, coa->hansi_id,
                                appconn->session.usermac,
                                appconn->session.g_radioid,
                                appconn->session.wlanid,
                                appconn->session.bandwidthmaxdown);
	#endif
        }
	}
	
    /* User Role */
	if (!radius_getattr(reqpkt, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
			RADIUS_VENDOR_AUTELAN,
			RADIUS_ATTR_AUTELAN_USER_ROLE, 0)) {
		appconn->session.tag_is_set = 1;
		memset(user_role, 0, sizeof(user_role));
		memcpy(user_role, attr->v.t, attr->l - 2);
		if (!strncmp(user_role, NON_CAPTIVE_STR, strlen(user_role))) {
			auth_tag = NON_CAPTIVE_TAG;
		} else if (!strncmp(user_role, NON_CAPTIVE_FILTER_STR, strlen(NON_CAPTIVE_FILTER_STR))) {
			auth_tag = atol((char *)&user_role[strlen(NON_CAPTIVE_FILTER_STR)]);
			if (auth_tag < MIN_TAG_NUMBER || auth_tag > MAX_TAG_NUMBER) {
				error_cause = RADIUS_ERROR_CAUSE_402;
                eag_log_err("eag_coa_proc_coa_request user-role:%s out of max tag", user_role);
        		goto error;
			}
		} else if (!strncmp(user_role, CAPTIVE_STR, strlen(user_role))) {
            /* TODO */
		} else {
            error_cause = RADIUS_ERROR_CAUSE_402;
			eag_log_err("eag_coa_proc_coa_request user-role:%s error", user_role);
            goto error;
		}

        eag_log_info("user_ip=%s, init_tag=%u, before_tag=%u, auth_tag=%u, tag_is_set=%d",
                user_ipstr, appconn->session.init_tag, appconn->session.auth_tag, auth_tag, appconn->session.tag_is_set);
		
        if (0 == appconn->session.auth_tag && 0 != auth_tag) {
        	appconn->session.auth_tag = auth_tag;
			eag_radius_auth_success(coa->radius, appconn);
		} else if (0 != appconn->session.auth_tag && auth_tag != appconn->session.auth_tag) {
        	appconn->session.auth_tag = auth_tag;
			eag_radius_auth_change_tag(coa->radius, appconn);				
        } else {
            /* TODO */
		}
	} else {
		/* TODO */
	}

	radius_packet_init(&rsppkt, RADIUS_CODE_COA_ACK);
    rsppkt.id = reqpkt->id;

    /* Prepare for message authenticator TODO */
    memset(rsppkt.authenticator, 0, RADIUS_AUTHLEN);
    memcpy(rsppkt.authenticator, reqpkt->authenticator, RADIUS_AUTHLEN);
    
    /* If packet contains message authenticator: Calculate it! */
    if (!radius_getattr(&(rsppkt), &ma,
                RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 0, 0, 0)) {
        radius_hmac_md5(&(rsppkt), coaconn->secret, 
                coaconn->secretlen, ma->v.t);
    }
    
    radius_authresp_authenticator(&(rsppkt), reqpkt->authenticator,
        coaconn->secret, coaconn->secretlen);
    memcpy(&(coaconn->rsppkt), &(rsppkt), sizeof(coaconn->rsppkt));
    eag_coa_send_packet(coa, coaconn->ip, coaconn->port, &(rsppkt));
    
    eag_log_debug("eag_coa", "RadiusCoaAck___UserName:%s,UserIP:%s,SessionID:%s",
        appconn->session.username, user_ipstr, appconn->session.sessionid);
    admin_log_notice("RadiusCoaAck___UserName:%s,UserIP:%s,SessionID:%s",
        appconn->session.username, user_ipstr, appconn->session.sessionid);

    return EAG_RETURN_OK;
error:
    radius_packet_init(&rsppkt, RADIUS_CODE_COA_NAK);
    rsppkt.id = reqpkt->id;
    radius_addattr(&(rsppkt), RADIUS_ATTR_ERROR_CAUSE, 0, 0,
                error_cause, NULL, 0);
    /* Prepare for message authenticator TODO */
    memset(rsppkt.authenticator, 0, RADIUS_AUTHLEN);
    memcpy(rsppkt.authenticator, reqpkt->authenticator, RADIUS_AUTHLEN);

    /* If packet contains message authenticator: Calculate it! */
    if (!radius_getattr(&(rsppkt), &ma,
                RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 0, 0, 0)) {
        radius_hmac_md5(&(rsppkt), coaconn->secret, 
                coaconn->secretlen, ma->v.t);
    }

    radius_authresp_authenticator(&(rsppkt), reqpkt->authenticator,
        coaconn->secret, coaconn->secretlen);
    memcpy(&(coaconn->rsppkt), &(rsppkt), sizeof(coaconn->rsppkt));
    eag_coa_send_packet(coa, coaconn->ip, coaconn->port, &(rsppkt));

    if (RADIUS_ERROR_CAUSE_402 != error_cause) {
        admin_log_notice("RadiusCoaNAK___UserName:%s,UserIP:%s,SessionID:%s,ErrorCause:%d",
            session.username, user_ipstr, session.sessionid, error_cause);
    } else {
        admin_log_notice("RadiusCoatNAK,RADIUS_ERROR_CAUSE_402");
    }
    
    return EAG_RETURN_OK;
}

static int
eag_coa_proc_request(eag_coa_t *coa,
					uint32_t radius_ip,
					uint16_t radius_port,
					struct radius_packet_t *packet)
{
	eag_coaconn_t *coaconn = NULL;
	char secret[RADIUS_SECRETSIZE] = "";
	size_t secretlen = 0;
	int ret = 0;
	char radius_ipstr[32] = "";
	int retry_interval = 0;
	int retry_times = 0;
	int vice_retry_times = 0;
	
	if (NULL == coa || NULL == packet) {
		eag_log_err("eag_coa_proc_request input error");
		return -1;
	}
	eag_radius_get_retry_params(coa->radius, 
			&retry_interval, &retry_times, &vice_retry_times);
	ip2str(radius_ip, radius_ipstr, sizeof(radius_ipstr));
	
	ret = get_secret_by_radius_ip(coa->radiusconf, radius_ip, secret, &secretlen);
	if (EAG_RETURN_OK != ret) {
		eag_log_warning("eag_coa_proc_request not find secret by radius ip %s",
			radius_ipstr);
		return -1;
	}
	
	eag_log_debug("eag_coa", "eag_coa_proc_request get secret by radius ip %s "
		"secret(%s) secretlen(%d)", radius_ipstr, secret, secretlen);

	if (0 != radius_request_check(packet, secret, secretlen)) {
		eag_log_warning("eag_coa_proc_request coa authenticator not match secret(%s)",
			secret);
		return -1;
	}

	coaconn = eag_coaconn_lookup(coa, radius_ip, radius_port, packet->id);
	if (NULL == coaconn) {
		eag_log_debug("eag_coa", "coa proc request not find coaconn(%s,%u,%u)",
			radius_ipstr, radius_port, packet->id);
		coaconn = eag_coaconn_new(coa, radius_ip, radius_port, packet->id);
		if (NULL == coaconn) {
			eag_log_err("server_process_request pktconn_new failed");
			return -1;
		}
		eag_coaconn_add(coa, coaconn);
		memcpy(coaconn->secret, secret, sizeof(coaconn->secret));
		memcpy(coaconn->req_auth, packet->authenticator, RADIUS_AUTHLEN);
		coaconn->secretlen = secretlen;
		coaconn->timeout = retry_interval * (retry_times+vice_retry_times+1);
		eag_coaconn_event(EAG_COACONN_TIMEOUT, coaconn);
		if (RADIUS_CODE_DISCONNECT_REQUEST == packet->code) {
			if (ACCURIS_MACAUTH == eag_macauth_type) {
				eag_coa_proc_accuris_disconnect_request(coa, coaconn, packet);
			} else {
				eag_coa_proc_disconnect_request(coa, coaconn, packet);
			}
		} else {
			eag_coa_proc_coa_request(coa, coaconn, packet);
		}
	} else if (coaconn->on_proc) {
		eag_log_warning("eag_coa_proc_request coaconn(%s,%u,%u) on process",
			radius_ipstr, radius_port,  packet->id);
	} else {
		eag_coa_send_packet(coa, radius_ip, radius_port, &(coaconn->rsppkt));
	}

	return 0;
}

static int
coa_receive(eag_thread_t *thread)
{
	eag_coa_t *coa = NULL;
	socklen_t len = 0;
	struct sockaddr_in addr = {0};
	ssize_t nbyte = 0;
	struct radius_packet_t packet = {0};
	uint32_t radius_ip = 0;
	uint16_t radius_port = 0;
	char radius_ipstr[32] = "";
	//int is_distributed = 0;
	int rdc_distributed = 0;
	
	if (NULL == thread) {
		eag_log_err("coa_receive input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	
	coa = eag_thread_get_arg(thread);
	if (NULL == coa) {
		eag_log_err("coa_receive server null");
		return EAG_ERR_NULL_POINTER;
	}

	len = sizeof(addr);
	
		nbyte = recvfrom(coa->sockfd, &packet, sizeof(packet), 0,
							(struct sockaddr *)&addr, &len);
		if (nbyte < 0) {
			eag_log_err("coa_receive recvfrom failed: fd(%d) %s",
				coa->sockfd, safe_strerror (errno));
			return EAG_ERR_SOCKET_RECV_FAILED;
		}
	

	radius_ip = ntohl(addr.sin_addr.s_addr);
	radius_port = ntohs(addr.sin_port);
	ip2str(radius_ip, radius_ipstr, sizeof(radius_ipstr));
	eag_log_debug("eag_coa", "coa fd(%d) receive %d bytes from %s:%u",
		coa->sockfd, nbyte, radius_ipstr, radius_port);
	
	if (nbyte < RADIUS_PACKET_HEADSIZE) {
		eag_log_warning("coa_receive packet size %d < min %d",
			nbyte, RADIUS_PACKET_HEADSIZE);
		return -1;
	}
			
	if (nbyte > sizeof(packet)) {
		eag_log_warning("coa_receive packet size %d > max %d",
			nbyte, sizeof(packet));
		return -1;
	}
			
	if (nbyte != ntohs(packet.length)) {
		eag_log_warning("coa_receive packet size %d != len %d",
			nbyte, ntohs(packet.length));
		return -1;
	}

	if (RADIUS_CODE_DISCONNECT_REQUEST != packet.code
		&& RADIUS_CODE_COA_REQUEST != packet.code) {
		eag_log_warning("coa_receive unexpected packet code %d",
			packet.code);
		return -1;
	}

	eag_coa_proc_request(coa, radius_ip, radius_port, &packet);
	
	return EAG_RETURN_OK;
}

int
eag_coa_set_local_addr(eag_coa_t *coa,
		uint32_t local_ip,
		uint16_t local_port)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_set_local_addr input error");
		return -1;
	}

	coa->local_ip = local_ip;
	coa->local_port = local_port;
	
	return 0;
}

int
eag_coa_set_thread_master(eag_coa_t *coa,
		eag_thread_master_t *master)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_set_thread_master input error");
		return -1;
	}

	coa->master = master;

	return 0;
}

int
eag_coa_set_portal(eag_coa_t *coa,
		eag_portal_t *portal)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_set_portal input error");
		return -1;
	}

	coa->portal = portal;

	return EAG_RETURN_OK;
}

int
eag_coa_set_radius(eag_coa_t *coa,
		eag_radius_t *radius)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_set_radius input error");
		return -1;
	}

	coa->radius = radius;

	return EAG_RETURN_OK;
}


int
eag_coa_set_appdb(eag_coa_t *coa,
		appconn_db_t *appdb)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_set_appdb input error");
		return -1;
	}

	coa->appdb = appdb;

	return EAG_RETURN_OK;
}

int
eag_coa_set_eagins(eag_coa_t *coa,
		eag_ins_t *eagins)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_set_eagins input error");
		return -1;
	}

	coa->eagins = eagins;

	return 0;
}

int
eag_coa_set_radius_conf(eag_coa_t *coa,
		struct radius_conf *radiusconf)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_set_radius_conf input error");
		return -1;
	}

	coa->radiusconf = radiusconf;

	return EAG_RETURN_OK;
}

int
eag_coa_set_captive(eag_coa_t *coa,
		eag_captive_t *cap)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_set_captive input error");
		return -1;
	}

	coa->cap = cap;

	return EAG_RETURN_OK;
}

/*int
eag_coa_set_eag_dbus(eag_coa_t *coa,
		eag_dbus_t *eagdbus)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_set_eag_dbus input error");
		return -1;
	}
	
	coa->eagdbus = eagdbus;
	return EAG_RETURN_OK;
}*/

int
eag_coa_set_stamsg(eag_coa_t *coa,
		eag_stamsg_t *stamsg)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_set_stamsg input error");
		return -1;
	}

	coa->stamsg = stamsg;

	return EAG_RETURN_OK;
}

int
eag_coa_set_fastfwd(eag_coa_t *coa,
		eag_fastfwd_t *fastfwd)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_set_fastfwd input error");
		return -1;
	}

	//coa->fastfwd = fastfwd;

	return EAG_RETURN_OK;
}

static void
eag_coa_event(eag_coa_event_t event,
					eag_coa_t *coa)
{
	if (NULL == coa) {
		eag_log_err("eag_coa_event input error");
		return;
	}
	
	switch (event) {
	case EAG_COA_READ:
		coa->t_read =
		    eag_thread_add_read(coa->master, coa_receive,
					coa, coa->sockfd);
		if (NULL == coa->t_read) {
			eag_log_err("eag_coa_event thread_add_read failed");
		}
		break;
	default:
		break;
	}
}

static void
eag_coaconn_event(eag_coaconn_event_t event,
						eag_coaconn_t *coaconn)
{
	if (NULL == coaconn) {
		eag_log_err("eag_coaconn_event input error");
		return;
	}
	
	switch (event) {
	case EAG_COACONN_TIMEOUT:
		coaconn->t_timeout =
		    eag_thread_add_timer(coaconn->master, eag_coaconn_timeout,
					coaconn, coaconn->timeout);
		break;
	default:
		break;
	}
}

