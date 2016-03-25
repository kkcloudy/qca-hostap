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
* eag_statistics.h
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* eag statistics
*
*
*******************************************************************************/

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
	
#include "nm_list.h"
#include "hashtable.h"
#include "eag_mem.h"
#include "eag_log.h"
#include "eag_blkmem.h"
#include "eag_time.h"
#include "eag_util.h"

#include "appconn.h"
#include "eag_statistics.h"
#include "eag_interface.h"

#define AP_STAT_BLKMEM_NAME		"ap_stat_blkmem"
#define AP_STAT_BLKMEM_ITEMNUM		1024
#define AP_STAT_BLKMEM_MAXNUM		4
#define BSS_STAT_BLKMEM_NAME		"bss_stat_blkmem"
#define BSS_STAT_BLKMEM_ITEMNUM		1024
#define BSS_STAT_BLKMEM_MAXNUM		16

struct eag_statistics {
	struct list_head ap_head;			//apÁ´±í
	hashtable *ap_htable;				//¹þÏ£±í
	eag_blk_mem_t *ap_blkmem;
	eag_blk_mem_t *bss_blkmem;
	appconn_db_t *appdb;

	int ap_num;
};

eag_statistics_t *
eag_statistics_create(uint32_t size)
{
	eag_statistics_t *eagstat = NULL;
	
	if (0 == size) {
		eag_log_err("eag_statistics_create input error");
		return NULL;
	}

	eagstat = eag_malloc(sizeof(eag_statistics_t));
	if (NULL == eagstat) {
		eag_log_err("eag_statistics_create malloc failed");
		goto failed_0;
	}
	
	memset(eagstat, 0, sizeof(eag_statistics_t));
	if (EAG_RETURN_OK != hashtable_create_table(&(eagstat->ap_htable), size)) {
		eag_log_err("eag_statistics_create hashtable create failed");
		goto failed_1;
	}

	if (EAG_RETURN_OK != eag_blkmem_create(&(eagstat->ap_blkmem),
							AP_STAT_BLKMEM_NAME,
							sizeof(struct eag_ap_statistics),
							AP_STAT_BLKMEM_ITEMNUM,
							AP_STAT_BLKMEM_MAXNUM)) {
		eag_log_err("eag_statistics_create blkmem_create failed");
		goto failed_2;
	}

	if (EAG_RETURN_OK != eag_blkmem_create(&(eagstat->bss_blkmem),
							BSS_STAT_BLKMEM_NAME,
							sizeof(struct eag_bss_statistics),
							BSS_STAT_BLKMEM_ITEMNUM,
							BSS_STAT_BLKMEM_MAXNUM)) {
		eag_log_err("eag_statistics_create blkmem_create failed");
		goto failed_3;
	}
	INIT_LIST_HEAD(&(eagstat->ap_head));

	eagstat->ap_num = 0;

	eag_log_info("eag_statistics create ok");
	return eagstat;

failed_3:
	eag_blkmem_destroy(&(eagstat->ap_blkmem));
failed_2:
	hashtable_destroy_table(&(eagstat->ap_htable));
failed_1:
	eag_free(eagstat);
failed_0:
	return NULL;
}

int
eag_statistics_destroy(eag_statistics_t *eagstat)
{
	if (NULL == eagstat) {
		eag_log_err("eag_statistics_destroy input error");
		return -1;
	}
	
	if (NULL != eagstat->bss_blkmem) {
		eag_blkmem_destroy(&(eagstat->bss_blkmem));
	}
	if (NULL != eagstat->ap_blkmem) {
		eag_blkmem_destroy(&(eagstat->ap_blkmem));
	}
	if (NULL != eagstat->ap_htable) {
		hashtable_destroy_table(&(eagstat->ap_htable));
	}
	eag_free(eagstat);

	eag_log_info("eag_statistics destroy ok");

	return 0;
}

static struct eag_ap_statistics *
eag_ap_statistics_new(eag_statistics_t *eagstat, uint8_t apmac[6])
{
	struct eag_ap_statistics *ap_stat = NULL;
	char ap_macstr[32] = "";

	if (NULL == eagstat || NULL == apmac) {
		eag_log_err("eag_ap_stat_new input error");
		return NULL;
	}
	mac2str(apmac, ap_macstr, sizeof(ap_macstr), ':');
	ap_stat = eag_blkmem_malloc_item(eagstat->ap_blkmem);
	if (NULL == ap_stat) {
		eag_log_err("eag_bss_stat_new blkmem_malloc_item failed");
		return NULL;
	}

	memset(ap_stat, 0, sizeof(struct eag_ap_statistics));
	ap_stat->eagstat = eagstat;
	ap_stat->bss_num = 0;
	memcpy(ap_stat->ap_mac, apmac, 6);
	INIT_LIST_HEAD(&(ap_stat->bss_head));

	eag_log_debug("eag_statistics",
		"eag_ap_statistics apmac=%s new ok", ap_macstr);

	return ap_stat;
}

static int
eag_ap_statistics_free(struct eag_ap_statistics *ap_stat)
{
	eag_statistics_t *eagstat = NULL;
	char ap_macstr[32] = "";
	
	if (NULL == ap_stat) {
		eag_log_err("eag_ap_statistics_free input error");
		return -1;
	}
	eagstat = ap_stat->eagstat;
	mac2str(ap_stat->ap_mac, ap_macstr, sizeof(ap_macstr), ':');
	
	eag_log_debug("eag_statistics",
		"eag_ap_statistics apmac=%s free ok", ap_macstr);

	eag_blkmem_free_item(eagstat->ap_blkmem, ap_stat);

	return 0;
}

static int
eag_ap_statistics_add(eag_statistics_t *eagstat,
		struct eag_ap_statistics *ap_stat)
{
	if (NULL == eagstat || NULL == ap_stat) {
		eag_log_err("eag_ap_statistics_add input error");
		return -1;
	}
		
	hashtable_check_add_node(eagstat->ap_htable, ap_stat->ap_mac, 6,
			&(ap_stat->ap_hnode));
	list_add_tail(&(ap_stat->ap_node), &(eagstat->ap_head));

	eagstat->ap_num++;

	return 0;
}

static int
eag_ap_statistics_del(struct eag_ap_statistics *ap_stat)
{
	eag_statistics_t *eagstat = NULL;

	if (NULL == ap_stat) {
		eag_log_err("eag_ap_statistics_del input error");
		return -1;
	}

	eagstat = ap_stat->eagstat;
	list_del(&(ap_stat->ap_node));
	hlist_del(&(ap_stat->ap_hnode));

	eagstat->ap_num--;
	
	return 0;
}

static struct eag_ap_statistics *
eag_ap_statistics_find(eag_statistics_t *eagstat, uint8_t apmac[6])
{
	struct eag_ap_statistics *ap_stat = NULL;
	struct hlist_head *head = NULL;
	struct hlist_node *node = NULL;
	char ap_macstr[32] = "";
	
	if (NULL == eagstat || NULL == apmac) {
		eag_log_err("eag_ap_statistics_find input error");
		return NULL;
	}
	
	mac2str(apmac, ap_macstr, sizeof(ap_macstr), ':');
	
	head = hashtable_get_hash_list(eagstat->ap_htable, apmac, 6);
	if (NULL == head) {
		eag_log_err("eag_bss_statistics_find head null");
		return NULL;
	}
	
	hlist_for_each_entry(ap_stat, node, head, ap_hnode) {
		if (0 == memcmp(apmac, ap_stat->ap_mac, 6)) {
			eag_log_debug("eag_statistics",
				"find bss statistics apmac=%s",	ap_macstr);
			return ap_stat;
		}
	}

	eag_log_debug("eag_statistics", "find bss statistics apmac=%s",	ap_macstr);
	
	return NULL;
}

int
eag_ap_statistics_count(eag_statistics_t *eagstat)
{
	int num = 0;
	struct eag_ap_statistics *ap_stat = NULL;
	
	if (NULL == eagstat) {
		eag_log_err("eag_statistics_count stat null");
		return 0;
	}

	list_for_each_entry(ap_stat, &(eagstat->ap_head), ap_node) {
		num++;
	}

	eag_log_debug("eag_statistics",
		"eag_ap_statistics_count num=%d", num);
		
	return num;
}

static struct eag_bss_statistics *
eag_bss_statistics_new(struct eag_ap_statistics *ap_stat,
		uint8_t apmac[6], uint8_t wlanid, uint8_t radioid)
{
	struct eag_bss_statistics *bss_stat = NULL;
	eag_statistics_t *eagstat = NULL;
	char ap_macstr[32] = "";
	
	if (NULL == ap_stat || NULL == apmac) {
		eag_log_err("eag_bss_stat_new input error");
		return NULL;
	}

	eagstat = ap_stat->eagstat;
	
	mac2str(apmac, ap_macstr, sizeof(ap_macstr), ':');
	bss_stat = eag_blkmem_malloc_item(eagstat->bss_blkmem);
	if (NULL == bss_stat) {
		eag_log_err("eag_bss_stat_new blkmem_malloc_item failed");
		return NULL;
	}

	memset(bss_stat, 0, sizeof(struct eag_bss_statistics));
	bss_stat->ap_stat = ap_stat;
	bss_stat->eagstat = eagstat;
	memcpy(bss_stat->data.apmac, apmac, 6);
	bss_stat->data.wlanid = wlanid;
	bss_stat->data.radioid = radioid;

	eag_log_debug("eag_statistics",
		"eag_bss_statistics apmac=%s, wlanid=%u, radioid=%u new ok",
		ap_macstr, bss_stat->data.wlanid, bss_stat->data.radioid);
	
	return bss_stat;
}

static int
eag_bss_statistics_free(struct eag_bss_statistics *bss_stat)
{
	eag_statistics_t *eagstat = NULL;
	char ap_macstr[32] = "";
	
	if (NULL == bss_stat) {
		eag_log_err("eag_bss_statistics_free input error");
		return -1;
	}
	eagstat = bss_stat->eagstat;
	mac2str(bss_stat->data.apmac, ap_macstr, sizeof(ap_macstr), ':');
	
	eag_log_debug("eag_statistics",
		"eag_bss_statistics apmac=%s, wlanid=%u, radioid=%u free ok",
		ap_macstr, bss_stat->data.wlanid, bss_stat->data.radioid);

	eag_blkmem_free_item(eagstat->bss_blkmem, bss_stat);

	return 0;
}

static int
eag_bss_statistics_add(struct eag_ap_statistics *ap_stat,
		struct eag_bss_statistics *bss_stat)
{
	if (NULL == ap_stat || NULL == bss_stat) {
		eag_log_err("eag_bss_statistics_add input error");
		return -1;
	}
	
	list_add_tail(&(bss_stat->bss_node), &(ap_stat->bss_head));

	ap_stat->bss_num++;

	return 0;
}

static int
eag_bss_statistics_del(struct eag_bss_statistics *bss_stat)
{
	struct eag_ap_statistics *ap_stat;
	
	if (NULL == bss_stat) {
		eag_log_err("eag_bss_statistics_del input error");
		return -1;
	}
	ap_stat = bss_stat->ap_stat;
	list_del(&(bss_stat->bss_node));

	ap_stat->bss_num--;

	return 0;
}

static struct eag_bss_statistics *
eag_bss_statistics_find(struct eag_ap_statistics *ap_stat,
		uint8_t apmac[6], uint8_t wlanid, uint8_t radioid)
{
	struct eag_bss_statistics *bss_stat = NULL;
	struct list_head *head = NULL;
	char ap_macstr[32] = "";
	
	if (NULL == ap_stat || NULL == apmac) {
		eag_log_err("eag_bss_statistics_find input error");
		return NULL;
	}
	
	mac2str(apmac, ap_macstr, sizeof(ap_macstr), ':');
	head = &(ap_stat->bss_head);
	
	if (NULL == head) {
		eag_log_err("eag_bss_statistics_find head null");
		return NULL;
	}
	
	list_for_each_entry(bss_stat, head, bss_node) {
		if (wlanid == bss_stat->data.wlanid
			&& radioid == bss_stat->data.radioid)
		{
			eag_log_debug("eag_statistics",
				"find bss statistics apmac=%s, wlanid=%u, radioid=%u",
				ap_macstr, wlanid, radioid);
				return bss_stat;
		}
	}

	eag_log_debug("eag_statistics",
		"not find bss statistics apmac=%s, wlanid=%u, radioid=%u",
		ap_macstr, wlanid, radioid);
	
	return NULL;
}

int
eag_bss_statistics_count(eag_statistics_t *eagstat)
{
	int num = 0;
	struct eag_ap_statistics *ap_stat = NULL;
	struct eag_bss_statistics *bss_stat = NULL;
	
	if (NULL == eagstat) {
		eag_log_err("eag_statistics_count stat null");
		return 0;
	}

	list_for_each_entry(ap_stat, &(eagstat->ap_head), ap_node) {
		list_for_each_entry(bss_stat, &(ap_stat->bss_head), bss_node) {
			num++;
		}
	}

	eag_log_debug("eag_statistics",
		"eag_bss_statistics_count num=%d", num);
		
	return num;
}

int 
ins_bss_auth_count(eag_statistics_t *eagstat,
		uint8_t apmac[6], uint8_t wlanid, uint8_t radioid,
		bss_stat_info_type info_type, uint32_t value)
{
	struct eag_ap_statistics *ap_stat = NULL;
	struct eag_bss_statistics *bss_stat = NULL;
	char ap_macstr[32] = "";
	
	if (NULL == eagstat || NULL == apmac) {
		eag_log_err("ins_bss_auth_count input error");
		return -1;
	}
	mac2str(apmac, ap_macstr, sizeof(ap_macstr), ':');
	ap_stat = eag_ap_statistics_find(eagstat, apmac);
	if (NULL == ap_stat) {
		eag_log_debug("eag_statistics", "ins_bss_auth_count "
			"not found ap_statistics by apmac=%s new one", ap_macstr);
		ap_stat = eag_ap_statistics_new(eagstat, apmac);
		if (NULL == ap_stat) {
			eag_log_err("ins_bss_auth_count eag_ap_statistics_new failed");
			return -1;
		}
		eag_ap_statistics_add(eagstat, ap_stat);
	}
	
	bss_stat = eag_bss_statistics_find(ap_stat, apmac, wlanid, radioid);
	if (NULL == bss_stat) {
		eag_log_debug("eag_statistics", "ins_bss_auth_count "
			"not found bss_statistics by apmac=%s,wlanid=%u,radioid=%u, new one",
			ap_macstr, wlanid, radioid);
		bss_stat = eag_bss_statistics_new(ap_stat, apmac, wlanid, radioid);
		if (NULL == bss_stat) {
			eag_log_err("ins_bss_auth_count eag_bss_statistics_new failed");
			return -1;
		}
		eag_bss_statistics_add(ap_stat, bss_stat);
	}

	switch (info_type) {
	case BSS_ONLINE_USER_NUM:
		bss_stat->data.online_user_num += value;
		break;
	case BSS_USER_CONNECTED_TOTAL_TIME:
		bss_stat->data.user_connected_total_time += value;
		break;
	case BSS_USER_CONNECTING_TOTAL_TIME:
		bss_stat->data.user_connecting_total_time += value;
		break;
	case BSS_MACAUTH_ONLINE_USER_NUM:
		bss_stat->data.macauth_online_user_num += value;
		break;
	case BSS_MACAUTH_USER_CONNECTED_TOTAL_TIME:
		bss_stat->data.macauth_user_connected_total_time += value;
		break;
	case BSS_MACAUTH_USER_CONNECTING_TOTAL_TIME:
		bss_stat->data.macauth_user_connecting_total_time += value;
		break;
	#if 1	
	case BSS_HTTP_REDIR_REQ_COUNT:
		bss_stat->data.http_redir_request_count += value;
		break;
	case BSS_HTTP_REDIR_SUCCESS_COUNT:
		bss_stat->data.http_redir_success_count += value;
		break;
	#endif	
	case BSS_CHALLENGE_REQ_COUNT:
		bss_stat->data.challenge_req_count += value;
		break;
	case BSS_CHALLENGE_ACK_0_COUNT:
		bss_stat->data.challenge_ack_0_count += value;
		break;
	case BSS_CHALLENGE_ACK_1_COUNT:
		bss_stat->data.challenge_ack_1_count += value;
		break;
	case BSS_CHALLENGE_ACK_2_COUNT:
		bss_stat->data.challenge_ack_2_count += value;
		break;
	case BSS_CHALLENGE_ACK_3_COUNT:
		bss_stat->data.challenge_ack_3_count += value;
		break;
	case BSS_CHALLENGE_ACK_4_COUNT:
		bss_stat->data.challenge_ack_4_count += value;
		break;
	case BSS_AUTH_REQ_COUNT:
		bss_stat->data.auth_req_count += value;
		break;
	case BSS_AUTH_ACK_0_COUNT:
		bss_stat->data.auth_ack_0_count += value;
		break;
	case BSS_AUTH_ACK_1_COUNT:
		bss_stat->data.auth_ack_1_count += value;
		break;
	case BSS_AUTH_ACK_2_COUNT:
		bss_stat->data.auth_ack_2_count += value;
		break;
	case BSS_AUTH_ACK_3_COUNT:
		bss_stat->data.auth_ack_3_count += value;
		break;
	case BSS_AUTH_ACK_4_COUNT:
		bss_stat->data.auth_ack_4_count += value;
		break;
	case BSS_MACAUTH_REQ_COUNT:
		bss_stat->data.macauth_req_count += value;
		break;
	case BSS_MACAUTH_ACK_0_COUNT:
		bss_stat->data.macauth_ack_0_count += value;
		break;
	case BSS_MACAUTH_ACK_1_COUNT:
		bss_stat->data.macauth_ack_1_count += value;
		break;
	case BSS_MACAUTH_ACK_2_COUNT:
		bss_stat->data.macauth_ack_2_count += value;
		break;
	case BSS_MACAUTH_ACK_3_COUNT:
		bss_stat->data.macauth_ack_3_count += value;
		break;
	case BSS_MACAUTH_ACK_4_COUNT:
		bss_stat->data.macauth_ack_4_count += value;
		break;
	#if 0 	
	case BSS_LOGOUT_REQ_0_COUNT:
		bss_stat->data.logout_req_0_count += value;
		break;
	case BSS_LOGOUT_REQ_1_COUNT:
		bss_stat->data.logout_req_1_count += value;
		break;
	case BSS_LOGOUT_ACK_0_COUNT:
		bss_stat->data.logout_ack_0_count += value;
		break;
	case BSS_LOGOUT_ACK_1_COUNT:
		bss_stat->data.logout_ack_1_count += value;
		break;
	case BSS_LOGOUT_ACK_2_COUNT:
		bss_stat->data.logout_ack_2_count += value;
		break;
	case BSS_NTF_LOGOUT_COUNT:
		bss_stat->data.ntf_logout_count += value;
		break;
	#endif	
	case BSS_NORMAL_LOGOFF_COUNT:
		bss_stat->data.normal_logoff_count += value;
		break;
	case BSS_ABNORMAL_LOGOFF_COUNT:
		bss_stat->data.abnormal_logoff_count += value;
		break;
	case BSS_MACAUTH_ABNORMAL_LOGOFF_COUNT:
		bss_stat->data.macauth_abnormal_logoff_count += value;
		break;
	case BSS_CHALLENGE_TIMEOUT_COUNT:
		bss_stat->data.challenge_timeout_count += value;
		break;
	case BSS_CHALLENGE_BUSY_COUNT:
		bss_stat->data.challenge_busy_count += value;
		break;
	case BSS_REQ_AUTH_PASSWORD_MISSING_COUNT:
		bss_stat->data.req_auth_password_missing_count += value;
		break;
	case BSS_REQ_AUTH_UNKNOWN_TYPE_COUNT:
		bss_stat->data.req_auth_unknown_type_count += value;
		break;
	case BSS_ACK_AUTH_BUSY_COUNT:
		bss_stat->data.ack_auth_busy_count += value;
		break;
	case BSS_AUTH_DISORDER_COUNT:
		bss_stat->data.auth_disorder_count += value;
		break;
	case BSS_ACCESS_REQUEST_COUNT:
		bss_stat->data.access_request_count += value;
		break;
	case BSS_ACCESS_REQUEST_RETRY_COUNT:
		bss_stat->data.access_request_retry_count += value;
		break;
	case BSS_ACCESS_REQUEST_TIMEOUT_COUNT:
		bss_stat->data.access_request_timeout_count += value;
		break;
	case BSS_ACCESS_ACCEPT_COUNT:
		bss_stat->data.access_accept_count += value;
		break;
	case BSS_ACCESS_REJECT_COUNT:
		bss_stat->data.access_reject_count += value;
		break;
	case BSS_ACCT_REQUEST_START_COUNT:
		bss_stat->data.acct_request_start_count += value;
		break;
	case BSS_ACCT_REQUEST_START_RETRY_COUNT:
		bss_stat->data.acct_request_start_retry_count += value;
		break;
	case BSS_ACCT_RESPONSE_START_COUNT:
		bss_stat->data.acct_response_start_count += value;
		break;
	case BSS_ACCT_REQUEST_UPDATE_COUNT:
		bss_stat->data.acct_request_update_count += value;
		break;
	case BSS_ACCT_REQUEST_UPDATE_RETRY_COUNT:
		bss_stat->data.acct_request_update_retry_count += value;
		break;
	case BSS_ACCT_RESPONSE_UPDATE_COUNT:
		bss_stat->data.acct_response_update_count += value;
		break;
	case BSS_ACCT_REQUEST_STOP_COUNT:
		bss_stat->data.acct_request_stop_count += value;
		break;
	case BSS_ACCT_REQUEST_STOP_RETRY_COUNT:
		bss_stat->data.acct_request_stop_retry_count += value;
		break;
	case BSS_ACCT_RESPONSE_STOP_COUNT:
		bss_stat->data.acct_response_stop_count += value;
		break;
	default:
		eag_log_err("ins_bss_auth_count unknown bss_stat_info_type %d",
				info_type);
		break;
	}

	return 0;
}

int
eag_bss_message_count(eag_statistics_t *eagstat,
		struct app_conn_t *appconn,
		bss_stat_info_type info_type, uint32_t value)
{
	uint8_t zero_mac[6] = {0};
	
	if (NULL == appconn) {
		ins_bss_auth_count(eagstat, zero_mac, 0, 0, info_type, value);
	} else {
		ins_bss_auth_count(eagstat, appconn->session.apmac, appconn->session.wlanid,
					appconn->session.radioid, info_type, value);
	}
	return 0;
}

int
eag_statistics_clear(eag_statistics_t *eagstat)
{
	struct eag_ap_statistics *ap_stat = NULL;
	struct eag_ap_statistics *ap_next = NULL;
	struct eag_bss_statistics *bss_stat = NULL;
	struct eag_bss_statistics *bss_next = NULL;
	
	if (NULL == eagstat) {
		eag_log_err("eag_statistics_clear input error");
		return -1;
	}
	
	list_for_each_entry_safe(ap_stat, ap_next, &(eagstat->ap_head), ap_node) {
		list_for_each_entry_safe(bss_stat, bss_next, &(ap_stat->bss_head), bss_node) {
			eag_bss_statistics_del(bss_stat);
			eag_bss_statistics_free(bss_stat);
		}
		eag_ap_statistics_del(ap_stat);
		eag_ap_statistics_free(ap_stat);
	}

	return 0;
}

int
eag_statistics_count_online_user_info(eag_statistics_t *eagstat)
{
	struct eag_ap_statistics *ap_stat = NULL;
	struct eag_bss_statistics *bss_stat = NULL;
	appconn_db_t *appdb = NULL;
	struct app_conn_t *appconn = NULL;
	struct list_head *head = NULL;
	struct timeval tv = {0};
	time_t timenow = 0;

	eag_time_gettimeofday(&tv, NULL);
	timenow = tv.tv_sec;
	
	if (NULL == eagstat) {
		eag_log_err("eag_statistics_count_online_user_info input error");
		return -1;
	}
	appdb = eagstat->appdb;
	head = appconn_db_get_head(appdb);
	
	list_for_each_entry(ap_stat, &(eagstat->ap_head), ap_node) {
		list_for_each_entry(bss_stat, &(ap_stat->bss_head), bss_node) {
			bss_stat->data.online_user_num = 0;
			bss_stat->data.user_connecting_total_time = 0;
			bss_stat->data.macauth_online_user_num= 0;
			bss_stat->data.macauth_user_connecting_total_time = 0;
		}
	}

	list_for_each_entry(appconn, head, node) {
		if (APPCONN_STATUS_AUTHED == appconn->session.state ) {
			if (SESSION_STA_STATUS_CONNECT == appconn->session.sta_state) {
                if (EAG_AUTH_TYPE_MAC == appconn->session.server_auth_type ) {
                	ins_bss_auth_count(eagstat, appconn->session.apmac,
						appconn->session.wlanid, appconn->session.radioid,
						BSS_MACAUTH_ONLINE_USER_NUM, 1);
                } else {
                	ins_bss_auth_count(eagstat, appconn->session.apmac,
						appconn->session.wlanid, appconn->session.radioid,
						BSS_ONLINE_USER_NUM, 1);
				}
			}
            if (EAG_AUTH_TYPE_MAC == appconn->session.server_auth_type ) {
				ins_bss_auth_count(eagstat, appconn->session.apmac,
					appconn->session.wlanid, appconn->session.radioid,
					BSS_MACAUTH_USER_CONNECTING_TOTAL_TIME, (timenow - appconn->session.last_connect_ap_time));
			} else {
				ins_bss_auth_count(eagstat, appconn->session.apmac,
					appconn->session.wlanid, appconn->session.radioid,
					BSS_USER_CONNECTING_TOTAL_TIME, (timenow - appconn->session.last_connect_ap_time));
            }
		}
	}

	return 0;
}

int
eag_statistics_set_appdb(eag_statistics_t *eagstat,
		appconn_db_t *appdb)
{
	if (NULL == eagstat) {
		eag_log_err("eag_statistics_set_appdb input error");
		return -1;
	}

	eagstat->appdb = appdb;

	return EAG_RETURN_OK;
}

struct list_head *
eag_statistics_get_appconn_head(eag_statistics_t *eagstat)
{
    return appconn_db_get_head(eagstat->appdb);

}

struct list_head *
eag_statistics_get_ap_head(eag_statistics_t *eagstat)
{
	return &(eagstat->ap_head);
}

#ifdef eag_statistics_test
#include "eag_mem.c"
#include "eag_log.c"
#include "eag_blkmem.c"
#include "hashtable.c"
#include "eag_errcode.c"


#define EAG_SHOW_HASHTABLE(ht, type, member, content) 	do{	\
	int i=0;		\
	struct hlist_node *hlist_node=NULL;	\
	for (i=0; i < ht->hash_num; i++){	\
		hlist_for_each_entry(type , hlist_node, &(ht->head_nodes[i]), member ){		\
		printf("hash_num is %d ptr is %p\n",i,type);	\
		}	\
	}	\
}while (0)


int main()
{
	unsigned char mac[6]={0,1,2,3,4,5};
	struct eag_bss_statistics *bss_stat,*bss_stat_tmp;
	//eag_log_init("test");
	//eag_log_add_filter("eag_statistics");
	/*do test*/
	eag_statistics_init();
	EAG_SHOW_HASHTABLE(eagstatistics.ht, bss_stat_tmp, hnode, NULL);

	int i=0;
	/*mac test*/
	for (i=0;i<5;i++){
		mac[1]=i;
		bss_stat = eag_bss_statistics_get(mac,1,1);
		printf ("mac test bss_stat=%p eag_statistics_get_head:%p bss_statistic_total_num:%d\n",bss_stat,eag_statistics_get_head(&eagstatistics),eag_statistics_get_nodenum(&eagstatistics));
		EAG_SHOW_HASHTABLE(eagstatistics.ht, bss_stat_tmp, hnode, NULL);
	}
	for (i=0;i<5;i++){
		mac[1]=i;
		bss_stat = eag_bss_statistics_get(mac,1,1);
		printf ("mac test bss_stat=%p eag_statistics_get_head:%p bss_statistic_total_num:%d\n",bss_stat,eag_statistics_get_head(&eagstatistics),eag_statistics_get_nodenum(&eagstatistics));
		EAG_SHOW_HASHTABLE(eagstatistics.ht, bss_stat_tmp, hnode, NULL);
	}
	/*radioid hash test*/
	for (i=0;i<5;i++){
		bss_stat = eag_bss_statistics_get(mac,1,i);
		printf ("mac test bss_stat=%p eag_statistics_get_head:%p bss_statistic_total_num:%d\n",bss_stat,eag_statistics_get_head(&eagstatistics),eag_statistics_get_nodenum(&eagstatistics));
		EAG_SHOW_HASHTABLE(eagstatistics.ht, bss_stat_tmp, hnode, NULL);
	}
	for (i=0;i<5;i++){
		bss_stat = eag_bss_statistics_get(mac,1,i);
		printf ("mac test bss_stat=%p eag_statistics_get_head:%p bss_statistic_total_num:%d\n",bss_stat,eag_statistics_get_head(&eagstatistics),eag_statistics_get_nodenum(&eagstatistics));
		EAG_SHOW_HASHTABLE(eagstatistics.ht, bss_stat_tmp, hnode, NULL);
	}
	/*wlanid test*/
	for (i=5;i<10;i++){
		bss_stat = eag_bss_statistics_get(mac,i,1);
		printf ("mac test bss_stat=%p eag_statistics_get_head:%p bss_statistic_total_num:%d\n",bss_stat,eag_statistics_get_head(&eagstatistics),eag_statistics_get_nodenum(&eagstatistics));
		EAG_SHOW_HASHTABLE(eagstatistics.ht, bss_stat_tmp, hnode, NULL);
	}
	for (i=5;i<10;i++){
		bss_stat = eag_bss_statistics_get(mac,i,1);
		printf ("mac test bss_stat=%p eag_statistics_get_head:%p bss_statistic_total_num:%d\n",bss_stat,eag_statistics_get_head(&eagstatistics),eag_statistics_get_nodenum(&eagstatistics));
		EAG_SHOW_HASHTABLE(eagstatistics.ht, bss_stat_tmp, hnode, NULL);
	}
	
	eag_statistics_uninit();

	/*mem check no mem leak!*/
	return 0;
}

#endif

