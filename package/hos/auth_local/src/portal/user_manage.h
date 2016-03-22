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
* user_manage.h
*
*
* CREATOR:
* autelan.software.xxx. team
*
* DESCRIPTION:
* xxx module main routine
*
*
*******************************************************************************/

#ifndef _USER_MANAGE_H
#define _USER_MANAGE_H
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>


#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>


#define USER_NAME_SIZE	64
#define SESSIONID_LEN   64
#define MAC_LEN			6

/*for  user manage*/
typedef struct {
    int index;
    int ipaddr;
    char  username[USER_NAME_SIZE];/**/
    unsigned char usermac[MAC_LEN];
    int session_time;
    /*add for guangzhou mobile test*/
    uint64_t input_octets;
    uint64_t output_octets;

    char sessionid[SESSIONID_LEN];/*need??*/
}STOnlineUserInfo;

struct st_bss_user_info
{
	unsigned char ap_mac[6];
	unsigned int wlan_id;
	unsigned int radio_id;
	unsigned int online_user_num;
	unsigned int user_auth_request_count;
	unsigned int user_auth_success_count;
	unsigned int user_auth_logoff_abnormal_count;
	unsigned int user_auth_logoff_normal_count;
	unsigned int user_req_challenge_count;
	unsigned int user_ack_challenge_count;
	unsigned int user_req_auth_count;
	unsigned int user_ack_auth_success_count;
	unsigned int user_ack_auth_failure_count;
	unsigned int user_access_request_count;
	unsigned int user_access_request_retry_count;
	unsigned int user_access_request_timeout_count;
	unsigned int user_access_accept_count;
	unsigned int user_access_reject_count;
	unsigned int user_acct_request_start_count;
	unsigned int user_acct_request_update_count;
	unsigned int user_acct_request_stop_count;
	//unsigned int user_acct_request_retry_count;
	//unsigned int user_acct_response_count;
};

struct st_ap_user_info
{
	unsigned char ap_mac[6];
	int online_user_num;
	int user_auth_request_count;
	int user_auth_success_count;
	int user_auth_logoff_abnormal_count;
	int user_auth_logoff_normal_count;
	int user_req_challenge_count;
	int user_ack_challenge_count;
	int user_req_auth_count;
	int user_ack_auth_success_count;
	int user_ack_auth_failure_count;
	int user_access_request_count;
	int user_access_request_retry_count;
	int user_access_request_timeout_count;
	int user_access_accept_count;
	int user_access_reject_count;
	int user_acct_request_start_count;
	int user_acct_request_update_count;
	int user_acct_request_stop_count;
	//int user_acct_request_retry_count;
	//int user_acct_response_count;
};

typedef struct {
    int pkg_type;
	int eagins_id;
	int vrrp_id;
    unsigned int len;
    unsigned int all_user_num;/*在线用户的总数*/
	int auth_type;
    int err_code;
    union {
    	struct {
			union {
				struct {
					unsigned int idx_begin;
					unsigned int idx_end;
				} idx;
				unsigned int idx_get;
				char username[USER_NAME_SIZE];
				unsigned char user_mac[MAC_LEN];
				unsigned int user_ip;
				STOnlineUserInfo user_info;
			} reqinfo;
    	}req;    	
    	struct {
			int LOGOUT_FLAG; /* 用来记录只回复logout 消息的包*/
    		int user_num_in_pkg;/*0 or more当前包中记录的用户数*/
    		STOnlineUserInfo users[0];/*实际大小由user_num来确定,创建pkg的大小时，也需要根据大小先计算包的大小*/
    	} ack;
		struct {
			int msg_len;
			char msg_eapol[0];/*for rj*/
		} msg;
		struct {
			unsigned int auth_req_count;
			unsigned int auth_req_success_count;
			unsigned int user_auth_logoff_abnormal_count;
			unsigned int user_auth_logoff_normal_count;
			unsigned int user_req_challenge_count;
			unsigned int user_ack_challenge_count;
			unsigned int user_req_auth_count;
			unsigned int user_ack_auth_success_count;
			unsigned int user_ack_auth_failure_count;
			unsigned int user_access_request_count;
			unsigned int user_access_request_retry_count;
			unsigned int user_access_request_timeout_count;
			unsigned int user_access_accept_count;
			unsigned int user_access_reject_count;
			unsigned int user_acct_request_start_count;
			unsigned int user_acct_request_update_count;
			unsigned int user_acct_request_stop_count;
			unsigned int user_acct_request_retry_count;
			//unsigned int user_acct_response_count;
		} info;
		struct {
			//unsigned char ap_mac[6];
			//int online_user_num;
			//int user_auth_request_count;
			//int user_auth_success_count;
			//int user_auth_logoff_abnormal;
			unsigned int node_num;
			struct st_ap_user_info info_array[0];
		}ap_user_info;
		struct {
			unsigned int node_num;
			struct st_bss_user_info info_array[0];
		}bss_user_info;	
    } data;
}STUserManagePkg;


typedef enum{
    REQ_GET_ONLINE_NUM=1,
    ACK_GET_ONLINE_NUM,
    REQ_GET_AUTH_TYPE,
    ACK_GET_AUTH_TYPE,
    REQ_GET_USR_BY_INDEX_RANG,
    ACK_GET_USR_BY_INDEX_RANG,
    REQ_LOGOUT_BY_INFO,
    ACK_LOGOUT_BY_INFO,
    /*use for search*/
    REQ_GET_BY_INDEX,
    ACK_GET_BY_INDEX,
    REQ_GET_BY_NAME,
    ACK_GET_BY_NAME,
    REQ_GET_BY_MAC,
    ACK_GET_BY_MAC,
    REQ_GET_BY_IP,
    ACK_GET_BY_IP,
    SET_TIME_MSG,		//ADD BY LT FOR RJ 
    /*kick by diff way add by tangsq*/
    REQ_LOGOUT_BY_INFO_MAC,
    ACK_LOGOUT_BY_INFO_MAC,
    REQ_LOGOUT_BY_INFO_NAME,
    ACK_LOGOUT_BY_INFO_NAME,
    /*add end*/	
    REQ_GET_EAG_USER_INFO,
    ACK_GET_EAG_USER_INFO,
    REQ_GET_AP_USER_INFO,
    ACK_GET_AP_USER_INFO,
    REQ_GET_BSS_USER_INFO,
    ACK_GET_BSS_USER_INFO
}USER_MNG_TYPE;


/*定义错误*/
#define ERR_NO				0
#define ERR_INDEX_RANG		1
#define ERR_HASNO_USER		2/*用户不存在*/
#define ERR_HASNO_MAC		3/*该mac不存在*/
#define ERR_HASNO_IP		4/*IP不存在*/
#define ERR_LOGOUT_FAILED	5



/*这个头文件将会被cgi直接引用，定义成宏两端都可以用，如果做成函数后，就必须定义成static或则inline的！！！*/
static void MNG_PKG_HTON( STUserManagePkg *p )
{
	STUserManagePkg *_pkg_mng = p;
	int i = 0;
	
	if( NULL == p )
	{
		return;	
	}
	switch( _pkg_mng->pkg_type )
	{
		case REQ_GET_ONLINE_NUM:
			break;
		case REQ_GET_USR_BY_INDEX_RANG:
			_pkg_mng->data.req.reqinfo.idx.idx_begin = htonl(_pkg_mng->data.req.reqinfo.idx.idx_begin);
			_pkg_mng->data.req.reqinfo.idx.idx_end = htonl(_pkg_mng->data.req.reqinfo.idx.idx_end);
			break;
		case REQ_LOGOUT_BY_INFO:
			break;
		case REQ_GET_BY_INDEX:
			_pkg_mng->data.req.reqinfo.idx_get = htonl(_pkg_mng->data.req.reqinfo.idx_get);
			break;
		case REQ_GET_BY_NAME:
			break;
		case REQ_GET_BY_MAC:
			break;
		case REQ_GET_BY_IP:
			_pkg_mng->data.req.reqinfo.user_ip = htonl(_pkg_mng->data.req.reqinfo.user_ip);
			break;
		/*for ack*/
		case ACK_GET_ONLINE_NUM:
			break;
		case ACK_GET_USR_BY_INDEX_RANG:
		case ACK_LOGOUT_BY_INFO:
		case ACK_GET_BY_INDEX:
		case ACK_GET_BY_NAME:
		case ACK_GET_BY_MAC:
		case ACK_GET_BY_IP:			
			for( i=0; i< _pkg_mng->data.ack.user_num_in_pkg; i++ )
			{
				STOnlineUserInfo *users = _pkg_mng->data.ack.users;
				users[i].index = htonl( users[i].index );
				users[i].ipaddr = htonl( users[i].ipaddr );
				users[i].session_time = htonl( users[i].session_time );				
			}

			_pkg_mng->data.ack.user_num_in_pkg = htonl(_pkg_mng->data.ack.user_num_in_pkg);
			break;
		case SET_TIME_MSG:
			_pkg_mng->data.msg.msg_len = htonl(_pkg_mng->data.msg.msg_len);
			break;
		case ACK_GET_EAG_USER_INFO:
			_pkg_mng->data.info.auth_req_count = htonl(_pkg_mng->data.info.auth_req_count);
			_pkg_mng->data.info.auth_req_success_count = htonl(_pkg_mng->data.info.auth_req_success_count);
			_pkg_mng->data.info.user_auth_logoff_abnormal_count = htonl(_pkg_mng->data.info.user_auth_logoff_abnormal_count);
			_pkg_mng->data.info.user_auth_logoff_normal_count = htonl(_pkg_mng->data.info.user_auth_logoff_normal_count);
			_pkg_mng->data.info.user_req_challenge_count = htonl(_pkg_mng->data.info.user_req_challenge_count);
			_pkg_mng->data.info.user_ack_challenge_count = htonl(_pkg_mng->data.info.user_ack_challenge_count);
			_pkg_mng->data.info.user_req_auth_count = htonl(_pkg_mng->data.info.user_req_auth_count);
			_pkg_mng->data.info.user_ack_auth_success_count = htonl(_pkg_mng->data.info.user_ack_auth_success_count);
			_pkg_mng->data.info.user_ack_auth_failure_count = htonl(_pkg_mng->data.info.user_ack_auth_failure_count);
			_pkg_mng->data.info.user_access_request_count = htonl(_pkg_mng->data.info.user_access_request_count);
			_pkg_mng->data.info.user_access_request_retry_count = htonl(_pkg_mng->data.info.user_access_request_retry_count);
			_pkg_mng->data.info.user_access_request_timeout_count = htonl(_pkg_mng->data.info.user_access_request_timeout_count);
			_pkg_mng->data.info.user_access_accept_count = htonl(_pkg_mng->data.info.user_access_accept_count);
			_pkg_mng->data.info.user_access_reject_count = htonl(_pkg_mng->data.info.user_access_reject_count);
			_pkg_mng->data.info.user_acct_request_start_count = htonl(_pkg_mng->data.info.user_acct_request_start_count);
			_pkg_mng->data.info.user_acct_request_update_count = htonl(_pkg_mng->data.info.user_acct_request_update_count);
			_pkg_mng->data.info.user_acct_request_stop_count = htonl(_pkg_mng->data.info.user_acct_request_stop_count);
			_pkg_mng->data.info.user_acct_request_retry_count = htonl(_pkg_mng->data.info.user_acct_request_retry_count);
			//_pkg_mng->data.info.user_acct_response_count = htonl(_pkg_mng->data.info.user_acct_response_count);
			break;
		case ACK_GET_BSS_USER_INFO:
		{
			struct st_bss_user_info *bss_user_info = _pkg_mng->data.bss_user_info.info_array;
			for (i = 0; i < _pkg_mng->data.bss_user_info.node_num; i++)
			{
				bss_user_info[i].wlan_id = htonl(bss_user_info[i].wlan_id);
				bss_user_info[i].radio_id = htonl(bss_user_info[i].radio_id);
				bss_user_info[i].online_user_num = htonl(bss_user_info[i].online_user_num);
				bss_user_info[i].user_auth_request_count = htonl(bss_user_info[i].user_auth_request_count);
				bss_user_info[i].user_auth_success_count = htonl(bss_user_info[i].user_auth_success_count);
				bss_user_info[i].user_auth_logoff_abnormal_count = htonl(bss_user_info[i].user_auth_logoff_abnormal_count);
				bss_user_info[i].user_auth_logoff_normal_count = htonl(bss_user_info[i].user_auth_logoff_normal_count);
				bss_user_info[i].user_req_challenge_count = htonl(bss_user_info[i].user_req_challenge_count);
				bss_user_info[i].user_ack_challenge_count = htonl(bss_user_info[i].user_ack_challenge_count);
				bss_user_info[i].user_req_auth_count = htonl(bss_user_info[i].user_req_auth_count);
				bss_user_info[i].user_ack_auth_success_count = htonl(bss_user_info[i].user_ack_auth_success_count);
				bss_user_info[i].user_ack_auth_failure_count = htonl(bss_user_info[i].user_ack_auth_failure_count);
				bss_user_info[i].user_access_request_count = htonl(bss_user_info[i].user_access_request_count);
				bss_user_info[i].user_access_request_retry_count = htonl(bss_user_info[i].user_access_request_retry_count);
				bss_user_info[i].user_access_request_timeout_count = htonl(bss_user_info[i].user_access_request_timeout_count);
				bss_user_info[i].user_access_accept_count = htonl(bss_user_info[i].user_access_accept_count);
				bss_user_info[i].user_access_reject_count = htonl(bss_user_info[i].user_access_reject_count);
				bss_user_info[i].user_acct_request_start_count = htonl(bss_user_info[i].user_acct_request_start_count);
				bss_user_info[i].user_acct_request_update_count = htonl(bss_user_info[i].user_acct_request_update_count);
				bss_user_info[i].user_acct_request_stop_count = htonl(bss_user_info[i].user_acct_request_stop_count);
				//bss_user_info[i].user_acct_request_retry_count = htonl(bss_user_info[i].user_acct_request_retry_count);
				//bss_user_info[i].user_acct_response_count = htonl(bss_user_info[i].user_acct_response_count);
			}
			_pkg_mng->data.bss_user_info.node_num = htonl(_pkg_mng->data.bss_user_info.node_num);
		}
			break;
		case ACK_GET_AP_USER_INFO:
		{
			struct st_ap_user_info *ap_user_info = _pkg_mng->data.ap_user_info.info_array;
			for (i = 0; i < _pkg_mng->data.ap_user_info.node_num; i++)
			{
				ap_user_info[i].online_user_num = htonl(ap_user_info[i].online_user_num);
				ap_user_info[i].user_auth_request_count = htonl(ap_user_info[i].user_auth_request_count);
				ap_user_info[i].user_auth_success_count = htonl(ap_user_info[i].user_auth_success_count);
				ap_user_info[i].user_auth_logoff_abnormal_count = htonl(ap_user_info[i].user_auth_logoff_abnormal_count);
				ap_user_info[i].user_auth_logoff_normal_count = htonl(ap_user_info[i].user_auth_logoff_normal_count);
				ap_user_info[i].user_req_challenge_count = htonl(ap_user_info[i].user_req_challenge_count);
				ap_user_info[i].user_ack_challenge_count = htonl(ap_user_info[i].user_ack_challenge_count);
				ap_user_info[i].user_req_auth_count = htonl(ap_user_info[i].user_req_auth_count);
				ap_user_info[i].user_ack_auth_success_count = htonl(ap_user_info[i].user_ack_auth_success_count);
				ap_user_info[i].user_ack_auth_failure_count = htonl(ap_user_info[i].user_ack_auth_failure_count);
				ap_user_info[i].user_access_request_count = htonl(ap_user_info[i].user_access_request_count);
				ap_user_info[i].user_access_request_retry_count = htonl(ap_user_info[i].user_access_request_retry_count);
				ap_user_info[i].user_access_request_timeout_count = htonl(ap_user_info[i].user_access_request_timeout_count);
				ap_user_info[i].user_access_accept_count = htonl(ap_user_info[i].user_access_accept_count);
				ap_user_info[i].user_access_reject_count = htonl(ap_user_info[i].user_access_reject_count);
				ap_user_info[i].user_acct_request_start_count = htonl(ap_user_info[i].user_acct_request_start_count);
				ap_user_info[i].user_acct_request_update_count = htonl(ap_user_info[i].user_acct_request_update_count);
				ap_user_info[i].user_acct_request_stop_count = htonl(ap_user_info[i].user_acct_request_stop_count);
				//ap_user_info[i].user_acct_request_retry_count = htonl(ap_user_info[i].user_acct_request_retry_count);
				//ap_user_info[i].user_acct_response_count = htonl(ap_user_info[i].user_acct_response_count);
				
			}
			_pkg_mng->data.ap_user_info.node_num = htonl(_pkg_mng->data.ap_user_info.node_num);
		}
			break;
		default:
			break;
	}
	
	_pkg_mng->len = htonl( _pkg_mng->len );
	_pkg_mng->pkg_type = htonl( _pkg_mng->pkg_type );
	_pkg_mng->all_user_num = htonl( _pkg_mng->all_user_num );
	
	return;
}

static void MNG_PKG_NTOH( STUserManagePkg *p )
{
	STUserManagePkg *_pkg_mng = p;
	int i = 0;

	/*log_dbg("MNG_PKG_NTOH  p = %p", p );*/
	if( NULL == p )
	{
		return;	
	}
	
	_pkg_mng->len = ntohl( _pkg_mng->len );
	_pkg_mng->pkg_type = ntohl( _pkg_mng->pkg_type );
	_pkg_mng->all_user_num = ntohl( _pkg_mng->all_user_num );
		
	switch( _pkg_mng->pkg_type )
	{
		case REQ_GET_ONLINE_NUM:
			break;
		case REQ_GET_USR_BY_INDEX_RANG:
			_pkg_mng->data.req.reqinfo.idx.idx_begin = ntohl(_pkg_mng->data.req.reqinfo.idx.idx_begin);
			_pkg_mng->data.req.reqinfo.idx.idx_end = ntohl(_pkg_mng->data.req.reqinfo.idx.idx_end);
			break;
		case REQ_LOGOUT_BY_INFO:
			break;
		case REQ_GET_BY_INDEX:
			_pkg_mng->data.req.reqinfo.idx_get = ntohl(_pkg_mng->data.req.reqinfo.idx_get);
			break;
		case REQ_GET_BY_NAME:
			break;
		case REQ_GET_BY_MAC:
			break;
		case REQ_GET_BY_IP:
			_pkg_mng->data.req.reqinfo.user_ip = ntohl(_pkg_mng->data.req.reqinfo.user_ip);
			break;
		/*for ack*/
		case ACK_GET_ONLINE_NUM:
			break;
		case ACK_GET_USR_BY_INDEX_RANG:
		case ACK_LOGOUT_BY_INFO:
		case ACK_GET_BY_INDEX:
		case ACK_GET_BY_NAME:
		case ACK_GET_BY_MAC:
		case ACK_GET_BY_IP:
			_pkg_mng->data.ack.user_num_in_pkg = ntohl(_pkg_mng->data.ack.user_num_in_pkg);			
			for( i=0; i< _pkg_mng->data.ack.user_num_in_pkg; i++ )
			{
				STOnlineUserInfo *users = _pkg_mng->data.ack.users;
				users[i].index = ntohl( users[i].index );
				users[i].ipaddr = ntohl( users[i].ipaddr );
				users[i].session_time = ntohl( users[i].session_time );				
			}
			break;
		case SET_TIME_MSG:
			break;
		case ACK_GET_EAG_USER_INFO:
			_pkg_mng->data.info.auth_req_count = ntohl(_pkg_mng->data.info.auth_req_count);
			_pkg_mng->data.info.auth_req_success_count = ntohl(_pkg_mng->data.info.auth_req_success_count);
			_pkg_mng->data.info.user_auth_logoff_abnormal_count = ntohl(_pkg_mng->data.info.user_auth_logoff_abnormal_count);
			_pkg_mng->data.info.user_auth_logoff_normal_count = ntohl(_pkg_mng->data.info.user_auth_logoff_normal_count);
			_pkg_mng->data.info.user_req_challenge_count = ntohl(_pkg_mng->data.info.user_req_challenge_count);
			_pkg_mng->data.info.user_ack_challenge_count = ntohl(_pkg_mng->data.info.user_ack_challenge_count);
			_pkg_mng->data.info.user_req_auth_count = ntohl(_pkg_mng->data.info.user_req_auth_count);
			_pkg_mng->data.info.user_ack_auth_success_count = ntohl(_pkg_mng->data.info.user_ack_auth_success_count);
			_pkg_mng->data.info.user_ack_auth_failure_count = ntohl(_pkg_mng->data.info.user_ack_auth_failure_count);
			_pkg_mng->data.info.user_access_request_count = ntohl(_pkg_mng->data.info.user_access_request_count);
			_pkg_mng->data.info.user_access_request_retry_count = ntohl(_pkg_mng->data.info.user_access_request_retry_count);
			_pkg_mng->data.info.user_access_request_timeout_count = ntohl(_pkg_mng->data.info.user_access_request_timeout_count);
			_pkg_mng->data.info.user_access_accept_count = ntohl(_pkg_mng->data.info.user_access_accept_count);
			_pkg_mng->data.info.user_access_reject_count = ntohl(_pkg_mng->data.info.user_access_reject_count);
			_pkg_mng->data.info.user_acct_request_start_count = ntohl(_pkg_mng->data.info.user_acct_request_start_count);
			_pkg_mng->data.info.user_acct_request_update_count = ntohl(_pkg_mng->data.info.user_acct_request_update_count);
			_pkg_mng->data.info.user_acct_request_stop_count = ntohl(_pkg_mng->data.info.user_acct_request_stop_count);
			_pkg_mng->data.info.user_acct_request_retry_count = ntohl(_pkg_mng->data.info.user_acct_request_retry_count);
			//_pkg_mng->data.info.user_acct_response_count = ntohl(_pkg_mng->data.info.user_acct_response_count);
			break;
		case ACK_GET_BSS_USER_INFO:
		{
			_pkg_mng->data.bss_user_info.node_num = ntohl(_pkg_mng->data.bss_user_info.node_num);
			struct st_bss_user_info *bss_user_info = _pkg_mng->data.bss_user_info.info_array;
			for (i = 0; i < _pkg_mng->data.bss_user_info.node_num; i++)
			{
				bss_user_info[i].wlan_id = ntohl(bss_user_info[i].wlan_id);
				bss_user_info[i].radio_id = ntohl(bss_user_info[i].radio_id);
				bss_user_info[i].online_user_num = ntohl(bss_user_info[i].online_user_num);
				bss_user_info[i].user_auth_request_count = ntohl(bss_user_info[i].user_auth_request_count);
				bss_user_info[i].user_auth_success_count = ntohl(bss_user_info[i].user_auth_success_count);
				bss_user_info[i].user_auth_logoff_abnormal_count = ntohl(bss_user_info[i].user_auth_logoff_abnormal_count);
				bss_user_info[i].user_auth_logoff_normal_count = ntohl(bss_user_info[i].user_auth_logoff_normal_count);
				bss_user_info[i].user_req_challenge_count = ntohl(bss_user_info[i].user_req_challenge_count);
				bss_user_info[i].user_ack_challenge_count = ntohl(bss_user_info[i].user_ack_challenge_count);
				bss_user_info[i].user_req_auth_count = ntohl(bss_user_info[i].user_req_auth_count);
				bss_user_info[i].user_ack_auth_success_count = ntohl(bss_user_info[i].user_ack_auth_success_count);
				bss_user_info[i].user_ack_auth_failure_count = ntohl(bss_user_info[i].user_ack_auth_failure_count);
				bss_user_info[i].user_access_request_count = ntohl(bss_user_info[i].user_access_request_count);
				bss_user_info[i].user_access_request_retry_count = ntohl(bss_user_info[i].user_access_request_retry_count);
				bss_user_info[i].user_access_request_timeout_count = ntohl(bss_user_info[i].user_access_request_timeout_count);
				bss_user_info[i].user_access_accept_count = ntohl(bss_user_info[i].user_access_accept_count);
				bss_user_info[i].user_access_reject_count = ntohl(bss_user_info[i].user_access_reject_count);
				bss_user_info[i].user_acct_request_start_count = ntohl(bss_user_info[i].user_acct_request_start_count);
				bss_user_info[i].user_acct_request_update_count = ntohl(bss_user_info[i].user_acct_request_update_count);
				bss_user_info[i].user_acct_request_stop_count = ntohl(bss_user_info[i].user_acct_request_stop_count);
				//bss_user_info[i].user_acct_request_retry_count = ntohl(bss_user_info[i].user_acct_request_retry_count);
				//bss_user_info[i].user_acct_response_count = ntohl(bss_user_info[i].user_acct_response_count);
			}
		}
			break;
		case ACK_GET_AP_USER_INFO:
		{
			_pkg_mng->data.ap_user_info.node_num = ntohl(_pkg_mng->data.ap_user_info.node_num);
			struct st_ap_user_info *ap_user_info = _pkg_mng->data.ap_user_info.info_array;
			for (i = 0; i < _pkg_mng->data.ap_user_info.node_num; i++)
			{
				ap_user_info[i].online_user_num = ntohl(ap_user_info[i].online_user_num);
				ap_user_info[i].user_auth_request_count = ntohl(ap_user_info[i].user_auth_request_count);
				ap_user_info[i].user_auth_success_count = ntohl(ap_user_info[i].user_auth_success_count);
				ap_user_info[i].user_auth_logoff_abnormal_count = ntohl(ap_user_info[i].user_auth_logoff_abnormal_count);
				ap_user_info[i].user_auth_logoff_normal_count = ntohl(ap_user_info[i].user_auth_logoff_normal_count);
				ap_user_info[i].user_req_challenge_count = ntohl(ap_user_info[i].user_req_challenge_count);
				ap_user_info[i].user_ack_challenge_count = ntohl(ap_user_info[i].user_ack_challenge_count);
				ap_user_info[i].user_req_auth_count = ntohl(ap_user_info[i].user_req_auth_count);
				ap_user_info[i].user_ack_auth_success_count = ntohl(ap_user_info[i].user_ack_auth_success_count);
				ap_user_info[i].user_ack_auth_failure_count = ntohl(ap_user_info[i].user_ack_auth_failure_count);
				ap_user_info[i].user_access_request_count = ntohl(ap_user_info[i].user_access_request_count);
				ap_user_info[i].user_access_request_retry_count = ntohl(ap_user_info[i].user_access_request_retry_count);
				ap_user_info[i].user_access_request_timeout_count = ntohl(ap_user_info[i].user_access_request_timeout_count);
				ap_user_info[i].user_access_accept_count = ntohl(ap_user_info[i].user_access_accept_count);
				ap_user_info[i].user_access_reject_count = ntohl(ap_user_info[i].user_access_reject_count);
				ap_user_info[i].user_acct_request_start_count = ntohl(ap_user_info[i].user_acct_request_start_count);
				ap_user_info[i].user_acct_request_update_count = ntohl(ap_user_info[i].user_acct_request_update_count);
				ap_user_info[i].user_acct_request_stop_count = ntohl(ap_user_info[i].user_acct_request_stop_count);
				//ap_user_info[i].user_acct_request_retry_count = ntohl(ap_user_info[i].user_acct_request_retry_count);
				//ap_user_info[i].user_acct_response_count = ntohl(ap_user_info[i].user_acct_response_count);
			}
		}
			break;
		default:
			break;
	}
	
	return;
}
#if 0
static int getpkg( int fd, int wait, STUserManagePkg **pp_usr_mng_pkg )
{

	ssize_t recvlen = 0;
	size_t buflen = 0;
	char buffer[5125];


	int done=0;

	memset(buffer, 0, sizeof(buffer));



	/* read whatever the client send to us */ 
	{
	
		fd_set fdset;
		struct timeval tv;
		int status;
		FD_ZERO(&fdset);
		FD_SET(fd,&fdset);
		
		tv.tv_sec = wait;
		tv.tv_usec = 0;
		/*log_dbg("wait = %d\n",wait);*/
		status = select(fd + 1, &fdset, (fd_set *) 0,(fd_set *) 0,&tv);
		/*log_dbg("status = %d", status );*/

		if( (status > 0) && FD_ISSET(fd, &fdset))
		{
			/*while( !done )*/
			{
				if (buflen + 2 >= sizeof(buffer)) { /* ensure space for a least one more byte + null */
					log_dbg("select error2222 !!!!");
					return -1;
				}
	
				if ((recvlen = recv(fd, buffer + buflen,  sizeof(buffer) - 1 - buflen, 0 )) < 0) {
					log_dbg( "errno == %d  %s ECONNRESET = %d ", errno, strerror(errno),ECONNRESET );
					if (errno != ECONNRESET)
						return -1;
				}
	
				if (recvlen == 0) done=1;
				
				buflen += recvlen;
				buffer[buflen] = 0;
			}
		}
	}
   
	
	if( buflen <= 0 )
	{
		/*log_dbg( "xxxxxxxx\n" );*/
		return -1;
	}
	
	*pp_usr_mng_pkg = (STUserManagePkg *)calloc( 1, buflen );
 
	if( NULL == *pp_usr_mng_pkg )
	{ 
		return -1;
	}
   
	memcpy( *pp_usr_mng_pkg, buffer, buflen );
	
	MNG_PKG_NTOH( *pp_usr_mng_pkg );

	return 0;
}
#endif
#if 0  // for test
static void log_buffer(char *buf, int n)
{
	char tmp[100] = "";  // len > 16*3
	int i = 0;

	log_dbg("log_buffer n=%d, buf =", n);
	for (i = 0; i < n; i++)
	{
		snprintf(tmp+(i%16)*3, 3, "%02X", (unsigned char)buf[i]);
		if ((i+1) % 16 == 0)
		{
			tmp[(i%16)*3+2] = '\0';
		}
		else if ((i+1) % 4 == 0)
		{
			tmp[(i%16)*3+2] = '*';
		}
		else
		{
			tmp[(i%16)*3+2] = ' ';
		}
		if ((i+1) % 16 == 0)
		{
			log_dbg("%d: %s", (i/16)*16, tmp);
			memset(tmp, 0, sizeof(tmp));
		}
	}
	if ((i%16) != 0)
		log_dbg("%d: %s", (i/16)*16, tmp);
}
#endif

#define PREFETCH_LEN sizeof(STUserManagePkg)

static int getpkg(int fd, int wait, STUserManagePkg **pp_usr_mng_pkg)
{
	//#define PREFETCH_LEN ((size_t) &((STUserManagePkg *)0)->len + sizeof(((STUserManagePkg *)0)->len))
	
	char buff[PREFETCH_LEN]={0};
	//char buff[sizeof(STUserManagePkg)]={0};
	time_t begin_time = time(NULL);
	time_t now;
	fd_set fdset;
	struct timeval tv;
	int status = 0;
	ssize_t n = 0;
	size_t recvlen = 0;
	int pkg_len = 0;
	int done = 0;
	STUserManagePkg *usr_mng_pkg = NULL;

	//log_dbg("getpkg PREFETCH_LEN=%d, wait=%d", PREFETCH_LEN, wait);
	for (now = time(NULL); now < begin_time + wait; now = time(NULL))
	{
		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
		tv.tv_sec = 0;
		tv.tv_usec = 500000;

		status = select(fd+1, &fdset, NULL, NULL, &tv);
		//log_dbg("getpkg select status=%d", status);
		/*status == 0, continue*/
		if (status < 0)
		{
			log_dbg("getpkg select status=%d, errno=%d", status, errno);
			/* how to handle? */
			if (EINTR != errno)
			{
				goto end;
			}
		}
		else if (status > 0 && FD_ISSET(fd, &fdset))
		{
			if (NULL == usr_mng_pkg)
			{
				n = recv(fd, buff + recvlen, PREFETCH_LEN - recvlen, 0);
				//log_dbg("getpkg recv buff n=%d", n);
				//log_buffer(buff + recvlen, n);
			}
			else
			{
				n = recv(fd, (char *)usr_mng_pkg + recvlen,  pkg_len - recvlen, 0);
				//log_dbg("getpkg recv usr_mng_pkg n=%d", n);
				//log_buffer((char *)usr_mng_pkg + recvlen, n);
			}
			
			if (0 == n)
			{
				log_dbg("getpkg recv n=%d", n);
				/* how to handle? tcp n == 0 is peer close*/
				goto end;
			}
			else if (n < 0)
			{
				log_dbg("getpkg recv n=%d, errno=%d", n, errno);
				/* how to handle? */
				if (EINTR != errno)
				{
					goto end;
				}
			}
			else if (n > 0)
			{
				recvlen += n;
				if (NULL == usr_mng_pkg && recvlen >= PREFETCH_LEN)
				{
					pkg_len = ((STUserManagePkg *)buff)->len;
					pkg_len = ntohl(pkg_len);
					//log_dbg("getpkg pkg_len=%d", pkg_len);
					if (pkg_len < PREFETCH_LEN)
					{
						goto end;
					}
					if ( (usr_mng_pkg = malloc(pkg_len)) == NULL)
					{
						goto end;
					}
					memset(usr_mng_pkg, 0, pkg_len);
					memcpy(usr_mng_pkg, buff, PREFETCH_LEN);
					recvlen = PREFETCH_LEN;
				}
				if (NULL != usr_mng_pkg && recvlen >= pkg_len)
				{
					done = 1;
					goto end;
				}
			}
		}
	}

end:
	if (done)
	{	
		*pp_usr_mng_pkg = usr_mng_pkg;
		//log_dbg("getpkg done pkg_len=%d", pkg_len);
		//log_buffer(*pp_usr_mng_pkg, pkg_len);
		MNG_PKG_NTOH(*pp_usr_mng_pkg);
		return 0;
	}
	if (NULL != usr_mng_pkg)
		free(usr_mng_pkg);
	*pp_usr_mng_pkg = NULL;
	return -1;
}

static int sendpkg( int fd, int wait, STUserManagePkg *pkg )
{
	ssize_t c;
	size_t r = 0;
	ssize_t len = 0;
	char *buf = NULL;
	int starttime;
	
	if( NULL == pkg )
		return -1;

	len = pkg->len;
	buf = (char *)pkg;
	starttime = time(0);
	
	MNG_PKG_HTON( pkg );
	
	/*log_dbg("before send data  len = %d\n", len);*/
	while( r < len && (time(0)<starttime+wait) ) 
	{
		fd_set fdset;
		struct timeval tv;
		
		FD_ZERO(&fdset);
		FD_SET(fd,&fdset);
		
		tv.tv_sec = 0;
		tv.tv_usec = 500000;
		
		if (select(fd + 1,(fd_set *) 0,&fdset,(fd_set *) 0,&tv) == -1)
		{
			log_dbg("sellect err!");
			break;
		}
		
		if (FD_ISSET(fd, &fdset))
			c = send(fd,buf+r,len-r,0);
		
		if (c <= 0) break;
		r += (size_t)c;
		
	}
	/*log_dbg("after send data r = %d  len = %d", r, len);*/
	if( len > r )
	{
		return -1;
	}
	/*log_dbg("send ok!!!");*/
	return 0;
}



struct app_conn_t * user_getstate(struct in_addr *addr);
int get_userip_by_reqpkg( STUserManagePkg * p_userpkg );


 
#endif

