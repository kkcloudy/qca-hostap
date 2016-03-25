
#ifndef _EAG_INTERFACE_H
#define _EAG_INTERFACE_H

#include <stdint.h>
#include "nm_list.h"



#define EAG_AUTH_TYPE_PORTAL	0
#define EAG_AUTH_TYPE_MAC		1

#define PORTAL_PROTOCOL_MOBILE		0
#define PORTAL_PROTOCOL_TELECOM		1

typedef enum {
	FLUX_FROM_IPTABLES = 0,
	FLUX_FROM_IPTABLES_L2,
	FLUX_FROM_WIRELESS,
	FLUX_FROM_FASTFWD,
	FLUX_FROM_FASTFWD_IPTABLES,
} FLUX_FROM_TYPE;

typedef enum {
	SHOW_LOG_BY_IP = 0,
	SHOW_LOG_BY_MAC,
	SHOW_LOG_BY_UNAME,
} SHOW_LOG_TYPE;

typedef enum {
	AUTELAN_LOG = 0,
	HENAN_LOG,
} LOG_FORMAT;

struct eag_base_conf {
	int status;
	uint32_t nasip;
	//int is_distributed;
	int rdc_distributed;
	int pdc_distributed;
	//int rdcpdc_slotid;
	//int rdcpdc_insid;
	int rdc_slotid;
	int rdc_insid;
	int pdc_slotid;
	int pdc_insid;
	uint16_t portal_port;
	int portal_retry_times;
	int portal_retry_interval;
	int auto_session;
	int radius_acct_interval;
	int radius_retry_interval;
	int radius_retry_times;
	int vice_radius_retry_times;
	int max_redir_times;
	int force_dhcplease;
	int check_errid;
	unsigned long idle_timeout;
	uint64_t idle_flow;
	int force_wireless;
	int flux_from;
	int flux_interval;
	uint32_t input_correct_factor;
	uint32_t output_correct_factor;
	int ipset_auth;
	int check_nasportid;
	int class_to_bandwidth;
	int trap_switch_abnormal_logoff;
	int trap_onlineusernum_switch;
	int threshold_onlineusernum;
	int portal_protocol;
	int macauth_switch;
	int macauth_type;
	int macauth_ipset_auth;
	int macauth_flux_from;
	int macauth_flux_interval;
	int macauth_flux_threshold;
	int macauth_check_interval;
	int macauth_notice_bindserver;
	int autelan_log;
	int henan_log;
	int l2super_vlan;
	int username_check;
	int telecom_idletime_valuecheck;
};

struct api_nasid_map_t {
	NASID_KEY_TYPE key_type;
	unsigned long keywd_1;	//wlanid vlanid wtpid iprange.ip_begin
	unsigned long keywd_2;	//iprange.ip_end
	char keystr[MAX_NASID_KEY_BUFF_LEN];	//interface
	char nasid[MAX_NASID_LEN];
	uint32_t conid;
};

struct api_nasid_conf {
	int current_num;
	struct api_nasid_map_t nasid_map[MAX_NASID_NUM];
};

/*eag_captive*/
#define MAX_IF_NAME_LEN			16
#define MIN_TAG_NUMBER			1
#define MAX_TAG_NUMBER			2048

#define CP_MAX_BW_DOMAIN_NAME_LEN	256
#define CP_MAX_PORTS_BUFF_LEN		128
#define CP_MAX_INTERFACE_NUM		128
#define CP_DEL_LIST				"cp_del_list"
#define CP_ADD_LIST				"cp_add_list"
#define CP_WHITE_LIST			"cp_white_list"
#define CP_BLACK_LIST			"cp_black_list"

typedef enum {
	RULE_IPADDR,
	RULE_DOMAIN,
} RULE_TYPE;

#define MAX_DOMAIN_IP_NUM	16

struct bw_rule_t {
	RULE_TYPE type;
	union {
		struct {
			unsigned long ipbegin;
			unsigned long ipend;
			char ports[CP_MAX_PORTS_BUFF_LEN];
		} ip;
		struct {
			char name[CP_MAX_BW_DOMAIN_NAME_LEN];
			int num;
			unsigned long ip[MAX_DOMAIN_IP_NUM];
		}domain;
		//char domain[CP_MAX_BW_DOMAIN_NAME_LEN];
	} key;
	char intf[MAX_IF_NAME_LEN];
	uint32_t tag;     /*policy id*/
};

#define MAX_BW_RULES_NUM	128
struct bw_rules{
	unsigned long curr_num;
	struct bw_rule_t rule[MAX_BW_RULES_NUM];
};

typedef struct{
	unsigned long curr_ifnum;
	char cpif[CP_MAX_INTERFACE_NUM][MAX_IF_NAME_LEN];
}eag_captive_intfs;

typedef struct{
	unsigned long curr_tagnum;
	uint32_t cptag[CP_MAX_INTERFACE_NUM];
}eag_captive_tag;

struct eag_bss_stat {
	struct list_head node;
	uint8_t ap_mac[6];
	uint8_t wlanid;
	uint8_t radioid;
	
	uint32_t online_user_num;
	uint32_t user_connect_total_time;
	/* macauth */
	uint32_t macauth_online_user_num;
	uint32_t macauth_user_connect_total_time;
#if 1
/* http信息: */	
	uint32_t http_redir_request_count;		//Portal页面请求数
	uint32_t http_redir_success_count;	//Portal页面成功推送数
#endif
/* portal信息: */
	/* challenge: */
	uint32_t challenge_req_count;		//challenge请求次数		REQ_CHALLENGE
	  					//challenge回复次数	ACK_CHALLENGE
	uint32_t challenge_ack_0_count;		//请求Challenge成功		ErrCode＝0
	uint32_t challenge_ack_1_count;		//请求Challenge被拒绝	ErrCode＝1
	uint32_t challenge_ack_2_count;		//此链接已建立		ErrCode＝2
	uint32_t challenge_ack_3_count;		//用户正在认证过程中	ErrCode＝3
	uint32_t challenge_ack_4_count;		//请求Challenge失败		ErrCode＝4

	/* auth */
	uint32_t auth_req_count;		//认证请求次数		REQ_AUTH
						//auth回复次数		ACK_AUTH
	uint32_t auth_ack_0_count;		//认证请求成功		ErrCode＝0
	uint32_t auth_ack_1_count;		//认证请求被拒绝		ErrCode＝1
	uint32_t auth_ack_2_count;		//此链接已建立		ErrCode＝2
	uint32_t auth_ack_3_count;		//用户正在认证过程中	ErrCode＝3
	uint32_t auth_ack_4_count;		//认证失败		ErrCode＝4
	/* macauth */
	uint32_t macauth_req_count;		//认证请求次数		REQ_AUTH
						//auth回复次数		ACK_AUTH
	uint32_t macauth_ack_0_count;		//认证请求成功		ErrCode＝0
	uint32_t macauth_ack_1_count;		//认证请求被拒绝		ErrCode＝1
	uint32_t macauth_ack_2_count;		//此链接已建立		ErrCode＝2
	uint32_t macauth_ack_3_count;		//用户正在认证过程中	ErrCode＝3
	uint32_t macauth_ack_4_count;		//认证失败		ErrCode＝4
	#if 0
	/* logout */
						//请求下线次数		REQ_LOGOUT
	uint32_t logout_req_0_count;		//请求下线次数		ErrCode＝0
	uint32_t logout_req_1_count;		//请求下线次数		ErrCode＝1
						//下线回复次数		ACK_LOGOUT
	uint32_t logout_ack_0_count;		//用户下线成功		ErrCode＝0
	uint32_t logout_ack_1_count;		//用户下线被拒绝	ErrCode＝1
	uint32_t logout_ack_2_count;		//用户下线失败		ErrCode＝2
	
	/* ntf logout */
	uint32_t ntf_logout_count;		//异常报文次数		NTF_LOGOUT
	#endif
	/* logoff count */
	uint32_t normal_logoff_count;		//正常下线次数
	uint32_t abnormal_logoff_count;		//异常下线次数
	uint32_t macauth_abnormal_logoff_count;
	/* 其他统计 */
	uint32_t challenge_timeout_count;	//Challenge超时次数
	uint32_t challenge_busy_count;		//Challenge忙碌次数	
	
	uint32_t req_auth_password_missing_count;//用户密码信息缺失次数
	uint32_t req_auth_unknown_type_count;	//未知类型错误次数
	uint32_t ack_auth_busy_count;		//auth忙碌次数
	uint32_t auth_disorder_count;		//auth过程乱续次数
	
/* radius信息: */
	/* access */
	uint32_t access_request_count;		//Radius的认证请求次数	Access-Request
	uint32_t access_request_retry_count;	//Radius的认证请求重传次数
	uint32_t access_request_timeout_count;	//Radius的认证请求超时次数
	uint32_t access_accept_count;		//Radius的认证通过次数	Access-Accept
	uint32_t access_reject_count;		//Radius的认证拒绝次数	Access-Reject
	
		
	/* accounting */
	uint32_t acct_request_start_count;	//计费开始请求次数		Accounting-Request(Start)
	uint32_t acct_request_start_retry_count;
	uint32_t acct_response_start_count;	//计费开始请求响应次数	Accounting-Response(Start)			
	
	uint32_t acct_request_update_count;	//计费更新次数		Accounting-Request(Interim-Update)
	uint32_t acct_request_update_retry_count;
	uint32_t acct_response_update_count;	//计费更新响应次数		Accounting-Response(Interim-Update)
	
	uint32_t acct_request_stop_count;	//计费停止请求次数		Accounting-Request(stop)
	uint32_t acct_request_stop_retry_count;
	uint32_t acct_response_stop_count;	//计费停止请求响应次数	Accounting-Response(stop)	
};

struct eag_ap_stat {
	struct list_head node;
	uint8_t ap_mac[6];
	
	uint32_t online_user_num;
	uint32_t user_connect_total_time;
	/* macauth */
	uint32_t macauth_online_user_num;
	uint32_t macauth_user_connect_total_time;
#if 1
/* http信息: */	
	uint32_t http_redir_request_count;		//Portal页面请求数
	uint32_t http_redir_success_count;	//Portal页面成功推送数
#endif
/* portal信息: */
	/* challenge: */
	uint32_t challenge_req_count;		//challenge请求次数		REQ_CHALLENGE
	  					//challenge回复次数	ACK_CHALLENGE
	uint32_t challenge_ack_0_count;		//请求Challenge成功		ErrCode＝0
	uint32_t challenge_ack_1_count;		//请求Challenge被拒绝	ErrCode＝1
	uint32_t challenge_ack_2_count;		//此链接已建立		ErrCode＝2
	uint32_t challenge_ack_3_count;		//用户正在认证过程中	ErrCode＝3
	uint32_t challenge_ack_4_count;		//请求Challenge失败		ErrCode＝4

	/* auth */
	uint32_t auth_req_count;		//认证请求次数		REQ_AUTH
						//auth回复次数		ACK_AUTH
	uint32_t auth_ack_0_count;		//认证请求成功		ErrCode＝0
	uint32_t auth_ack_1_count;		//认证请求被拒绝		ErrCode＝1
	uint32_t auth_ack_2_count;		//此链接已建立		ErrCode＝2
	uint32_t auth_ack_3_count;		//用户正在认证过程中	ErrCode＝3
	uint32_t auth_ack_4_count;		//认证失败		ErrCode＝4
	/* macauth */
	uint32_t macauth_req_count;		//认证请求次数		REQ_AUTH
						//auth回复次数		ACK_AUTH
	uint32_t macauth_ack_0_count;		//认证请求成功		ErrCode＝0
	uint32_t macauth_ack_1_count;		//认证请求被拒绝		ErrCode＝1
	uint32_t macauth_ack_2_count;		//此链接已建立		ErrCode＝2
	uint32_t macauth_ack_3_count;		//用户正在认证过程中	ErrCode＝3
	uint32_t macauth_ack_4_count;		//认证失败		ErrCode＝4
	#if 0
	/* logout */
						//请求下线次数		REQ_LOGOUT
	uint32_t logout_req_0_count;		//请求下线次数		ErrCode＝0
	uint32_t logout_req_1_count;		//请求下线次数		ErrCode＝1
						//下线回复次数		ACK_LOGOUT
	uint32_t logout_ack_0_count;		//用户下线成功		ErrCode＝0
	uint32_t logout_ack_1_count;		//用户下线被拒绝	ErrCode＝1
	uint32_t logout_ack_2_count;		//用户下线失败		ErrCode＝2
	
	/* ntf logout */
	uint32_t ntf_logout_count;		//异常报文次数		NTF_LOGOUT
	#endif
	/* logoff count */
	uint32_t normal_logoff_count;		//正常下线次数
	uint32_t abnormal_logoff_count;		//异常下线次数
	uint32_t macauth_abnormal_logoff_count;
	/* 其他统计 */
	uint32_t challenge_timeout_count;	//Challenge超时次数
	uint32_t challenge_busy_count;		//Challenge忙碌次数	
	
	uint32_t req_auth_password_missing_count;//用户密码信息缺失次数
	uint32_t req_auth_unknown_type_count;	//未知类型错误次数
	uint32_t ack_auth_busy_count;		//auth忙碌次数
	uint32_t auth_disorder_count;		//auth过程乱续次数
	
/* radius信息: */
	/* access */
	uint32_t access_request_count;		//Radius的认证请求次数	Access-Request
	uint32_t access_request_retry_count;	//Radius的认证请求重传次数
	uint32_t access_request_timeout_count;	//Radius的认证请求超时次数
	uint32_t access_accept_count;		//Radius的认证通过次数	Access-Accept
	uint32_t access_reject_count;		//Radius的认证拒绝次数	Access-Reject
	
		
	/* accounting */
	uint32_t acct_request_start_count;	//计费开始请求次数		Accounting-Request(Start)
	uint32_t acct_request_start_retry_count;
	uint32_t acct_response_start_count;	//计费开始请求响应次数	Accounting-Response(Start)			
	
	uint32_t acct_request_update_count;	//计费更新次数		Accounting-Request(Interim-Update)
	uint32_t acct_request_update_retry_count;
	uint32_t acct_response_update_count;	//计费更新响应次数		Accounting-Response(Interim-Update)
	
	uint32_t acct_request_stop_count;	//计费停止请求次数		Accounting-Request(stop)
	uint32_t acct_request_stop_retry_count;
	uint32_t acct_response_stop_count;	//计费停止请求响应次数	Accounting-Response(stop)	
};

struct eag_all_stat {
	uint32_t ap_num;
	uint32_t online_user_num;
	uint32_t user_connect_total_time;
	/* macauth */
	uint32_t macauth_online_user_num;
	uint32_t macauth_user_connect_total_time;
#if 1
/* http信息: */	
	uint32_t http_redir_request_count;		//Portal页面请求数
	uint32_t http_redir_success_count;	//Portal页面成功推送数
#endif
/* portal信息: */
	/* challenge: */
	uint32_t challenge_req_count;		//challenge请求次数		REQ_CHALLENGE
	  					//challenge回复次数	ACK_CHALLENGE
	uint32_t challenge_ack_0_count;		//请求Challenge成功		ErrCode＝0
	uint32_t challenge_ack_1_count;		//请求Challenge被拒绝	ErrCode＝1
	uint32_t challenge_ack_2_count;		//此链接已建立		ErrCode＝2
	uint32_t challenge_ack_3_count;		//用户正在认证过程中	ErrCode＝3
	uint32_t challenge_ack_4_count;		//请求Challenge失败		ErrCode＝4

	/* auth */
	uint32_t auth_req_count;		//认证请求次数		REQ_AUTH
						//auth回复次数		ACK_AUTH
	uint32_t auth_ack_0_count;		//认证请求成功		ErrCode＝0
	uint32_t auth_ack_1_count;		//认证请求被拒绝		ErrCode＝1
	uint32_t auth_ack_2_count;		//此链接已建立		ErrCode＝2
	uint32_t auth_ack_3_count;		//用户正在认证过程中	ErrCode＝3
	uint32_t auth_ack_4_count;		//认证失败		ErrCode＝4
	/* macauth */
	uint32_t macauth_req_count;		//认证请求次数		REQ_AUTH
						//auth回复次数		ACK_AUTH
	uint32_t macauth_ack_0_count;		//认证请求成功		ErrCode＝0
	uint32_t macauth_ack_1_count;		//认证请求被拒绝		ErrCode＝1
	uint32_t macauth_ack_2_count;		//此链接已建立		ErrCode＝2
	uint32_t macauth_ack_3_count;		//用户正在认证过程中	ErrCode＝3
	uint32_t macauth_ack_4_count;		//认证失败		ErrCode＝4
	#if 0
	/* logout */
						//请求下线次数		REQ_LOGOUT
	uint32_t logout_req_0_count;		//请求下线次数		ErrCode＝0
	uint32_t logout_req_1_count;		//请求下线次数		ErrCode＝1
						//下线回复次数		ACK_LOGOUT
	uint32_t logout_ack_0_count;		//用户下线成功		ErrCode＝0
	uint32_t logout_ack_1_count;		//用户下线被拒绝	ErrCode＝1
	uint32_t logout_ack_2_count;		//用户下线失败		ErrCode＝2
	
	/* ntf logout */
	uint32_t ntf_logout_count;		//异常报文次数		NTF_LOGOUT
	#endif
	/* logoff count */
	uint32_t normal_logoff_count;		//正常下线次数
	uint32_t abnormal_logoff_count;		//异常下线次数
	uint32_t macauth_abnormal_logoff_count;
	/* 其他统计 */
	uint32_t challenge_timeout_count;	//Challenge超时次数
	uint32_t challenge_busy_count;		//Challenge忙碌次数	
	
	uint32_t req_auth_password_missing_count;//用户密码信息缺失次数
	uint32_t req_auth_unknown_type_count;	//未知类型错误次数
	uint32_t ack_auth_busy_count;		//auth忙碌次数
	uint32_t auth_disorder_count;		//auth过程乱续次数
	
/* radius信息: */
	/* access */
	uint32_t access_request_count;		//Radius的认证请求次数	Access-Request
	uint32_t access_request_retry_count;	//Radius的认证请求重传次数
	uint32_t access_request_timeout_count;	//Radius的认证请求超时次数
	uint32_t access_accept_count;		//Radius的认证通过次数	Access-Accept
	uint32_t access_reject_count;		//Radius的认证拒绝次数	Access-Reject
	
		
	/* accounting */
	uint32_t acct_request_start_count;	//计费开始请求次数		Accounting-Request(Start)
	uint32_t acct_request_start_retry_count;
	uint32_t acct_response_start_count;	//计费开始请求响应次数	Accounting-Response(Start)			
	
	uint32_t acct_request_update_count;	//计费更新次数		Accounting-Request(Interim-Update)
	uint32_t acct_request_update_retry_count;
	uint32_t acct_response_update_count;	//计费更新响应次数		Accounting-Response(Interim-Update)
	
	uint32_t acct_request_stop_count;	//计费停止请求次数		Accounting-Request(stop)
	uint32_t acct_request_stop_retry_count;
	uint32_t acct_response_stop_count;	//计费停止请求响应次数	Accounting-Response(stop)	
};

#define USERNAMESIZE               256	/* Max length of username */

struct eag_user {
	struct list_head node;	
	char username[USERNAMESIZE];
	uint32_t userip;
	uint8_t usermac[6];
	uint32_t session_time;
	long accurate_start_time;
	uint64_t input_octets;
	uint64_t output_octets;	
	uint32_t input_packets;
	uint32_t output_packets;
	uint8_t apmac[6];
	uint32_t vlanid;
	int sta_state;
	uint32_t auth_tag;
};

struct eag_userdb {
	uint32_t num;
	struct list_head head;
};

struct eag_id_range_t {
	unsigned long begin;
	unsigned long end;
};
#if 0
int
eag_set_nasip(DBusConnection *connection, 
				int hansitype, int insid,
				uint32_t nasip);
/*
int
eag_set_distributed(DBusConnection *connection, 
				int hansitype, int insid,
			int distributed);
*/

int
eag_set_rdc_distributed(DBusConnection *connection, 
				int hansitype, int insid,
				int rdc_distributed);
int
eag_set_pdc_distributed(DBusConnection *connection, 
				int hansitype, int insid,
				int pdc_distributed);
/*
int
eag_set_rdcpdc_ins(DBusConnection *connection, 
				int hansitype, int insid,
				int rdcpdc_slotid, int rdcpdc_insid);
*/	
int
eag_set_rdc_ins(DBusConnection *connection, 
				int hansitype, int insid,
				int rdc_slotid, int rdc_insid);
				
int
eag_set_pdc_ins(DBusConnection *connection, 
				int hansitype, int insid,
				int pdc_slotid, int pdc_insid);

int
eag_set_portal_port(DBusConnection *connection, 
				int hansitype,int insid,
				uint16_t portal_port);

int
eag_set_portal_retry_params(DBusConnection *connection, 
				int hansitype, int insid,
				int retry_interval,
				int retry_times);

int
eag_set_auto_session(DBusConnection *connection, 
				int hansitype, int insid,
				int auto_session);


int
eag_set_acct_interval( DBusConnection *connection, 
				int hansitype, int insid, 					
				int acct_interval);

int
eag_set_radius_retry_params( DBusConnection *connection, 
				int hansitype, int insid,					
				int retry_interval,
				int retry_times,
				int vice_retry_times);

int
eag_set_max_redir_times( DBusConnection *connection, 
				int hansitype, int insid,
				int max_redir_times);

int
eag_set_force_dhcplease(DBusConnection *connection, 
				int hansitype, int insid,
				int force_dhcplease);

int
eag_set_check_errid(DBusConnection *connection, 
				int hansitype, int insid,
				int check_errid);

int
eag_set_idle_params( DBusConnection *connection, 
				int hansitype, int insid,
				unsigned long idle_timeout,
				uint64_t idle_flow);

int
eag_set_force_wireless(DBusConnection *connection, 
				int hansitype, int insid,
				int force_wireless);

int
eag_set_flux_from( DBusConnection *connection, 
							int hansitype, int insid,
							int flux_from);

int
eag_set_flux_interval( DBusConnection *connection, 
							int hansitype, int insid,
							int flux_interval);

int
eag_set_ipset_auth(DBusConnection *connection, 
				int hansitype, int insid,
				int ipset_auth);

int
eag_set_check_nasportid(DBusConnection *connection, 
				int hansitype, int insid,
				int check_nasportid);

int
eag_set_octets_correct_factor( DBusConnection *connection, 
				int hansitype, int insid,
				uint32_t input_correct_factor,
				uint32_t output_correct_factor);

int
eag_set_services_status( DBusConnection *connection, 
				int hansitype, int insid,
				int status);

int
eag_set_portal_protocol(DBusConnection *connection, 
				int hansitype, int insid,
				int portal_protocol);
				
int
eag_set_telecom_idletime_valuecheck(DBusConnection *connection, 
				int hansitype, int insid,
				int value_check);

int
eag_set_l2super_vlan_switch(DBusConnection *connection, 
				int hansitype, int insid,
				int l2super_vlan_switch);

int
eag_set_macauth_switch(DBusConnection *connection, 
				int hansitype, int insid,
				int macauth_switch);

int
eag_set_macauth_type(DBusConnection *connection, 
				int hansitype, int insid,
				int macauth_type);

int
eag_set_macauth_ipset_auth(DBusConnection *connection, 
				int hansitype, int insid,
				int ipset_auth);

int
eag_set_macauth_flux_from( DBusConnection *connection, 
				int hansitype, int insid,
				int flux_from);

int
eag_set_macauth_flux_interval(DBusConnection *connection, 
				int hansitype, int insid,
				int flux_interval);

int
eag_set_macauth_flux_threshold(DBusConnection *connection, 
				int hansitype, int insid,
				int flux_threshold, int check_interval);
int
eag_set_macauth_notice_bindserver(DBusConnection *connection,
				int hansitype, int insid,
				int notice_bindserver);

int
eag_get_base_conf( DBusConnection *connection, 
				int hansitype, int insid,
				struct eag_base_conf *baseconf);

int
eag_get_relative_time (DBusConnection *connection, 
				int hansitype, int insid, 
				unsigned long *timenow );

int
eag_add_nasid( DBusConnection *connection, 
				int hansitype,int insid,
				struct nasid_map_t *nasidmap);

int
eag_modify_nasid( DBusConnection *connection, 
				int hansitype,int insid,
				struct nasid_map_t *nasidmap);

int
eag_del_nasid( DBusConnection *connection, 
				int hansitype,int insid,
				struct nasid_map_t *nasidmap);

int 
eag_get_nasid ( DBusConnection *connection, 
				int hansitype,int insid,
				struct api_nasid_conf *nasidconf);

int
eag_add_nasportid( DBusConnection *connection, 
				int hansitype,int insid, 
				struct eag_id_range_t wlanid,
				struct eag_id_range_t wtpid,
				struct eag_id_range_t vlanid,
				unsigned long key_type,
				unsigned long nasportid);
int
eag_del_nasportid( DBusConnection *connection, 
				int hansitype,int insid, 
				struct eag_id_range_t wlanid,
				struct eag_id_range_t wtpid,
				struct eag_id_range_t vlanid,
				unsigned long key_type,
				unsigned long nasportid);

int
eag_get_nasportid ( DBusConnection *connection, 
				int hansitype,int insid,
				struct nasportid_conf *nasportid);

int
eag_add_captive_intf( DBusConnection *connection, 
				int hansitype, int insid,
				char *intfs );

int
eag_del_captive_intf(DBusConnection *connection, 
				int hansitype, int insid, 
				char *intfs);

int
eag_get_captive_intfs(DBusConnection *connection, 
				int hansitype, int insid, 
				eag_captive_intfs *captive_intfs);

int
eag_add_captive_tag( DBusConnection *connection, 
				int hansitype, int insid,
				uint32_t tag);

int
eag_del_captive_tag( DBusConnection *connection, 
				int hansitype, int insid,
				uint32_t tag);

int
eag_get_captive_tag(DBusConnection *connection, 
				int hansitype, int insid, 
				eag_captive_tag *captive_tag);

int
eag_conf_captive_list(DBusConnection *connection, 
				int hansitype, int insid,
				RULE_TYPE type_tmp, char *iprange, char *portset, char * domain, char * intfs, uint32_t tag,
				char *add_or_del, char *white_or_black);

int
eag_show_white_list(DBusConnection *connection, 
				int hansitype, int insid,
				struct bw_rules *white);

int
eag_show_black_list(DBusConnection *connection, 
				int hansitype, int insid,
				struct bw_rules *black);

int
eag_add_portal_server( DBusConnection *connection, 
				int hansitype, int insid, 					
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				const char *keystr,
				const char *portal_url, 
				uint16_t ntf_port,
				const char *domain,
				uint32_t mac_server_ip,
				uint16_t mac_server_port);

int
eag_modify_portal_server( DBusConnection *connection, 
				int hansitype, int insid, 					
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				const char *keystr,
				const char *portal_url, 
				unsigned short ntf_port,
				const char *domain,
				uint32_t mac_server_ip,
				uint16_t mac_server_port);

int
eag_del_portal_server( DBusConnection *connection, 
				int hansitype, int insid, 					
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *keystr);

int
eag_set_macbind_server( DBusConnection *connection, 
				int hansitype, int insid, 					
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				const char *keystr,
				int ip_or_domain,
				char *domain,
				uint32_t macbind_server_ip,
				uint16_t macbind_server_port);

int
eag_get_portal_conf( DBusConnection *connection, 
				int hansitype, int insid, 					
				struct portal_conf *portalconf);

int
eag_set_portal_server_acname( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				const char *acname );

int
eag_set_portal_server_acip_to_url( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int acip_to_url);

int
eag_set_portal_server_nasid_to_url( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int nasid_to_url);

int
eag_set_portal_server_wlanparameter( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int status,
				char *deskey);


int
eag_set_portal_server_wlanuserfirsturl( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int wlanuserfirsturl );


int
eag_set_portal_server_url_suffix( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				const char *url_suffix );

int
eag_set_portal_server_secret( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				const char *key_word,
				const char *secret );

int
eag_set_portal_server_wlanapmac( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int wlanapmac_to_url );

int
eag_set_portal_server_usermac_to_url( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int usermac_to_url );

int
eag_set_portal_server_clientmac_to_url( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int clientmac_to_url );
				
int
eag_set_portal_server_apmac_to_url( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int apmac_to_url );
				
int
eag_set_portal_server_wlan_to_url( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int wlan_to_url );
				
int
eag_set_portal_server_redirect_to_url( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int redirect_to_url );

int
eag_set_portal_server_wlanusermac( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int status,
				char *deskey);

int
eag_set_portal_server_wisprlogin( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int status,
				char *type);

int
eag_set_portal_server_mobile_urlparam( DBusConnection *connection, 
				int hansitype, int insid, 	
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				int mobile_urlparam );

int
eag_set_portal_server_urlparam( DBusConnection *connection, 
				int hansitype, int insid, 
				PORTAL_KEY_TYPE key_type, 
				unsigned long keyid, 
				char *key_word, 
				int add_or_del, 
				char *url_param );

int
eag_show_portal_server_urlparam( DBusConnection *connection, 
				int hansitype, int insid, 
				PORTAL_KEY_TYPE key_type,
				unsigned long keyid,
				char *key_word,
				struct portal_srv_t *portal_srv );

int
eag_add_radius( DBusConnection *connection, 
				int hansitype, int insid, 					
				char *domain,
				uint32_t auth_ip,
				uint16_t auth_port,
				char *auth_secret,
				uint32_t acct_ip,
				uint16_t acct_port,
				char *acct_secret,
				uint32_t backup_auth_ip,
				uint16_t backup_auth_port,
				char *backup_auth_secret,
				uint32_t backup_acct_ip,
				uint16_t backup_acct_port,
				char *backup_acct_secret );

int
eag_modify_radius( DBusConnection *connection, 
				int hansitype, int insid, 					
				char *domain,
				uint32_t auth_ip,
				uint16_t auth_port,
				char *auth_secret,
				uint32_t acct_ip,
				uint16_t acct_port,
				char *acct_secret,
				uint32_t backup_auth_ip,
				uint16_t backup_auth_port,
				char *backup_auth_secret,
				uint32_t backup_acct_ip,
				uint16_t backup_acct_port,
				char *backup_acct_secret );

int
eag_del_radius( DBusConnection *connection, 
				int hansitype, int insid, 
				const char *domain );

int
eag_get_radius_conf(DBusConnection *connection, 
				int hansitype, int insid, 
				char *domain,
				struct radius_conf *radiusconf );

int
eag_set_remove_domain_switch(DBusConnection *connection, 
				int hansitype, int insid, 
				char *domain,
				int remove_domain_switch);

int
eag_set_class_to_bandwidth_switch(DBusConnection *connection, 
				int hansitype, int insid,
				char *domain,
				int class_to_bandwidth);

int
eag_get_bss_statistics (DBusConnection *connection, 
				int hansitype, int insid, 
				struct list_head *bss_stat );

int 
eag_free_bss_statistics (struct list_head *bss_stat);

int
eag_get_ap_statistics (DBusConnection *connection, 
				int hansitype, int insid,
				struct list_head *ap_stat );

int
eag_free_ap_statistics (struct list_head *ap_stat);

int
eag_get_eag_statistics (DBusConnection *connection, 
				int hansitype, int insid, 
				struct eag_all_stat *eag_stat);

int
eag_userdb_init(struct eag_userdb *userdb);

int
eag_userdb_destroy(struct eag_userdb *userdb);

int
eag_show_user_all(DBusConnection *connection,
				int hansitype, int insid,
				struct eag_userdb *userdb);

int
eag_show_user_by_username(DBusConnection *connection,
				int hansitype, int insid,
				struct eag_userdb *userdb,
				const char *username);

int
eag_show_user_by_userip(DBusConnection *connection,
				int hansitype, int insid,
				struct eag_userdb *userdb,
				uint32_t userip);

int
eag_show_user_by_usermac(DBusConnection *connection,
				int hansitype, int insid,
				struct eag_userdb *userdb,
				uint8_t usermac[6]);

int
eag_show_user_by_index(DBusConnection *connection,
				int hansitype, int insid,
				struct eag_userdb *userdb,
				uint32_t index);

int
eag_kick_user_by_username(DBusConnection *connection,
				int hansitype, int insid,
				const char *username);

int
eag_kick_user_by_userip(DBusConnection *connection,
				int hansitype, int insid,
				uint32_t userip);

int
eag_kick_user_by_usermac(DBusConnection *connection,
				int hansitype, int insid,
				uint8_t usermac[6]);

int
eag_kick_user_by_index(DBusConnection *connection,
				int hansitype, int insid,
				uint32_t index);

int
eag_set_user_log_status( DBusConnection *connection, 
				int hansitype, int insid,
				int status);

int
eag_set_log_format_status( DBusConnection *connection, 
				int hansitype, int insid,
				int key, int status);
int
eag_set_username_check_status( DBusConnection *connection, 
				int hansitype, int insid,
				int status);

int
eag_add_debug_filter( DBusConnection *connection, 
				int hansitype,int insid, 					
				char *filter );
int
eag_del_debug_filter( DBusConnection *connection, 
				int hansitype,int insid, 					
				char *filter );

int
eag_del_debug_filter( DBusConnection *connection, 
				int hansitype,int insid, 					
				char *filter );

int
eag_log_all_redirconn( DBusConnection *connection, 
				int hansitype,int insid );

int
eag_log_all_portalsess( DBusConnection *connection, 
				int hansitype,int insid );

int
eag_log_all_sockradius( DBusConnection *connection, 
				int hansitype,int insid );

int
eag_log_all_thread( DBusConnection *connection, 
				int hansitype,int insid );

int
eag_log_all_blkmem( DBusConnection *connection, 
				int hansitype,int insid );

int
eag_log_all_mac_preauth( DBusConnection *connection, 
				int hansitype,int insid );

int
eag_set_rdc_client_log( DBusConnection *connection, 
				int hansitype,int insid, 					
				int flag );

int
eag_set_pdc_client_log( DBusConnection *connection, 
				int hansitype,int insid, 					
				int flag );

#endif
#endif

