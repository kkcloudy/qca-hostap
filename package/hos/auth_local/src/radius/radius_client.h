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
* radius_client.h
*
*
* CREATOR:
* autelan.software.WirelessControl. team
*
* DESCRIPTION:
* asd module
*
*
*******************************************************************************/

#ifndef RADIUS_CLIENT_H
#define RADIUS_CLIENT_H

#include "ip_addr.h"

struct radius_msg;
struct radius_coa_info;
struct asd_radius_server {
	/* MIB prefix for shared variables:
	 * @ = radiusAuth or radiusAcc depending on the type of the server */
	struct asd_ip_addr addr; /* @ServerAddress */
	int port; /* @ClientServerPortNumber */
	u8 *shared_secret;
	size_t shared_secret_len;

	/* Dynamic (not from configuration file) MIB data */
	int index; /* @ServerIndex */
	int round_trip_time; /* @ClientRoundTripTime; in hundredths of a
			      * second */
	u32 requests; /* @Client{Access,}Requests */
	u32 retransmissions; /* @Client{Access,}Retransmissions */
	u32 access_accepts; /* radiusAuthClientAccessAccepts */
	u32 access_rejects; /* radiusAuthClientAccessRejects */
	u32 access_challenges; /* radiusAuthClientAccessChallenges */
	u32 responses; /* radiusAccClientResponses */
	u32 malformed_responses; /* @ClientMalformed{Access,}Responses */
	u32 bad_authenticators; /* @ClientBadAuthenticators */
	u32 timeouts; /* @ClientTimeouts */
	u32 unknown_types; /* @ClientUnknownTypes */
	u32 packets_dropped; /* @ClientPacketsDropped */
	/* @ClientPendingRequests: length of wasd->radius->msgs for matching
	 * msg_type */
};

struct asd_radius_servers {
	/* RADIUS Authentication and Accounting servers in priority order */
	struct asd_radius_server *auth_servers, *auth_server;
	int num_auth_servers;
	struct asd_radius_server *acct_servers, *acct_server;
	int num_acct_servers;

	int retry_primary_interval;
	int acct_interim_interval;

	int msg_dumps;

	struct asd_ip_addr client_addr;			//ht add,081105
	int force_client_addr;
	u8 accounting_on_disable;				//ht add,090827
	u8 radius_extend_attr;				//ht add,091015
	unsigned int distribute_off;	//mahz add 2011.10.25
	unsigned int slot_value;		   //mahz add 2011.10.25
	unsigned int inst_value;		   //mahz add 2011.10.25
	//qiuchen add it for master_bak radius server 2012.12.11
	double radius_res_fail_percent;
	double radius_res_suc_percent;
	unsigned int radius_access_test_interval;
	unsigned int radius_server_change_test_timer;
	unsigned int radius_server_reuse_test_timer;
	unsigned char radius_heart_test_type;/*0-auth 1-acct 2-both*/
	unsigned char radius_server_binding_type;/*0-unbinded 1-binded*/
	u8 auth_server_current_use;/*2-not master_bak radius 0-master 1-bak*/
	u8 acct_server_current_use;/*2-not master_bak radius 0-master 1-bak*/
	unsigned int radius_auth_heart_req_num;
	unsigned int radius_acct_heart_req_num;
	unsigned int radius_auth_heart_res_num;
	unsigned int radius_acct_heart_res_num;
	unsigned int radius_auth_heart_fail_num;
	unsigned int radius_acct_heart_fail_num;
	unsigned char *c_test_window_auth;
	unsigned char *r_test_window_auth;
	unsigned char *c_test_window_acct;
	unsigned char *r_test_window_acct;
	unsigned int c_window_size;
	unsigned int r_window_size;
	//unsigned int heart_test_identifier_auth;
	//unsigned int heart_test_identifier_acct;
	//end 
};


typedef enum {
	RADIUS_AUTH,
	RADIUS_ACCT,
	RADIUS_ACCT_INTERIM, /* used only with radius_client_send(); just like
			     * RADIUS_ACCT, but removes any pending interim
			     * RADIUS Accounting packages for the same STA
			     * before sending the new interim update */
	RADIUS_DM		     
} RadiusType;

typedef enum {
	RADIUS_RX_PROCESSED,
	RADIUS_RX_QUEUED,
	RADIUS_RX_UNKNOWN,
	RADIUS_RX_INVALID_AUTHENTICATOR
} RadiusRxResult;
struct radius_send_info{
	struct radius_msg_info *msg;
	struct sta_info *sta;
	void *ctx;
};
struct radius_client_info{
	int sock,sock6;
	struct radius_send_info *sta[256];
	size_t num;

	u8 next_radius_identifier;
	
	struct radius_rx_handler *client_handlers;
	size_t num_client_handers;
	
	u32 acct_session_id_hi, acct_session_id_lo;
	struct radius_client_info *next;
	struct radius_client_data *ctx;

};
struct radius_client_data {
	void *ctx;
	struct asd_radius_servers *conf;

	int auth_serv_sock; /* socket for authentication RADIUS messages */
	int acct_serv_sock; /* socket for accounting RADIUS messages */
	int auth_serv_sock6;
	int acct_serv_sock6;
	int auth_sock; /* currently used socket */
	int acct_sock; /* currently used socket */
	int dm_sock; /*ht add,for receive message from radius server,090826*/
	

	u8 dm_radius_identifier;
	u8 accounting_on_disable;
	struct radius_client_info *auth;
	struct radius_client_info *acct;
};
//qiuchen
struct heart_test_radius_data{
	unsigned char SecurityID;
	int auth_serv_sock; /* socket for authentication RADIUS messages */
	int acct_serv_sock; /* socket for accounting RADIUS messages */
	int auth_serv_sock6;
	int acct_serv_sock6;
	int auth_sock; /* currently used socket */
	int acct_sock; /* currently used socket */
	u8 next_radius_identifier;
	int ieee802_1x; /* use IEEE 802.1X */
	struct asd_ip_addr own_ip_addr;
	struct asd_radius_servers *conf;
};
int radius_client_register(struct radius_client_info *radius_client,
			   RadiusRxResult (*handler)(struct radius_msg *msg,
						     struct radius_msg *req,
						     u8 *shared_secret,
						     size_t shared_secret_len,
						     void *data),
			   void *data);
int radius_client_send(struct radius_client_info *client_info,
		       struct radius_msg *msg, RadiusType msg_type,
		       struct sta_info *sta);
int radius_client_get_id(struct radius_client_info *client_info);

//void radius_client_flush(struct radius_client_data *radius, int only_auth);
struct radius_client_data *
radius_client_init(void *ctx, struct asd_radius_servers *conf);
void radius_client_deinit(struct radius_client_data *radius);
//void radius_client_flush_auth(struct radius_client_data *radius, u8 *addr);
int radius_client_get_mib(struct radius_client_data *radius, char *buf,
			  size_t buflen);
struct radius_client_data *
radius_client_reconfig(struct radius_client_data *old, void *ctx,
		       struct asd_radius_servers *oldconf,
		       struct asd_radius_servers *newconf);
int radius_client_init_acct(void *circle_ctx, void *timeout_ctx);
int radius_client_init_auth(void *circle_ctx, void *timeout_ctx);
struct radius_client_info *radius_client_get_sock(const int wlanid ,int auth);
void radius_client_info_free(struct radius_send_info *client_info);
struct radius_send_info *radius_client_get_sta_info(struct sta_info *sta,const int wlanid,RadiusType type);
void radius_client_info_deinit(struct radius_client_info *client_info);

void radius_client_dm_init();
void radius_receive_dm_message(int sock,void *circle_ctx,void *sock_ctx);
void radius_client_send_dm_message(struct radius_msg *msg, struct radius_coa_info *coa_info);
/*
static RadiusRxResult
radius_receive_dm(struct radius_msg *msg, struct radius_msg *req,
	struct radius_client_data *radius,
	 struct sockaddr *from_addr, int fromlen,
	 void *data);
*/
//qiuchen add it for master_bak radius server 2012.12.17
u8 radius_client_test_get_id(struct heart_test_radius_data *radius);
int radius_test_client_send_without_retrans(struct heart_test_radius_data *radius,struct radius_msg *msg, RadiusType msg_type);
int radius_test_client_init_auth(void *circle_ctx, void *timeout_ctx);
int radius_test_client_init_acct(void *circle_ctx, void *timeout_ctx);
int radius_change_server_both(unsigned char SID,unsigned char bak);
int radius_change_server_auth(unsigned char SID,unsigned char bak);
int radius_change_server_acct(unsigned char SID,unsigned char bak);
void radius_test_client_deinit(struct heart_test_radius_data *radius);
int radius_test_client_init(struct heart_test_radius_data *radius);
void radius_server_change(unsigned char SID,unsigned char type,unsigned char state);
void radius_test_client_receive(int sock, void *circle_ctx, void *sock_ctx);
//end
#endif /* RADIUS_CLIENT_H */
