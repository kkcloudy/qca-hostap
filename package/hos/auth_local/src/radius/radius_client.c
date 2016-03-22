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
* AsdRadiusClient.c
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

#include "includes.h"

#include "common.h"
#include "radius.h"
#include "radius_client.h"
#include "circle.h"
#include "../../app/ASDEapolSM.h"
#include "../../app/asd.h"
#include "wcpss/waw.h"
#include "wcpss/asd/asd.h"
#include "../rdc_handle.h"
#include "../rdc_packet.h"
#include "../ASDDbus.h"
#include "../asd_bak.h"//qiuchen
#include "../ASDCallback_asd.h"
#include "../ASD8021XOp.h"
#include "../ASDStaInfo.h"
/* Defaults for RADIUS retransmit values (exponential backoff) */
#define RADIUS_CLIENT_FIRST_WAIT 3 /* seconds */
#define RADIUS_CLIENT_MAX_WAIT 120 /* seconds */
#define RADIUS_CLIENT_MAX_RETRIES 10 /* maximum number of retransmit attempts
				      * before entry is removed from retransmit
				      * list */
#define RADIUS_CLIENT_MAX_ENTRIES 30 /* maximum number of entries in retransmit
				      * list (oldest will be removed, if this
				      * limit is exceeded) */
#define RADIUS_CLIENT_NUM_FAILOVER 4 /* try to change RADIUS server after this
				      * many failed retry attempts */
#define SLOT_IPV4_BASE  0XA9FE0200 /* 169.254.2.0 */
#define RDC_RADIUS_PORT_BASE	4150
#define ASD_RDC_COA_PORT_BASE 4300

static int radius_auth_server_connect_failed_times;
static int radius_acct_server_connect_failed_times;
static int radius_auth_serv_sock_creat_failed_times = 0;
static int radius_acct_serv_sock_creat_failed_times = 0;
//static int dm_sock = 0;

/*
static int radius_auth_server_connect_failed;
static int radius_auth_server_connect_failed_old;
static int radius_acct_server_connect_failed;
static int radius_acct_server_connect_failed_old;
*/
struct radius_rx_handler {
	RadiusRxResult (*handler)(struct radius_msg *msg,
				  struct radius_msg *req,
				  u8 *shared_secret, size_t shared_secret_len,
				  void *data);
	void *data;
};


/* RADIUS message retransmit list */
struct radius_msg_list {
	u8 addr[ETH_ALEN]; /* STA/client address; used to find RADIUS messages
			    * for the same STA. */
	struct radius_msg *msg;
	RadiusType msg_type;
	os_time_t first_try;
	os_time_t next_try;
	int attempts;
	int next_wait;
	struct os_time last_attempt;

	u8 *shared_secret;
	size_t shared_secret_len;

	/* TODO: server config with failover to backup server(s) */

	struct radius_msg_list *next;
};
struct radius_msg_info {
	struct radius_msg *msg;
	RadiusType msg_type;
	os_time_t first_try;
	os_time_t next_try;
	int attempts;
	int next_wait;
	struct os_time last_attempt;

	u8 *shared_secret;
	size_t shared_secret_len;
};
extern unsigned char FD_CHANGE;
#if 0
struct radius_client_data {
	void *ctx;
	struct asd_radius_servers *conf;

	int auth_serv_sock; /* socket for authentication RADIUS messages */
	int acct_serv_sock; /* socket for accounting RADIUS messages */
	int auth_serv_sock6;
	int acct_serv_sock6;
	int auth_sock; /* currently used socket */
	int acct_sock; /* currently used socket */

	struct radius_rx_handler *auth_handlers;
	size_t num_auth_handlers;
	struct radius_rx_handler *acct_handlers;
	size_t num_acct_handlers;

	struct radius_msg_list *msgs;
	size_t num_msgs;

	u8 next_radius_identifier;
};
#endif

static int
radius_change_server(struct radius_client_info *radius_client,
		     struct asd_radius_server *nserv,
		     struct asd_radius_server *oserv,
		     int sock, int sock6, int auth);


/*static void radius_client_msg_free(struct radius_msg_info *req)
{
	radius_msg_free(req->msg);
	os_free(req->msg);
	os_free(req);
}*/
int radius_client_register(struct radius_client_info *radius_client,
			   RadiusRxResult (*handler)(struct radius_msg *msg,
						     struct radius_msg *req,
						     u8 *shared_secret,
						     size_t shared_secret_len,
						     void *data),
			   void *data)
{
	struct radius_rx_handler **handlers, *newh;
	size_t *num;

	handlers = &radius_client->client_handlers;
	num = &radius_client->num_client_handers;
	
	newh = os_realloc(*handlers,
			  (*num + 1) * sizeof(struct radius_rx_handler));
	if (newh == NULL)
		return -1;

	newh[*num].handler = handler;
	newh[*num].data = data;
	(*num)++;
	*handlers = newh;

	return 0;
}
static void radius_test_client_handle_send_error(struct heart_test_radius_data *radius,int s,RadiusType msg_type){
	int _errno = errno;
	asd_printf(ASD_DEFAULT,MSG_WARNING,"%s sendtoradius %s\n",__func__,strerror(errno));
	perror("send[RADIUS]");
	if (_errno == ENOTCONN || _errno == EDESTADDRREQ || _errno == EINVAL ||
	    _errno == EBADF) {
	asd_printf(ASD_80211,MSG_DEBUG,"Send failed - maybe interface status changed -"
			       " try to connect again");
		circle_unregister_read_sock(s);
		FD_CHANGE = 1;
		close(s);
		if (msg_type == RADIUS_ACCT)
			radius_test_client_init_acct((void*)radius, (void *)0);
		else
			radius_test_client_init_auth((void*)radius, (void *)0);
	}
}

static void radius_client_handle_send_error(struct radius_client_info *client_info,
					    int s, RadiusType msg_type)
{
	int _errno = errno;
	perror("send[RADIUS]");
	if (_errno == ENOTCONN || _errno == EDESTADDRREQ || _errno == EINVAL ||
	    _errno == EBADF) {
		asd_printf(ASD_DEFAULT,MSG_INFO,"Send failed - maybe interface status changed -"
				" try to connect again");
		circle_unregister_read_sock(s);
		FD_CHANGE = 1;
		close(s);
		if (msg_type == RADIUS_ACCT || msg_type == RADIUS_ACCT_INTERIM)
		{
			radius_client_init_acct((void*)client_info, (void *)1);
		}
		else
		{
			radius_client_init_auth((void*)client_info, (void *)1);
		}
	}
}


static int radius_client_retransmit(struct radius_send_info *send_info,
				    struct radius_msg_info *entry,
				    os_time_t now)
{
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"in func:%s\n",__func__);
	struct radius_client_info *client_info = send_info->ctx;
	struct radius_client_data *radius = client_info->ctx;
	struct asd_radius_servers *conf = radius->conf;
	int s;
	int res;
	socklen_t addrlen = 0;
	struct sockaddr_in serv;
	struct sockaddr *serv_addr = NULL;
	struct asd_radius_server *nserv;
#ifdef ASD_IPV6
		struct sockaddr_in6 serv6;
#endif

	if (entry->msg_type == RADIUS_ACCT ||
	    entry->msg_type == RADIUS_ACCT_INTERIM) {
		s = client_info->sock;
		nserv = conf->acct_server;
		if (entry->attempts == 0)
			conf->acct_server->requests++;
		else {
			conf->acct_server->timeouts++;
			conf->acct_server->retransmissions++;
			radius_acct_server_connect_failed_times++;
		}
	} else {
		s = client_info->sock;
		nserv = conf->auth_server;
		if (entry->attempts == 0)
			conf->auth_server->requests++;
		else {
			conf->auth_server->timeouts++;
			conf->auth_server->retransmissions++;
			radius_auth_server_connect_failed_times++;
		}
	}

	switch (nserv->addr.af) {
	case AF_INET:
		os_memset(&serv, 0, sizeof(serv));
		serv.sin_family = AF_INET;
		serv.sin_addr.s_addr = nserv->addr.u.v4.s_addr;
		serv.sin_port = htons(nserv->port);
		serv_addr = (struct sockaddr *) &serv;
		addrlen = sizeof(serv);
		break;
#ifdef ASD_IPV6
	case AF_INET6:
		os_memset(&serv6, 0, sizeof(serv6));
		serv6.sin6_family = AF_INET6;
		os_memcpy(&serv6.sin6_addr, &nserv->addr.u.v6,
			  sizeof(struct in6_addr));
		serv6.sin6_port = htons(nserv->port);
		serv_addr = (struct sockaddr *) &serv6;
		addrlen = sizeof(serv6);
		break;
#endif /* ASD_IPV6 */
	default:
		break;
	}
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"%s server.ip: %s\n",__func__, inet_ntoa(serv.sin_addr));		//for test
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"%s server.port: %d\n",__func__, ntohs(serv.sin_port)); 	//for test
	
	/* retransmit; remove entry if too many attempts */
	entry->attempts++;

	os_get_time(&entry->last_attempt);

	
	if(conf->distribute_off)
		res = sendto(s, entry->msg->buf, entry->msg->buf_used, 0,serv_addr,addrlen);//qiuchen
	else
		res = rdc_sendto(s, entry->msg->buf, entry->msg->buf_used, 0, serv_addr, addrlen, conf->slot_value, conf->inst_value);
	if (res < 0)
		radius_client_handle_send_error(client_info, s, entry->msg_type);

	if(conf->distribute_off)
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"%s after successfully send to radius server\n",__func__);
	else
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"%s after successfully send to rdc server\n",__func__);		//for test
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"%s send length %d\n",__func__,res);		//for test

	entry->next_try = now + entry->next_wait;
	entry->next_wait *= 2;
	if (entry->next_wait > RADIUS_CLIENT_MAX_WAIT)
		entry->next_wait = RADIUS_CLIENT_MAX_WAIT;
	if (entry->attempts >= RADIUS_CLIENT_MAX_RETRIES) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Removing un-ACKed RADIUS message due to too many "
		       "failed retransmit attempts\n");
		return 1;
	}

	return 0;
}


static void radius_client_timer(void *circle_ctx, void *timeout_ctx)
{
	struct radius_send_info *send_info = circle_ctx;
	struct radius_client_info *client_info = send_info->ctx;
	struct radius_client_data *radius = client_info->ctx;
	struct asd_radius_servers *conf = radius->conf;
	struct os_time now;
	struct radius_msg_info *entry;
	int auth_failover = 0, acct_failover = 0;
	char abuf[50];

	entry = send_info->msg;
	if(!entry)
		return;

	os_get_time(&now);
	if(now.sec >= entry->next_try &&
		radius_client_retransmit(send_info,entry,now.sec))
	{
		radius_client_info_free(send_info);	
		send_info = NULL;
		entry = NULL;
	}
	 if (entry&&entry->attempts > RADIUS_CLIENT_NUM_FAILOVER) {
			if (entry->msg_type == RADIUS_ACCT ||
			    entry->msg_type == RADIUS_ACCT_INTERIM)
				acct_failover++;
			else
				auth_failover++;
		}

	if (radius_auth_server_connect_failed_times > 4) {		//ht 090403
		signal_radius_connect_failed(asd_ip_txt(&conf->auth_server->addr, abuf, sizeof(abuf)),0);
	}
	if (radius_acct_server_connect_failed_times > 4) {
		signal_radius_connect_failed(asd_ip_txt(&conf->acct_server->addr, abuf, sizeof(abuf)),1);
	}

/*
	if (auth_failover) {		//ht 090224
		radius_auth_server_connect_failed = 1;
		signal_radius_connect_failed(asd_ip_txt(&conf->auth_server->addr, abuf, sizeof(abuf)),0);
	}
	if (acct_failover) {
		radius_acct_server_connect_failed = 1;
		signal_radius_connect_failed(asd_ip_txt(&conf->acct_server->addr, abuf, sizeof(abuf)),1);
	}
*/
	if(send_info != NULL)
	{
		circle_register_timeout((send_info->msg->next_try - now.sec),0,radius_client_timer,send_info,NULL);
		asd_logger(radius->ctx,NULL,asd_MODULE_RADIUS,
			asd_LEVEL_DEBUG,"Next RADIUS client retransmit in %ld seconds",
			(long int )(send_info->msg->next_try-now.sec));
	}
	/*
	if (auth_failover && conf->num_auth_servers > 1) {
		struct asd_radius_server *next, *old;
		old = conf->auth_server;
		asd_logger(radius->ctx, NULL, asd_MODULE_RADIUS,
			       asd_LEVEL_NOTICE,
			       "No response from Authentication server "
			       "%s:%d - failover",
			       asd_ip_txt(&old->addr, abuf, sizeof(abuf)),
			       old->port);

		for (entry = radius->msgs; entry; entry = entry->next) {
			if (entry->msg_type == RADIUS_AUTH)
				old->timeouts++;
		}

		next = old + 1;
		if (next > &(conf->auth_servers[conf->num_auth_servers - 1]))
			next = conf->auth_servers;
		conf->auth_server = next;
		radius_change_server(radius, next, old,
				     radius->auth_serv_sock,
				     radius->auth_serv_sock6, 1);
	}

	if (acct_failover && conf->num_acct_servers > 1) {
		struct asd_radius_server *next, *old;
		old = conf->acct_server;
		asd_logger(radius->ctx, NULL, asd_MODULE_RADIUS,
			       asd_LEVEL_NOTICE,
			       "No response from Accounting server "
			       "%s:%d - failover",
			       asd_ip_txt(&old->addr, abuf, sizeof(abuf)),
			       old->port);

		for (entry = radius->msgs; entry; entry = entry->next) {
			if (entry->msg_type == RADIUS_ACCT ||
			    entry->msg_type == RADIUS_ACCT_INTERIM)
				old->timeouts++;
		}

		next = old + 1;
		if (next > &conf->acct_servers[conf->num_acct_servers - 1])
			next = conf->acct_servers;
		conf->acct_server = next;
		radius_change_server(client_info, next, old,
				     radius->acct_serv_sock,
				     radius->acct_serv_sock6, 0);
	}*/
}
struct radius_send_info *radius_client_get_sta_info(struct sta_info *sta,const int wlanid,RadiusType type)
{
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"in func:%s\n",__func__);
	if(!sta ||!ASD_WLAN[wlanid])
		return NULL;
	if(!ASD_WLAN[wlanid]->radius)
		return NULL;
	struct radius_client_info *client_info;
	int radius_id = -1;;
	if(sta&&sta->eapol_sm)
		radius_id = sta->eapol_sm->radius_identifier;
	if(radius_id < 0 ||radius_id > 255)
	{
		asd_printf(ASD_DEFAULT,MSG_INFO,"free send_info,sta radius_id is %d error!\n",radius_id);
		return NULL;
	}
	if(RADIUS_AUTH == type)
		client_info = ASD_WLAN[wlanid]->radius->auth;
	else
		client_info = ASD_WLAN[wlanid]->radius->acct;		
	while(client_info)
	{
		if(client_info->sta[radius_id]&&client_info->sta[radius_id]->sta)
		{
			if(!os_memcmp(client_info->sta[radius_id]->sta->addr,sta->addr,MAC_LEN))
			{
				asd_printf(ASD_DEFAULT,MSG_DEBUG,"sta radius id : %d,got the send_info\n",radius_id);
				return client_info->sta[radius_id];
			}
		}
		client_info = client_info->next;
	}
	/*Qiuchen add this incase:
		when a station is online and it sends the association frame again,an accounting stop package will be send 
		at the same time radius auth packet will be send too.
		this is added to make sure at one time only acct or auth packet is sending.
		if not:!incase ac dosn't get any response from radius and the station is offline,one of the packet retransmit timer will not be canceled.
	*/
	if(RADIUS_AUTH == type)
		client_info = ASD_WLAN[wlanid]->radius->acct;	
	else
		client_info = ASD_WLAN[wlanid]->radius->auth;
	while(client_info)
	{
		if(client_info->sta[radius_id]&&client_info->sta[radius_id]->sta)
		{
			if(!os_memcmp(client_info->sta[radius_id]->sta->addr,sta->addr,MAC_LEN))
			{
				asd_printf(ASD_DEFAULT,MSG_DEBUG,"sta radius id : %d,got the send_info in the other type\n",radius_id);
				return client_info->sta[radius_id];
			}
		}
		client_info = client_info->next;
	}
	//end
	return NULL;
}
void radius_client_info_free(struct radius_send_info *send_info)
{
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"now in func:%s\n",__func__);
	if(!send_info)
		return;
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"send_info != NULL");
	struct radius_client_info *client_info = send_info->ctx;

	int radius_id = -1;
	circle_cancel_timeout(radius_client_timer,send_info,NULL);
	if(send_info->msg)
	{
		if(send_info->msg->msg)
		{
			radius_msg_free(send_info->msg->msg);
			os_free(send_info->msg->msg);
			send_info->msg->msg = NULL;
		}
		//os_free(send_info->msg->shared_secret);
		send_info->msg->shared_secret = NULL;
		os_free(send_info->msg);
		send_info->msg = NULL;
	}
	if(send_info->sta)
	{
		if(send_info->sta->eapol_sm){
			asd_printf(ASD_DEFAULT,MSG_DEBUG,"send_info->sta->eapol_sm->radius_id %d\n",send_info->sta->eapol_sm->radius_identifier);
			radius_id  = send_info->sta->eapol_sm->radius_identifier;
			send_info->sta->eapol_sm->radius_identifier = -1;
		}
		send_info->sta = NULL;
	}	
	os_free(send_info);
	send_info = NULL;
	if(client_info){
		if(radius_id != -1){
			asd_printf(ASD_DEFAULT,MSG_DEBUG,"in func:%s ; set the client_info sta %d NULL\n",__func__,radius_id);	
			client_info->sta[radius_id] = NULL;
		}
		client_info->num--;
	}
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"client_info sock :%d\n",client_info->sock);
	if(radius_id == -1){
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"got or free radiusid error!\n");
		return;
	}
	if(client_info->sta[radius_id])
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"client_info %d is not NULL!\n",radius_id);
	else
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"client_info %d is NULL\n",radius_id);
}

#if 0
static void radius_client_update_timeout(struct radius_client_data *radius)
{
	struct os_time now;
	os_time_t first;
	struct radius_msg_list *entry;

	circle_cancel_timeout(radius_client_timer, radius, NULL);

	if (radius->msgs == NULL) {
		return;
	}

	first = 0;
	for (entry = radius->msgs; entry; entry = entry->next) {
		if (first == 0 || entry->next_try < first)
			first = entry->next_try;
	}

	os_get_time(&now);
	if (first < now.sec)
		first = now.sec;
	circle_register_timeout(first - now.sec, 0, radius_client_timer, radius,
			       NULL);
	asd_logger(radius->ctx, NULL, asd_MODULE_RADIUS,
		       asd_LEVEL_DEBUG, "Next RADIUS client retransmit in"
		       " %ld seconds\n", (long int) (first - now.sec));
}

#endif
static void radius_client_list_add(struct radius_client_info *client_info,
				   struct radius_msg *msg,
				   RadiusType msg_type, u8 *shared_secret,
				   size_t shared_secret_len,struct sta_info *sta)
{
	struct radius_msg_info *entry;
	struct radius_send_info *send_info;
	int radius_id = -1;
	if(sta&&sta->eapol_sm)
		radius_id = sta->eapol_sm->radius_identifier;
	if(radius_id <0 ||radius_id > 255)
	{
		asd_printf(ASD_DEFAULT,MSG_INFO,"radius id get error!\n");
		return ;
	}
	if (circle_terminated()) {
		/* No point in adding entries to retransmit queue since event
		 * loop has already been terminated. */
		radius_msg_free(msg);
		os_free(msg);
		msg = NULL;
		return;
	}
	
	entry = os_zalloc(sizeof(struct radius_msg_info));
	if (entry == NULL) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Failed to add RADIUS packet into retransmit list\n");
		radius_msg_free(msg);
		os_free(msg);
		msg = NULL;
		return;
	}
	memset(entry,0,sizeof(struct radius_msg_info));
	entry->msg = msg;
	entry->msg_type = msg_type;
	entry->shared_secret = shared_secret;
	entry->shared_secret_len = shared_secret_len;
	os_get_time(&entry->last_attempt);
	entry->first_try = entry->last_attempt.sec;
	entry->next_try = entry->first_try + RADIUS_CLIENT_FIRST_WAIT;
	entry->attempts = 1;
	entry->next_wait = RADIUS_CLIENT_FIRST_WAIT * 2;
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"radius id = %d\n",radius_id);
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"client_info sock = %d\n",client_info->sock);

	send_info = os_zalloc(sizeof(struct radius_send_info));
	if(send_info == NULL)
	{
		asd_printf(ASD_DEFAULT,MSG_CRIT,"send_info malloc error!\n");
		os_free(entry);
		return;
	}
	memset(send_info,0,sizeof(struct radius_send_info));
	send_info->msg = entry;
	send_info->sta = sta;
	send_info->ctx = client_info;
	if(client_info->sta[radius_id] != NULL)
	{
		asd_printf(ASD_DEFAULT,MSG_INFO,"radius_id  %d is conflict!will delete the prev!\n",radius_id);
		radius_client_info_free(client_info->sta[radius_id]);
	}
	client_info->sta[radius_id] = send_info;
	client_info->num++;
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"send_info add successfully");
	circle_register_timeout(RADIUS_CLIENT_FIRST_WAIT,0,radius_client_timer,send_info,NULL);
/*	
	if (radius->num_msgs >= RADIUS_CLIENT_MAX_ENTRIES) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Removing the oldest un-ACKed RADIUS packet due to "
		       "retransmit list limits.\n");
		prev = NULL;
		while (entry->next) {
			prev = entry;
			entry = entry->next;
		}
		if (prev) {
			prev->next = NULL;
			radius_client_msg_free(entry);
		}
	} else
		radius->num_msgs++;*/
}

#if 0
static void radius_client_list_del(struct radius_client_data *radius,
				   RadiusType msg_type, const u8 *addr)
{
	struct radius_msg_list *entry, *prev, *tmp;

	if (addr == NULL)
		return;

	entry = radius->msgs;
	prev = NULL;
	while (entry) {
		if (entry->msg_type == msg_type &&
		    os_memcmp(entry->addr, addr, ETH_ALEN) == 0) {
			if (prev)
				prev->next = entry->next;
			else
				radius->msgs = entry->next;
			tmp = entry;
			entry = entry->next;
			asd_logger(radius->ctx, addr,
				       asd_MODULE_RADIUS,
				       asd_LEVEL_DEBUG,
				       "Removing matching RADIUS message");
			radius_client_msg_free(tmp);
			radius->num_msgs--;
			if(radius->num_msgs == 0)		//mahz add 2011.7.15
				radius->msgs = NULL;
			continue;
		}
		prev = entry;
		entry = entry->next;
	}
}
#endif
//qiuchen add 
int radius_test_client_send_without_retrans(struct heart_test_radius_data *radius,
		       struct radius_msg *msg, RadiusType msg_type)
{
	struct asd_radius_servers *conf = radius->conf;
	u8 *shared_secret;
	size_t shared_secret_len;
	char *name;
	int s, res;
	socklen_t addrlen = 0;
	struct sockaddr_in serv;
	struct sockaddr *serv_addr = NULL;
	struct asd_radius_server *nserv;
#ifdef ASD_IPV6
		struct sockaddr_in6 serv6;
#endif

	if (msg_type == RADIUS_ACCT) {
		if (conf->acct_servers == NULL) {
			asd_printf(ASD_80211,MSG_DEBUG,"There is no radius acct server!");
			return -1;
		}
		shared_secret = conf->acct_servers->shared_secret;
		shared_secret_len = conf->acct_servers->shared_secret_len;
		radius_msg_finish_acct(msg, shared_secret, shared_secret_len);
		name = "radius heart test type acct";
		s = radius->acct_sock;
		conf->acct_servers->requests++;
		nserv = conf->acct_servers;
	} else {
		if (conf->auth_servers == NULL) {
			asd_printf(ASD_80211,MSG_DEBUG,"There is no radius auth server!");
			return -1;
		}
		shared_secret = conf->auth_servers->shared_secret;
		shared_secret_len = conf->auth_servers->shared_secret_len;
		radius_msg_finish(msg, shared_secret, shared_secret_len);
		name = "radius heart test type auth";
		s = radius->auth_sock;
		conf->auth_servers->requests++;
		nserv = conf->auth_servers;
	}

	switch (nserv->addr.af) {
	case AF_INET:
		os_memset(&serv, 0, sizeof(serv));
		serv.sin_family = AF_INET;
		serv.sin_addr.s_addr = nserv->addr.u.v4.s_addr;
		serv.sin_port = htons(nserv->port);
		serv_addr = (struct sockaddr *) &serv;
		addrlen = sizeof(serv);
		break;
#ifdef ASD_IPV6
	case AF_INET6:
		os_memset(&serv6, 0, sizeof(serv6));
		serv6.sin6_family = AF_INET6;
		os_memcpy(&serv6.sin6_addr, &nserv->addr.u.v6,
			  sizeof(struct in6_addr));
		serv6.sin6_port = htons(nserv->port);
		serv_addr = (struct sockaddr *) &serv6;
		addrlen = sizeof(serv6);
		break;
#endif /* ASD_IPV6 */
	default:
		break;
	}
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"%s server.ip: %s\n",__func__, inet_ntoa(serv.sin_addr));		//for test
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"%s server.port: %d\n",__func__, ntohs(serv.sin_port));		//for test
	asd_printf(ASD_80211,MSG_DEBUG,"Sending RADIUS message  %s",name);
	
	if(conf->distribute_off)
		res = sendto(s, msg->buf, msg->buf_used, 0,serv_addr,addrlen);
	else
		res = rdc_sendto(s, msg->buf, msg->buf_used, 0, serv_addr, addrlen, conf->slot_value, conf->inst_value);
	if (res < 0)
		radius_test_client_handle_send_error(radius, s, msg_type);

	asd_printf(ASD_DEFAULT,MSG_DEBUG,"func:%s,after successfully send to rdc server\n",__func__);		//for test
	return res;
}
int radius_change_server_acct(unsigned char SID,unsigned char bak){
	struct radius_client_info *client_info_acct = NULL;;
	struct heart_test_radius_data *radius = NULL;
	if(ASD_SECURITY[SID])
		radius = ASD_SECURITY[SID]->radius_conf;
	if(radius == NULL || radius->conf == NULL)
		return -1;
	unsigned int i = 1;
	if (radius->conf->num_acct_servers > 1){
		struct asd_radius_server *next, *old;
		asd_printf(ASD_80211,MSG_DEBUG,"radius server change acct to %s!\n",(bak == 1)?"bak":"master");
		if(bak >1){
			asd_printf(ASD_80211,MSG_DEBUG,"%s:<error> bak is %d!\n",__func__,bak);
			return -1;
		}
		for(i=1;i<WLAN_NUM;i++){
			if(ASD_WLAN[i] && ASD_WLAN[i]->SecurityID == SID){
				client_info_acct = ASD_WLAN[i]->radius->acct;
				old = client_info_acct->ctx->conf->acct_server;
				next = &(client_info_acct->ctx->conf->acct_servers[bak]);
				if(next == NULL)
					return -1;
				ASD_WLAN[i]->radius_server->acct_server = next;
				while(client_info_acct){
				if(radius_change_server(client_info_acct, next, old,
								client_info_acct->sock,
								client_info_acct->sock6, 0))
					asd_printf(ASD_80211,MSG_DEBUG,"WLAN[%d] securityID %d change server fail!\n",i,SID);
					client_info_acct = client_info_acct->next;
				}
			}
		}
		return 0;
	}
	asd_printf(ASD_80211,MSG_DEBUG,"There is no bak radius server for change!\n");
	return -1;
}
int radius_change_server_auth(unsigned char SID,unsigned char bak){
	struct radius_client_info *client_info_auth = NULL;;
	struct heart_test_radius_data *radius = NULL;
	if(ASD_SECURITY[SID])
		radius = ASD_SECURITY[SID]->radius_conf;
	if(radius == NULL || radius->conf == NULL)
		return -1;
	unsigned int i = 1;
	if (radius->conf->num_auth_servers > 1){
		struct asd_radius_server *next, *old;
		asd_printf(ASD_80211,MSG_DEBUG,"radius server change auth to %s!\n",(bak == 1)?"bak":"master");
		if(bak >1){
			asd_printf(ASD_80211,MSG_DEBUG,"%s:<error> bak is %d!\n",__func__,bak);
			return -1;
		}
		for(i=1;i<WLAN_NUM;i++){
			if(ASD_WLAN[i] && ASD_WLAN[i]->SecurityID == SID){
				client_info_auth = ASD_WLAN[i]->radius->auth;
				old = client_info_auth->ctx->conf->auth_server;
				next = &(client_info_auth->ctx->conf->auth_servers[bak]);
				if(next == NULL)
					return -1;
				ASD_WLAN[i]->radius_server->auth_server = next;
				while(client_info_auth){
					if(radius_change_server(client_info_auth, next, old,
									client_info_auth->sock,
									client_info_auth->sock6, 1))
						asd_printf(ASD_80211,MSG_DEBUG,"WLAN[%d] securityID %d change server fail!\n",i,SID);
					client_info_auth = client_info_auth->next;
				}
			}
		}
		return 0;
	}
	asd_printf(ASD_80211,MSG_DEBUG,"There is no bak radius server for change!\n");
	return -1;
}
int radius_change_server_both(unsigned char SID,unsigned char bak){

	struct radius_client_info *client_info_auth = NULL;;
	struct radius_client_info *client_info_acct = NULL;;
	struct heart_test_radius_data *radius = NULL;
	if(ASD_SECURITY[SID])
		radius = ASD_SECURITY[SID]->radius_conf;
	if(radius == NULL || radius->conf == NULL)
		return -1;
	unsigned int i = 1;
	if (radius->conf->num_auth_servers > 1 && radius->conf->num_acct_servers > 1) {
		struct asd_radius_server *next, *old,*next_acct,*old_acct;
		asd_printf(ASD_80211,MSG_DEBUG,"server change both together to the %s!\n",(bak == 1)?"bak":"master");
		if(bak >1){
			asd_printf(ASD_80211,MSG_DEBUG,"%s:<error> bak is %d!\n",__func__,bak);
			return -1;
		}
		for(i=1;i<WLAN_NUM;i++){
			if(ASD_WLAN[i] && ASD_WLAN[i]->SecurityID == SID){
				client_info_auth = ASD_WLAN[i]->radius->auth;
				client_info_acct = ASD_WLAN[i]->radius->acct;
				old = client_info_auth->ctx->conf->auth_server;
				old_acct = client_info_acct->ctx->conf->acct_server;
				next = &(client_info_auth->ctx->conf->auth_servers[bak]);
				next_acct = &(client_info_acct->ctx->conf->acct_servers[bak]);
				if(next == NULL || next_acct == NULL)
					return -1;
				ASD_WLAN[i]->radius_server->auth_server = next;
				ASD_WLAN[i]->radius_server->acct_server = next_acct;
				while(client_info_auth){
					if(radius_change_server(client_info_auth, next, old,
									client_info_auth->sock,
									client_info_auth->sock6, 1))
						asd_printf(ASD_80211,MSG_DEBUG,"WLAN[%d] securityID %d change server fail!\n",i,SID);
					client_info_auth = client_info_auth->next;
				}
				while(client_info_acct){
					if(radius_change_server(client_info_acct, next_acct, old_acct,
									client_info_acct->sock,
									client_info_acct->sock6, 0))
						asd_printf(ASD_80211,MSG_DEBUG,"WLAN[%d] securityID %d change server fail!\n",i,SID);
					client_info_acct = client_info_acct->next;
				}
			}
		}
		return 0;
	}
	asd_printf(ASD_80211,MSG_DEBUG,"There is no bak radius server for change!\n");
	return -1;
}
void radius_server_change(unsigned char SID,unsigned char type,unsigned char state)
{
	asd_printf(ASD_80211,MSG_DEBUG,"%s\n",__func__);
	int ret = 0;
	struct asd_radius_servers *radius = ASD_SECURITY[SID]->radius_conf->conf;
	if(is_secondary == 1){
		return;
	}
	if(type == RADIUS_AUTH_TEST){
		/*###Change radius server to bak*/
			if(ASD_SECURITY[SID]->radius_server_binding_type == RADIUS_SERVER_BINDED){
				/*###Radius Server change together!(Auth/Acct)###*/
				ret = radius_change_server_both(SID,state);
				if(ret)
					asd_printf(ASD_80211,MSG_DEBUG,"%s:radius change server both fail!\n",__func__);
				else{
					update_radius_state_to_bakAC(SID,state,state);
					ASD_SECURITY[SID]->acct_server_current_use = state;
					ASD_SECURITY[SID]->auth_server_current_use = state;
				}
			}
			else if(ASD_SECURITY[SID]->radius_server_binding_type == RADIUS_SERVER_UNBINDED){
				ret = radius_change_server_auth(SID,state);
				if(ret)
					asd_printf(ASD_80211,MSG_DEBUG,"%s:radius change server auth fail!\n",__func__);
				else{
					/*Here to make a notice to the bak AC that the radius server has changed!*/
					update_radius_state_to_bakAC(SID,state,RADIUS_HOLD_ON);
					ASD_SECURITY[SID]->auth_server_current_use = state;
				}
			}
			radius->radius_auth_heart_fail_num = 0;
			radius->radius_auth_heart_req_num = 0;
			radius->radius_auth_heart_res_num = 0;
			memset(radius->r_test_window_auth,0,radius->r_window_size);
			memset(radius->c_test_window_auth,0,radius->c_window_size);
	}
	else if (type == RADIUS_ACCT_TEST){
		/*###Change radius server*/
			if(radius->radius_server_binding_type == RADIUS_SERVER_BINDED){
				/*###Radius Server change together!(Auth/Acct)###*/
				ret = radius_change_server_both(SID,state);
				if(ret)
					asd_printf(ASD_80211,MSG_DEBUG,"%s:radius change server both fail!\n",__func__);
				else{
					update_radius_state_to_bakAC(SID,state,state);
					ASD_SECURITY[SID]->acct_server_current_use = state;
					ASD_SECURITY[SID]->auth_server_current_use = state;
				}
			}
			else if(radius->radius_server_binding_type == RADIUS_SERVER_UNBINDED){
				ret = radius_change_server_acct(SID,state);
				if(ret)
					asd_printf(ASD_80211,MSG_DEBUG,"%s:radius change server acct fail!\n",__func__);
				else{
					update_radius_state_to_bakAC(SID,RADIUS_HOLD_ON,state);
					ASD_SECURITY[SID]->acct_server_current_use = state;
				}
			}
			radius->radius_acct_heart_fail_num = 0;
			radius->radius_acct_heart_req_num = 0;
			radius->radius_acct_heart_res_num = 0;
			memset(radius->r_test_window_acct,0,radius->r_window_size);
			memset(radius->c_test_window_acct,0,radius->c_window_size);
	}
}



//end
int radius_client_send(struct radius_client_info *client_info,
		       struct radius_msg *msg, RadiusType msg_type,
		       struct sta_info *sta)
{
	struct radius_client_data *radius = client_info->ctx;
	struct asd_radius_servers *conf = radius->conf;
	struct radius_client_info *client_tmp;
	u8 *shared_secret;
	size_t shared_secret_len;
	char *name;
	int s, res,radius_id;
	socklen_t addrlen = 0;
	struct sockaddr_in serv;
	struct sockaddr *serv_addr = NULL;
	struct asd_radius_server *nserv;
	radius_id = sta->eapol_sm->radius_identifier;
#ifdef ASD_IPV6
		struct sockaddr_in6 serv6;
#endif
#if 0
	if (msg_type == RADIUS_ACCT_INTERIM) {
		/* Remove any pending interim acct update for the same STA. */
		radius_client_list_del(radius, msg_type, addr);
		
	}
#endif
	if(msg_type == RADIUS_ACCT_INTERIM)
	{
		if((radius_id >= 0)&&(radius_id <= 255))
		{
			for(client_tmp = radius->acct ; client_tmp != NULL;client_tmp = client_tmp->next)
			{
				if((client_tmp != NULL)&&(client_tmp->sta[radius_id])&&(client_tmp->sta[radius_id]->sta))
				{
					if(!os_memcmp(client_tmp->sta[radius_id]->sta->addr,sta->addr,MAC_LEN)){
						radius_client_info_free(client_tmp->sta[radius_id]);
						client_tmp->sta[radius_id] = NULL;
					}
				}
			}
		}	
	}
	if (msg_type == RADIUS_ACCT || msg_type == RADIUS_ACCT_INTERIM) {
		if (conf->acct_server == NULL) {
			asd_logger(radius->ctx, NULL,
				       asd_MODULE_RADIUS,
				       asd_LEVEL_INFO,
				       "No accounting server configured");
			return -1;
		}
		shared_secret = conf->acct_server->shared_secret;
		shared_secret_len = conf->acct_server->shared_secret_len;
		radius_msg_finish_acct(msg, shared_secret, shared_secret_len);
		name = "accounting";
		//s = radius->acct_sock;
		s = client_info->sock;
		conf->acct_server->requests++;
		nserv = conf->acct_server;
	} else {
		if (conf->auth_server == NULL) {
			asd_logger(radius->ctx, NULL,
				       asd_MODULE_RADIUS,
				       asd_LEVEL_INFO,
				       "No authentication server configured");
			return -1;
		}
		shared_secret = conf->auth_server->shared_secret;
		shared_secret_len = conf->auth_server->shared_secret_len;
		radius_msg_finish(msg, shared_secret, shared_secret_len);
		name = "authentication";
		//s = radius->auth_sock;
		s = client_info->sock;
		conf->auth_server->requests++;
		nserv = conf->auth_server;
	}

	switch (nserv->addr.af) {
	case AF_INET:
		os_memset(&serv, 0, sizeof(serv));
		serv.sin_family = AF_INET;
		serv.sin_addr.s_addr = nserv->addr.u.v4.s_addr;
		serv.sin_port = htons(nserv->port);
		serv_addr = (struct sockaddr *) &serv;
		addrlen = sizeof(serv);
		break;
#ifdef ASD_IPV6
	case AF_INET6:
		os_memset(&serv6, 0, sizeof(serv6));
		serv6.sin6_family = AF_INET6;
		os_memcpy(&serv6.sin6_addr, &nserv->addr.u.v6,
			  sizeof(struct in6_addr));
		serv6.sin6_port = htons(nserv->port);
		serv_addr = (struct sockaddr *) &serv6;
		addrlen = sizeof(serv6);
		break;
#endif /* ASD_IPV6 */
	default:
		break;
	}
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"%s server.ip: %s\n",__func__, inet_ntoa(serv.sin_addr));		//for test
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"%s server.port: %d\n",__func__, ntohs(serv.sin_port));		//for test

	asd_logger(radius->ctx, NULL, asd_MODULE_RADIUS,
		       asd_LEVEL_DEBUG, "Sending RADIUS message to %s "
		       "server", name);
	if (conf->msg_dumps)
		radius_msg_dump(msg);

	if(conf->distribute_off)
		res = sendto(s, msg->buf, msg->buf_used, 0,serv_addr,addrlen);//qiuchen
	else
		res = rdc_sendto(s, msg->buf, msg->buf_used, 0, serv_addr, addrlen, conf->slot_value, conf->inst_value);
	if (res < 0)
		radius_client_handle_send_error(client_info, s, msg_type);
	if(conf->distribute_off)
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"send to radius server successfully!\n");
	else
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"after successfully send to rdc server\n");		//for test
	radius_client_list_add(client_info, msg, msg_type, shared_secret,
			       shared_secret_len,sta);
	return res;
}

/*ht add 090826*/
/* Process the RADIUS frames from DM */
#if 0
static RadiusRxResult
radius_receive_dm(struct radius_msg *msg, struct radius_msg *req,
		   struct radius_client_data *radius,
			struct sockaddr *from_addr, int fromlen,
		   	void *data)
{
	struct eapol_state_machine *sm ;
	struct asd_stainfo *stainfo = NULL;
	struct radius_msg *msg_resp;
	unsigned char mac[6]={0};
	int code;
	int res;
	
	printf("%s code:%d\n",__func__,msg->hdr->code);
	if (msg->hdr->code != RADIUS_CODE_DISCONNECT_REQUEST) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Unknown RADIUS message code\n");
		return RADIUS_RX_UNKNOWN;
	}

	if (radius_msg_get_attr(msg, RADIUS_ATTR_CALLING_STATION_ID, mac,6) < 0 ) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG, "Failed to get sta mac in the Disconnect Message");
		return RADIUS_RX_UNKNOWN;
	}
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"To kick sta "MACSTR"\n",MAC2STR(mac));
	
	stainfo = ASD_SEARCH_STA(mac);
	if (stainfo == NULL)
		return RADIUS_RX_UNKNOWN;

	code = RADIUS_CODE_DISCONNECT_ACK;
	msg_resp = radius_msg_new(code, msg->hdr->identifier);
	if (msg_resp == NULL) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Failed to allocate reply message");
		goto fail;
	}
	radius_msg_make_authenticator(msg_resp, (u8 *) stainfo->sta, sizeof(*(stainfo->sta)));

	sm = stainfo->sta->eapol_sm;
	if (sm->identity &&
	    !radius_msg_add_attr(msg_resp, RADIUS_ATTR_USER_NAME,
				 sm->identity, sm->identity_len)) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Could not add User-Name\n");
	}
	msg_resp->hdr->length = htons(msg_resp->buf_used);
	stainfo->sta->acct_terminate_cause = RADIUS_ACCT_TERMINATE_CAUSE_USER_REQUEST;

	accounting_sta_stop(stainfo->bss, stainfo->sta);
	bss_kick_sta(stainfo->bss, stainfo->sta);
	res = sendto(radius->dm_sock, msg_resp->buf, msg_resp->buf_used, 0,
			 (struct sockaddr *) from_addr, fromlen);
	printf("%s dm_sock=%d res=%d\n",__func__,radius->dm_sock,res);
	asd_printf(ASD_DEFAULT,MSG_INFO,"%s dm_sock=%d res=%d\n",__func__,radius->dm_sock,res);
	if (res < 0){
		perror("sendto[RADIUS DM]");
		asd_printf(ASD_DEFAULT,MSG_INFO,"Send DM response failed\n");
	}

fail:	
	if(stainfo != NULL){
		stainfo->bss = NULL;
		stainfo->sta = NULL;
		free(stainfo);
		stainfo = NULL;
	}
	radius_msg_free(msg_resp);
	
	return RADIUS_RX_PROCESSED;
}
#endif
//qiuchen
void radius_test_client_receive(int sock, void *circle_ctx, void *sock_ctx){
	struct heart_test_radius_data *radius = circle_ctx;
	if(radius == NULL || radius->conf == NULL)
		return;
	struct asd_radius_servers *conf = radius->conf;
	RadiusType msg_type = (RadiusType) sock_ctx;
	int len;
	unsigned int i = 0;
	unsigned char buf[3000];
	struct sockaddr serv_addr;
	socklen_t addrlen = sizeof(struct sockaddr);
	struct radius_msg *msg;
	unsigned char SID = radius->SecurityID;
	unsigned char *c_test_acct = conf->c_test_window_acct;
	unsigned char *r_test_acct = conf->r_test_window_acct;
	unsigned char *c_test_auth = conf->c_test_window_auth;
	unsigned char *r_test_auth = conf->r_test_window_auth;
	if(conf->distribute_off)
		len = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
	else
		len = rdc_recvfrom(sock, buf, sizeof(buf), 0, &serv_addr, &addrlen);
	msg = radius_msg_parse(buf, len);
	if (msg == NULL) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"radius test client parsing incoming RADIUS frame failed\n");
		return;
	}

	if((ASD_SECURITY[SID]->heart_test_identifier_acct == (unsigned int)msg->hdr->identifier) && msg_type == RADIUS_ACCT){
		radius->conf->radius_acct_heart_res_num++;
		if(ASD_SECURITY[SID]->acct_server_current_use == RADIUS_MASTER){
			i = (radius->conf->radius_acct_heart_req_num-1)%radius->conf->c_window_size;
			if(c_test_acct[i] == RADIUS_TEST_SUC)
				radius->conf->radius_acct_heart_res_num--;
			else if(c_test_acct[i] == RADIUS_TEST_FAIL)
				radius->conf->radius_acct_heart_fail_num--;
		}
		else if(ASD_SECURITY[SID]->acct_server_current_use == RADIUS_BAK){
			i = (radius->conf->radius_acct_heart_req_num-1)%radius->conf->r_window_size;
			if(r_test_acct[i] == RADIUS_TEST_SUC)
				radius->conf->radius_acct_heart_res_num--;
			else if(r_test_acct[i] == RADIUS_TEST_FAIL)
				radius->conf->radius_acct_heart_fail_num--;
		}
		ASD_SECURITY[SID]->heart_test_identifier_acct = 32768;
	}
	else if((ASD_SECURITY[SID]->heart_test_identifier_auth == (unsigned int)msg->hdr->identifier) && msg_type == RADIUS_AUTH){
		radius->conf->radius_auth_heart_res_num++;
		if(ASD_SECURITY[SID]->auth_server_current_use == RADIUS_MASTER){
			i = (radius->conf->radius_auth_heart_req_num-1)%radius->conf->c_window_size;
			if(c_test_auth[i] == RADIUS_TEST_SUC)
				radius->conf->radius_auth_heart_res_num--;
			else if(c_test_auth[i] == RADIUS_TEST_FAIL)
				radius->conf->radius_auth_heart_fail_num--;
			c_test_auth[i] = RADIUS_TEST_SUC;
		}
		else if(ASD_SECURITY[SID]->auth_server_current_use == RADIUS_BAK){
			i = (radius->conf->radius_auth_heart_req_num-1)%radius->conf->r_window_size;
			if(r_test_auth[i] == RADIUS_TEST_SUC)
				radius->conf->radius_auth_heart_res_num--;
			else if(r_test_auth[i] == RADIUS_TEST_FAIL)
				radius->conf->radius_auth_heart_fail_num--;
			r_test_auth[i] = RADIUS_TEST_SUC;
		}
		ASD_SECURITY[SID]->heart_test_identifier_auth = 32768;
	}
	radius_msg_free(msg);
	os_free(msg);
}
//end
static void radius_client_receive(int sock, void *circle_ctx, void *sock_ctx)
{
	struct radius_client_info *client_info = circle_ctx;
	if(client_info == NULL || client_info->ctx == NULL || client_info->ctx->conf == NULL)
		return;
	struct radius_client_data *radius = client_info->ctx;
	struct asd_radius_servers *conf = radius->conf;
	RadiusType msg_type = (RadiusType) sock_ctx;
	int len, roundtrip,radius_id;
	unsigned char buf[3000];
	char abuf[50];
	struct radius_msg *msg;
	struct radius_rx_handler *handlers;
	size_t num_handlers, i;
	struct radius_msg_info *req;
	struct os_time now;
	struct asd_radius_server *rconf;
	int invalid_authenticator = 0;
	struct sockaddr serv_addr;
	socklen_t addrlen = sizeof(struct sockaddr);

	handlers = client_info->client_handlers;
	num_handlers = client_info->num_client_handers;
	if(RADIUS_AUTH == msg_type)
		rconf = conf->auth_server;
	else
		rconf = conf->acct_server;
	if(rconf == NULL)
		return;
	if(conf->distribute_off)
		len = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
	else
		len = rdc_recvfrom(sock, buf, sizeof(buf), 0, &serv_addr, &addrlen);
	if (len <= 0) {
		/*
		if ((msg_type == RADIUS_ACCT)&&(conf->num_acct_servers > 1)) {
			old = conf->acct_server;
			next = old + 1;
			if (next > &conf->acct_servers[conf->num_acct_servers - 1])
				next = conf->acct_servers;
			conf->acct_server = next;
			asd_printf(ASD_DEFAULT,MSG_DEBUG,"change acct server 111\n");		//for test
			radius_change_server(client_info, next, old,
						 radius->acct_serv_sock,
						 radius->acct_serv_sock6, 0);
		}
		else if ((msg_type == RADIUS_AUTH)&&(conf->num_auth_servers > 1)) {
			old = conf->auth_server;
			next = old + 1;
			if (next > &(conf->auth_servers[conf->num_auth_servers - 1]))
				next = conf->auth_servers;
			conf->auth_server = next;
			asd_printf(ASD_DEFAULT,MSG_DEBUG,"change auth server 111\n");		//for test
			radius_change_server(client_info, next, old,
						 radius->auth_serv_sock,
						 radius->auth_serv_sock6, 1);
		}*/
		return;
/*		circle_unregister_read_sock(sock);
		close(sock);
		if (msg_type == RADIUS_ACCT || msg_type == RADIUS_ACCT_INTERIM)
			radius_client_init_acct((void*)radius, (void *)0);
		else
			radius_client_init_auth((void*)radius, (void *)0);
		
		perror("recv[RADIUS]");
		return;
*/	}
	asd_logger(radius->ctx, NULL, asd_MODULE_RADIUS,
		       asd_LEVEL_DEBUG, "Received %d bytes from RADIUS "
		       "server", len);
	if (len == sizeof(buf)) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Possibly too long UDP frame for our buffer - "
		       "dropping it\n");
		return;
	}

	msg = radius_msg_parse(buf, len);
	if (msg == NULL) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Parsing incoming RADIUS frame failed\n");
		rconf->malformed_responses++;
		return;
	}

	if (msg_type == RADIUS_ACCT) {
		if (radius_acct_server_connect_failed_times > 4) {
			radius_acct_server_connect_failed_times = 0;
			signal_radius_connect_failed_clean(asd_ip_txt(&conf->auth_server->addr, abuf, sizeof(abuf)),1);
		}else 
			radius_acct_server_connect_failed_times = 0;
	} else {
		if (radius_auth_server_connect_failed_times > 4) {
			radius_auth_server_connect_failed_times = 0;
			signal_radius_connect_failed_clean(asd_ip_txt(&conf->auth_server->addr, abuf, sizeof(abuf)),0);
		}else
			radius_auth_server_connect_failed_times = 0;
	}

	asd_logger(radius->ctx, NULL, asd_MODULE_RADIUS,
		       asd_LEVEL_DEBUG, "Received RADIUS message");
	if (conf->msg_dumps)
		radius_msg_dump(msg);

	switch (msg->hdr->code) {
	case RADIUS_CODE_ACCESS_ACCEPT:
		rconf->access_accepts++;
		break;
	case RADIUS_CODE_ACCESS_REJECT:
		rconf->access_rejects++;
		break;
	case RADIUS_CODE_ACCESS_CHALLENGE:
		rconf->access_challenges++;
		break;
	case RADIUS_CODE_ACCOUNTING_RESPONSE:
		rconf->responses++;
		break;
	}
#if 0
	prev_req = NULL;
	req = radius->msgs;
	while (req) {
		/* TODO: also match by src addr:port of the packet when using
		 * alternative RADIUS servers (?) */
		if ((req->msg_type == msg_type ||
		     (req->msg_type == RADIUS_ACCT_INTERIM &&
		      msg_type == RADIUS_ACCT)) &&
		    req->msg->hdr->identifier == msg->hdr->identifier)
			break;

		prev_req = req;
		req = req->next;
	}
#endif
	req = NULL;
	radius_id = msg->hdr->identifier;
	if((radius_id >= 0)&&(radius_id <= 255)&&(client_info->sta[radius_id]))
	req = client_info->sta[radius_id]->msg;
	if (req == NULL) {
		asd_logger(radius->ctx, NULL, asd_MODULE_RADIUS,
			       asd_LEVEL_DEBUG,
			       "No matching RADIUS request found (type=%d "
			       "id=%d) - dropping packet",
			       msg_type, msg->hdr->identifier);
		goto fail;
	}

	os_get_time(&now);
	roundtrip = (now.sec - req->last_attempt.sec) * 100 +
		(now.usec - req->last_attempt.usec) / 10000;
	asd_logger(radius->ctx, client_info->sta[radius_id]->sta->addr, asd_MODULE_RADIUS,
		       asd_LEVEL_DEBUG,
		       "Received RADIUS packet matched with a pending "
		       "request, round trip time %d.%02d sec",
		       roundtrip / 100, roundtrip % 100);
	rconf->round_trip_time = roundtrip;

	/* Remove ACKed RADIUS packet from retransmit list */
	//	radius_client_free_sta(client_info,radius_id);
	
	circle_cancel_timeout(radius_client_timer,client_info->sta[radius_id],NULL);
	for (i = 0; i < num_handlers; i++) {
		RadiusRxResult res;
		res = handlers[i].handler(msg, req->msg, req->shared_secret,
					  req->shared_secret_len,
					  handlers[i].data);
		switch (res) {
		case RADIUS_RX_PROCESSED:
			radius_msg_free(msg);
			os_free(msg);
			msg = NULL;
			/* continue */
		case RADIUS_RX_QUEUED:
//			radius_client_msg_free(req);
			radius_client_info_free(client_info->sta[radius_id]);
			client_info->sta[radius_id] = NULL;
			return;
		case RADIUS_RX_INVALID_AUTHENTICATOR:
			invalid_authenticator++;
			/* continue */
		case RADIUS_RX_UNKNOWN:
			/* continue with next handler */
			break;
		}
	}

	if (invalid_authenticator)
		rconf->bad_authenticators++;
	else
		rconf->unknown_types++;
	asd_logger(radius->ctx, client_info->sta[radius_id]->sta->addr, asd_MODULE_RADIUS,
		       asd_LEVEL_NOTICE, "No RADIUS RX handler found "
		       "(type=%d code=%d id=%d)%s - dropping packet",
		       msg_type, msg->hdr->code, msg->hdr->identifier,
		       invalid_authenticator ? " [INVALID AUTHENTICATOR]" :
		       "");
	//radius_client_msg_free(req);
	radius_client_info_free(client_info->sta[radius_id]);
	client_info->sta[radius_id] = NULL;

 fail:
	radius_msg_free(msg);
	os_free(msg);
	msg = NULL;
}

#if 0
u8 radius_client_get_id(struct radius_client_data *radius)
{
	struct radius_msg_list *entry, *prev, *_remove;
	u8 id = radius->next_radius_identifier++;

	/* remove entries with matching id from retransmit list to avoid
	 * using new reply from the RADIUS server with an old request */
	entry = radius->msgs;
	prev = NULL;
	while (entry) {
		if (entry->msg->hdr->identifier == id) {
			asd_logger(radius->ctx, entry->addr,
				       asd_MODULE_RADIUS,
				       asd_LEVEL_DEBUG,
				       "Removing pending RADIUS message, "
				       "since its id (%d) is reused", id);
			if (prev)
				prev->next = entry->next;
			else
				radius->msgs = entry->next;
			_remove = entry;
		} else {
			_remove = NULL;
			prev = entry;
		}
		entry = entry->next;

		if (_remove)
			radius_client_msg_free(_remove);
	}

	return id;
}
#endif
struct radius_client_info *radius_client_get_sock(const int wlanid ,int auth)
{
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"in func:%s\n",__func__);
	struct radius_client_info *client_info,*client_tmp;
	client_info = NULL;
	if((ASD_WLAN[wlanid])&&(ASD_WLAN[wlanid]->radius)&&(ASD_WLAN[wlanid]->radius->auth))
	{
		if(auth)
			client_tmp = ASD_WLAN[wlanid]->radius->auth;
		else
			client_tmp = ASD_WLAN[wlanid]->radius->acct;
		while(client_tmp)
		{
			if(client_tmp->next == NULL)
			{
				if(client_info == NULL)
					client_info = client_tmp;
				break;
			}
			else if(client_tmp->num > client_tmp->next->num)
				client_info = client_tmp->next;
			else 
				client_info = client_tmp ; 
			client_tmp = client_tmp->next;
		}
	}
	if(client_info)
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"select client_info  sock  = %d\n",client_info->sock);
	return client_info;
}
//qiuchen
u8 radius_client_test_get_id(struct heart_test_radius_data *radius){
	u8 id = radius->next_radius_identifier++;
	if((id == ASD_SECURITY[radius->SecurityID]->heart_test_identifier_acct)||
		(id == ASD_SECURITY[radius->SecurityID]->heart_test_identifier_auth))
		id = radius->next_radius_identifier++;
	return id;
}
//end
int radius_client_get_id(struct radius_client_info *client_info)
{
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"in func:%s\n",__func__);
	int radius_id = -1;
	int  i ; 
	
	if(client_info->num > 255)
		return -1;
	for( i = 0; i < 256 ; i++)
	{
		radius_id = client_info->next_radius_identifier++;
		if(client_info->sta[radius_id] == NULL)
		{
			asd_printf(ASD_DEFAULT,MSG_DEBUG,"get radius id %d\n",radius_id);
			return radius_id;
		}
	}
	//for provisonal
	if(radius_id > 0 &&radius_id < 255){
		asd_printf(ASD_DEFAULT,MSG_INFO,"Removing pending RADIUS message, "
				       "since its id (%d) is reused",radius_id);
		radius_client_info_free(client_info->sta[radius_id]);
		client_info->sta[radius_id] = NULL;
	}
	
	return radius_id;
}
#if 0
void radius_client_flush(struct radius_client_data *radius, int only_auth)
{
	struct radius_msg_list *entry, *prev, *tmp;

	if (!radius)
		return;

	prev = NULL;
	entry = radius->msgs;

	while (entry) {
		if (!only_auth || entry->msg_type == RADIUS_AUTH) {
			if (prev)
				prev->next = entry->next;
			else
				radius->msgs = entry->next;

			tmp = entry;
			entry = entry->next;
			radius_client_msg_free(tmp);
			radius->num_msgs--;
			if(radius->num_msgs == 0)	//mahz add 2011.7.15
				radius->msgs = NULL;
		} else {
			prev = entry;
			entry = entry->next;
		}
	}

	if (radius->msgs == NULL)
		circle_cancel_timeout(radius_client_timer, radius, NULL);
}
#endif

void radius_client_update_acct_msgs(struct radius_client_info *client_info,
				    u8 *shared_secret,
				    size_t shared_secret_len)
{
	struct radius_send_info *entry;
	unsigned int radius_id;
	if (!client_info)
		return;
	for(radius_id = 0 ; radius_id  < 256 ; radius_id++)
	{
		entry = client_info->sta[radius_id];
		if(entry != NULL)
		{
			entry->msg->shared_secret = shared_secret;
			entry->msg->shared_secret_len = shared_secret_len;
			radius_msg_finish_acct(entry->msg->msg,shared_secret,shared_secret_len);
		}
	}
}
//qiuchen 
static int radius_test_config_server(struct heart_test_radius_data *radius,
		     struct asd_radius_server *nserv,
		     struct asd_radius_server *oserv,
		     int sock, int sock6, int auth)
	{
		struct sockaddr_in serv;
		struct sockaddr_in claddr;
#ifdef ASD_IPV6
		struct sockaddr_in6 serv6, claddr6;
#endif /* ASD_IPV6 */
		struct sockaddr *addr;
		struct sockaddr *cl_addr;
		socklen_t addrlen;
		socklen_t claddrlen;
		int sel_sock;
		struct asd_radius_servers *conf = radius->conf; 	
	
		switch (nserv->addr.af) {
		case AF_INET:
			os_memset(&serv, 0, sizeof(serv));
			serv.sin_family = AF_INET;
			if(conf->distribute_off){
				serv.sin_addr.s_addr = nserv->addr.u.v4.s_addr;
				serv.sin_port = htons(nserv->port);
			}else{
				serv.sin_addr.s_addr = SLOT_IPV4_BASE + conf->slot_value;
				if(local)
					serv.sin_port = htons(RDC_RADIUS_PORT_BASE + conf->inst_value);
				else
					serv.sin_port = htons(RDC_RADIUS_PORT_BASE + 16 + conf->inst_value);
			}
			addr = (struct sockaddr *) &serv;
			addrlen = sizeof(serv);
			sel_sock = sock;
			break;
#ifdef ASD_IPV6
		case AF_INET6:
			os_memset(&serv6, 0, sizeof(serv6));
			serv6.sin6_family = AF_INET6;
			os_memcpy(&serv6.sin6_addr, &nserv->addr.u.v6,
				  sizeof(struct in6_addr));
			serv6.sin6_port = htons(nserv->port);
			addr = (struct sockaddr *) &serv6;
			addrlen = sizeof(serv6);
			sel_sock = sock6;
			break;
#endif /* ASD_IPV6 */
		default:
			return -1;
		}
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"to send.ip: %s\n",inet_ntoa(serv.sin_addr));		//for test
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"to send.port: %d\n", ntohs(serv.sin_port));		//for test
	
		if (conf->force_client_addr) {
			switch (conf->client_addr.af) {
			case AF_INET:
				os_memset(&claddr, 0, sizeof(claddr));
				claddr.sin_family = AF_INET;
				if(conf->distribute_off == 1)
					claddr.sin_addr.s_addr = conf->client_addr.u.v4.s_addr;
				else
					claddr.sin_addr.s_addr = SLOT_IPV4_BASE + slotid;
				claddr.sin_port = htons(0);
				cl_addr = (struct sockaddr *) &claddr;
				claddrlen = sizeof(claddr);
				asd_printf(ASD_DEFAULT,MSG_DEBUG,"claddr.ip: %s\n",inet_ntoa(claddr.sin_addr)); 	//for test
				break;
#ifdef ASD_IPV6
			case AF_INET6:
				os_memset(&claddr6, 0, sizeof(claddr6));
				claddr6.sin6_family = AF_INET6;
				os_memcpy(&claddr6.sin6_addr, &conf->client_addr.u.v6,
					  sizeof(struct in6_addr));
				claddr6.sin6_port = htons(0);
				cl_addr = (struct sockaddr *) &claddr6;
				claddrlen = sizeof(claddr6);
				break;
#endif 
			default:
				return -1;
			}
			if (bind(sel_sock, cl_addr, claddrlen) < 0) {
				asd_printf(ASD_DEFAULT,MSG_INFO,"radius %d bind error: %s",auth,strerror(errno));
				perror("bind[radius]");
				return -1;
			}
		}
		if (auth)
			radius->auth_sock = sel_sock;
		else
			radius->acct_sock = sel_sock;
	
		return 0;
	}

//end

static int
radius_change_server(struct radius_client_info *radius_client,
		     struct asd_radius_server *nserv,
		     struct asd_radius_server *oserv,
		     int sock, int sock6, int auth)
{
	if((radius_client == NULL)||(radius_client->ctx == NULL)||(radius_client->ctx->conf == NULL))
	{
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"any is null!\n");
		return -1;
	}
	struct sockaddr_in serv;
	struct sockaddr_in claddr;
#ifdef ASD_IPV6
	struct sockaddr_in6 serv6, claddr6;
#endif /* ASD_IPV6 */
	struct sockaddr *addr;
	struct sockaddr *cl_addr;
	socklen_t addrlen;
	socklen_t claddrlen;
	char abuf[50];
	int sel_sock;
	struct radius_client_data *radius = radius_client->ctx;
	struct asd_radius_servers *conf = radius->conf;		//ht add,081105
	struct radius_client_info *client_info;
	struct radius_send_info *send_info;
	int i ;
	asd_logger(radius->ctx, NULL, asd_MODULE_RADIUS,
		       asd_LEVEL_INFO,
		       "%s server %s:%d",
		       auth ? "Authentication" : "Accounting",
		       asd_ip_txt(&nserv->addr, abuf, sizeof(abuf)),
		       nserv->port);

	if (!oserv || nserv->shared_secret_len != oserv->shared_secret_len ||
	    os_memcmp(nserv->shared_secret, oserv->shared_secret,
		      nserv->shared_secret_len) != 0) {
		/* Pending RADIUS packets used different shared secret, so
		 * they need to be modified. Update accounting message
		 * authenticators here. Authentication messages are removed
		 * since they would require more changes and the new RADIUS
		 * server may not be prepared to receive them anyway due to
		 * missing state information. Client will likely retry
		 * authentication, so this should not be an issue. */
		if (auth)
		{
			client_info = radius->auth;
			while(client_info)
			{
				for( i = 0 ; i < 256 ; i++)
				{
					send_info = client_info->sta[i];
					if(send_info){
						radius_client_info_free(send_info);
						send_info = NULL;
					}
				}
				client_info = client_info->next;
			}
		}
		else
		{
			client_info = radius->acct;
			while(client_info)
			{
				radius_client_update_acct_msgs(
					client_info, nserv->shared_secret,
					nserv->shared_secret_len);
				client_info = client_info->next;
			}	
		}
	}

	/* Reset retry counters for the new server */
	/*
	for (entry  = radius->msgs;entry; entry = entry->next) {
		if ((auth && entry->msg_type != RADIUS_AUTH) ||
		    (!auth && entry->msg_type != RADIUS_ACCT))
			continue;
		entry->next_try = entry->first_try + RADIUS_CLIENT_FIRST_WAIT;
		entry->attempts = 0;
		entry->next_wait = RADIUS_CLIENT_FIRST_WAIT * 2;
	}

	if (radius->msgs) {
		circle_cancel_timeout(radius_client_timer, radius, NULL);
		circle_register_timeout(RADIUS_CLIENT_FIRST_WAIT, 0,
				       radius_client_timer, radius, NULL);
	}*/

	client_info = radius_client;
	if((client_info)&&(client_info->num > 0))
	{	
		struct radius_send_info *send_info;
		for(i = 0 ; i < 256 ; i++)
		{
			send_info = client_info->sta[i];
			if(send_info != NULL)
			{
				send_info->msg->next_try = send_info->msg->first_try + RADIUS_CLIENT_FIRST_WAIT;
				send_info->msg->attempts = 0;
				send_info->msg->next_wait = RADIUS_CLIENT_FIRST_WAIT * 2;
				circle_cancel_timeout(radius_client_timer,send_info,NULL);
				circle_register_timeout(RADIUS_CLIENT_FIRST_WAIT, 0,
							   radius_client_timer, send_info, NULL);
			}
		}
	}	
	
	switch (nserv->addr.af) {
	case AF_INET:
		os_memset(&serv, 0, sizeof(serv));
		serv.sin_family = AF_INET;
		if(conf->distribute_off){
			serv.sin_addr.s_addr = nserv->addr.u.v4.s_addr;
			serv.sin_port = htons(nserv->port);
		}else{
			serv.sin_addr.s_addr = SLOT_IPV4_BASE + conf->slot_value;
			if(local)
				serv.sin_port = htons(RDC_RADIUS_PORT_BASE + conf->inst_value);
			else
				serv.sin_port = htons(RDC_RADIUS_PORT_BASE + 16 + conf->inst_value);
		}
		addr = (struct sockaddr *) &serv;
		addrlen = sizeof(serv);
		sel_sock = sock;
		break;
#ifdef ASD_IPV6
	case AF_INET6:
		os_memset(&serv6, 0, sizeof(serv6));
		serv6.sin6_family = AF_INET6;
		os_memcpy(&serv6.sin6_addr, &nserv->addr.u.v6,
			  sizeof(struct in6_addr));
		serv6.sin6_port = htons(nserv->port);
		addr = (struct sockaddr *) &serv6;
		addrlen = sizeof(serv6);
		sel_sock = sock6;
		break;
#endif /* ASD_IPV6 */
	default:
		return -1;
	}
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"to send.ip: %s\n",inet_ntoa(serv.sin_addr));		//for test
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"to send.port: %d\n", ntohs(serv.sin_port));		//for test

	if (conf->force_client_addr) {
		switch (conf->client_addr.af) {
		case AF_INET:
			os_memset(&claddr, 0, sizeof(claddr));
			claddr.sin_family = AF_INET;
			if(conf->distribute_off == 1)
				claddr.sin_addr.s_addr = conf->client_addr.u.v4.s_addr;
			else
				claddr.sin_addr.s_addr = SLOT_IPV4_BASE + slotid;
			claddr.sin_port = htons(0);
			cl_addr = (struct sockaddr *) &claddr;
			claddrlen = sizeof(claddr);
			asd_printf(ASD_DEFAULT,MSG_DEBUG,"claddr.ip: %s\n",inet_ntoa(claddr.sin_addr)); 	//for test
			break;
#ifdef ASD_IPV6
		case AF_INET6:
			os_memset(&claddr6, 0, sizeof(claddr6));
			claddr6.sin6_family = AF_INET6;
			os_memcpy(&claddr6.sin6_addr, &conf->client_addr.u.v6,
				  sizeof(struct in6_addr));
			claddr6.sin6_port = htons(0);
			cl_addr = (struct sockaddr *) &claddr6;
			claddrlen = sizeof(claddr6);
			break;
#endif 
		default:
			return -1;
		}
		
		if (bind(sel_sock, cl_addr, claddrlen) < 0) {
			asd_printf(ASD_DEFAULT,MSG_INFO,"radius %d bind error: %s",auth,strerror(errno));
			perror("bind[radius]");
			return -1;
		}
	}
//	radius_client_dm_init();
	/*
	if(conf->distribute_off == 1){
		if (connect(sel_sock, addr, addrlen) < 0) {
			if ((auth)&&(oserv == NULL)&&(conf->num_auth_servers > 1)) {
				old = conf->auth_server;
				next = old + 1;
				if (next > &(conf->auth_servers[conf->num_auth_servers - 1]))
					next = conf->auth_servers;
				conf->auth_server = next;
				asd_printf(ASD_DEFAULT,MSG_INFO,"change auth server 222\n");		//for test
				radius_change_server(client_info, next, old,
							 radius->auth_serv_sock,
							 radius->auth_serv_sock6, 1);
				return 0;
			}
			else if ((!auth)&&(oserv == NULL)&&(conf->num_acct_servers > 1)) {
				old = conf->acct_server;
				next = old + 1;
				if (next > &conf->acct_servers[conf->num_acct_servers - 1])
					next = conf->acct_servers;
				conf->acct_server = next;
				asd_printf(ASD_DEFAULT,MSG_INFO,"change acct server 222\n");		//for test
				radius_change_server(client_info, next, old,
							 radius->acct_serv_sock,
							 radius->acct_serv_sock6, 0);
			}
			else{
				asd_printf(ASD_DEFAULT,MSG_INFO,"connect error\n");		//for test
				perror("connect[radius]");
				return -1;
			}
		}
	}*/

#ifdef ASD_IPV6
	radius_client->sock6 = sel_sock;
#endif
	radius_client->sock = sel_sock;
	return 0;
}

#if 0
static void radius_retry_primary_timer(void *circle_ctx, void *timeout_ctx)
{
	struct radius_client_info *client_info;
	struct radius_client_data *radius = circle_ctx;
	struct asd_radius_servers *conf = radius->conf;
	struct asd_radius_server *oserv;


	client_info = radius->auth;
	while(client_info)
	{
		if (client_info->sock >= 0 && conf->auth_servers &&
			conf->auth_server != conf->auth_servers) {
			oserv = conf->auth_server;
			conf->auth_server = conf->auth_servers;
			
			radius_change_server(client_info, conf->auth_server, oserv,
						 radius->auth_serv_sock,
						 radius->auth_serv_sock6, 1);
		}
		client_info = client_info->next;
	}
	client_info = radius->acct;
	while(client_info)
	{
		if (client_info->sock >= 0 && conf->acct_servers &&
			conf->acct_server != conf->acct_servers) {
			oserv = conf->acct_server;
			conf->acct_server = conf->acct_servers;
			radius_change_server(client_info, conf->acct_server, oserv,
						 radius->acct_serv_sock,
						 radius->acct_serv_sock6, 0);
		}
	}

	if (conf->retry_primary_interval)
		circle_register_timeout(conf->retry_primary_interval, 0,
				       radius_retry_primary_timer, radius,
				       NULL);
}
#endif
//qiuchen
int radius_test_client_init_auth(void *circle_ctx, void *timeout_ctx){
	struct heart_test_radius_data *radius = circle_ctx;
	struct asd_radius_servers *conf = radius->conf;
	int ok = 0;
	int ret = 0;
	if(radius == NULL)
		return -1;
	radius->auth_serv_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (radius->auth_serv_sock < 0)
		perror("socket[PF_INET,SOCK_DGRAM]");
	else
		ok++;
#ifdef ASD_IPV6
		radius->auth_serv_sock6 = socket(PF_INET6, SOCK_DGRAM, 0);
		if (radius->auth_serv_sock6 < 0)
			perror("socket[PF_INET6,SOCK_DGRAM]");
		else
			ok++;
#endif /* ASD_IPV6 */
	if (ok == 0){
		asd_printf(ASD_DBUS,MSG_CRIT,"%s socket create failed\n",__func__);
		exit(1);
	}
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"radius->auth_serv_sock: %d\n",radius->auth_serv_sock);		//for test
	ret = radius_test_config_server(radius, conf->auth_server, NULL,
			     radius->auth_serv_sock, radius->auth_serv_sock6,
			     1);
	if(ret == -1){
		close(radius->auth_serv_sock);
		radius->auth_serv_sock = -1;
		circle_cancel_timeout((void *)radius_test_client_init_auth, radius, (void*)1);		
		circle_register_timeout(10, 0,
				       (void *)radius_test_client_init_auth, radius, (void*)1);
		return 0;
	}
		if (radius->auth_serv_sock >= 0 &&
			circle_register_read_sock(radius->auth_serv_sock,
						 radius_test_client_receive, radius,
						 (void *) RADIUS_AUTH)) {
			asd_printf(ASD_DEFAULT,MSG_DEBUG,"Could not register read socket for authentication "
				   "server\n");
			return -1;
		}
	
#ifdef ASD_IPV6
		if (radius->auth_serv_sock6 >= 0 &&
			circle_register_read_sock(radius->auth_serv_sock6,
						 radius_test_client_receive, radius,
						 (void *) RADIUS_AUTH)) {
			asd_printf(ASD_DEFAULT,MSG_DEBUG,"Could not register read socket for authentication "
				   "server\n");
			return -1;
		}
#endif /* ASD_IPV6 */
	
		return 0;

}
//end

int radius_client_init_auth(void *circle_ctx, void *timeout_ctx)
{
	struct radius_client_info *client_info = circle_ctx;
	if(client_info  == NULL)
	{
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"client_info = NULL\n");
		return -1;
	}
	struct radius_client_data *radius = client_info->ctx;
	if(radius == NULL)
	{
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"radius = NULL\n");
		return -1;
	}
	struct asd_radius_servers *conf = radius->conf;
	if(conf == NULL)
	{
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"conf = NULL\n");
		return -1;
	}
	//struct sockaddr_in serv;
	//struct sockaddr *addr;
	//socklen_t addrlen;
	int ok = 0;
	int ret = 0;
	//int yes = 1;
	radius->auth_serv_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (radius->auth_serv_sock < 0){
        perror("socket[PF_INET,SOCK_DGRAM]");
		asd_printf(ASD_DBUS,MSG_CRIT,"auth_serv_sock creat failed:%s\n",strerror(errno));
	}	
	else
		ok++;

#ifdef ASD_IPV6
	radius->auth_serv_sock6 = socket(PF_INET6, SOCK_DGRAM, 0);
	if (radius->auth_serv_sock6 < 0){	
	    perror("socket[PF_INET6,SOCK_DGRAM]");
		asd_printf(ASD_DBUS,MSG_CRIT,"auth_serv_sock6 creat failed:%s\n",strerror(errno));
	}	
	else
		ok++;
#endif /* ASD_IPV6 */

	if (ok == 0){
		asd_printf(ASD_DBUS,MSG_CRIT,"%s socket create failed\n",__func__);
		radius_auth_serv_sock_creat_failed_times++;
		if(radius_auth_serv_sock_creat_failed_times == 10){
			asd_printf(ASD_DBUS,MSG_CRIT,"%s try to create socket again failed\n",__func__);
            exit(1);
		}
		circle_cancel_timeout((void *)radius_client_init_auth, radius, (void*)1);		
		circle_register_timeout(10, 0,
				       (void *)radius_client_init_auth, radius,(void*)1 );
		return 0;
	}
	
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"radius->auth_serv_sock: %d\n",radius->auth_serv_sock);		//for test
	//setsockopt(radius->auth_serv_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef ASD_IPV6
	//setsockopt(radius->auth_serv_sock6, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#endif
	
	ret = radius_change_server(client_info, conf->auth_server, NULL,
			     radius->auth_serv_sock, radius->auth_serv_sock6,
			     1);
	if(ret == -1){
		close(radius->auth_serv_sock);
		radius->auth_serv_sock = -1;
		/*
		circle_cancel_timeout((void *)radius_client_init_auth, radius, (void*)1);		
		circle_register_timeout(10, 0,
				       (void *)radius_client_init_auth, radius, (void*)1);*/
		return 0;
	}
	if (radius->auth_serv_sock >= 0 &&
	    circle_register_read_sock(radius->auth_serv_sock,
				     radius_client_receive, client_info,
				     (void *) RADIUS_AUTH)) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Could not register read socket for authentication "
		       "server\n");
		return -1;
	}

#ifdef ASD_IPV6
	if (radius->auth_serv_sock6 >= 0 &&
	    circle_register_read_sock(radius->auth_serv_sock6,
				     radius_client_receive, client_info,
				     (void *) RADIUS_AUTH)) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Could not register read socket for authentication "
		       "server\n");
		return -1;
	}
#endif /* ASD_IPV6 */

	return 0;
}
//qiuchen
int radius_test_client_init_acct(void *circle_ctx, void *timeout_ctx){
	struct heart_test_radius_data *radius = circle_ctx;
	struct asd_radius_servers *conf = radius->conf;
	int ok = 0;
	int ret = 0;
	if(radius == NULL)
		return -1;
	radius->acct_serv_sock = socket(PF_INET, SOCK_DGRAM, 0);
		if (radius->acct_serv_sock < 0)
			perror("socket[PF_INET,SOCK_DGRAM]");
		else
			ok++;
	
#ifdef ASD_IPV6
		radius->acct_serv_sock6 = socket(PF_INET6, SOCK_DGRAM, 0);
		if (radius->acct_serv_sock6 < 0)
			perror("socket[PF_INET6,SOCK_DGRAM]");
		else
			ok++;
#endif /* ASD_IPV6 */
	
		if (ok == 0){
			asd_printf(ASD_DBUS,MSG_CRIT,"%s socket create failed\n",__func__);
			exit(1);
		}
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"radius->acct_serv_sock: %d\n",radius->acct_serv_sock);		//for test
		ret = radius_test_config_server(radius, conf->acct_server, NULL,
					 radius->acct_serv_sock, radius->acct_serv_sock6,
					 0);
			if((ret == -1)&&(timeout_ctx != NULL)){
				close(radius->acct_serv_sock);
				radius->acct_serv_sock = -1;		
				circle_cancel_timeout((void *)radius_test_client_init_acct, radius, (void *)1);
				circle_register_timeout(10, 0,
							   (void *)radius_test_client_init_acct, radius, (void *)1);
				return 0;
			}
		
			if (radius->acct_serv_sock >= 0 &&
				circle_register_read_sock(radius->acct_serv_sock,
							 radius_test_client_receive, radius,
							 (void *) RADIUS_ACCT)) {
				asd_printf(ASD_DEFAULT,MSG_DEBUG,"Could not register read socket for accounting "
					   "server\n");
				return -1;
			}
		
#ifdef ASD_IPV6
			if (radius->acct_serv_sock6 >= 0 &&
				circle_register_read_sock(radius->acct_serv_sock6,
							 radius_test_client_receive, radius,
							 (void *) RADIUS_ACCT)) {
				asd_printf(ASD_DEFAULT,MSG_DEBUG,"Could not register read socket for accounting "
					   "server\n");
				return -1;
			}
#endif /* ASD_IPV6 */
		
	return 0;	
}
//end

int radius_client_init_acct(void *circle_ctx, void *timeout_ctx)
{
	struct radius_client_info *client_info = circle_ctx;
	if(client_info  == NULL)
	{
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"client_info = NULL\n");
		return -1;
	}
	struct radius_client_data *radius = client_info->ctx;
	if(radius == NULL)
	{
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"radius = NULL\n");
		return -1;
	}
	struct asd_radius_servers *conf = radius->conf;
	if(conf == NULL)
	{
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"conf = NULL\n");
		return -1;
	}
	//struct sockaddr_in serv;
	//struct sockaddr *addr;
	//socklen_t addrlen;
	int ok = 0;
	int ret = 0;
	//int yes = 1;
	//struct sockaddr_in serv;
	//struct sockaddr *addr;
	//socklen_t addrlen;
	radius->acct_serv_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (radius->acct_serv_sock < 0){
		perror("socket[PF_INET,SOCK_DGRAM]");
	    asd_printf(ASD_DBUS,MSG_CRIT,"acct_serv_sock creat failed:%s\n",strerror(errno));
	}
	else
		ok++;

#ifdef ASD_IPV6
	radius->acct_serv_sock6 = socket(PF_INET6, SOCK_DGRAM, 0);
	if (radius->acct_serv_sock6 < 0){
		perror("socket[PF_INET6,SOCK_DGRAM]");
		asd_printf(ASD_DBUS,MSG_CRIT,"acct_serv_sock6 creat failed:%s\n",strerror(errno));
	}
	else
		ok++;
#endif /* ASD_IPV6 */

	if (ok == 0){
		asd_printf(ASD_DBUS,MSG_CRIT,"%s socket create failed\n",__func__);
		radius_acct_serv_sock_creat_failed_times++;
		if(radius_acct_serv_sock_creat_failed_times == 10){
			asd_printf(ASD_DBUS,MSG_CRIT,"%s try to create socket again failed\n",__func__);
            exit(1);
		}
		circle_cancel_timeout((void *)radius_client_init_acct, radius, (void*)1);	
		circle_register_timeout(10, 0,
				       (void *)radius_client_init_acct, radius,(void*)1);
		return 0;
	}

	asd_printf(ASD_DEFAULT,MSG_DEBUG,"radius->acct_serv_sock: %d\n",radius->acct_serv_sock);		//for test
	//setsockopt(radius->acct_serv_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef ASD_IPV6
	//setsockopt(radius->acct_serv_sock6, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#endif

	ret = radius_change_server(client_info, conf->acct_server, NULL,
			     radius->acct_serv_sock, radius->acct_serv_sock6,
			     0);
	//if((ret == -1)&&(timeout_ctx == 1)){
	if(ret == -1){
		close(radius->acct_serv_sock);
		radius->acct_serv_sock = -1;		
		/*
		circle_cancel_timeout((void *)radius_client_init_acct, radius, client_info);
		circle_register_timeout(10, 0,
				       (void *)radius_client_init_acct, radius, client_info);
				       */
		return 0;
	}

	if (radius->acct_serv_sock >= 0 &&
	    circle_register_read_sock(radius->acct_serv_sock,
				     radius_client_receive, client_info,
				     (void *) RADIUS_ACCT)) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Could not register read socket for accounting "
		       "server\n");
		return -1;
	}

#ifdef ASD_IPV6
	if (radius->acct_serv_sock6 >= 0 &&
	    circle_register_read_sock(radius->acct_serv_sock6,
				     radius_client_receive, client_info,
				     (void *) RADIUS_ACCT)) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Could not register read socket for accounting "
		       "server\n");
		return -1;
	}
#endif /* ASD_IPV6 */

	return 0;
}

/*ht add 090826*/
#if 0
static int radius_client_init_dm_sock(struct radius_client_data *radius)
{
	int s;
	int port = 3799;
	struct sockaddr_in addr;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		close(s);
		return -1;
	}

	radius->dm_sock = s;
	dm_sock = s;
	if (s >= 0 &&
	    circle_register_read_sock(s,
				     radius_client_receive, radius,
				     (void *) RADIUS_DM)) {
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"Could not register read socket for receive DM "
		       "\n");
		return -1;
	}

	return 0;
}
#endif
int radius_client_malloc(struct radius_client_data *radius,int num,int auth)
{
	if( (num <= 0 )||(radius == NULL))
		return -1;
	struct radius_client_info *client_info,*client_tmp;
	client_info = NULL;
	int i ,j;
	for(i = 0 ; i < num ; i++)
	{
		client_tmp  = os_zalloc(sizeof(struct radius_client_info));
		if(client_tmp == NULL)
			return -1;
		client_tmp->sock = -1;
		client_tmp->next_radius_identifier = 0;
		client_tmp->client_handlers = NULL;
		client_tmp->next = NULL;
		client_tmp->num = 0;
		client_tmp->num_client_handers =0;
		client_tmp->ctx = radius;
		for(j = 0 ; j < 256 ; j++)
			client_tmp->sta[j] = NULL;
		if(client_info == NULL)
		{
			client_info = client_tmp;	
			if(auth){
				asd_printf(ASD_DEFAULT,MSG_DEBUG,"auth malloc!\n");
				radius->auth  = client_info;
			}
			else{
				radius->acct  = client_info;
				asd_printf(ASD_DEFAULT,MSG_DEBUG,"acct malloc!\n");
				}				
		}
		else
		{
			client_info->next  = client_tmp;
			client_info = client_tmp;
			asd_printf(ASD_DEFAULT,MSG_DEBUG,"malloc once more!\n");
		}
	}
	return 0;
}
//qiuchen
int radius_test_client_init(struct heart_test_radius_data *radius){
	struct asd_radius_servers *conf = radius->conf;
	radius->auth_serv_sock = radius->acct_serv_sock =
		radius->auth_serv_sock6 = radius->acct_serv_sock6 =
		radius->auth_sock = radius->acct_sock = -1;
	if(conf->distribute_off == 0){
		rdc_client_init(0, slotid, local, vrrid, RDC_ASD, NULL);
	}
	if (conf->auth_server && radius_test_client_init_auth((void*)radius, (void *)1)) {
		radius_test_client_deinit(radius);
		return -1;
	}
	if (conf->acct_server && radius_test_client_init_acct((void*)radius, (void *)1)) {
		radius_test_client_deinit(radius);
		return -1;
	}
	return 0;
}
//end
struct radius_client_data *
radius_client_init(void *ctx, struct asd_radius_servers *conf)
{
	struct radius_client_data *radius;
	struct radius_client_info *client_info;
	
	radius = os_zalloc(sizeof(struct radius_client_data));
	if (radius == NULL)
	{
		asd_printf(ASD_DEFAULT,MSG_ERROR,"radius malloc error!\n");
		return NULL;
	}	
	if(radius_client_malloc(radius,2,1) < 0)
	{
		asd_printf(ASD_DEFAULT,MSG_ERROR,"radius client auth malloc error!\n");
		return NULL;
	}		
	if(radius_client_malloc(radius,2,0) < 0)
	{
		asd_printf(ASD_DEFAULT,MSG_ERROR,"radius client acct malloc error!\n");
		return NULL;
	}
	radius->ctx = ctx;
	radius->conf = conf;
	radius->auth_serv_sock = radius->acct_serv_sock =
		radius->auth_serv_sock6 = radius->acct_serv_sock6 =
		radius->auth_sock = radius->acct_sock = -1;

	if(conf->distribute_off == 0){
		//rdc_set_server_hansi(conf->slot_value, conf->inst_value);
		if(local)
			rdc_client_init(ASD_RDC_COA_PORT_BASE+vrrid, slotid, local, vrrid, RDC_ASD, NULL);
		else
			rdc_client_init(ASD_RDC_COA_PORT_BASE+16+vrrid,slotid,local,vrrid,RDC_ASD,NULL);
	}
	client_info = radius->auth;
	while(client_info != NULL)
	{
		if(client_info->sta[0] == NULL)
			asd_printf(ASD_DEFAULT,MSG_DEBUG,"client_info sta is NULL");
		else
			asd_printf(ASD_DEFAULT,MSG_DEBUG,"client_info sta is not null!\n");
		if (conf->auth_server && radius_client_init_auth((void*)client_info, (void *)1)) {
			radius_client_deinit(radius);
			return NULL;
		}
		client_info = client_info->next;
	}
	client_info = radius->acct;
	while(client_info != NULL)
	{
		if (conf->acct_server && radius_client_init_acct((void*)client_info, (void *)1)) {
			radius_client_deinit(radius);
			return NULL;
		}
		client_info = client_info->next;
	}
	/*if (conf->retry_primary_interval)
		circle_register_timeout(conf->retry_primary_interval, 0,
				       radius_retry_primary_timer, radius,
				       NULL);*/

	asd_printf(ASD_1X,MSG_DEBUG,"radius_client_init() is OK.\n");
	return radius;
}

 void radius_client_info_deinit(struct radius_client_info *client_info)
{
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"now in func:%s\n",__func__);
	if(!client_info)
		return ;
	struct radius_send_info *send_info = NULL;
	int i =0;
	if(client_info->sock >= 0)
	{
		circle_unregister_read_sock(client_info->sock);
		FD_CHANGE = 1;
		close(client_info->sock);
		client_info->sock = -1;
	}
	for( i = 0 ; i < 256 ; i++)
	{
		send_info = client_info->sta[i];
		if(send_info)
		{
			asd_printf(ASD_DEFAULT,MSG_DEBUG,"func:%s radius id %d\n",__func__,i);
			radius_client_info_free(send_info);
			send_info = NULL;
		
		}
	}
	os_free(client_info->client_handlers);
	client_info->client_handlers = NULL;
	client_info->next = NULL;
	client_info->ctx = NULL;
	os_free(client_info);
	client_info  = NULL;

}
//qiuchen
void radius_test_client_deinit(struct heart_test_radius_data *radius){
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"%s\n",__func__);
	if (!radius)
		return;

	if (radius->auth_serv_sock >= 0){
		circle_unregister_read_sock(radius->auth_serv_sock);
		FD_CHANGE = 1;
		close(radius->auth_serv_sock);
		radius->auth_serv_sock = -1;
	}
	if (radius->acct_serv_sock >= 0){
		circle_unregister_read_sock(radius->acct_serv_sock);
		FD_CHANGE = 1;
		close(radius->acct_serv_sock);
		radius->acct_serv_sock = -1;
	}
}
//end

void radius_client_deinit(struct radius_client_data *radius)
{
	if (!radius)
		return;
	struct radius_client_info *client_info,*client_next;
	client_info = radius->auth;
	while(client_info)
	{
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"client_info->sock:%d\n",client_info->sock);
		client_next = client_info->next;
		radius_client_info_deinit(client_info);
		client_info  = client_next;
	}
	radius->auth = NULL;
	client_info = radius->acct;
	while(client_info)
	{
		asd_printf(ASD_DEFAULT,MSG_DEBUG,"client_info->sock:%d\n",client_info->sock);
		client_next = client_info->next;
		radius_client_info_deinit(client_info);
		client_info  = client_next;
	}
	radius->acct = NULL;
	//circle_cancel_timeout(radius_retry_primary_timer, radius, NULL);
	
	radius->conf = NULL;
	os_free(radius);
}
#if 0

void radius_client_flush_auth(struct radius_client_data *radius, u8 *addr)
{
	struct radius_msg_list *entry, *prev, *tmp;

	prev = NULL;
	entry = radius->msgs;
	while (entry) {
		if (entry->msg_type == RADIUS_AUTH &&
		    os_memcmp(entry->addr, addr, ETH_ALEN) == 0) {
			asd_logger(radius->ctx, addr,
				       asd_MODULE_RADIUS,
				       asd_LEVEL_DEBUG,
				       "Removing pending RADIUS authentication"
				       " message for removed client");

			if (prev)
				prev->next = entry->next;
			else
				radius->msgs = entry->next;

			tmp = entry;
			entry = entry->next;
			radius_client_msg_free(tmp);
			radius->num_msgs--;
			if(radius->num_msgs == 0)	//mahz add 2011.7.15
				radius->msgs = NULL;
			continue;
		}

		prev = entry;
		entry = entry->next;
	}
}
#endif

static int radius_client_dump_auth_server(char *buf, size_t buflen,
					  struct asd_radius_server *serv,
					  struct radius_client_data *cli)
{
	int pending = 0;
	char abuf[50];
	struct radius_client_info *radius_client;
	int radius_id;
	radius_client = cli->auth;
	while(radius_client)
	{
		for(radius_id = 0 ; radius_id < 256 ; radius_id++)
			if(radius_client->sta[radius_id])
				pending++;
		}

	return os_snprintf(buf, buflen,
			   "radiusAuthServerIndex=%d\n"
			   "radiusAuthServerAddress=%s\n"
			   "radiusAuthClientServerPortNumber=%d\n"
			   "radiusAuthClientRoundTripTime=%d\n"
			   "radiusAuthClientAccessRequests=%u\n"
			   "radiusAuthClientAccessRetransmissions=%u\n"
			   "radiusAuthClientAccessAccepts=%u\n"
			   "radiusAuthClientAccessRejects=%u\n"
			   "radiusAuthClientAccessChallenges=%u\n"
			   "radiusAuthClientMalformedAccessResponses=%u\n"
			   "radiusAuthClientBadAuthenticators=%u\n"
			   "radiusAuthClientPendingRequests=%u\n"
			   "radiusAuthClientTimeouts=%u\n"
			   "radiusAuthClientUnknownTypes=%u\n"
			   "radiusAuthClientPacketsDropped=%u\n",
			   serv->index,
			   asd_ip_txt(&serv->addr, abuf, sizeof(abuf)),
			   serv->port,
			   serv->round_trip_time,
			   serv->requests,
			   serv->retransmissions,
			   serv->access_accepts,
			   serv->access_rejects,
			   serv->access_challenges,
			   serv->malformed_responses,
			   serv->bad_authenticators,
			   pending,
			   serv->timeouts,
			   serv->unknown_types,
			   serv->packets_dropped);
}


static int radius_client_dump_acct_server(char *buf, size_t buflen,
					  struct asd_radius_server *serv,
					  struct radius_client_data *cli)
{
	int pending = 0;
	char abuf[50];
	struct radius_client_info *radius_client;
	int radius_id;
	radius_client = cli->acct;
	while(radius_client)
	{
		for(radius_id = 0 ; radius_id < 256 ; radius_id++)
			if(radius_client->sta[radius_id])
				pending++;
	}

	return os_snprintf(buf, buflen,
			   "radiusAccServerIndex=%d\n"
			   "radiusAccServerAddress=%s\n"
			   "radiusAccClientServerPortNumber=%d\n"
			   "radiusAccClientRoundTripTime=%d\n"
			   "radiusAccClientRequests=%u\n"
			   "radiusAccClientRetransmissions=%u\n"
			   "radiusAccClientResponses=%u\n"
			   "radiusAccClientMalformedResponses=%u\n"
			   "radiusAccClientBadAuthenticators=%u\n"
			   "radiusAccClientPendingRequests=%u\n"
			   "radiusAccClientTimeouts=%u\n"
			   "radiusAccClientUnknownTypes=%u\n"
			   "radiusAccClientPacketsDropped=%u\n",
			   serv->index,
			   asd_ip_txt(&serv->addr, abuf, sizeof(abuf)),
			   serv->port,
			   serv->round_trip_time,
			   serv->requests,
			   serv->retransmissions,
			   serv->responses,
			   serv->malformed_responses,
			   serv->bad_authenticators,
			   pending,
			   serv->timeouts,
			   serv->unknown_types,
			   serv->packets_dropped);
}


int radius_client_get_mib(struct radius_client_data *radius, char *buf,
			  size_t buflen)
{
	struct asd_radius_servers *conf = radius->conf;
	int i;
	struct asd_radius_server *serv;
	int count = 0;

	if (conf->auth_servers) {
		for (i = 0; i < conf->num_auth_servers; i++) {
			serv = &conf->auth_servers[i];
			count += radius_client_dump_auth_server(
				buf + count, buflen - count, serv,
				serv == conf->auth_server ?
				radius : NULL);
		}
	}

	if (conf->acct_servers) {
		for (i = 0; i < conf->num_acct_servers; i++) {
			serv = &conf->acct_servers[i];
			count += radius_client_dump_acct_server(
				buf + count, buflen - count, serv,
				serv == conf->acct_server ?
				radius : NULL);
		}
	}

	return count;
}


static int radius_servers_diff(struct asd_radius_server *nserv,
			       struct asd_radius_server *oserv,
			       int num)
{
	int i;

	for (i = 0; i < num; i++) {
		if (asd_ip_diff(&nserv[i].addr, &oserv[i].addr) ||
		    nserv[i].port != oserv[i].port ||
		    nserv[i].shared_secret_len != oserv[i].shared_secret_len ||
		    os_memcmp(nserv[i].shared_secret, oserv[i].shared_secret,
			      nserv[i].shared_secret_len) != 0)
			return 1;
	}

	return 0;
}


struct radius_client_data *
radius_client_reconfig(struct radius_client_data *old, void *ctx,
		       struct asd_radius_servers *oldconf,
		       struct asd_radius_servers *newconf)
{
//	radius_client_flush(old, 0);

	if (newconf->retry_primary_interval !=
	    oldconf->retry_primary_interval ||
	    newconf->num_auth_servers != oldconf->num_auth_servers ||
	    newconf->num_acct_servers != oldconf->num_acct_servers ||
	    radius_servers_diff(newconf->auth_servers, oldconf->auth_servers,
				newconf->num_auth_servers) ||
	    radius_servers_diff(newconf->acct_servers, oldconf->acct_servers,
				newconf->num_acct_servers)) {
		asd_logger(ctx, NULL, asd_MODULE_RADIUS,
			       asd_LEVEL_DEBUG,
			       "Reconfiguring RADIUS client");
		radius_client_deinit(old);
		return radius_client_init(ctx, newconf);
	}

	return old;
}
//add for dm socket ,receive dm message from rdc
/*will not receive from radius server directly*/
void radius_client_dm_init()
{
	struct sockaddr_in claddr;	

	DmSock = socket(AF_INET, SOCK_DGRAM, 0);
	if(DmSock < 0)
	{
		asd_printf(ASD_DEFAULT,MSG_ERROR,"DmSock init error!\n");
		perror("error:\n");
		exit(1);
	}
	os_memset(&claddr, 0, sizeof(claddr));
	claddr.sin_family = AF_INET;
	claddr.sin_addr.s_addr = SLOT_IPV4_BASE + slotid;
	if(local)
		claddr.sin_port = htons(ASD_RDC_COA_PORT_BASE+vrrid);	
	else
		claddr.sin_port = htons(ASD_RDC_COA_PORT_BASE+16+vrrid);
	/*claddr.sin_addr.s_addr = inet_addr("192.168.70.61");
	claddr.sin_port = htons(3799);*/
	//asd_printf(ASD_DEFAULT,MSG_ERROR,"bind:ip:%x port :%d\n",ntohs(claddr.sin_addr.s_addr),ntohs(claddr.sin_port));
	if(bind(DmSock,(struct sockaddr *)&claddr,sizeof(claddr)) < 0)
	{
		asd_printf(ASD_DEFAULT,MSG_ERROR,"bind error : %s , errno:%d\n",strerror(errno),errno);
		perror("bind DmSock\n");
		return;
	}
	circle_register_read_sock(DmSock,radius_receive_dm_message,NULL,NULL);
}
void radius_receive_dm_message(int sock,void *circle_ctx,void *sock_ctx)
{
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"func:%s\n",__func__);
	unsigned char buf[3000];
	struct radius_msg *msg;
	int len = 0;
	struct sockaddr_in serv_addr;
	socklen_t addrlen = sizeof(serv_addr);
	int radius_ip,radius_port;
	len = rdc_recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&serv_addr, &addrlen);
	//len = recvfrom(sock,buf,sizeof(buf),0,(struct sockaddr *)&serv_addr,&addrlen);
	if(len <=  0)
	{
		asd_printf(ASD_DEFAULT,MSG_ERROR,"recieve dm message error,len < 0!\n");
		return;
	}	
	if(addrlen < 0)
	{
		asd_printf(ASD_DEFAULT,MSG_ERROR,"we have not get the server addr,drop it!\n");
		return;
	}
	radius_ip = ntohl(serv_addr.sin_addr.s_addr);
	radius_port = ntohl(serv_addr.sin_port);

	msg = radius_msg_parse(buf, len);
	if(msg == NULL)
	{
		asd_printf(ASD_DEFAULT,MSG_ERROR,"parse msg error!\n");
		return;
	}
	if(len != msg->hdr->length)
	{
		asd_printf(ASD_DEFAULT,MSG_INFO,"coa recieve len != radius length!\n");
	}
	if(RADIUS_CODE_COA_REQUEST != msg->hdr->code 
		&&RADIUS_CODE_DISCONNECT_REQUEST != msg->hdr->code)
	{
		asd_printf(ASD_DEFAULT,MSG_ERROR,"func:%s recieve msg is not expected!\n",__func__);
		goto fail;
	}
	asd_radius_coa_request(msg,radius_ip,radius_port);
fail:
	   radius_msg_free(msg);
	   os_free(msg);
	   msg = NULL;

}
void radius_client_send_dm_message(struct radius_msg *msg,struct radius_coa_info *coa_info)
{
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"func: %s\n",__func__);
	if(!msg || !coa_info)
		return;
	struct sockaddr_in serv_addr;
	socklen_t addrlen ;

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = coa_info->ip;
	serv_addr.sin_port  = htons(coa_info->port);
	addrlen =  sizeof(serv_addr);
	
	int res = 0;
	
	res = rdc_sendto(DmSock, msg->buf, msg->buf_used, 0, (struct sockaddr *)&serv_addr, addrlen, coa_info->slot_value, coa_info->inst_value);
	//res = sendto(DmSock,msg->buf,msg->buf_used,0,(struct sockaddr *)&serv_addr,addrlen);
	if(res < 0)
	{
		asd_printf(ASD_1X,MSG_ERROR,"func: %s,send to rdc error!\n",__func__);
		perror("send error!\n");
	}
	asd_printf(ASD_DEFAULT,MSG_DEBUG,"res = %d,msg->buf_used: %d\n",res,msg->buf_used);
	
}

