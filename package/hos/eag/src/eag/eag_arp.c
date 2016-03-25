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
* eag_arp.c
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* eag arp
*
*
*******************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <time.h>


#include "eag_mem.h"
#include "eag_log.h"
#include "eag_thread.h"
#include "eag_util.h"
#include "eag_arp.h"
#include "appconn.h"
#include "eag_ins.h"
#include "eag_macauth.h"
#include "radius_packet.h"

typedef struct
{
	unsigned char family;
	unsigned char bytelen;
	unsigned char bitlen;
	unsigned char flags;
	unsigned char data[4];
} inet_prefix;

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

struct eag_arplisten {
	int sockfd;
	struct sockaddr_nl local;
	struct sockaddr_nl peer;
	__u32 seq;
	__u32 dump;
	
	eag_ins_t *eagins;
	eag_portal_t *portal;
	eag_macauth_t *macauth;
	appconn_db_t *appdb;
	eag_thread_t *t_read;
	eag_thread_master_t *master;
};

typedef enum {
	EAG_ARP_READ,
} eag_arp_event_t;

static unsigned char zero_mac[6] = {0};
static unsigned char broad_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static void
eag_arp_event(eag_arp_event_t event, eag_arplisten_t *arp);

static int 
parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	if (NULL == tb || NULL == rta) {
		eag_log_err("eag_arp parse_rtattr tb or rta is null");
		return EAG_ERR_NULL_POINTER;
	}
	
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
	if (len) {
		eag_log_warning("eag_arp parse_rtattr !!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	}
	return 0;
}



eag_arplisten_t *eag_arp_new()
{	
	eag_arplisten_t *arp = NULL;
	
	arp = eag_malloc(sizeof(*arp));
	if (NULL == arp) {
		eag_log_err("eag_arp_new eag_malloc failed");
		return NULL;
	}
	memset(arp, 0, sizeof(*arp));
	arp->sockfd = -1;
	eag_log_info("arp new ok, sockfd(%d)", arp->sockfd);
	return arp;
}

int
eag_arp_free(eag_arplisten_t *arp)
{
	if (NULL == arp) {
		eag_log_err("eag_arp_free input error");
		return EAG_ERR_NULL_POINTER;
	}

	if (arp->sockfd >= 0) {
		close(arp->sockfd);
		arp->sockfd = -1;
	}
	eag_free(arp);

	eag_log_info( "arp free ok");
	return 0;
}

int 
eag_arp_start(eag_arplisten_t *arp)
{
	socklen_t addr_len = 0;
	int sndbuf = 32768;
	int rcvbuf = 32768;
	int ret = 0;

	if (NULL == arp) {
		eag_log_err("eag_arp_start arp is null");
		return EAG_ERR_NULL_POINTER;
	}
	if (arp->sockfd >= 0) {
		eag_log_err("eag_arp_start already start fd(%d)", arp->sockfd);
		return EAG_RETURN_OK;
	}

	arp->sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (arp->sockfd < 0) {
		eag_log_err("eag_arp_start: can't create arp netlink socket: %s", safe_strerror(errno));
		arp->sockfd = -1;
		return EAG_ERR_SOCKET_FAILED;
	}
	ret = setsockopt(arp->sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	if (ret < 0) {
		eag_log_err("eag_arp_start setsockopt SO_SNDBUF failed: %s", safe_strerror(errno));
		return EAG_ERR_SOCKET_OPT_FAILED;
	}

	ret = setsockopt(arp->sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	if (ret < 0) {
		eag_log_err("eag_arp_start setsockopt SO_RCVBUF failed: %s", safe_strerror(errno));
		return EAG_ERR_SOCKET_OPT_FAILED;
	}

	ret = set_nonblocking(arp->sockfd);
	if (0 != ret) {
		eag_log_err("eag_arp_start set socket nonblocking failed");
		close(arp->sockfd);
		arp->sockfd = -1;
		return EAG_ERR_SOCKET_OPT_FAILED;
	}
	memset(&arp->local, 0, sizeof(arp->local));
	arp->local.nl_family = AF_NETLINK;
	arp->local.nl_groups = RTMGRP_NEIGH;

	ret = bind(arp->sockfd, (struct sockaddr*)&arp->local, sizeof(arp->local));
	if (ret < 0) {
		eag_log_err("eag_arp_start cannot bind netlink socket: %s", safe_strerror(errno));
		return -1;
	}
	addr_len = sizeof(arp->local);

	ret = getsockname(arp->sockfd, (struct sockaddr*)&arp->local, &addr_len);
	if (ret < 0) {
		eag_log_err("eag_arp_start cannot getsockname: %s", safe_strerror(errno));
		return -1;
	}
	if (addr_len != sizeof(arp->local)) {
		eag_log_err(" eag_arp_start wrong address length %d\n", addr_len);
		return -1;
	}
	if (arp->local.nl_family != AF_NETLINK) {
		eag_log_err("eag_arp_start wrong address family %d\n", arp->local.nl_family);
		return -1;
	}
	arp->seq = time(NULL);
	
	eag_arp_event(EAG_ARP_READ, arp);
	eag_log_info("eag_arp_start: fd(%d) start ok", arp->sockfd);
	return EAG_RETURN_OK;		
}

int
eag_arp_stop(eag_arplisten_t *arp)
{
	if (NULL == arp) {
		eag_log_err("eag_arp_stop input error");
		return EAG_ERR_NULL_POINTER;
	}

	if (NULL != arp->t_read) {
		eag_thread_cancel(arp->t_read);
		arp->t_read = NULL;
	}
	if (arp->sockfd >= 0) {
		close(arp->sockfd);
		arp->sockfd = -1;
	}
	eag_log_info("arp fd(%d) stop ok", arp->sockfd);

	return EAG_RETURN_OK;
}

int
eag_arp_listen_proc(eag_arplisten_t *arp, struct nlmsghdr *arpmsg) 
{
	struct app_conn_t *appconn = NULL;
	struct ndmsg *arp_data = NULL;
	struct rtattr *tb[RTA_MAX+1];	
	uint32_t ip = 0;
	unsigned char *lladdr = NULL;
	char macstr[32] = {0};
	char macstr2[32] = {0};
	char ipstr[32] = {0};
	int len = 0;	

	if (NULL == arp || NULL == arpmsg) {
		eag_log_err("eag_arp_listen_proc input is null");
		return EAG_ERR_NULL_POINTER;
	}

	if (arpmsg->nlmsg_type != RTM_NEWNEIGH) {
		eag_log_debug("eag_arp", "eag_arp_receive arpmsg->nlmsg_type=%u is not RTM_NEWNEIGH(%u)",
					arpmsg->nlmsg_type, RTM_NEWNEIGH);
		return EAG_RETURN_OK;
	}

	arp_data = NLMSG_DATA(arpmsg);
	len = arpmsg->nlmsg_len;

	len -= NLMSG_LENGTH(sizeof(*arp_data));
	if (len < 0) {
		eag_log_err("eag_arp_listen_proc wrong nlmsg len %d", len);
		return -1;
	}

	if (AF_INET != arp_data->ndm_family) {
		eag_log_debug("eag_arp", "eag_arp_listen_proc arp_data->ndm_family(%d) "
						"is not AF_INET", arp_data->ndm_family);
		return EAG_RETURN_OK;
	}

	parse_rtattr(tb, RTA_MAX, RTM_RTA(arp_data), len);

	if (tb[NDA_DST]) {
		ip = *(uint32_t *)RTA_DATA(tb[NDA_DST]);
		ip2str(ip, ipstr, sizeof(ipstr));
	}
	if (tb[NDA_LLADDR]) {
		lladdr = (unsigned char *)RTA_DATA(tb[NDA_LLADDR]);
		mac2str(lladdr, macstr, sizeof(macstr), ':');
	}
	if (NULL == lladdr) {
		eag_log_debug("eag_arp", "eag_arp_listen_proc not get mac, ip is %s", ipstr);
		return EAG_RETURN_OK;
	}
	if (0 == memcmp(zero_mac, lladdr, 6) || 0 == memcmp(broad_mac, lladdr, 6)) {
		eag_log_debug("eag_arp", "eag_arp_listen_proc get arp(ip:%s, mac:%s) and ignored", ipstr, macstr);
		return EAG_RETURN_OK;
	}

	appconn = appconn_find_by_userip(arp->appdb, ip);
	if (NULL == appconn) {
		eag_log_debug("eag_arp", "eag_arp_listen_proc get arp(ip:%s, mac:%s) and not appconn user", ipstr, macstr);
		return EAG_RETURN_OK;
	}
	if (0 == memcmp(appconn->session.usermac, lladdr, 6)) {
		eag_log_debug("eag_arp", "eag_arp_listen_proc get arp(ip:%s, mac:%s) and mac matched", ipstr, macstr);
		return EAG_RETURN_OK;
	}

	mac2str(appconn->session.usermac, macstr2, sizeof(macstr2), ':');
	eag_log_warning("eag_arp_listen_proc ip(%s) conflict, arplisten mac is %s,"
			"appconn mac is %s", ipstr, macstr, macstr2);

	if (eag_macauth_get_macauth_switch(arp->macauth)) {
		del_eag_preauth_by_ip_or_mac(arp->macauth, appconn->session.user_ip, appconn->session.usermac);
	}
	
	if (APPCONN_STATUS_AUTHED == appconn->session.state) {
		terminate_appconn_nowait(appconn, arp->eagins,
				RADIUS_TERMINATE_CAUSE_LOST_CARRIER);
	} else {
		appconn_del_from_db(appconn);
		appconn_free(appconn);
	}

	return EAG_RETURN_OK;
}

static int 
eag_arp_receive(eag_thread_t *thread)
{
	eag_arplisten_t *arp = NULL;
	int nbyte = 0;
	struct nlmsghdr *arpmsg = NULL;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	char buf[8192] = {0};

	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	memset(&iov, 0, sizeof(iov));
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	iov.iov_base = buf;	
	iov.iov_len = sizeof(buf);
	
	if (NULL == thread) {
		eag_log_err("eag_arp_receive input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	
	arp = eag_thread_get_arg(thread);
	if (NULL == arp) {
		eag_log_err("eag_arp_receive arp null");
		return EAG_ERR_NULL_POINTER;
	}
	
	nbyte = recvmsg(arp->sockfd, &msg, 0);
	if (nbyte <= 0) {
		eag_log_err("eag_arp_receive recvmsg failed: %s, fd(%d)",
			safe_strerror(errno), arp->sockfd);
		return EAG_ERR_SOCKET_RECV_FAILED;
	}

	for (arpmsg = (struct nlmsghdr*)buf; nbyte >= sizeof(*arpmsg); ) {
		int err = 0;
		int len = arpmsg->nlmsg_len;
		int l = len - sizeof(*arpmsg);

		if (l < 0 || len > nbyte) {
			eag_log_debug("eag_arp", "eag_arp_receive malformed message: "
				"len=%d, nbtye=%d, sizeof(buf)=%d\n", len, nbyte, sizeof(*arpmsg));
			return -1;
		}

		err = eag_arp_listen_proc(arp, arpmsg);
		if (EAG_RETURN_OK != err) {
			eag_log_warning("eag_arp_receive eag_arp_listen_proc err(%d)", err);
		}
		
		nbyte -= NLMSG_ALIGN(len);
		arpmsg = (struct nlmsghdr*)((char*)arpmsg + NLMSG_ALIGN(len));
	}
	
	if (msg.msg_flags & MSG_TRUNC) {
		eag_log_debug("eag_arp", "Message truncated\n");
		return -1;
	}
	if (nbyte) {
		eag_log_debug("eag_arp", "!!!Remnant of size %d\n", nbyte);
		return -1;
	}

	return EAG_RETURN_OK;
}

void
eag_arp_set_thread_master(eag_arplisten_t *arp,
		eag_thread_master_t *master)
{
	if (NULL == arp ||NULL == master) {
		eag_log_err("eag_arp_set_thread_master input error");
		return;
	}
	arp->master = master;
}

static void
eag_arp_event(eag_arp_event_t event,
						eag_arplisten_t *arp)
{
	if (NULL == arp) {
		eag_log_err("eag_arp_event input error");
		return;
	}
	switch (event) {
	case EAG_ARP_READ:
		arp->t_read =
		    eag_thread_add_read(arp->master, eag_arp_receive,
					arp, arp->sockfd);
		break;
	default:
		break;
	}
}

int
eag_arp_set_eagins(eag_arplisten_t *arp,
		eag_ins_t *eagins)
{
	if (NULL == arp) {
		eag_log_err("eag_arp_set_eagins input error");
		return -1;
	}

	arp->eagins = eagins;

	return EAG_RETURN_OK;
}

int
eag_arp_set_portal(eag_arplisten_t *arp,
		eag_portal_t *portal)
{
	if (NULL == arp) {
		eag_log_err("eag_arp_set_portal input error");
		return -1;
	}

	arp->portal = portal;

	return EAG_RETURN_OK;
}

int
eag_arp_set_macauth(eag_arplisten_t *arp,
		eag_macauth_t *macauth)
{
	if (NULL == arp) {
		eag_log_err("eag_arp_set_macauth input error");
		return -1;
	}

	arp->macauth = macauth;

	return EAG_RETURN_OK;
}

int
eag_arp_set_appdb(eag_arplisten_t *arp,
		appconn_db_t *appdb)
{
	if (NULL == arp) {
		eag_log_err("eag_arp_set_appdb input error");
		return -1;
	}

	arp->appdb = appdb;

	return EAG_RETURN_OK;
}

