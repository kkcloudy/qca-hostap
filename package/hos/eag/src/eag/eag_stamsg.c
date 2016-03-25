/* eag_stamsg.c */

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "nm_list.h"
#include "hashtable.h"
#include "eag_mem.h"
#include "eag_log.h"
#include "eag_blkmem.h"
#include "eag_thread.h"
#include "eag_conf.h"  //not need
#include "eag_time.h"
#include "eag_util.h"
#include "eag_stamsg.h"
#include "eag_ins.h"
#include "eag_portal.h"
#include "eag_captive.h"
#include "radius_packet.h"
#include "eag_wireless.h"
#include "eag_statistics.h"
#include "eag_macauth.h"
#include "eag_radius.h"
#include "eag_authorize.h"

extern int eag_macauth_type;

struct eag_stamsg {
	int sockfd;
	//uint8_t hansi_type;
	//uint8_t hansi_id;
	char sockpath[128];
	char ntf_asd_path[128];
	eag_thread_t *t_read;
	eag_thread_master_t *master;
	eag_ins_t *eagins;
	eag_portal_t *portal;
	eag_radius_t *radius;
	//eag_dbus_t *eagdbus;
	appconn_db_t *appdb;
	eag_captive_t *captive;
	eag_statistics_t *eagstat;
	eag_macauth_t *macauth;
	struct portal_conf *portalconf;
	struct nasid_conf *nasidconf;
	struct nasportid_conf *nasportidconf;
	//eag_hansi_t *eaghansi;
};

typedef enum {
	EAG_STAMSG_READ,
} eag_stamsg_event_t;

static void
eag_stamsg_event(eag_stamsg_event_t event,
		eag_stamsg_t *stamsg);

eag_stamsg_t *eag_stamsg_new()
{
	eag_stamsg_t *stamsg = NULL;

	stamsg = eag_malloc(sizeof(*stamsg));
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_new eag_malloc failed");
		return NULL;
	}

	memset(stamsg, 0, sizeof(*stamsg));
	stamsg->sockfd = -1;
	strcpy(stamsg->sockpath,STAMSG_SOCK_PATH_FMT);
	strcpy(stamsg->ntf_asd_path,STAMSG_ASD_SOCK_PATH_FMT);
	
	eag_log_debug("eag_stamsg", "stamsg new ok, sockpath=%s",
			stamsg->sockpath);
	return stamsg;
}

int
eag_stamsg_free(eag_stamsg_t *stamsg)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_free input error");
		return -1;
	}

	if (stamsg->sockfd >= 0) {
		close(stamsg->sockfd);
		stamsg->sockfd = -1;
	}
	eag_free(stamsg);

	eag_log_debug("eag_stamsg", "stamsg free ok");
	return 0;
}

int
eag_stamsg_start(eag_stamsg_t *stamsg)
{
	int ret = 0;
	int len = 0;
	struct sockaddr_un addr = {0};
	mode_t old_mask = 0;
  
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_start input error");
		return EAG_ERR_NULL_POINTER;
	}

	if (stamsg->sockfd >= 0) {
		eag_log_err("eag_stamsg_start already start fd(%d)", 
			stamsg->sockfd);
		return EAG_RETURN_OK;
	}

	stamsg->sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (stamsg->sockfd  < 0) {
		eag_log_err("Can't create stamsg unix dgram socket: %s",
			safe_strerror(errno));
		stamsg->sockfd = -1;
		return EAG_ERR_SOCKET_FAILED;
	}

	if (0 != set_nonblocking(stamsg->sockfd)){
		eag_log_err("eag_stamsg_start set socket nonblocking failed");
		close(stamsg->sockfd);
		stamsg->sockfd = -1;
		return EAG_ERR_SOCKET_OPT_FAILED;
	}
		
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, stamsg->sockpath, sizeof(addr.sun_path)-1);
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	unlink(addr.sun_path);
	old_mask = umask(0111);
	ret  = bind(stamsg->sockfd, (struct sockaddr *)&addr, len);
	if (ret < 0) {
		eag_log_err("Can't bind to stamsg socket(%d): %s",
			stamsg->sockfd, safe_strerror(errno));
		close(stamsg->sockfd);
		stamsg->sockfd = -1;
		umask(old_mask);
		return EAG_ERR_SOCKET_BIND_FAILED;
	}
	umask(old_mask);
	
	eag_stamsg_event(EAG_STAMSG_READ, stamsg);
	
	eag_log_info("stamsg(%s) fd(%d) start ok",
			stamsg->sockpath,
			stamsg->sockfd);

	return EAG_RETURN_OK;
}

int
eag_stamsg_stop(eag_stamsg_t *stamsg)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_stop input error");
		return EAG_ERR_NULL_POINTER;
	}

	eag_log_info("stamsg(%s) fd(%d) stop ok",
			stamsg->sockpath,
			stamsg->sockfd);
		
	if (NULL != stamsg->t_read) {
		eag_thread_cancel(stamsg->t_read);
		stamsg->t_read = NULL;
	}
	if (stamsg->sockfd >= 0)
	{
		close(stamsg->sockfd);
		stamsg->sockfd = -1;
	}
	unlink(stamsg->sockpath);
	
	return EAG_RETURN_OK;
}

static int
stamsg_proc(eag_stamsg_t *stamsg, uint8_t usermac[6],
		uint32_t user_ip, EagMsg *sta_msg,char *path)
{
	struct app_conn_t *appconn = NULL;
	struct appsession tmpsession = {0};
	struct timeval tv = {0};
	time_t timenow = 0;
	int ret = 0;
	char user_macstr[32] = "";
	char user_ipstr[32] = "";
	char ap_macstr[32] = "";
	char new_apmacstr[32] = "";
	unsigned int security_type = 0;
	int macauth_switch = 0;
	unsigned int key_type;
	eag_time_gettimeofday(&tv,NULL);
	timenow = tv.tv_sec;
	macauth_switch = eag_macauth_get_macauth_switch(stamsg->macauth);
	
	switch(sta_msg->Op) {
	case WID_ADD:
		if (0 == user_ip) {
			eag_log_warning("stamsg_proc receive WID_ADD, userip = 0");
		}
		#if 0
		if (0 != user_ip) {
			ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
			eag_log_info("stamsg_proc, WID_ADD del eap or none authorize user_ip %s",
				user_ipstr);
			eag_captive_del_eap_authorize(stamsg->captive, user_ip);
		}
		#endif
		/* TODO: if essid changed, del mac_preauth */
		mac2str(usermac, user_macstr, sizeof(user_macstr), ':');

		/*if (eag_hansi_is_enable(stamsg->eaghansi)
			&& !eag_hansi_is_master(stamsg->eaghansi))
		{
			eag_log_info("receive WID_ADD usermac=%s, but hansi is backup, ignore it",
				user_macstr);
			return 0;
		}*/
		
		strncpy(tmpsession.essid, (char *)sta_msg->STA.ssid, sizeof(tmpsession.essid)-1);
                    memcpy(tmpsession.usermac,usermac,PKT_ETH_ALEN);
                    tmpsession.user_ip = user_ip;
		memcpy(tmpsession.intf,(char *)sta_msg->STA.iface,sizeof(tmpsession.intf)-1);
		memcpy(tmpsession.bridge,(char *)sta_msg->STA.bridge,sizeof(tmpsession.bridge)-1);
                 	memcpy(tmpsession.sock_path,path,strlen(path));
		printf("%s,%d, sock_path %s,path %s\n",__func__,__LINE__,tmpsession.sock_path,path);
		key_type = PORTAL_KEYTYPE_ESSID;
                    if(( NULL == portal_srv_get_by_key(stamsg->portalconf,key_type,sta_msg->STA.ssid)) &&(0 != user_ip))
		{
			eag_authorize_t *eag_auth = NULL;
			eag_auth = eag_authorieze_get_iptables_auth();
                            eag_authorize_do_authorize(eag_auth,&tmpsession);
			printf("%s,%d\n",__func__,__LINE__);
			break;
		}

		appconn = appconn_find_by_usermac(stamsg->appdb, usermac);
		if (NULL == appconn) {
			eag_log_info("stamsg_proc, appconn not exist, usermac=%s",
				user_macstr);
			appconn = appconn_create_by_sta_v2(stamsg->appdb, &tmpsession);
			if (NULL == appconn)
			{			
				printf("%s,%d\n",__func__,__LINE__);
				return -1;
			}

		}		
		appconn->session.sta_state = SESSION_STA_STATUS_CONNECT;
                     strcpy(appconn->session.sock_path,tmpsession.sock_path);
              	printf("%s,%d, sock_path %s,appdb->path %s\n",__func__,__LINE__,tmpsession.sock_path,appconn->session.sock_path);

		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr), ':');
		ip2str(appconn->session.user_ip, user_ipstr, sizeof(user_ipstr));
		
		
		eag_log_info("Receive WID_ADD msg usermac:%s, userip:%s, status:%s,"
			" from apmac:%s, apname:%s, ssid:%s to apmac:%s, apname:%s, ssid:%s",
			user_macstr, user_ipstr,
			APPCONN_STATUS_AUTHED == appconn->session.state?
				"Authed":"NotAuthed",
			ap_macstr, appconn->session.apname, appconn->session.essid,
			new_apmacstr, tmpsession.apname, tmpsession.essid);

			if (APPCONN_STATUS_AUTHED == appconn->session.state) {
				if (EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
                			eag_bss_message_count(stamsg->eagstat, appconn, BSS_USER_CONNECTED_TOTAL_TIME, 
                                	(timenow - appconn->session.last_connect_ap_time));
    			    } else {
                			eag_bss_message_count(stamsg->eagstat, appconn, BSS_MACAUTH_USER_CONNECTED_TOTAL_TIME, 
                                	(timenow - appconn->session.last_connect_ap_time));
    			    }
			}
			appconn->session.last_connect_ap_time = timenow;
			appconn_set_nasid(appconn, stamsg->nasidconf);
			appconn_set_nasportid(appconn, stamsg->nasportidconf);
			ret = appconn_config_portalsrv(appconn, stamsg->portalconf);
			if (0 != ret) {
				eag_log_warning("stamsg_proc "
					"appconn_config_portalsrv failed, usermac:%s ret=%d",
					user_macstr, ret);
			}

			if (APPCONN_STATUS_AUTHED == appconn->session.state) {
				if (ACCURIS_MACAUTH == eag_macauth_type) {
                                    eag_radius_auth_change_tag(stamsg->radius, appconn);
				}
			}

		break;		
	case WID_DEL:
		if (0 == user_ip) {
			eag_log_warning("stamsg_proc receive WID_DEL, userip = 0");
		}
		#if 0
		if (0 != user_ip) {
			ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
			eag_log_info("stamsg_proc, WID_DEL del eap or none authorize user_ip %s",
				user_ipstr);
			eag_captive_del_eap_authorize(stamsg->captive, user_ip);
		}
		#endif
		if (macauth_switch) {
			del_eag_preauth_by_ip_or_mac(stamsg->macauth, user_ip, usermac);
		}
		mac2str(usermac, user_macstr, sizeof(user_macstr), ':');
	
		/*if (eag_hansi_is_enable(stamsg->eaghansi)
			&& !eag_hansi_is_master(stamsg->eaghansi))
		{
			eag_log_info("receive WID_DEL usermac=%s, but hansi is backup, ignore it",
				user_macstr);
			return 0;
		}*/
		strncpy(tmpsession.essid, (char *)sta_msg->STA.ssid, sizeof(tmpsession.essid)-1);
                    memcpy(tmpsession.usermac,usermac,PKT_ETH_ALEN);
                    tmpsession.user_ip = user_ip;
		memcpy(tmpsession.intf,(char *)sta_msg->STA.iface,sizeof(tmpsession.intf)-1);
		memcpy(tmpsession.bridge,(char *)sta_msg->STA.bridge,sizeof(tmpsession.bridge)-1);
                 	memcpy(tmpsession.sock_path,path,strlen(path));
                    key_type = PORTAL_KEYTYPE_ESSID;
                    if(( NULL == portal_srv_get_by_key(stamsg->portalconf,key_type,sta_msg->STA.ssid)) &&(0 != user_ip))
                    {
			eag_authorize_t *eag_auth = NULL;
			eag_auth = eag_authorieze_get_iptables_auth();
                              eag_authorize_de_authorize(eag_auth,&tmpsession);
			break;
		}
		
		appconn = appconn_find_by_usermac(stamsg->appdb, usermac);
		if (NULL == appconn) {
			eag_log_info("stamsg_proc, appconn not exist, usermac=%s",
				user_macstr);
			return 0;
		}

		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr), ':');
		ip2str(appconn->session.user_ip, user_ipstr, sizeof(user_ipstr));

		appconn->session.sta_state = SESSION_STA_STATUS_UNCONNECT;
		
		eag_log_info("Receive leave msg usermac:%s, userip:%s, status:%s,"
			" apmac:%s, apname:%s, ssid:%s, leave_reason:%d",
			user_macstr, user_ipstr,
			APPCONN_STATUS_AUTHED == appconn->session.state?
				"Authed":"NotAuthed",
			ap_macstr, appconn->session.apname, appconn->session.essid, 
			appconn->session.leave_reason);

		if (macauth_switch) {
			del_eag_preauth_by_ip_or_mac(stamsg->macauth, appconn->session.user_ip, usermac);
		}
		if (APPCONN_STATUS_AUTHED == appconn->session.state) {
#if 0
			if (SESSION_STA_LEAVE_NORMAL == sta_msg->STA.reason) {
				eag_log_debug("eag_stamsg", "stamsg_proc receive WID_DEL"
					" and user(%s) leave normal", user_ipstr);
				appconn->session.session_stop_time = timenow;
				eag_portal_notify_logout_nowait(stamsg->portal, appconn);
				terminate_appconn(appconn, stamsg->eagins,
					RADIUS_TERMINATE_CAUSE_LOST_CARRIER);
			} else {
				eag_log_debug("eag_stamsg", "stamsg_proc receive WID_DEL"
					" and user(%s) leave abnormal(%u)", user_ipstr, sta_msg->STA.reason);
			}
#endif			
		} else {
			appconn_del_from_db(appconn);
			appconn_free(appconn);
		}
		break;	
	case OPEN_ROAM:
		/* STAMSG_ROAM */
		if (0 == user_ip) {
			eag_log_warning("stamsg_proc receive OPEN_ROAM, userip = 0");
		}
		#if 0
		if (0 != user_ip) {
			ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
			eag_log_info("stamsg_proc, OPEN_ROAM del eap or none authorize user_ip %s",
				user_ipstr);
			eag_captive_del_eap_authorize(stamsg->captive, user_ip);
		}
		#endif
		/* TODO: if essid changed, del mac_preauth */
		mac2str(usermac, user_macstr, sizeof(user_macstr), ':');

		
		appconn = appconn_find_by_usermac(stamsg->appdb, usermac);
		if (NULL == appconn) {
			eag_log_info("stamsg_proc, appconn not exist, usermac=%s",
				user_macstr);
			return 0;
		}
		appconn->session.sta_state = SESSION_STA_STATUS_CONNECT;
		
		mac2str(appconn->session.apmac, ap_macstr, sizeof(ap_macstr), ':');
		ip2str(appconn->session.user_ip, user_ipstr, sizeof(user_ipstr));
		
		/*ret = eag_get_sta_info_by_mac_v2(stamsg->eagdbus, stamsg->hansi_type,
					stamsg->hansi_id, usermac, &tmpsession, &security_type);*/
		if (0 != ret) {
			eag_log_err("stamsg_proc, get_sta_info_by_mac_v2 failed,"
				" usermac:%s ret=%d", user_macstr, ret);
			return -1;
		}

		mac2str(tmpsession.apmac, new_apmacstr, sizeof(new_apmacstr), ':');

		eag_log_info("Receive roam msg usermac:%s, userip:%s, status:%s,"
			" from apmac:%s, apname:%s, ssid:%s to apmac:%s, apname:%s, ssid:%s",
			user_macstr, user_ipstr,
			APPCONN_STATUS_AUTHED == appconn->session.state?
				"Authed":"NotAuthed",
			ap_macstr, appconn->session.apname, appconn->session.essid,
			new_apmacstr, tmpsession.apname, tmpsession.essid);

		if (0 != strcmp(tmpsession.essid, appconn->session.essid)) {
			if (macauth_switch) {
				del_eag_preauth_by_ip_or_mac(stamsg->macauth, user_ip, usermac);
			}
			if (APPCONN_STATUS_AUTHED == appconn->session.state) {
				appconn->session.session_stop_time = timenow;
				eag_portal_notify_logout_nowait(stamsg->portal, appconn);
				terminate_appconn(appconn, stamsg->eagins, 
						RADIUS_TERMINATE_CAUSE_LOST_CARRIER);
			} else {
				appconn_del_from_db(appconn);
				appconn_free(appconn);
			}
		} else {   /* essid not changed */
			if (APPCONN_STATUS_AUTHED == appconn->session.state) {
				if (EAG_AUTH_TYPE_PORTAL == appconn->session.server_auth_type) {
        			eag_bss_message_count(stamsg->eagstat, appconn, BSS_USER_CONNECTED_TOTAL_TIME, 
                        	(timenow - appconn->session.last_connect_ap_time));
    			} else {
        			eag_bss_message_count(stamsg->eagstat, appconn, BSS_MACAUTH_USER_CONNECTED_TOTAL_TIME, 
                        	(timenow - appconn->session.last_connect_ap_time));
    			}
			}
			appconn->session.last_connect_ap_time = timenow;
			appconn->session.wlanid = tmpsession.wlanid;
			appconn->session.g_radioid = tmpsession.g_radioid;
			appconn->session.radioid = tmpsession.radioid;
			appconn->session.wtpid= tmpsession.wtpid;
			strncpy(appconn->session.essid, tmpsession.essid,
								sizeof(appconn->session.essid)-1);
			strncpy(appconn->session.apname, tmpsession.apname,
								sizeof(appconn->session.apname)-1);
			memcpy(appconn->session.apmac, tmpsession.apmac, 
							sizeof(appconn->session.apmac));
			appconn->session.vlanid = tmpsession.vlanid;

			appconn_set_nasid(appconn, stamsg->nasidconf);
			appconn_set_nasportid(appconn, stamsg->nasportidconf);
			ret = appconn_config_portalsrv(appconn, stamsg->portalconf);
			if (0 != ret) {
				eag_log_warning("stamsg_proc "
					"appconn_config_portalsrv failed, usermac:%s ret=%d",
					user_macstr, ret);
			}
			
		}
		break;
	#if 0
	case ASD_AUTH:
		if (0 == user_ip) {
			eag_log_warning("stamsg_proc receive ASD_AUTH, userip = 0");
			return -1;
		}
		
		ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
		eag_log_info("stamsg_proc, ASD_AUTH add eap or none authorize user_ip %s",
				user_ipstr);
		eag_captive_eap_authorize(stamsg->captive, user_ip);
		break;
	case ASD_DEL_AUTH:
		if (0 == user_ip) {
			eag_log_warning("stamsg_proc receive ASD_DEL_AUTH, userip = 0");
			return -1;
		}
		
		ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
		eag_log_info("stamsg_proc, ASD_DEL_AUTH del eap or none authorize user_ip %s",
				user_ipstr);
		eag_captive_del_eap_authorize(stamsg->captive, user_ip);
		break;
	#endif
	default:
		eag_log_err("stamsg_proc unexpected stamsg type %u", sta_msg->Op);
		break;
	}

	return EAG_RETURN_OK;
}

static int
stamsg_receive(eag_thread_t *thread)
{
	eag_stamsg_t *stamsg = NULL;
	struct sockaddr_un addr = {0};
	socklen_t len = 0;
	ssize_t nbyte = 0;
	EagMsg sta_msg = {0};
	uint8_t usermac[6] = {0};
	uint32_t user_ip=0;
	char user_ipstr[32] = "";
	char user_macstr[32] = "";
	
	if (NULL == thread) {
		eag_log_err("stamsg_receive input error");
		return EAG_ERR_INPUT_PARAM_ERR;
	}
	
	stamsg = eag_thread_get_arg(thread);
	if (NULL == stamsg) {
		eag_log_err("stamsg_receive stamsg null");
		return EAG_ERR_NULL_POINTER;
	}

	len = sizeof(addr);
	nbyte = recvfrom(stamsg->sockfd, &sta_msg, sizeof(EagMsg), 0,
					(struct sockaddr *)&addr, &len);
	if (nbyte < 0) {
		eag_log_err("stamsg_receive recvfrom failed: %s, fd(%d)",
			safe_strerror(errno), stamsg->sockfd);
		return EAG_ERR_SOCKET_RECV_FAILED;
	}
	
	addr.sun_path[sizeof(addr.sun_path)-1] = '\0'; 
	eag_log_info( "stamsg fd(%d) receive %d bytes from sockpath(%s)",
		stamsg->sockfd,
		nbyte,
		addr.sun_path);
	
	if (nbyte < sizeof(EagMsg)) {
		eag_log_warning("stamsg_receive msg size %d < EagMsg size %d",
			nbyte, sizeof(EagMsg));
		return -1;
	}
	
	if (WID_ADD != sta_msg.Op && WID_DEL != sta_msg.Op && OPEN_ROAM != sta_msg.Op){
		eag_log_warning("stamsg receive unexpected EagMsg Op:%d",
			sta_msg.Op);
		return -1;
	}

	memcpy(usermac, sta_msg.STA.addr, sizeof(sta_msg.STA.addr));
	user_ip=sta_msg.STA.ip_addr;
	ip2str(user_ip, user_ipstr, sizeof(user_ipstr));
	mac2str(usermac, user_macstr, sizeof(user_macstr), ':');
	
	eag_log_info(
		"stamsg receive EagMsg tm.Op=%d, userip=%s, usermac=%s",
		sta_msg.Op, user_ipstr, user_macstr);

	stamsg_proc(stamsg, usermac, user_ip, &sta_msg,addr.sun_path);

	return EAG_RETURN_OK;
}

/*notify ASD  the user authorize state*/
int
eag_stamsg_send(eag_stamsg_t *stamsg,
		struct appsession *session,
		Operate Op)
{
	EagMsg sta_msg = {0};
	struct sockaddr_un addr = {0};
	socklen_t len = 0;
	ssize_t nbyte = 0;
	char ipstr[32] = "";
	char macstr[32] = "";
	
	if (NULL == stamsg || NULL == session) {
		eag_log_err("eag_stamsg_send input error");
		return EAG_ERR_NULL_POINTER;
	}

	memset(&sta_msg, 0, sizeof(sta_msg));
	sta_msg.Op = Op;
	sta_msg.STA.ip_addr = session->user_ip;
	memcpy(sta_msg.STA.addr, session->usermac, sizeof(sta_msg.STA.addr));

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, session->sock_path, sizeof(addr.sun_path)-1);
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	ip2str(session->user_ip, ipstr, sizeof(ipstr));
	mac2str(session->usermac, macstr, sizeof(macstr), ':');
	eag_log_info("stamsg send sockpath:%s, userip:%s, usermac:%s, Op:%d",
			addr.sun_path, ipstr, macstr, Op);
	nbyte = sendto(stamsg->sockfd, &sta_msg, sizeof(EagMsg), MSG_DONTWAIT,
					(struct sockaddr *)(&addr), len);
	if (nbyte < 0) {
		eag_log_err("eag_stamsg_send sendto failed, fd(%d), path(%s), %s",
			stamsg->sockfd, addr.sun_path, safe_strerror(errno));
		return -1;
	}
	if (nbyte != sizeof(sta_msg)) {
		eag_log_err("eag_stamsg_send sendto failed, nbyte(%d)!=sizeof(tm)(%d)",
			nbyte, sizeof(sta_msg));
		return -1;
	}

	return 0;
}

int
eag_stamsg_set_thread_master(eag_stamsg_t *stamsg,
		eag_thread_master_t *master)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_thread_master input error");
		return -1;
	}

	stamsg->master = master;

	return 0;
}

int
eag_stamsg_set_eagins(eag_stamsg_t *stamsg,
		eag_ins_t *eagins)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_eagins input error");
		return -1;
	}

	stamsg->eagins = eagins;

	return 0;
}

int
eag_stamsg_set_portal(eag_stamsg_t *stamsg,
		eag_portal_t *portal)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_portal input error");
		return -1;
	}

	stamsg->portal = portal;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_radius(eag_stamsg_t *stamsg,
		eag_radius_t *radius)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_radius input error");
		return -1;
	}

	stamsg->radius = radius;

	return EAG_RETURN_OK;
}

/*int
eag_stamsg_set_eagdbus(eag_stamsg_t *stamsg,
		eag_dbus_t *eagdbus)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_eagdbus input error");
		return -1;
	}

	stamsg->eagdbus = eagdbus;

	return EAG_RETURN_OK;
}*/

int
eag_stamsg_set_appdb(eag_stamsg_t *stamsg,
		appconn_db_t *appdb)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_appdb input error");
		return -1;
	}

	stamsg->appdb = appdb;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_captive(eag_stamsg_t *stamsg,
		eag_captive_t *captive)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_captive input error");
		return -1;
	}

	stamsg->captive = captive;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_macauth(eag_stamsg_t *stamsg,
		eag_macauth_t *macauth)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_macauth input error");
		return -1;
	}

	stamsg->macauth = macauth;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_portal_conf(eag_stamsg_t *stamsg,
		struct portal_conf *portalconf)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_portal_conf input error");
		return -1;
	}

	stamsg->portalconf = portalconf;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_nasid_conf(eag_stamsg_t *stamsg,
		struct nasid_conf *nasidconf)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_nasid_conf input error");
		return -1;
	}

	stamsg->nasidconf = nasidconf;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_nasportid_conf(eag_stamsg_t *stamsg,
		struct nasportid_conf *nasportidconf)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_nasportid_conf input error");
		return -1;
	}

	stamsg->nasportidconf = nasportidconf;

	return EAG_RETURN_OK;
}

int
eag_stamsg_set_eagstat(eag_stamsg_t *stamsg,
		eag_statistics_t *eagstat)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_eagstat input error");
		return -1;
	}

	stamsg->eagstat = eagstat;

	return EAG_RETURN_OK;

}

/*int
eag_stamsg_set_eaghansi(eag_stamsg_t *stamsg,
		eag_hansi_t *eaghansi)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_set_eaghansi input error");
		return -1;
	}

	stamsg->eaghansi = eaghansi;

	return EAG_RETURN_OK;

}*/

static void
eag_stamsg_event(eag_stamsg_event_t event,
		eag_stamsg_t *stamsg)
{
	if (NULL == stamsg) {
		eag_log_err("eag_stamsg_event input error");
		return;
	}

	switch (event) {
	case EAG_STAMSG_READ:
		stamsg->t_read =
		    eag_thread_add_read(stamsg->master, stamsg_receive,
					stamsg, stamsg->sockfd);
		break;
	default:
		break;
	}
}

