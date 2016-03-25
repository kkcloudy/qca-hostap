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
* eag_macauth_server.c
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <syslog.h>

#include "limits2.h"
#include "nm_list.h"
#include "eag_conf.h"
#include "eag_errcode.h"
#include "eag_log.h"
#include "eag_util.h"
#include "eag_mem.h"
#include "eag_blkmem.h"
#include "eag_thread.h"
#include "eag_radius.h"
#include "eag_portal.h"
#include "md5.h"




#include "eag_log.c"
#include "eag_mem.c"
#include "eag_blkmem.c"
#include "eag_errcode.c"
#include "eag_thread.c"
#include "eag_util.c"
#include "eag_portal.c"
#include "eag_radius.c"
#include "eag_conf.c"
#include "md5.c"
#include "eag_time.c"
#include "hashtable.c"
#include "appconn.c"

struct mac_user_t {
	struct list_head node;
	unsigned char mac[6];
	char username[256];
	char password[256];
	AUTH_TYPE authtype;
};

struct list_head macuserlst;
eag_blk_mem_t *blkmem = NULL;

struct mac_user_t *
eag_macauth_get_user_by_mac(unsigned char *mac)
{
	struct mac_user_t *user;

	list_for_each_entry(user, &macuserlst, node) {
		if (0 == memcmp(user->mac, mac, sizeof (user->mac))) {
			return user;
		}
	}

	return NULL;
}

int
load_mac_auth_conf(char *filepath)
{

	/*file format    00:11:22:33:44:55#username#password.     should not has '#' in username and password!! */
	FILE *fp;
	char line[512];

	INIT_LIST_HEAD(&macuserlst);

	if (EAG_RETURN_OK != eag_blkmem_create(&blkmem, "mac_auth_conf",
					       sizeof (struct mac_user_t), 128, MAX_BLK_NUM))
	{
		eag_log_err("load_mac_auth_conf eag_blkmem_create failed!");
		return EAG_ERR_MALLOC_FAILED;
	}

	fp = fopen(filepath, "r");
	if (NULL == fp) {
		eag_log_err("load_mac_auth_conf file %s open failed!",
			    filepath);
		return EAG_ERR_UNKNOWN;
	}

	while (fgets(line, sizeof (line), fp)) {
		char *temp;
		struct mac_user_t *user;
		struct mac_user_t *find;
		char macstr[32];

		user = (struct mac_user_t *) eag_blkmem_malloc_item(blkmem);
		if (NULL == user) {
			eag_log_err("eag_blkmem_malloc_item failed!");
			break;
		}
		eag_log_debug("macauth", "load_mac_auth_conf line=%s", line);
		delete_0d0a(line);
		temp = strtok(line, "#");
		if (NULL == temp) {
			eag_log_err("get mac failed!");
			eag_blkmem_free_item(blkmem, user);
			continue;
		}
		str2mac(user->mac, sizeof(user->mac),temp);

		find = eag_macauth_get_user_by_mac(user->mac);
		if (NULL != find) {
			eag_log_err
			    ("load_mac_auth_conf  mac already in list! Ignore it!");
			eag_blkmem_free_item(blkmem, user);
			continue;
		}

		temp = strtok(NULL, "#");
		if (NULL == temp) {
			eag_log_err("get username failed!");
			eag_blkmem_free_item(blkmem, user);
			continue;
		}
		strncpy(user->username, temp, sizeof (user->username) - 1);

		temp = strtok(NULL, "#");
		if (NULL == temp) {
			eag_log_err("get passwd failed!");
			eag_blkmem_free_item(blkmem, user);
			continue;
		}
		strncpy(user->password, temp, sizeof (user->password) - 1);

		mac2str(macstr, sizeof(macstr), user->mac, '-');
		eag_log_debug("macauth",
			      "add macauth mac=%s  user=%s passwd =%s", macstr,
			      user->username, user->password);

		temp = strtok(NULL, "#");
		if (NULL == temp || 0 == strcasecmp("chap", temp)) {
			user->authtype = AUTH_CHAP;
		} else {
			user->authtype = AUTH_PAP;
		}

		list_add_tail(&(user->node), &macuserlst);
	}

	fclose(fp);

	return EAG_RETURN_OK;
}

eag_blk_mem_t *macblkmem = NULL;
struct list_head macauth_conns;

struct macauth_conn_t {
	struct list_head node;
	eag_thread_t *t_timeout;
	eag_thread_master_t *master;

	struct mac_user_t *user;
	unsigned long userip;
	unsigned short sn;
	unsigned short reqid;

	unsigned char chal[16];
};

int
is_sn_in_list(struct list_head *head, unsigned short sn)
{
	struct macauth_conn_t *pos;

	list_for_each_entry(pos, head, node) {
		if (pos->sn == sn) {
			return EAG_TRUE;
		}
	}

	return EAG_FALSE;
}

unsigned short
get_unique_sn(struct list_head *head)
{
	static unsigned long prvsn = 1;
	unsigned short ret = prvsn++;

	while (ret != prvsn) {
		if (EAG_TRUE == is_sn_in_list(head, ret)) {
			ret++;
		} else {
			return ret;
		}
	}

	eag_log_err("with no sn could be used!");
	return ret;
}

struct macauth_conn_t *
eag_macauth_get_conn(struct list_head *head, unsigned short sn)
{
	struct macauth_conn_t *conn;

	list_for_each_entry(conn, head, node) {
		if (conn->sn == sn) {
			return conn;
		}
	}

	return NULL;
}

struct macauth_conn_t *
eag_macauth_conn_new(eag_blk_mem_t * macblkmem)
{
	struct macauth_conn_t *conn = NULL;

	conn = (struct macauth_conn_t *) eag_blkmem_malloc_item(macblkmem);
	if (NULL == conn) {
		return NULL;
	}

	memset(conn, 0, sizeof (struct macauth_conn_t));
	return conn;
}

void
eag_macauth_conn_free(eag_blk_mem_t * macblkmem, struct macauth_conn_t *conn)
{
	eag_blkmem_free_item(macblkmem, conn);
	return;
}

int
eag_macauth_challenge_timeout(eag_thread_t * eag_thread_t)
{
	struct macauth_conn_t *conn;

	conn = eag_thread_get_arg(eag_thread_t);

	list_del(&(conn->node));
	eag_macauth_conn_free(macblkmem, conn);
	return EAG_RETURN_OK;
}

int
eag_macauth_auth_timeout(eag_thread_t * eag_thread_t)
{
	struct macauth_conn_t *conn;

	conn = eag_thread_get_arg(eag_thread_t);

	list_del(&(conn->node));
	eag_macauth_conn_free(macblkmem, conn);
	return EAG_RETURN_OK;
}

struct portal_pkg_attr *
	eag_portal_pkg_get_attr(struct portal_pkg_t *pkg, ATTR_TYPE type);

int
eag_macauth_portal_decaps_cb(eag_portal_t * portal,
			     struct sockaddr_in *addr,
			     struct portal_pkg_t *pkg_get,
			     struct portal_pkg_t *pkg_req,
			     struct portal_pkg_t *pkg_rsp)
{
	struct mac_user_t *user;

	if (NULL == portal || NULL == pkg_get || NULL == pkg_req
	    || NULL == pkg_rsp) {
		eag_log_err("eag_eagins_portal_decaps_cb input param err!");
		return EAG_FALSE;
	}

	eag_log_debug("eag_portal",
		      "eag_macauth_portal_decaps_cb get pkg type=%#x",
		      pkg_get->pkg_type);
	switch (pkg_get->pkg_type) {
	case REQ_MACINFO:
		{
			struct portal_pkg_attr *attr;
			struct mac_user_t *user;

			eag_portal_pkg_init_rsp(portal, pkg_rsp, pkg_get);

			attr = eag_portal_pkg_get_attr(pkg_get, ATTR_USERMAC);
			if (NULL == attr || attr->len - 2 != 6) {
				eag_log_err
				    ("get REQ_MACINFO error! attr = %p len=%u",
				     attr, (NULL == attr) ? 0 : attr->len);
				pkg_rsp->err_code = 1;
			} else {
				user = eag_macauth_get_user_by_mac(attr->value);
				if (NULL == user) {
					char macstr[32];

					mac2str(macstr, sizeof(macstr), attr->value, '-');
					eag_log_err("mac %s not find in list!",
						    macstr,
						    (NULL ==
						     attr) ? 0 : attr->len);
					pkg_rsp->err_code = 1;
				}
			}
			eag_portal_send_pkg(portal, pkg_rsp, addr);
			/*PAP or CHAP auth flow */
#if 1
			if (NULL != user) {
				char macstr[32];
				eag_log_debug("macauth",
					      "REQ_MACINFO before send auth user ip = %x",
					      pkg_get->user_ip);

				mac2str(macstr, sizeof(macstr), user->mac, '-');
				eag_log_debug("macauth",
					      "mac=%s username=%s passwd=%s",
					      macstr, user->username,
					      user->password);
				if (AUTH_PAP == user->authtype) {
					eag_log_info
					    ("eag_macauth_portal_decaps_cb  do auth for user %s",
					     user->username);
					eag_portal_pkg_init_rsp(portal, pkg_rsp,
								pkg_get);

					pkg_rsp->pkg_type = REQ_AUTH;
					pkg_rsp->auth_type = AUTH_PAP;
					eag_portal_pkg_add_attr(pkg_rsp,
								ATTR_USERNAME,
								user->username,
								strlen(user->
								       username));
					eag_portal_pkg_add_attr(pkg_rsp,
								ATTR_PASSWORD,
								user->password,
								strlen(user->
								       password));
					eag_portal_send_pkg(portal, pkg_rsp,
							    addr);
				} else {
					struct macauth_conn_t *conn = NULL;
					eag_portal_pkg_init_rsp(portal, pkg_rsp,
								pkg_get);
					pkg_rsp->pkg_type = REQ_CHALLENGE;
					pkg_rsp->auth_type = AUTH_CHAP;
					conn = eag_macauth_conn_new(macblkmem);
					if (NULL == conn) {
						break;
					}
					conn->sn =
					    get_unique_sn(&macauth_conns);
					conn->user = user;
					pkg_rsp->serial_no = conn->sn;
					list_add_tail(&(conn->node),
						      &macauth_conns);
					eag_portal_send_pkg(portal, pkg_rsp,
							    addr);
					conn->t_timeout =
					    eag_thread_add_timer
					    (eag_portal_get_thread_master
					     (portal),
					     eag_macauth_challenge_timeout,
					     conn, 10);

				}
			}
#endif
		}
		break;
	case ACK_CHALLENGE:
		{
			struct macauth_conn_t *conn = NULL;

			conn =
			    eag_macauth_get_conn(&macauth_conns,
						 pkg_get->serial_no);
			if (NULL != conn) {
				char passwd[RADIUS_PWSIZE] = { 0 };
				unsigned long pwlen = 0;
				unsigned char chapid = pkg_get->req_id;
				struct portal_pkg_attr *attr;
				char macstr[32];

				eag_thread_cancel(conn->t_timeout);
				conn->t_timeout = NULL;
				user = conn->user;

				eag_portal_pkg_init_rsp(portal, pkg_rsp,
							pkg_get);
				pkg_rsp->pkg_type = REQ_AUTH;
				pkg_rsp->auth_type = AUTH_CHAP;

				attr =
				    eag_portal_pkg_get_attr(pkg_get,
							    ATTR_CHALLENGE);

				if (NULL != attr && NULL != user
				    && 16 == attr->len - 2) {
					char macstr[32];
					mac2str(macstr,sizeof(macstr), user->mac, '-');
					eag_log_debug("macauth",
						      "mac=%s username=%s passwd=%s namelen=%d",
						      macstr, user->username,
						      user->password,
						      strlen(user->username));
					eag_portal_pkg_add_attr(pkg_rsp,
								ATTR_USERNAME,
								user->username,
								strlen(user->
								       username));

					/*how to caculate chappasswd? */
					{
						MD5_CTX context;
						unsigned char chappasswd[16];
						MD5Init(&context);
						eag_log_debug("macauth",
							      "xxxxxx 333 chapid = %u",
							      chapid);
						MD5Update(&context, &chapid, 1);
						MD5Update(&context,
							  user->password,
							  strlen(user->
								 password));
						MD5Update(&context, attr->value,
							  16);
						MD5Final(chappasswd, &context);

						eag_portal_pkg_add_attr(pkg_rsp,
									ATTR_CHAPPASSWORD,
									chappasswd,
									16);
					}

					eag_portal_send_pkg(portal, pkg_rsp,
							    addr);
					conn->t_timeout =
					    eag_thread_add_timer
					    (eag_portal_get_thread_master
					     (portal), eag_macauth_auth_timeout,
					     conn, 3);
				} else {
					eag_log_err
					    ("ATTR_CHALLENGE attr error or user session not find!"
					     "attr=%p  user=%p attr->len=%d",
					     attr, user,
					     (NULL == attr) ? 0 : attr->len);
				}
			} else {
				eag_log_err("get challenge error!");
			}
		}
		break;
	case ACK_AUTH:
		{
			struct macauth_conn_t *conn = NULL;
			conn =
			    eag_macauth_get_conn(&macauth_conns,
						 pkg_get->serial_no);
			if (NULL != conn) {
				eag_thread_cancel(conn->t_timeout);
			}

			if (0 == pkg_get->err_code) {
				eag_portal_pkg_init_rsp(portal, pkg_rsp,
							pkg_get);
				eag_portal_send_pkg(portal, pkg_rsp, addr);
			} else {
				eag_log_warning("ack_auth   user logon faile!");
			}
		}
		break;
	case ACK_LOGOUT:
		eag_log_debug("macauth",
			      "eag_macauth_portal_decaps_cb get ACK_LOGOUT!");
		break;
	case ACK_INFO:
		break;
	case ACK_MACINFO:
		eag_log_debug("macauth",
			      "eag_macauth_portal_decaps_cb get ACK_MACINFO!");
		break;
	case NTF_MACLOGON:
		eag_log_debug("macauth",
			      "eag_macauth_portal_decaps_cb get NTF_MACLOGON!");
		eag_portal_pkg_log_pkg(pkg_get);
		break;
	case NTF_MACLOGOFF:
		eag_log_debug("macauth",
			      "eag_macauth_portal_decaps_cb get NTF_MACLOGOFF!");
		eag_portal_pkg_log_pkg(pkg_get);
		break;
	default:
		eag_log_err("eag_portal_decaps get error pkg");
		return EAG_ERR_PORTAL_GET_INVALID_PKG;
	}

	return EAG_TRUE;
}







eag_thread_master_t eag_thread_master;

eag_portal_t *portal = NULL;
unsigned int listen_ip = 0;	//192.168.1.16;
unsigned short listen_port = 5000;
struct in_addr addr;



int
eag_macauth_server_decaps(eag_thread_t * t_read)
{
	eag_portal_t *portal;
	struct portal_pkg_t pkg_get;
	struct portal_pkg_t pkg_req;
	struct portal_pkg_t pkg_rsp;	
	int recv_len;
	struct sockaddr_in addr;
	socklen_t fromlen = sizeof (addr);

	memset(&pkg_get, 0, sizeof (pkg_get));
	memset(&pkg_req, 0, sizeof (pkg_req));
	memset(&pkg_rsp, 0, sizeof (pkg_rsp));

	portal = (eag_portal_t *) eag_thread_get_arg(t_read);
	/*read pkg */
	recv_len = recvfrom(portal->fd, (void *)(&pkg_get), sizeof (pkg_get), 0,
				 		(struct sockaddr *) &addr, &fromlen );
	if ( recv_len <= 0) {
		eag_log_err("recvfrom() failed");
		return EAG_ERR_SOCKET_RECV_FAILED;
	}

	eag_portal_pkg_ntoh(&pkg_get);

	return eag_macauth_portal_decaps_cb(portal,&addr,&pkg_get, &pkg_req, &pkg_rsp );
}


int
main(int argc, char *argv[])
{
	int iret = 0;

	if (argc != 4) {
		printf("usage:%s ip port configfile", argv[0]);
		return 0;
	}
	INIT_LIST_HEAD(&macauth_conns);

	eag_blkmem_create(&macblkmem, "macauth_conn",
			  		  sizeof (struct macauth_conn_t), 128, MAX_BLK_NUM);
	eag_log_init(0,0);
	forward = 1;

	iret = eag_log_add_filter("eag_portal:macauth:portal_pkg");

	if (EAG_RETURN_OK != load_mac_auth_conf(argv[3])) {
		eag_log_err("load_mac_auth_conf failed!");
		return -1;
	}

	if (EAG_RETURN_OK != eag_thread_master_init(&eag_thread_master)) {
		return -1;
	}

	inet_aton(argv[1], &addr);
	listen_ip = ntohl(addr.s_addr);
	listen_port = atoi(argv[2]);

	portal = eag_portal_create();
	if (NULL == portal) {
		eag_log_err("eag_portal_create failed!");
		return -1;
	}
	eag_portal_set_params(portal, listen_ip, listen_port);
	eag_portal_set_thread_master(portal, &eag_thread_master);
	eag_portal_set_resend_params(portal, 3, 3);

	if( EAG_RETURN_OK != eag_portal_start(portal) ){
		eag_log_err("eag_portal_start failed!");
		return -1;
	}
#if 0	
	eag_portal_set_decaps_cb(portal, eag_macauth_portal_decaps_cb);
#endif
	eag_thread_cancel(portal->t_read);
	portal->t_read = eag_thread_add_read(portal->master,
					eag_macauth_server_decaps, portal, portal->fd);
	
	while (1) {
		struct timeval timer_wait;
		timer_wait.tv_sec = 1;
		timer_wait.tv_usec = 0;

		//eag_portal_timeout(portal);
		eag_thread_dispatch(&eag_thread_master, &timer_wait);
	}

	return 0;

}
