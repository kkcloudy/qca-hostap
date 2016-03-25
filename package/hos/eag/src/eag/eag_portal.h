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
* eag_portal.h
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

#ifndef _EAG_PORTAL_H
#define _EAG_PORTAL_H

#include <stdint.h>
#include "eag_def.h"

#define PORTAL_PORT_DEFAULT		2000
#define GUEST_DATABASE_PATH	"/var/run/userdb/guest" 
#define EMPLOYEE_DATABASE_PATH	"/var/run/userdb/employee"
extern int notice_to_bindserver;
extern int username_check_switch;

eag_portal_t *eag_portal_new();

int
eag_portal_free(eag_portal_t *portal);

int
eag_portal_start(eag_portal_t *portal);

int
eag_portal_stop(eag_portal_t *portal);

int
eag_portal_auth_failure(eag_portal_t *portal,
		uint32_t userip,
		uint8_t err_code,
		const char *err_id);

int
eag_portal_auth_success(eag_portal_t *portal,
		struct app_conn_t *appconn);

int
eag_portal_notify_logout(eag_portal_t * portal,
		struct app_conn_t *appconn,
		int terminate_cause);

int
eag_portal_notify_logout_nowait(eag_portal_t * portal,
		struct app_conn_t *appconn);

int
eag_portal_proc_dm_request(eag_portal_t *portal,
		struct app_conn_t *appconn,
		uint32_t radius_ip, 
		uint16_t radius_port,
		uint8_t id);

int
eag_portal_macbind_req(eag_portal_t *portal,
		struct app_conn_t *appconn);

int
eag_portal_ntf_user_logon(eag_portal_t *portal,
		struct app_conn_t *appconn);

int
eag_portal_ntf_user_logoff(eag_portal_t *portal,
		struct app_conn_t *appconn);


int
eag_portal_set_nasip(eag_portal_t *portal,
		uint32_t nasip);

int
eag_portal_set_portal_port(eag_portal_t *portal,
		uint16_t portal_port);

uint16_t
eag_portal_get_portal_port(eag_portal_t *portal);

int
eag_portal_set_local_addr(eag_portal_t *portal,
		uint32_t local_ip,
		uint16_t local_port);

int
eag_portal_set_slot_id(eag_portal_t *portal,
							uint8_t slot_id);

int
eag_portal_set_distributed(eag_portal_t *portal,
		int is_distributed);

int
eag_portal_set_thread_master(eag_portal_t *portal,
		eag_thread_master_t *master);

int
eag_portal_set_retry_params(eag_portal_t *portal,
		int retry_interval,
		int retry_times);

int
eag_portal_get_retry_params(eag_portal_t *portal,
		int *retry_interval,
		int *retry_times);

int
eag_portal_set_auto_session(eag_portal_t *portal,
		int auto_session);

int
eag_portal_get_auto_session(eag_portal_t *portal);

int
eag_portal_set_check_errid(eag_portal_t *portal,
		int check_errid);

int
eag_portal_get_check_errid(eag_portal_t *portal);

int
eag_portal_set_eagins(eag_portal_t *portal,
		eag_ins_t *eagins);

int
eag_portal_set_appdb(eag_portal_t *portal,
		appconn_db_t *appdb);

int
eag_portal_set_radius(eag_portal_t *portal,
		eag_radius_t *radius);

int
eag_portal_set_coa(eag_portal_t *portal,
		eag_coa_t *coa);

int
eag_portal_set_captive(eag_portal_t *portal,
		eag_captive_t *cap);

int
eag_portal_set_stamsg(eag_portal_t *portal,
		eag_stamsg_t *stamsg);

int
eag_portal_set_fastfwd(eag_portal_t *portal,
		eag_fastfwd_t *fastfwd);

int
eag_portal_set_eagstat(eag_portal_t *portal,
		eag_statistics_t *eagstat);

int
eag_portal_set_portal_conf(eag_portal_t *portal,
		struct portal_conf *portalconf);

int
eag_portal_set_radius_conf(eag_portal_t *portal,
		struct radius_conf *radiusconf);

int
eag_portal_log_all_portalsess(eag_portal_t *portal);

int
eag_portal_set_macauth(eag_portal_t *portal,
		eag_macauth_t *macauth);

#endif /* _EAG_PORTAL_H */

