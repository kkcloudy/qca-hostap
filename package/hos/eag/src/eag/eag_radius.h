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
* eag_radius.h
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* eag radius
*
*
*******************************************************************************/

#ifndef _EAG_RADIUS_H
#define _EAG_RADIUS_H

#include <stdint.h>
#include "eag_def.h"
#include "appconn.h"

extern int idletime_valuecheck;

eag_radius_t *eag_radius_new();

int
eag_radius_free(eag_radius_t *radius);

int
eag_radius_start(eag_radius_t *radius);

int
eag_radius_stop(eag_radius_t *radius);

int
eag_radius_auth_change_tag(eag_radius_t *radius,
		struct app_conn_t *appconn);

int
eag_radius_auth_success(eag_radius_t *radius,
		struct app_conn_t *appconn);

int
radius_auth(eag_radius_t *radius,
		struct app_conn_t *appconn,
		uint8_t auth_type);

int
radius_acct(eag_radius_t *radius,
		struct app_conn_t *appconn,
		uint8_t status_type);

int
radius_acct_nowait(eag_radius_t *radius,
		struct app_conn_t *appconn,
		uint8_t status_type);

int
div_username_and_domain(char *username,
		char *domain,
		size_t domain_size,
		struct radius_conf *radiusconf);

int
eag_radius_set_local_ip(eag_radius_t *radius,
		uint32_t local_ip);

int
eag_radius_set_distributed(eag_radius_t *radius,
		int is_distributed);

int
eag_radius_set_retry_params(eag_radius_t *radius,
		int retry_interval,
		int retry_times,
		int vice_retry_times);

int
eag_radius_get_retry_params(eag_radius_t *radius,
		int *retry_interval,
		int *retry_times,
		int *vice_retry_times);

int
eag_radius_set_acct_interval(eag_radius_t *radius,
		int acct_interval);

int
eag_radius_get_acct_interval(eag_radius_t *radius);

int
eag_radius_set_thread_master(eag_radius_t *radius,
		eag_thread_master_t *master);

int
eag_radius_set_radius_conf(eag_radius_t *radius,
		struct radius_conf *radiusconf);

int
eag_radius_set_eagins(eag_radius_t *radius,
		eag_ins_t *eagins);

int
eag_radius_set_appdb(eag_radius_t *radius,
		appconn_db_t *appdb);

int
eag_radius_set_portal(eag_radius_t *radius,
		eag_portal_t *portal);

int
eag_radius_set_eagstat(eag_radius_t *radius,
		eag_statistics_t *eagstat);

int 
eag_radius_set_captive(eag_radius_t *radius,
		eag_captive_t *cap);

int
eag_radius_set_coa(eag_radius_t *radius,
		eag_coa_t *coa);

int
eag_radius_set_stamsg(eag_radius_t *radius,
		eag_stamsg_t *stamsg);

int
eag_radius_set_fastfwd(eag_radius_t *radius,
		eag_fastfwd_t *fastfwd);

int
eag_radius_set_macauth(eag_radius_t *radius,
		eag_macauth_t *macauth);

int 
eag_radius_log_all_sockradius(eag_radius_t *radius);

const char *
radius_terminate_cause_to_str(int terminate_cause);

int
eag_set_idletime_valuecheck(int value_check);

#endif		/* _EAG_RADIUS_H */
