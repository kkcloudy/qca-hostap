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
* eag_ins.h
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* eag ins
*
*
*******************************************************************************/

#ifndef _EAG_INS_H
#define _EAG_INS_H

#include <stdint.h>
#include "eag_def.h"
#include "appconn.h"
#include "eag_statistics.h"

#define SLOT_IPV4_BASE  0XA9FE0200 /* 169.254.2.0 */

#define EAG_PORTAL_PORT_BASE 			4050
/* EAG进程与PDC交互Portal报文的端口，基值*/
#define EAG_RADIUS_COA_PORT_BASE		4200		
#define EAG_REDIR_LISTEN_PORT_BASE		4250

#define MAX_HANSI_ID  16	

typedef enum {
	PDC_SELF = 0,
	PDC_EAG,
} PDC_CLIENT_TYPE;

typedef enum {
	RDC_SELF = 0,
	RDC_EAG,
} RDC_CLIENT_TYPE;

eag_ins_t *eag_ins_new();

int
eag_ins_free(eag_ins_t *eagins);

int
eag_ins_start(eag_ins_t *eagins);

int
eag_ins_stop(eag_ins_t *eagins);

int 
eag_ins_dispatch(eag_ins_t *eagins);

int
eag_ins_is_running(eag_ins_t *eagins);

uint32_t
eag_ins_get_nasip(eag_ins_t *eagins);

/* 
int
eag_ins_get_distributed(eag_ins_t *eagins); 
*/



int
eag_ins_set_flux_from(eag_ins_t *eagins,
		int flux_from);

int
eag_ins_get_flux_from(eag_ins_t *eagins);

/*int
eag_ins_syn_user(eag_ins_t *eagins,
		struct app_conn_t *appconn);

int
eag_ins_syn_finish_flag(eag_ins_t *eagins);

int
eag_ins_syn_statistic(eag_ins_t *eagins,
		struct eag_bss_statistics *bss);
*/
void
terminate_appconn(struct app_conn_t *appconn,
		eag_ins_t *eagins, int terminate_cause);

void
terminate_appconn_nowait(struct app_conn_t *appconn,
				eag_ins_t *eagins, int terminate_cause);

int
eag_get_debug_filter_key(char *session_filter_prefix, int size, const char *ip_str,
					const char *mac_str, const char *username);
#if 0
int
eag_ins_get_trap_online_user_num_params(
										eag_ins_t *eagins, 
										int *trap_onlineusernum_switch,
										int *threshold_onlineusernum);
#endif
#endif		/* _EAG_INS_H */

