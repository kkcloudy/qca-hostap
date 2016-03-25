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
* eag_coa.h
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

#ifndef _EAG_COA_H
#define _EAG_COA_H

#include <stdint.h>
#include "eag_def.h"
#include "appconn.h"

eag_coa_t *eag_coa_new();

int
eag_coa_free(eag_coa_t *coa);

int
eag_coa_start(eag_coa_t *coa);

int
eag_coa_stop(eag_coa_t *coa);

int
eag_coa_ack_logout_proc(eag_coa_t *coa,
		uint32_t radius_ip,
		uint16_t radius_port,
		uint8_t reqpkt_id);

int
eag_coa_set_local_addr(eag_coa_t *coa,
		uint32_t local_ip,
		uint16_t local_port);

int
eag_coa_set_thread_master(eag_coa_t *coa,
		eag_thread_master_t *master);

int
eag_coa_set_portal(eag_coa_t *coa,
		eag_portal_t *portal);

int
eag_coa_set_radius(eag_coa_t *coa,
		eag_radius_t *radius);

int
eag_coa_set_appdb(eag_coa_t *coa,
		appconn_db_t *appdb);

int
eag_coa_set_eagins(eag_coa_t *coa,
		eag_ins_t *eagins);


int
eag_coa_set_radius_conf(eag_coa_t *coa,
		struct radius_conf *radiusconf);

int
eag_coa_set_captive(eag_coa_t *coa,
		eag_captive_t *cap);

/*int
eag_coa_set_eag_dbus(eag_coa_t *coa,
		eag_dbus_t *eagdbus);*/

int
eag_coa_set_stamsg(eag_coa_t *coa,
        eag_stamsg_t *stamsg);

int
eag_coa_set_fastfwd(eag_coa_t *coa,
		eag_fastfwd_t *fastfwd);
#endif		/* _EAG_COA_H */

