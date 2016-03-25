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
* eag_macauth.h
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* eag mac auth
*
*
*******************************************************************************/

#ifndef _EAG_MACAUTH_H
#define _EAG_MACAUTH_H

#include <stdint.h>
#include "eag_def.h"

#define SECURITY_MAC_AUTH			15	
#define SECURITY_NO_NEED_AUTH		11

eag_macauth_t *eag_macauth_new();

int
eag_macauth_free(eag_macauth_t *macauth);

int 
eag_macauth_start(eag_macauth_t *macauth);

int
eag_macauth_stop(eag_macauth_t *macauth);

int
eag_macauth_preauth_check(eag_macauth_t *macauth);

int
eag_add_mac_preauth(eag_macauth_t *macauth,
		uint32_t userip, uint8_t usermac[6]);

int
eag_del_mac_preauth(eag_macauth_t *macauth,
		uint32_t userip);

int
del_eag_preauth_by_ip_or_mac(eag_macauth_t *macauth,
		uint32_t userip, uint8_t usermac[6]);

int 
eag_macauth_log_all_preauth(eag_macauth_t *macauth);

void
eag_macauth_set_thread_master(eag_macauth_t *macauth,
		eag_thread_master_t *master);

int
eag_macauth_set_macauth_switch(eag_macauth_t *macauth,
		int macauth_switch);

int
eag_macauth_get_macauth_switch(eag_macauth_t *macauth);

int
eag_macauth_set_macauth_type(int macauth_type);

int
eag_macauth_set_flux_from(eag_macauth_t *macauth,
		int flux_from);

int
eag_macauth_get_flux_from(eag_macauth_t *macauth);

int
eag_macauth_set_flux_interval(eag_macauth_t *macauth,
		int flux_interval);

int
eag_macauth_get_flux_interval(eag_macauth_t *macauth);

int
eag_macauth_set_flux_threshold(eag_macauth_t *macauth,
		int flux_threshold, int check_interval);

int
eag_macauth_get_flux_threshold(eag_macauth_t *macauth);

int 
eag_macauth_get_check_interval(eag_macauth_t *macauth);

int
eag_macauth_set_eagins(eag_macauth_t *macauth,
		eag_ins_t *eagins);

/*int
eag_macauth_set_eagdbus(eag_macauth_t *macauth,
		eag_dbus_t *eagdbus);*/

int
eag_macauth_set_appdb(eag_macauth_t *macauth,
		appconn_db_t *appdb);

int
eag_macauth_set_captive(eag_macauth_t *macauth,
		eag_captive_t *cap);

/*int
eag_macauth_set_fastfwd(eag_macauth_t *macauth,
		eag_fastfwd_t *fastfwd);*/

int
eag_macauth_set_portal(eag_macauth_t *macauth,
		eag_portal_t *portal);

int
eag_macauth_set_radius(eag_macauth_t *macauth,
		eag_radius_t *radius);

int
eag_macauth_set_portal_conf(eag_macauth_t *macauth,
		struct portal_conf *portalconf);

int
eag_macauth_set_radius_conf(eag_macauth_t *macauth,
		struct radius_conf *radiusconf);

int
flush_preauth_flux_from_fastfwd(eag_macauth_t *macauth,
		uint32_t userip,
		uint64_t fastfwd_input_octets,
		uint64_t fastfwd_output_octets);

#endif	/* _EAG_MACAUTH_H */

