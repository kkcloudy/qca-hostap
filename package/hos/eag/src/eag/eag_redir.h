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
* eag_redir.h
*
*
* CREATOR:
* autelan.software.Network Dep. team
*
* DESCRIPTION:
* eag redir
*
*
*******************************************************************************/

#ifndef _EAG_REDIR_H
#define _EAG_REDIR_H

#include <stdint.h>
#include "eag_def.h"
#include "appconn.h"

#define EAG_REDIR_LISTEN_PORT   3990

eag_redir_t *
eag_redir_new();

int
eag_redir_free(eag_redir_t *redir);

int
eag_redir_start(eag_redir_t * redir);

int
eag_redir_stop(eag_redir_t *redir);

int
eag_redir_set_local_addr(eag_redir_t *redir,
							uint32_t local_ip,
							uint16_t local_port);

int
eag_redir_set_thread_master(eag_redir_t *redir,
						eag_thread_master_t *master);

int
eag_redir_set_portal_conf(eag_redir_t *redir,
					struct portal_conf *portalconf);

int
eag_redir_set_eagstat(eag_redir_t *redir,
					eag_statistics_t *eagstat);

int
eag_redir_set_appdb(eag_redir_t *redir,
						appconn_db_t *appdb);

int
eag_redir_set_portal(eag_redir_t *redir,
						eag_portal_t *portal);

int
eag_redir_set_eagins(eag_redir_t *redir,
						eag_ins_t *eagins);

int
eag_redir_set_stamsg(eag_redir_t *redir,
						eag_stamsg_t *stamsg);

/*int
eag_redir_set_eagdbus(eag_redir_t *redir,
						eag_dbus_t *eagdbus);
*/
int 
eag_redir_set_max_redir_times(eag_redir_t *redir,
									int max_redir_times);

int 
eag_redir_get_max_redir_times(eag_redir_t *redir,
									int *max_redir_times);

int
eag_redir_set_force_dhcplease(eag_redir_t *redir,
						int force_dhcplease);

int
eag_redir_get_force_dhcplease(eag_redir_t *redir);

int 
eag_redir_log_all_redirconn(eag_redir_t *redir);

#endif				/* _EAG_REDIR_H */
