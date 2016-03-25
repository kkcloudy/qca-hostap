/* eag_arp.h */
#ifndef _EAG_ARP_H
#define _EAG_ARP_H

#include "eag_def.h"

eag_arplisten_t *eag_arp_new();

int
eag_arp_free(eag_arplisten_t *arp);

int
eag_arp_start(eag_arplisten_t *arp);

int
eag_arp_stop(eag_arplisten_t *arp);


void 
eag_arp_set_thread_master(eag_arplisten_t *arp,
		eag_thread_master_t *master);

int
eag_arp_set_eagins(eag_arplisten_t *arp,
		eag_ins_t *eagins);

int
eag_arp_set_portal(eag_arplisten_t *arp,
		eag_portal_t *portal);

int
eag_arp_set_macauth(eag_arplisten_t *arp,
		eag_macauth_t *macauth);

int
eag_arp_set_appdb(eag_arplisten_t *arp,
		appconn_db_t *appdb);


#endif

