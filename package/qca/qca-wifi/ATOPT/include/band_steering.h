#ifndef __BAND_STEERING_H
#define __BAND_STEERING_H

#include <linux/types.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/list.h>
#include <ieee80211_var.h>
#include <han_ioctl.h>
#include "han_command.h"


#define HASH_SIZE    32
#define	HASH(addr)   \
    ((addr)[ETHER_ADDR_LEN - 1] % HASH_SIZE)
#define TABLE_LIMIT		512

#define STRING_EQ(s1, s2)	(0 == strncmp((s1), (s2), strlen(s2)))
#define STRING_CP(s1, s2)	(strncpy((s1), (s2), strlen(s2)))


struct client_capability {
	u_int8_t    mac[IEEE80211_ADDR_LEN];
	u_int8_t	identify;
	u_int8_t	probe_deny_count;
	u_int8_t	auth_deny_count;
	u_int8_t	if_5g_capable;
	u_int32_t	timestamp;
	u_int32_t	probe_timestamp;
	u_int32_t	prev_timestame;

	struct list_head    t_list;
	struct list_head	l_list;

};

struct bandsteering_stat {
	u_int32_t	non_5g_capable;
	u_int32_t	excessive_load_to_5g;
	u_int32_t	excessive_load_to_2g;
	u_int32_t	steer_to_5g;
	u_int32_t	weak_2g_signal;
};

#define IDENTIFY_FINISHED		1
#define IDENTIFY_RESET			0

#define BS_DROP_FRAME 0
#define BS_CONTINUE_WITH_MGMT_PROCESS  1

struct client_capability * 
band_steering_create_client(u_int8_t *client_mac);
struct client_capability * 
band_steering_find_client(u_int8_t * client_mac);
void 
band_steering_delete_client(void);
void 
band_steering_update_client(struct client_capability *client, int subtype);
int 
band_steering_ioctl(struct han_ioctl_priv_args *a, struct iwreq *iwr);
void 
band_steering_init_client_table(void);
int 
band_steering(struct ieee80211com *ic, struct ieee80211vap *vap, 
              struct ieee80211_node *ni, struct client_capability *client, 
              wbuf_t wbuf, int rssi);
bool 
check_probe_req(wbuf_t wbuf, struct ieee80211vap *vap);


#endif
