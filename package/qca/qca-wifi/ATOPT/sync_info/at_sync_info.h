#ifndef __AT_SYNC_INFO_H__
#define __AT_SYNC_INFO_H__
#include "ieee80211_var.h"
#include <at_user_mgmt.h>
#define SYNC_USER_INFO 0x01
#define SYNC_DEVICE_INFO 0x02
#define SYNC_DELETE_INFO 0x03
#define SYNC_OWN_DEVICE_INFO 0x04
#define SYNC_SET_GROUP_ID 0x0E
#define SYNC_CLEAN_INFO 0x0F

#define MAX_PKT_PAYLOAD 1400
#define IEEE80211_TABLE_SUPPORT2G 0x40 //01000000
#define IEEE80211_TABLE_SUPPORT5G 0x20 //00100000

#define ENABLE 1
#define DISALE 0

void set_sync_time(int time);
int  get_sync_time(void);
void set_sync_switch(int lvl);
int  get_sync_switch(void);
void set_sync_debug(int lvl);
int  get_sync_debug(void);
void set_sync_auto_group(int sw);
int  get_sync_auto_group(void);
void set_sync_neighbor_rssi_limit(int value);
int  get_sync_neighbor_rssi_limit(void);
void recv_sync_info(char * data);
void send_sync_info_single(struct userinfo_table * user,u_int8_t type);
void send_sync_info_all(void);
#endif /* __SYNC_INFO_H__ */

