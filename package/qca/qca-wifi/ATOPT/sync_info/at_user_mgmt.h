#ifndef __AT_USER_MGMT_H__
#define __AT_USER_MGMT_H__
#include "ieee80211_var.h"
#define MAX_NEIGHBOUR_AP 32
#define MAX_DEV 16
#define MAX_USER 512
#define IEEE80211_TABLE_USED 0x80 //10000000
#define IEEE80211_ADDR_LEN 6
#define MAX_USERINFO_HASH 32
#define MAX_LOCAL_USERINFO 512 
#define MAX_SCAN_LIST 64
#define MAX_BUF     2048

struct sync_userinfo_table
{
    TAILQ_ENTRY(sync_userinfo_table) sync_userinfo_hash;	
    TAILQ_ENTRY(sync_userinfo_table) user_list_hash;
    u_int16_t    index;
    u_int8_t     sta_mac[6];
    u_int8_t     ap_mac[6];
    u_int8_t     work_cap;
    u_int8_t     is_assoc;
    u_int8_t     avg_mgmt_rssi;
    u_int32_t    assoc_cnt;
    u_int32_t    update_time;	
    spinlock_t   sync_userinfo_lock; /* Add irq lock. wangjia 2012-10-11 */
};

struct sync_userinfo_table_tlv
{
    u_int16_t    index;
    u_int8_t     sta_mac[6];
    u_int8_t     work_cap;
    u_int8_t     is_assoc;
    u_int8_t     avg_mgmt_rssi;    
    u_int32_t    assoc_cnt;
};


struct sync_dev_info{
    u_int8_t dev_mac[6];
    u_int8_t essid[32];
    u_int8_t work_mode;
    u_int8_t is_up;
    u_int8_t channel;
    u_int8_t txpower;
    u_int8_t user_cnt;
};

struct AP_LIST{
    u_int8_t ap_base_mac[6];
    u_int8_t use;
    struct sync_dev_info vaps[MAX_DEV];
    TAILQ_HEAD(,sync_userinfo_table) sync_user_info[32];
    struct sync_userinfo_table stations[MAX_USER];
    u_int32_t active_time;
};

struct SYNC_TLV{
    u_int8_t  type;
    u_int8_t  group_id;
    u_int16_t len;
    char *    value;
};

struct scan_neighbor_ap{
    unsigned char dev_mac[6];
    char rssi;
    unsigned char channel;
    char reserve[4];
};

struct  userinfo_table
{
    u_int8_t     user_mac[IEEE80211_ADDR_LEN];
    u_int8_t     user_cap;
    u_int8_t     identify_count;
    u_int8_t     identify;
    u_int8_t     avg_mgmt_rssi;
    u_int8_t     avg_data_rssi;
    u_int8_t     allow_2g;
    u_int8_t     assoc;
    u_int8_t     update;
    u_int8_t     slow_connect;
    u_int8_t     index;
    u_int16_t    recv_probe_2g;
    u_int16_t    recv_auth_2g;
    u_int16_t    recv_probe_5g;
    u_int16_t    recv_auth_5g;
    u_int32_t    assoc_cnt;
    u_int32_t    slow_stamp_time;
    u_int32_t    prev_stamp_time;
    u_int32_t    stamp_time;
    spinlock_t   userinfo_lock; /* Add irq lock. wangjia 2012-10-11 */
    TAILQ_ENTRY(userinfo_table) userinfo_hash;
    TAILQ_HEAD(,sync_userinfo_table) user_list_head;
};

struct  userinfo_table_record
{
    u_int8_t    user_mac[IEEE80211_ADDR_LEN];
    u_int8_t    user_cap;
    u_int8_t    inact;
    u_int8_t    identify_count;
    u_int8_t    identify;
    u_int8_t    avg_mgmt_rssi;
    u_int8_t    avg_data_rssi;
    u_int8_t    assoc;
    u_int16_t   recv_probe_2g;
    u_int16_t   recv_auth_2g;
    u_int16_t   recv_probe_5g;
    u_int16_t   recv_auth_5g;
    u_int32_t   assoc_cnt;
    u_int32_t   stamp_time;
};


extern struct AP_LIST ap_list[MAX_NEIGHBOUR_AP];
//extern struct userinfo_table userinfo_table_t[IEEE80211_USERINFO_MAX];
extern u_int32_t local_userinfo_cnt;
extern struct sync_dev_info own_vaps[MAX_DEV];

#define	AT_USER_HASH(addr)   \
    (((const u_int8_t *)(addr))[IEEE80211_ADDR_LEN - 1] % IEEE80211_NODE_HASHSIZE)



struct userinfo_table * userinfo_alloc(char * mac);
struct userinfo_table * create_local_user(u_int8_t  user_mac[IEEE80211_ADDR_LEN]);
int create_neighbour_ap(char * base_mac);
const char * get_user_cap(u_int8_t flag);
struct userinfo_table * get_user_information(char * mac);
void show_scan_list(void);
u_int16_t show_local_table(u_int8_t *data);
u_int16_t show_neighbour_dev(u_int8_t *data);
void show_neighbour_table(void);
u_int16_t show_neighbour_user_by_mac(char *data,char *mac);
int find_neighbour_ap(char * base_mac);
struct userinfo_table * find_local_user(u_int8_t  user_mac[IEEE80211_ADDR_LEN]);
struct sync_userinfo_table * find_neighbour_user(int ap_index,u_int8_t  user_mac[IEEE80211_ADDR_LEN]);
void delete_neighbour_user(char * data);
void update_dev_info(char * base_mac, struct sync_dev_info * vap);
void update_own_dev_info(char * base_mac, struct sync_dev_info * vap);
void update_user_info(char * base_mac, struct sync_userinfo_table_tlv *user);
void update_user_cap(struct ieee80211com * ic,struct userinfo_table * sta,int rssi,int type);
u_int32_t calc_update_time(u_int32_t prev_time);
void sync_clean_table(char * base_mac);
void local_table_aging(void);
void neighbour_table_aging(void);
void neighbour_ap_aging(void);
void create_scan_list(struct scan_neighbor_ap * scan_ap);
#endif
