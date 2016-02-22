/************************************************************
Copyright (C), 2006-2013, AUTELAN. Co., Ltd.
FileName: at_sync_info.c
Author:Mingzhe Duan 
Version : 1.0
Date:2015-02-03
Description: This file 
***********************************************************/


#include "linux/if.h"
#include "linux/socket.h"
#include "linux/netlink.h"
#include <net/sock.h>

#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/cache.h>
#include <linux/proc_fs.h>

#include <ieee80211_var.h>
#include <ath_internal.h>
#include <if_athvar.h>
#include <osif_private.h>
#include <osdep_adf.h>

#include "ath_netlink.h"
#include "sys/queue.h"
#include "at_user_mgmt.h"
#include "at_sync_info.h"
//#include <net/ethernet.h> 

extern TAILQ_HEAD(,userinfo_table) local_user_info[];

u_int32_t sync_switch = 1; //sync switch;1=enable
EXPORT_SYMBOL(sync_switch);

u_int32_t sync_debug = 0; //debug switch
EXPORT_SYMBOL(sync_debug);

int sync_time = 10; //sync update time

u_int8_t sync_group_id = 0;  //current group ID, mutex with sync_auto_group
EXPORT_SYMBOL(sync_group_id);

u_int8_t sync_auto_group = 0; //auto group switch, mutex with sync_group_id ;enable=1
EXPORT_SYMBOL(sync_auto_group);

u_int8_t sync_neighbor_rssi_limit = 20; //for auto group, ignore neighbor AP from scan list if rssi less than this value
EXPORT_SYMBOL(sync_neighbor_rssi_limit);


struct timer_list sync_info_timer;
EXPORT_SYMBOL(sync_info_timer);

#define SECS(n) (n) % 60
#define MINS(n) ((n) / 60) % 60
#define HRS(n)  (n) / 3600 % 24
extern void sync_netlink_send(unsigned char * message,int buf_len);

void set_sync_time(int time)
{
    sync_time = time;
}

int get_sync_time(void)
{
    return sync_time;
}

void set_sync_switch(int lvl)
{
    sync_switch = lvl;
}
int get_sync_switch(void)
{
    return sync_switch;
}

void set_sync_debug(int lvl)
{
    sync_debug = lvl;
}
int get_sync_debug(void)
{
    return sync_debug;
}

void set_sync_auto_group(int sw)
{
    sync_auto_group = sw;
}

int get_sync_auto_group(void)
{
    return sync_auto_group;
}

void set_sync_neighbor_rssi_limit(int value)
{
    sync_neighbor_rssi_limit= value;
}

int get_sync_neighbor_rssi_limit(void)
{
    return sync_neighbor_rssi_limit;
}

void user_sync_info_parse(char * data)
{
    u_int8_t  TLV_HEAD_LEN = sizeof(struct SYNC_TLV) - sizeof(char *); //without VALUE
    u_int8_t  USER_INFO_LEN = sizeof(struct sync_userinfo_table_tlv);
    u_int16_t user_cnt = 0;
    int16_t pkt_payload_len = 0;
    struct ether_header * eh = (struct ether_header *)data;
    struct SYNC_TLV * tlv = (struct SYNC_TLV *)(data + sizeof(struct ether_header));
    struct sync_userinfo_table_tlv * p_station = (struct sync_userinfo_table_tlv *)&(tlv->value);
    
    /*If auto group switch is close and packet group id not equel my group id, ignore it!*/
    if(!sync_auto_group)
    {
        if(tlv->group_id != sync_group_id)
        {
           return;
        }
    }
    pkt_payload_len = tlv->len - TLV_HEAD_LEN;
    while(1)
    {
        user_cnt++;
        update_user_info(eh->ether_shost,p_station);
        p_station = (struct sync_userinfo_table_tlv *)(data + (sizeof(struct ether_header) + TLV_HEAD_LEN + (USER_INFO_LEN * user_cnt)));
        pkt_payload_len -= USER_INFO_LEN;
        if(pkt_payload_len <= 0)
            break;
    }
    return;

}

void dev_sync_info_parse(char * data)
{
    u_int8_t  TLV_HEAD_LEN = sizeof(struct SYNC_TLV) - sizeof(char *); //without VALUE
    u_int8_t  DEV_INFO_LEN = sizeof(struct sync_dev_info);
    u_int16_t dev_cnt = 0;
    int16_t pkt_payload_len = 0;
    struct ether_header *eh = (struct ether_header *)data;
    struct SYNC_TLV * tlv = (struct SYNC_TLV *)(data + sizeof(struct ether_header));
    struct sync_dev_info * p_vap = (struct sync_dev_info *)&(tlv->value);
    
    /*If auto group switch is close and packet group id not equel my group id, ignore it!*/
    if(!sync_auto_group)
    {
        if(tlv->group_id != sync_group_id)
        {
           return;
        }
    }

    pkt_payload_len = tlv->len - TLV_HEAD_LEN;
    
    while(1)
    {
        dev_cnt++;
        update_dev_info(eh->ether_shost,p_vap);
        p_vap = (struct sync_dev_info *)(data + (sizeof(struct ether_header) + TLV_HEAD_LEN + (DEV_INFO_LEN * dev_cnt)));
        pkt_payload_len -= DEV_INFO_LEN;
        if(pkt_payload_len <= 0)
            break;
    }

    return;

}

void own_dev_sync_info_parse(char * data)
{
    u_int8_t  TLV_HEAD_LEN = sizeof(struct SYNC_TLV) - sizeof(char *); //without VALUE
    u_int8_t  DEV_INFO_LEN = sizeof(struct sync_dev_info);
    u_int16_t dev_cnt = 0;
    int16_t pkt_payload_len = 0;
    struct ether_header *eh = (struct ether_header *)data;
    struct SYNC_TLV * tlv = (struct SYNC_TLV *)(data + sizeof(struct ether_header));
    struct sync_dev_info * p_vap = (struct sync_dev_info *)&(tlv->value);
    
    /*If auto group switch is close and packet group id not equel my group id, ignore it!*/
    if(!sync_auto_group)
    {
        if(tlv->group_id != sync_group_id)
        {
           return;
        }
    }

    pkt_payload_len = tlv->len - TLV_HEAD_LEN;
    
    while(1)
    {
        dev_cnt++;
        update_own_dev_info(eh->ether_shost,p_vap);
        p_vap = (struct sync_dev_info *)(data + (sizeof(struct ether_header) + TLV_HEAD_LEN + (DEV_INFO_LEN * dev_cnt)));
        pkt_payload_len -= DEV_INFO_LEN;
        if(pkt_payload_len <= 0)
            break;
    }

    return;

}

void sync_set_group(char * data)
{
    struct SYNC_TLV * tlv = (struct SYNC_TLV *)(data + sizeof(struct ether_header));
    sync_group_id = tlv->group_id;
    
    if(sync_debug)
        printk("%s sync_group_id = %d\n",__func__,sync_group_id);
}


/*Recv msg from neighbor ap and parse it*/
void recv_sync_info(char * data)
{
    struct ether_header *eh = (struct ether_header *)data;
    struct SYNC_TLV * tlv = (struct SYNC_TLV *)(data + sizeof(struct ether_header));
    if(!sync_switch)
        return;
    if(sync_debug)
        printk("%s tlv->type = %x\n",__func__,tlv->type);
    switch(tlv->type)
    {
        case SYNC_USER_INFO:
            user_sync_info_parse(data);
            break;
        case SYNC_DEVICE_INFO:
            dev_sync_info_parse(data);
            break;
        case SYNC_DELETE_INFO:
            delete_neighbour_user(data);
            break;
        case SYNC_OWN_DEVICE_INFO:
            own_dev_sync_info_parse(data);
            break;
        case SYNC_SET_GROUP_ID:
            sync_set_group(data);
            break;
        case SYNC_CLEAN_INFO:
            sync_clean_table(eh->ether_shost);
            break;
        default:            
            if(sync_debug)
                printk("%s UNKONW TLV->TYPE %d\n",__func__,tlv->type);
            break;
    }
  
}
EXPORT_SYMBOL(recv_sync_info);


/*Assemble all local station info and send to neighbor ap*/
void send_sync_info_all(void)
{
    u_int16_t  i = 0;
    u_int8_t  add_tlv_head = 0;
    u_int8_t  buf[MAX_PKT_PAYLOAD]= {0};
    u_int8_t  TLV_HEAD_LEN = sizeof(struct SYNC_TLV) - sizeof(char *); //without VALUE
    u_int8_t  USER_INFO_LEN = sizeof(struct sync_userinfo_table_tlv);
    u_int16_t buf_len = 0;   //buf_len = TLV_HEAD_LEN + (USER_INFO_LEN * N)
    u_int16_t user_cnt = 0;   
    u_int16_t fragment_cnt = 0;
    struct SYNC_TLV * tlv = NULL;
    struct sync_userinfo_table_tlv * p_station = NULL;    
    struct userinfo_table * user = NULL;

    if(!sync_switch)
        return;

    for(i = 0; i < IEEE80211_NODE_HASHSIZE; i++)
    {
    
        TAILQ_FOREACH(user, &(local_user_info[i]), userinfo_hash) {
            if(!(user->user_cap & IEEE80211_TABLE_USED))
            {
                continue;
            }
            if(user->update == 0)
            {
                continue;
            }
            user_cnt++;
            if(add_tlv_head == 0)
            {
                add_tlv_head = 1;
                memset(buf,0x0,MAX_PKT_PAYLOAD);
                tlv = (struct SYNC_TLV *)buf;
                p_station = (struct sync_userinfo_table_tlv *)&(tlv->value);
                tlv->type = SYNC_USER_INFO;
                tlv->group_id = sync_group_id;
                buf_len = TLV_HEAD_LEN; //without VALUE
            }
            p_station->index = user->index;
            memcpy(p_station->sta_mac,user->user_mac,6);
            p_station->avg_mgmt_rssi = user->avg_mgmt_rssi;
            p_station->work_cap = user->user_cap;        
            p_station->is_assoc = user->assoc;
            p_station->assoc_cnt = user->assoc_cnt;
            user->update = 0;
            p_station = (struct sync_userinfo_table_tlv *)(buf+(TLV_HEAD_LEN + (USER_INFO_LEN * user_cnt)));
            buf_len += USER_INFO_LEN;
            tlv->len = buf_len;

            /*If buf_len greater than MAX_PKT_PAYLOAD, fragment this msg*/
            if((buf_len + USER_INFO_LEN) > MAX_PKT_PAYLOAD)
            {
                sync_netlink_send(buf,buf_len); 
                add_tlv_head = 0;
                user_cnt = 0;            
                buf_len = 0;
                fragment_cnt++;
                continue;
            }
        }
    }
    
    sync_netlink_send(buf,buf_len); 
}

/*Assemble special station info and send to neighbor ap*/
void send_sync_info_single(struct userinfo_table * user,u_int8_t type)
{
    u_int8_t buf[64]= {0};
    u_int16_t buf_len = 0; //buf_len = TLV + USERINFO
    struct SYNC_TLV * tlv = (struct SYNC_TLV *)buf;
    struct sync_userinfo_table_tlv * p_station = (struct sync_userinfo_table_tlv *)&(tlv->value);

    if(!sync_switch)
        return;
    
    if(user == NULL)
    {
        return;
    }
    
    tlv->type = type;
    tlv->group_id = sync_group_id;
    buf_len += sizeof(struct SYNC_TLV) - sizeof(char *); //without VALUE
    p_station->index = user->index;
    memcpy(p_station->sta_mac,user->user_mac,6);
    p_station->avg_mgmt_rssi = user->avg_mgmt_rssi;
    p_station->work_cap = user->user_cap;
    p_station->is_assoc = user->assoc;
    p_station->assoc_cnt = user->assoc_cnt;
    buf_len += sizeof(struct sync_userinfo_table_tlv);
    tlv->len = buf_len;   
    sync_netlink_send(buf,buf_len); 
}


void sync_info_timer_fn(void)
{
    local_table_aging();
    //neighbour_table_aging();
    neighbour_ap_aging();
    send_sync_info_all();
    mod_timer(&sync_info_timer, jiffies + HZ * sync_time);
}
EXPORT_SYMBOL(sync_info_timer_fn);


