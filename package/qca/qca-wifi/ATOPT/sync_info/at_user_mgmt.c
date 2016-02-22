/************************************************************
Copyright (C), 2006-2013, AUTELAN. Co., Ltd.
FileName: at_user_mgmt.c
Author:Mingzhe Duan 
Version : 1.0
Date:2015-02-03
Description: 
***********************************************************/

#include <ieee80211_var.h>
#include <ath_internal.h>
#include <if_athvar.h>
#include <osif_private.h>
#include "at_connect_ctl.h"
#include "at_sync_info.h"

extern u_int32_t sync_debug;
extern u_int8_t sync_group_id;
extern u_int8_t sync_auto_group;
extern u_int8_t sync_neighbor_rssi_limit;

struct AP_LIST ap_list[MAX_NEIGHBOUR_AP];
EXPORT_SYMBOL(ap_list);
struct sync_dev_info own_vaps[MAX_DEV];
EXPORT_SYMBOL(own_vaps);
char own_base_mac[IEEE80211_ADDR_LEN];
EXPORT_SYMBOL(own_base_mac);
u_int32_t local_userinfo_cnt = 0;
EXPORT_SYMBOL(local_userinfo_cnt);
struct scan_neighbor_ap scan_ap_list[64];
EXPORT_SYMBOL(scan_ap_list);

TAILQ_HEAD(,userinfo_table) local_user_info[IEEE80211_NODE_HASHSIZE];
EXPORT_SYMBOL(local_user_info);

void at_null(void) //Added for source insight
{

}

int find_scan_list(char * mac)
{
    int i = 0;
    int index = -1;
    for(i = 0; i < MAX_SCAN_LIST; i++)
    {        
        if (IEEE80211_ADDR_EQ(scan_ap_list[i].dev_mac, mac))
        {
            index = i;
            return index;
        }
    }
    return index;
}

void create_scan_list(struct scan_neighbor_ap * scan_ap)
{
    int i = 0;
    int index = -1;    
    u_int8_t min_rssi = 0;
    u_int8_t NULL_MAC[6] = {0};
    if(scan_ap->rssi < sync_neighbor_rssi_limit)
    {
        return;
    }
    
    index = find_scan_list(scan_ap->dev_mac);
    if(index == -1)
    {
        for(i = 0; i < MAX_SCAN_LIST; i++)
        {
            if(IEEE80211_ADDR_EQ(scan_ap_list[i].dev_mac, NULL_MAC))
            {
                index = i;
                memcpy(scan_ap_list[index].dev_mac,scan_ap->dev_mac,6);
                scan_ap_list[index].channel = scan_ap->channel;
                scan_ap_list[index].rssi = scan_ap->rssi;
                return;
            }
        }
    }
    if(index == -1)
    {
        min_rssi = scan_ap->rssi;
        for(i = 0; i < MAX_SCAN_LIST; i++)
        {
            if(!IEEE80211_ADDR_EQ(scan_ap_list[i].dev_mac, NULL_MAC))
            {
                if(scan_ap_list[i].rssi < min_rssi)
                {
                    index = i;
                    min_rssi = scan_ap_list[i].rssi;
                }
            }
        }
    }
    if(index != -1)
    {    
        memcpy(scan_ap_list[index].dev_mac,scan_ap->dev_mac,6);
        scan_ap_list[index].channel = scan_ap->channel;
        scan_ap_list[index].rssi = scan_ap->rssi;
    }
}

int create_neighbour_ap(char * base_mac)
{
    int i = 0;
    int index = -1;
    int free_index = -1;
    for(i = 0; i < MAX_NEIGHBOUR_AP; i++)
    {
        if(ap_list[i].use == 0)
        {
            if(free_index == -1)
                free_index = i;
            continue;
        }
        if(memcmp(base_mac,ap_list[i].ap_base_mac,6) == 0)
        {
            index = i;
            return index;
        }
    }
    
    if(index == -1)
    {
        if(free_index == -1)
        {
            if(sync_debug)
                printk("%s AP table full!\n",__func__);
            return index;
        }
        index = free_index;        
        if(sync_debug)
            printk("Create new ap[%s] index %d!\n",ether_sprintf(base_mac),index);        
        ap_list[index].use = 1;
        memcpy(ap_list[index].ap_base_mac,base_mac,6);
    }

    return index;
    
}

struct userinfo_table *
create_local_user(u_int8_t  user_mac[IEEE80211_ADDR_LEN])
{
    int i = 0;
    unsigned long irq_lock_flags;   /* Temp variable, used for irq lock/unlock parameter. wangjia 2012-10-11 */
    struct userinfo_table * user = NULL;	
    struct sync_userinfo_table * sync_user = NULL;
    int user_hash = AT_USER_HASH(user_mac);	
    user = userinfo_alloc(user_mac);	
    if(user != NULL)
    {

        /**
        *  Add irq lock, spin_lock_irqsave/spin_unlock_irqrestore. wangjia 2012-10-11 
        */ 
        //spin_lock_init(&(user->userinfo_lock));
        spin_lock_irqsave(&(user->userinfo_lock), irq_lock_flags);	
        TAILQ_INSERT_HEAD(&(local_user_info[user_hash]), user, userinfo_hash);
        local_userinfo_cnt++;
        IEEE80211_ADDR_COPY(user->user_mac,user_mac);
        user->stamp_time = jiffies_to_msecs(jiffies);		
        user->prev_stamp_time = user->stamp_time;
        user->user_cap = IEEE80211_TABLE_USED;
        user->index = user_hash;
        user->identify = 0;
        user->identify_count = 0;
        user->recv_auth_2g = 0;
        user->recv_auth_5g = 0;
        user->recv_probe_2g = 0;
        user->recv_probe_5g = 0;
        user->allow_2g = 0;
        user->avg_mgmt_rssi= 0;
        //user->user_cap = 0;

        /*check neighbor sta and link together*/
        for(i = 0; i < MAX_NEIGHBOUR_AP; i++)
        {
            sync_user = find_neighbour_user(i,user->user_mac);
            if(sync_user != NULL)
            {
                TAILQ_INSERT_HEAD(&(user->user_list_head), sync_user, user_list_hash);
            }
        }

        spin_unlock_irqrestore(&(user->userinfo_lock), irq_lock_flags);
        if(sync_debug)
        {
            printk("create:sta mac=%s,support ",ether_sprintf(user->user_mac));
            if(user->user_cap & IEEE80211_TABLE_SUPPORT2G)//01000000
                printk("2G ");
            if(user->user_cap & IEEE80211_TABLE_SUPPORT5G)//00100000
                printk("5G ");
            printk("\n");
        }
    }

    if(local_userinfo_cnt >= MAX_LOCAL_USERINFO)
    {
        int i = 0;	
        int hash_cnt = 0;	
        struct userinfo_table * tmp_user = NULL;
        struct userinfo_table * user_del = NULL;
        for(i = 0; i < MAX_USERINFO_HASH; i++)
        {
            TAILQ_FOREACH(tmp_user, &(local_user_info[i]), userinfo_hash) {
                if(user_del == NULL)
                {
                    hash_cnt = i;
                    user_del = tmp_user;
                }
                else if(tmp_user->stamp_time < user_del->stamp_time){
                    hash_cnt = i;
                    user_del = tmp_user;
                }
            }
        }
        spin_lock_irqsave(&(user_del->userinfo_lock), irq_lock_flags);
        send_sync_info_single(user_del,SYNC_DELETE_INFO);
        TAILQ_REMOVE(&(local_user_info[hash_cnt]), user_del, userinfo_hash);
        spin_unlock_irqrestore(&(user_del->userinfo_lock), irq_lock_flags);
        kfree(user_del);		
        local_userinfo_cnt--;
    }
    return user;
}



const char * get_user_cap(u_int8_t flag)
{
    if((flag & IEEE80211_TABLE_SUPPORT2G) && (flag & IEEE80211_TABLE_SUPPORT5G))
        return "2G5G";

    if(flag & IEEE80211_TABLE_SUPPORT2G)
        return "2G";

    if(flag & IEEE80211_TABLE_SUPPORT5G)
        return "5G";
    return " ";
}

struct userinfo_table * get_user_information(char * mac)
{
    struct userinfo_table *user = NULL;
    int new = 0;
    user = find_local_user(mac);
    if(user == NULL)
    {
        user = create_local_user(mac);
        new = 1;
    }
    else
    {
        user->prev_stamp_time = user->stamp_time;
        user->stamp_time = jiffies_to_msecs(jiffies);
    }

    if(new)
    {
        user->slow_connect = 1;
        user->slow_stamp_time = user->stamp_time;
        send_sync_info_single(user,SYNC_USER_INFO);
    }
    return user;
}


int find_vap_dev(int ap_index,char * dev_mac)
{
    int i = 0;    
    int index = -1;
    int free_index = -1;
    u_int8_t NULL_MAC[6] = {0};
    for(i = 0; i < MAX_DEV; i++)
    {
        if(memcmp(ap_list[ap_index].vaps[i].dev_mac, NULL_MAC, 6) == 0)
        {        
            if(free_index == -1)
                free_index = i;
            continue;
        }
        if(memcmp(dev_mac,ap_list[ap_index].vaps[i].dev_mac,6) == 0)
        {
            index = i;
            //printk("Found dev index %d!\n",index);
            return index;
        }
    }
    if(index == -1)
    {
        if(free_index == -1)
        {
            if(sync_debug)
                printk("dev table full! BASE_MAC: %s\n",ether_sprintf(ap_list[ap_index].ap_base_mac));
            return index;
        }
        index = free_index;
        //printk("Create new dev table index %d!\n",index);
        memcpy(ap_list[ap_index].vaps[index].dev_mac,dev_mac,6);
    }
    return index;
}

int find_own_dev(char * dev_mac)
{
    int i = 0;    
    int index = -1;
    int free_index = -1;
    u_int8_t NULL_MAC[6] = {0};
    for(i = 0; i < MAX_DEV; i++)
    {
        if(memcmp(own_vaps[i].dev_mac, NULL_MAC, 6) == 0)
        {        
            if(free_index == -1)
                free_index = i;
            continue;
        }
        if(memcmp(dev_mac,own_vaps[i].dev_mac,6) == 0)
        {
            index = i;
            //printk("Found dev index %d!\n",index);
            return index;
        }
    }
    if(index == -1)
    {
        if(free_index == -1)
        {
            if(sync_debug)
                printk("own dev table full!\n");
            return index;
        }
        index = free_index;
        //printk("Create new dev table index %d!\n",index);
        memcpy(own_vaps[index].dev_mac,dev_mac,6);
    }
    return index;
}


struct userinfo_table * 
find_local_user(u_int8_t  user_mac[IEEE80211_ADDR_LEN])
{
    struct userinfo_table * user = NULL;
    int user_hash = AT_USER_HASH(user_mac);	
    TAILQ_FOREACH(user, &(local_user_info[user_hash]), userinfo_hash) {
        if (IEEE80211_ADDR_EQ(user->user_mac, user_mac))
        {
#if 0
            if(sync_debug)
            {
                printk("%s:find a sta in userinfo_table_t,mac is %s,support ",__func__,ether_sprintf(user->user_mac));
                if(user->user_cap & IEEE80211_TABLE_SUPPORT2G)//01000000
                    printk("2G ");
                if(user->user_cap & IEEE80211_TABLE_SUPPORT5G)//00100000
                    printk("5G ");
                printk("\n");
            }
#endif
            return user;
        }
    }
    return NULL;
}

struct sync_userinfo_table * 
find_neighbour_user(int ap_index,u_int8_t  user_mac[IEEE80211_ADDR_LEN])
{
    struct sync_userinfo_table * user = NULL;
    int user_hash = AT_USER_HASH(user_mac);	
    TAILQ_FOREACH(user, &(ap_list[ap_index].sync_user_info[user_hash]), sync_userinfo_hash) {
        if (IEEE80211_ADDR_EQ(user->sta_mac, user_mac))
        {
            return user;
        }
    }
    return NULL;
}

int find_neighbour_ap(char * base_mac)
{
    int i = 0;
    int index = -1;
    int free_index = -1;
    for(i = 0; i < MAX_NEIGHBOUR_AP; i++)
    {
        if(ap_list[i].use == 0)
        {
            if(free_index == -1)
                free_index = i;
            continue;
        }
        if(memcmp(base_mac,ap_list[i].ap_base_mac,6) == 0)
        {
            index = i;
            //printk("Found ap table index %d!\n",index);
            return index;
        }
    }

    /*Create new ap in ap_list*/
    /*If auto group did't open,create ap_list. Else create ap_list after checked scan list in update_dev_info function*/
    if(!sync_auto_group)
    {
        if(index == -1)
        {
            if(free_index == -1)
            {
                if(sync_debug)
                    printk("%s AP table full!\n",__func__);
                return index;
            }
            index = free_index;        
            if(sync_debug)
                printk("Create new ap[%s] index %d!\n",ether_sprintf(base_mac),index);        
            ap_list[index].use = 1;
            memcpy(ap_list[index].ap_base_mac,base_mac,6);
        }
    }
    return index;
}

void delete_neighbour_user(char * data)   
{
    u_int8_t  TLV_HEAD_LEN = sizeof(struct SYNC_TLV) - sizeof(char *); //without VALUE
    u_int8_t  USER_INFO_LEN = sizeof(struct sync_userinfo_table_tlv);
    u_int16_t user_cnt = 0;
    int16_t pkt_payload_len = 0;
    int ap_index = -1;
    //u_int8_t base_mac[6] = {0x00,0x1f,0x64,0x11,0x22,0x33};	 
    struct ether_header * eh = (struct ether_header *)data;
    struct SYNC_TLV * tlv = (struct SYNC_TLV *)(data + sizeof(struct ether_header));
    struct sync_userinfo_table_tlv * p_station = (struct sync_userinfo_table_tlv *)&(tlv->value);
    struct sync_userinfo_table * user = NULL;	
    struct userinfo_table * local_user = NULL;
    unsigned long irq_lock_flags;
    
    /*If auto group switch is close and packet group id not equel my group id, ignore it!*/
    if(!sync_auto_group)
    {
        if(tlv->group_id != sync_group_id)
        {
           return;
        }
    }

    pkt_payload_len = tlv->len - TLV_HEAD_LEN;

    ap_index = find_neighbour_ap(eh->ether_shost);
    if(ap_index == -1)
    {
        if(sync_debug)
            printk("%s Can't found neighbour ap in ap_list! base_mac[%s]\n",__func__,ether_sprintf(eh->ether_shost));
        return;
    }
    while(1)
    {
        user = find_neighbour_user(ap_index,p_station->sta_mac);		
        if(user != NULL)
        {
            if(sync_debug)
                printk("%s del neighbour sta mac[%s]\n",__func__,ether_sprintf(user->sta_mac));
            spin_lock_irqsave(&(user->sync_userinfo_lock), irq_lock_flags);	
            local_user = find_local_user(user->sta_mac);
            if(local_user != NULL)
            {
                TAILQ_REMOVE(&(local_user->user_list_head), user, user_list_hash);			
            }
            TAILQ_REMOVE(&(ap_list[ap_index].sync_user_info[user->index]), user, sync_userinfo_hash);				
            spin_unlock_irqrestore(&(user->sync_userinfo_lock), irq_lock_flags);
            kfree(user);
        }
        //update_user_info(eh->ether_shost,p_station);
        if(pkt_payload_len <= 0)
        	break;
        pkt_payload_len -= USER_INFO_LEN;
        p_station = (struct sync_userinfo_table_tlv *)(data + (sizeof(struct ether_header) + TLV_HEAD_LEN + (USER_INFO_LEN * user_cnt)));
    }
    return;

}

u_int32_t calc_update_time(u_int32_t prev_time)
{
    u_int32_t cur_time = jiffies_to_msecs(jiffies);
    u_int32_t overturn = -1;
    if(cur_time >= prev_time)
    {
        return (cur_time - prev_time);
    }
    else
    {
        return (overturn - prev_time) + cur_time;
    }
}

u_int16_t show_local_table(u_int8_t *data)
{
    //int count = 0;
    int i = 0;
    //int dev_index = 0;
    u_int16_t hash_cnt = 0;
    u_int16_t len = 0;    
    //u_int8_t NULL_MAC[6] = {0};  
    char *cp = data;
    u_int16_t *tmp_cp = NULL;
    struct userinfo_table * user = NULL;
    struct userinfo_table_record user_info;

    if(data == NULL)
    {
        return 0;
    }

#if 0
    /* copy base mac addr */
    memcpy(cp,own_base_mac,IEEE80211_ADDR_LEN);
    cp += IEEE80211_ADDR_LEN;
    len += IEEE80211_ADDR_LEN;

    printk("ownmac:%s len:%d\n",ether_sprintf(own_base_mac),len);
    
    /* copy vap count and mac addr */
    tmp_cp = cp;
    cp += sizeof(char);
    len += sizeof(char);
    for(dev_index = 0; dev_index < MAX_DEV; dev_index++)
    {
        if(memcmp(own_vaps[dev_index].dev_mac, NULL_MAC, 6) == 0)
        {        
            continue;
        }
        memcpy(cp,own_vaps[dev_index].dev_mac,IEEE80211_ADDR_LEN);
        cp += IEEE80211_ADDR_LEN;
        len += IEEE80211_ADDR_LEN;
        count ++;
        printk("vapsmac:%s len:%d\n",ether_sprintf(own_vaps),len);
    }
    (*tmp_cp) = count;

    printk("count:%d len:%d\n",count,len);
#endif

    /* copy user info */
    tmp_cp = (u_int16_t *)cp;
    cp += sizeof(u_int16_t);
    len += sizeof(u_int16_t);
    for(i = 0; i < MAX_USERINFO_HASH; i++)
    {
        TAILQ_FOREACH(user, &(local_user_info[i]), userinfo_hash) 
        {
            memset(&user_info,0,sizeof(struct userinfo_table_record));
            memcpy(&(user_info.user_mac),user->user_mac,IEEE80211_ADDR_LEN);
            user_info.user_cap = user->user_cap;
            user_info.identify = user->identify;
            user_info.identify_count = user->identify_count;
            user_info.recv_probe_2g = user->recv_probe_2g;
            user_info.recv_auth_2g = user->recv_auth_2g;
            user_info.recv_probe_5g = user->recv_probe_5g;
            user_info.recv_auth_5g = user->recv_auth_5g;
            user_info.avg_mgmt_rssi = user->avg_mgmt_rssi;
            user_info.avg_data_rssi = user->avg_data_rssi;
            user_info.assoc = user->assoc;
            user_info.assoc_cnt = user->assoc_cnt;
            user_info.stamp_time = user->stamp_time;
            user_info.inact = 1;
            
            if(calc_update_time(user->stamp_time) > inactive_time)
            {
                user_info.inact = 0;
            }
            
            memcpy(cp,&user_info,sizeof(struct userinfo_table_record));

            cp += sizeof(struct userinfo_table_record);
            len += sizeof(struct userinfo_table_record);
            hash_cnt ++;

            if(len > (MAX_BUF - sizeof(struct userinfo_table_record)))
            {
                (*tmp_cp) = hash_cnt;
                return len;
            }
        }
    }

    (*tmp_cp) = hash_cnt;
    return len;
}

u_int16_t show_neighbour_dev(u_int8_t *data)
{
    int i = 0,j = 0;
    u_int8_t dev_cnt = 0,vap_cnt = 0;
    u_int16_t len = 0;    
    u_int8_t NULL_MAC[6] = {0};  
    char *cp = data;
    u_int8_t *ap_count = NULL, *vap_count = NULL;
    struct sync_dev_info dev_info;

    if(data == NULL)
    {
        return 0;
    }

    ap_count = (u_int8_t *)data;
    cp += sizeof(u_int8_t);
    len += sizeof(u_int8_t);

    for(i = 0; i < MAX_NEIGHBOUR_AP; i++)
    {
        if(ap_list[i].use == 0)
        {
            continue;
        }

        memcpy(cp,ap_list[i].ap_base_mac,IEEE80211_ADDR_LEN);
        cp += IEEE80211_ADDR_LEN;
        len += IEEE80211_ADDR_LEN;
        vap_count = (u_int8_t *)cp;
        cp += sizeof(u_int8_t);
        len += sizeof(u_int8_t);
        dev_cnt++;
        vap_cnt = 0;
        for(j = 0; j < MAX_DEV; j++)
        {
            if(memcmp(ap_list[i].vaps[j].dev_mac, NULL_MAC, 6) == 0)
            {        
                continue;
            }

            memset(&dev_info,0,sizeof(struct sync_dev_info));
            memcpy(&dev_info.dev_mac,ap_list[i].vaps[j].dev_mac,IEEE80211_ADDR_LEN);
            memcpy(&dev_info.essid,ap_list[i].vaps[j].essid,32);
            dev_info.work_mode = ap_list[i].vaps[j].work_mode;
            dev_info.is_up = ap_list[i].vaps[j].is_up;
            dev_info.channel = ap_list[i].vaps[j].channel;
            dev_info.txpower = ap_list[i].vaps[j].txpower;
            dev_info.user_cnt = ap_list[i].vaps[j].user_cnt;

            memcpy(cp,&dev_info,sizeof(struct sync_dev_info));
            cp += sizeof(struct sync_dev_info);
            vap_cnt++;
            len += sizeof(struct sync_dev_info);            

            if(len > (MAX_BUF - sizeof(struct sync_dev_info)))
            {
                (*vap_count) = vap_cnt;
                (*ap_count) = dev_cnt;
                return len;
            }
        }

        (*vap_count) = vap_cnt;

        if(len > (MAX_BUF - IEEE80211_ADDR_LEN - sizeof(struct sync_dev_info) - sizeof(u_int8_t)))
        {
            (*vap_count) = vap_cnt;
            (*ap_count) = dev_cnt;
            return len;
        }
    }

    (*ap_count) = dev_cnt;
    
    return len;

}

u_int16_t show_neighbour_user_by_mac(char *data,char *mac)
{
    int i;
    unsigned int len = 0;
    u_int8_t *ap_count = NULL;
    char *cp = data;
    struct userinfo_table * user = NULL;   	 
    struct sync_userinfo_table * sync_user = NULL;
    struct userinfo_table_record user_info;

    user = find_local_user(mac);
    if(user == NULL)
    {
        (*cp) = 0;
        return len;
    }

    memset(&user_info,0,sizeof(struct userinfo_table_record));
    
    memcpy(&(user_info.user_mac),user->user_mac,IEEE80211_ADDR_LEN);
    user_info.user_cap = user->user_cap;
    user_info.identify = user->identify;
    user_info.identify_count = user->identify_count;
    user_info.recv_probe_2g = user->recv_probe_2g;
    user_info.recv_auth_2g = user->recv_auth_2g;
    user_info.recv_probe_5g = user->recv_probe_5g;
    user_info.recv_auth_5g = user->recv_auth_5g;
    user_info.avg_mgmt_rssi = user->avg_mgmt_rssi;
    user_info.avg_data_rssi = user->avg_data_rssi;
    user_info.assoc = user->assoc;
    user_info.assoc_cnt = user->assoc_cnt;
    user_info.stamp_time = user->stamp_time;
    user_info.inact = 1;
    
    if(calc_update_time(user->stamp_time) > inactive_time)
    {
        user_info.inact = 0;
    }
    
    memcpy(cp,&user_info,sizeof(struct userinfo_table_record));

    cp += sizeof(struct userinfo_table_record);
    len += sizeof(struct userinfo_table_record);
    ap_count = cp;
    cp += sizeof(u_int8_t);
    len += sizeof(u_int8_t);

    for(i = 0; i < MAX_NEIGHBOUR_AP; i++)
    {
        if(ap_list[i].use == 0)
        {
            continue;
        }
        sync_user = find_neighbour_user(i,mac);
        if(sync_user == NULL)
        {
            continue;
        }

        memcpy(cp,ap_list[i].ap_base_mac,IEEE80211_ADDR_LEN);

        (*ap_count) ++;
        cp += IEEE80211_ADDR_LEN;
        len += IEEE80211_ADDR_LEN;

        memset(&user_info,0,sizeof(struct userinfo_table_record));
        memcpy(&(user_info.user_mac),sync_user->sta_mac,IEEE80211_ADDR_LEN);
        user_info.user_cap = sync_user->work_cap;
        user_info.avg_mgmt_rssi = sync_user->avg_mgmt_rssi;
        user_info.avg_data_rssi = user->avg_data_rssi;
        user_info.assoc = sync_user->is_assoc;
        user_info.assoc_cnt = sync_user->assoc_cnt;
        user_info.stamp_time = sync_user->update_time;
        user_info.inact = 1;

        if(calc_update_time(sync_user->update_time) > inactive_time)
        {
            user_info.inact = 0;
        }

        memcpy(cp,&user_info,sizeof(struct userinfo_table_record));
        cp += sizeof(struct userinfo_table_record);
        len += sizeof(struct userinfo_table_record);

        if(len > (MAX_BUF - sizeof(struct userinfo_table_record) - IEEE80211_ADDR_LEN))
        {
            return len;
        }
    }
    
    return len;
}

#if 0
void show_local_table(void)
{
    int i = 0;
    int dev_index = 0;
    int hash_cnt = 0;
    u_int32_t inact_cnt = 0;    
    u_int8_t NULL_MAC[6] = {0};    
    //u_int32_t cur_time = jiffies_to_msecs(jiffies);	
    struct userinfo_table * user = NULL;
    printk("==============================================SHOW LOCAL TABLE================================================\n");
    printk("|AP BASE MAC:%s\n",ether_sprintf(own_base_mac));
    printk("|OWN_DEV-INFO:\n");
    for(dev_index = 0; dev_index < MAX_DEV; dev_index++)
    {
        if(memcmp(own_vaps[dev_index].dev_mac, NULL_MAC, 6) == 0)
        {        
            continue;
        }
        printk("|VAP(%s) ESSID(%s)\n",ether_sprintf(own_vaps[dev_index].dev_mac),own_vaps[dev_index].essid);
        printk("|MODE(%s) STATE(%s) CHANNEL(%d) TXPOWER(%d) STA_CNT(%d)\n",own_vaps[dev_index].work_mode==1?"2.4G":"5.8G",\
            own_vaps[dev_index].is_up?"UP":"DOWN",own_vaps[dev_index].channel,own_vaps[dev_index].txpower,own_vaps[dev_index].user_cnt);
    }
    printk("|\n");
    for(i = 0; i < MAX_USERINFO_HASH; i++)
    {
        hash_cnt = 0;
        TAILQ_FOREACH(user, &(local_user_info[i]), userinfo_hash) 
        {
            if(calc_update_time(user->stamp_time) > inactive_time)
            {
                inact_cnt++;
            }
            hash_cnt++;
            printk("INDEX(%d-%d)\tMAC[%s] cap=%s(0x%x)\tidentify=%d identify_count=%d 2G(pro %d, auth %d)\t5G(pro %d, auth %d)\tavg_rssi(%d)\t avg_data_rssi(%d)\tassoc(%d) assoc_cnt(%d) TIME(%d)\n",\
                i,hash_cnt,ether_sprintf(user->user_mac),get_user_cap(user->user_cap),user->user_cap,user->identify,user->identify_count,\
                user->recv_probe_2g,user->recv_auth_2g,user->recv_probe_5g,user->recv_auth_5g,user->avg_mgmt_rssi,user->avg_data_rssi,user->assoc,user->assoc_cnt,calc_update_time(user->stamp_time));
        }
    }
    printk("STATION CNT %d INACT CNT %d\n",local_userinfo_cnt,inact_cnt);
    printk("==============================================================================================================\n");
}

u_int16_t show_neighbour_dev(u_int8_t *data);
{
    int i = 0,j = 0;    
    u_int8_t NULL_MAC[6] = {0};    
    printk("============================================SHOW NEIGHBOUR DEV==============================================\n");
    printk("---LOCAL AP:\n");
    printk("|DEV-INFO:\n");      
    for(j= 0; j < MAX_DEV; j++)
    {
        if(memcmp(own_vaps[j].dev_mac, NULL_MAC, 6) == 0)
            continue;
        printk("|VAP(%s) ESSID(%s)\n",ether_sprintf(own_vaps[j].dev_mac),own_vaps[j].essid);
        printk("|MODE(%s) STATE(%s) CHANNEL(%d) TXPOWER(%d) STA_CNT(%d)\n",own_vaps[j].work_mode==1?"2.4G":"5.8G",\
            own_vaps[j].is_up?"UP":"DOWN",own_vaps[j].channel,own_vaps[j].txpower,own_vaps[j].user_cnt);
    }
    
    for(i = 0; i < MAX_NEIGHBOUR_AP; i++)
    {
        if(ap_list[i].use == 0)
        {
            continue;
        }
        printk("---NEIGHBOUR AP: %s\n",ether_sprintf(ap_list[i].ap_base_mac));
        printk("|DEV-INFO:\n");
        for(j= 0; j < MAX_DEV; j++)
        {
            if(memcmp(ap_list[i].vaps[j].dev_mac, NULL_MAC, 6) == 0)
            {        
                continue;
            }
            printk("|VAP(%s) ESSID(%s)\n",ether_sprintf(ap_list[i].vaps[j].dev_mac),ap_list[i].vaps[j].essid);
            printk("|MODE(%s) STATE(%s) CHANNEL(%d) TXPOWER(%d) STA_CNT(%d)\n",ap_list[i].vaps[j].work_mode==1?"2.4G":"5.8G",\
                ap_list[i].vaps[j].is_up?"UP":"DOWN",ap_list[i].vaps[j].channel,ap_list[i].vaps[j].txpower,ap_list[i].vaps[j].user_cnt);
        }
    }
    printk("\n==============================================================================================================\n");
}

u_int16_t show_neighbour_user_by_mac(char *data,char *mac)
{
    int i = 0;    
    struct userinfo_table * user = NULL;   	
    struct sync_userinfo_table * sync_user = NULL;   
    //u_int32_t cur_time = jiffies_to_msecs(jiffies);
    u_int8_t inact = 0;
    user = find_local_user(user_mac);
    
    printk("============================================SHOW NEIGHBOUR STA BY MAC==============================================\n");
    printk("|Local table:\n");
    if(user == NULL)
    {
        printk("|Can't found sta[%s] in local table\n",ether_sprintf(user_mac));
    }
    else
    {
        printk("|MAC[%s] cap=%s(0x%x) identify=%d identify_count=%d 2G(pro %d, auth %d)\t5G(pro %d, auth %d)\tavg_rssi(%d)\tavg_data_rssi(%d)\tassoc(%d) assoc_cnt(%d) TIME(%d)\n",ether_sprintf(user->user_mac),get_user_cap(user->user_cap),user->user_cap,user->identify,user->identify_count,
                user->recv_probe_2g,user->recv_auth_2g,user->recv_probe_5g,user->recv_auth_5g,user->avg_mgmt_rssi,user->avg_data_rssi,user->assoc,user->assoc_cnt,calc_update_time(user->stamp_time));
    }
    printk("|Neighbour table:\n");
    for(i = 0; i < MAX_NEIGHBOUR_AP; i++)
    {
        inact = 0;
        if(ap_list[i].use == 0)
        {
            continue;
        }
        sync_user = find_neighbour_user(i,user_mac);
        if(sync_user == NULL)
        {
            continue;
        }
        if(calc_update_time(sync_user->update_time) > inactive_time)
        {
            inact = 1;
        }
        printk("|INDEX(%d)\tAP[%s] ",sync_user->index,ether_sprintf(ap_list[i].ap_base_mac));
        printk("STATION[%s] \tWORK_CAP(%s)\tIS_ASSOC(%d) ASSOC_CNT(%d) AVG_RSSI(%d) UPDATE_TIME(%d) INACTIVE(%d)\n",ether_sprintf(sync_user->sta_mac),
            get_user_cap(sync_user->work_cap),sync_user->is_assoc,sync_user->assoc_cnt,sync_user->avg_mgmt_rssi,
            calc_update_time(sync_user->update_time),inact);
    }
	#if 0
	sync_user = NULL;
	printk("local link:\n");
	TAILQ_FOREACH(sync_user, &(user->user_list_head), user_list_hash) {
		if(sync_user != NULL)
		{
			if((cur_time - sync_user->update_time) > 30000)
			{
				aging = 1;
			}
			printk("|INDEX(%d)\tAP[%s] ",sync_user->index,ether_sprintf(sync_user->ap_mac));
			printk("STATION[%s] \tWORK_CAP(%s)\tIS_ASSOC(%d) ASSOC_CNT(%d) AVG_RSSI(%d) UPDATE_TIME(%d) AGING(%d)\n",ether_sprintf(sync_user->sta_mac),
				get_user_cap(sync_user->work_cap),sync_user->is_assoc,sync_user->assoc_cnt,sync_user->avg_mgmt_rssi,
				(cur_time - sync_user->update_time),aging);
		}
	}
	#endif
    printk("\n================================================================================================================\n");

}

#endif

void show_neighbour_table(void)
{
    int i,j,k;    
    u_int8_t NULL_MAC[6] = {0};    
    u_int32_t user_cnt = 0;
    //u_int32_t cur_time = jiffies_to_msecs(jiffies);	
    struct sync_userinfo_table * sync_user = NULL;   
    u_int8_t inact = 0;
    u_int32_t inact_cnt = 0;
    printk("============================================SHOW NEIGHBOUR TABLE==============================================\n");
    
    for(i = 0; i < MAX_NEIGHBOUR_AP; i++)
    {
        if(ap_list[i].use == 0)
        {
            continue;
        }
        printk("---NEIGHBOUR AP: %s\n",ether_sprintf(ap_list[i].ap_base_mac));
        printk("|DEV-INFO:\n");
        for(j= 0; j < MAX_DEV; j++)
        {
            if(memcmp(ap_list[i].vaps[j].dev_mac, NULL_MAC, 6) == 0)
            {        
                continue;
            }
            printk("|VAP(%s) ESSID(%s)\n",ether_sprintf(ap_list[i].vaps[j].dev_mac),ap_list[i].vaps[j].essid);
            printk("|MODE(%d) STATE(%s) CHANNEL(%d) TXPOWER(%d) STA_CNT(%d)\n",ap_list[i].vaps[j].work_mode,ap_list[i].vaps[j].is_up?"UP":"DOWN",
                    ap_list[i].vaps[j].channel,ap_list[i].vaps[j].txpower,ap_list[i].vaps[j].user_cnt);
        }
        printk("|\n");
        printk("|USER-INFO:\n");
        user_cnt = 0;
        inact_cnt = 0;
        for(k = 0; k < 32; k++)
        {
            TAILQ_FOREACH(sync_user, &(ap_list[i].sync_user_info[k]), sync_userinfo_hash) {				
                inact = 0;				
                if(calc_update_time(sync_user->update_time) > inactive_time)
                {
                    inact = 1;
                    inact_cnt++;
                }
                printk("|STATION(%s) INDEX(%d)\tWORK_CAP(%s)\tIS_ASSOC(%d) ASSOC_CNT(%d) AVG_RSSI(%d) UPDATE_TIME(%d) INACTIVE(%d)\n",ether_sprintf(sync_user->sta_mac),
                        sync_user->index,get_user_cap(sync_user->work_cap),sync_user->is_assoc,sync_user->assoc_cnt,sync_user->avg_mgmt_rssi,
                        calc_update_time(sync_user->update_time),inact);
                user_cnt++;
            }
        }
        printk("USER CNT %d INACT CNT %d---------------------------------------\n",user_cnt,inact_cnt);
    }
    printk("\n==============================================================================================================\n");

}


void show_scan_list(void)
{
    int i = 0;    
    u_int8_t NULL_MAC[6] = {0};
    printk("==============================================SHOW SCAN LIST================================================\n");
    
    for(i = 0; i < MAX_SCAN_LIST; i++)
    {        
        if(!IEEE80211_ADDR_EQ(scan_ap_list[i].dev_mac, NULL_MAC))
        {
            printk("AP-MAC[%s] CHANNEL[%d] RSSI[%d]\n",ether_sprintf(scan_ap_list[i].dev_mac),scan_ap_list[i].channel,scan_ap_list[i].rssi);
        }
    }

    printk("\n==========================================================================================================\n");

}

struct userinfo_table * userinfo_alloc(char * mac)
{
    struct userinfo_table * user;

    /* create a node */
    user = (struct userinfo_table *)kmalloc(sizeof(struct userinfo_table),0);
    if (user == NULL) {
        printk("Can't create an node[%s]\n",ether_sprintf(mac));
        return NULL;
    }
    memset(user,0,sizeof(struct userinfo_table));
    spin_lock_init(&(user->userinfo_lock));
    return user;
}

struct sync_userinfo_table * sync_userinfo_alloc(char * mac)
{
    struct sync_userinfo_table * user;

    /* create a node */
    user = (struct sync_userinfo_table *)kmalloc(sizeof(struct sync_userinfo_table),0);
    if (user == NULL) {
        printk("Can't create an node\n");
        return NULL;
    }
    memset(user,0,sizeof(struct sync_userinfo_table));
    spin_lock_init(&(user->sync_userinfo_lock));
    return user;
}
struct sync_userinfo_table * create_sync_user(int ap_index,char * mac)
{
    int user_hash = AT_USER_HASH(mac);	
    struct sync_userinfo_table * user;
    user = sync_userinfo_alloc(mac);
    if(user == NULL)
    {
        return NULL;
    }
    TAILQ_INSERT_HEAD(&(ap_list[ap_index].sync_user_info[user_hash]), user, sync_userinfo_hash);
    return user;
}

void update_user_cap(struct ieee80211com * ic,struct userinfo_table * user,int rssi,int type)
{
    u_int32_t time = 0;
    u_int32_t overturn = -1;
    if(user == NULL)
    {
        return;
    }
    if(IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan))
    {
        user->user_cap |= IEEE80211_TABLE_SUPPORT5G;
    }
    else if(IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
    {
        user->user_cap |= IEEE80211_TABLE_SUPPORT2G;
    }
    if(type == IEEE80211_FC0_TYPE_DATA)
    {
        
        if(user->avg_data_rssi == 0)
        {
            user->avg_data_rssi = (u_int8_t)rssi;
        }
        else
        {            
            user->avg_data_rssi = (u_int8_t)(((user->avg_data_rssi * 8) + (rssi * 2))/10);
        }
    }
    else
    {
        if(user->avg_mgmt_rssi == 0)
        {
            user->avg_mgmt_rssi = (u_int8_t)rssi;
        }
        else if(rssi != 0)
        {
            /*calc update interval*/
            if(user->stamp_time >= user->prev_stamp_time)
            {
                time = (user->stamp_time - user->prev_stamp_time);
            }
            else
            {
                time = (overturn - user->prev_stamp_time) + user->stamp_time;
            }

            /*if in inactive status reload rssi*/
            if(time > inactive_time)
            {
                user->avg_mgmt_rssi = (u_int8_t)rssi;
            }
            else
            {
                /*avg_rssi * 80% + cur_rssi * 20%*/
                user->avg_mgmt_rssi = (u_int8_t)(((user->avg_mgmt_rssi * 8) + (rssi * 2))/10);
            }

        }
    }
    user->update = 1;
}


void update_dev_info(char * base_mac, struct sync_dev_info * vap)
{
    int ap_index = -1;
    int dev_index = -1;
    if(sync_debug)
    {
        printk("---------%s\n",__func__);
        printk("---------base_mac :    %s\n",ether_sprintf(base_mac));
        printk("---------VAP mac:      %s\n",ether_sprintf(vap->dev_mac));
        printk("---------VAP ESSID:    %s\n",vap->essid);
        printk("---------VAP workmode: %d\n",vap->work_mode);
        printk("---------VAP is_up:    %d\n",vap->is_up);
        printk("---------VAP channel:  %d\n",vap->channel);
        printk("---------VAP txpower:  %d\n",vap->txpower);		
        printk("---------VAP txpower:  %d\n",vap->user_cnt);
    }
    ap_index = find_neighbour_ap(base_mac);
    if(ap_index == -1)
    {
        if(sync_auto_group)
        {
            /*Check scan list, if this dev mac exsit, create a new ap_list element*/
            if(find_scan_list(vap->dev_mac) != -1)
            {
                ap_index = create_neighbour_ap(base_mac);
                if(sync_debug)
                    printk("%s Found neighbour ap in scan_list! base_mac[%s]\n",__func__,ether_sprintf(base_mac));
            }
            else
            {
                if(sync_debug)
                    printk("%s Can't found neighbour ap in scan_list! base_mac[%s]\n",__func__,ether_sprintf(base_mac));
                return;
            }
        }
        else
        {
            if(sync_debug)
                printk("%s Can't found neighbour ap in ap_list! base_mac[%s]\n",__func__,ether_sprintf(base_mac));
            return;
        }
    }
    ap_list[ap_index].active_time = jiffies_to_msecs(jiffies);
    dev_index = find_vap_dev(ap_index,vap->dev_mac);
    if(dev_index == -1)
    {
        if(sync_debug)
            printk("%s Can't found neighbour ap[%s] vap dev[%s]!\n",__func__,ether_sprintf(base_mac),ether_sprintf(vap->dev_mac));
        return;
    }
    memcpy(ap_list[ap_index].vaps[dev_index].essid,vap->essid,32);
    ap_list[ap_index].vaps[dev_index].work_mode = vap->work_mode;
    ap_list[ap_index].vaps[dev_index].is_up = vap->is_up;
    ap_list[ap_index].vaps[dev_index].channel = vap->channel;
    ap_list[ap_index].vaps[dev_index].txpower = vap->txpower;
    ap_list[ap_index].vaps[dev_index].user_cnt= vap->user_cnt;
    return;
}

void update_own_dev_info(char * base_mac, struct sync_dev_info * vap)
{
    int dev_index = -1;    
    u_int8_t NULL_MAC[6] = {0};
    if(sync_debug)
    {
        printk("---------%s\n",__func__);
        printk("---------base_mac :    %s\n",ether_sprintf(base_mac));
        printk("---------VAP mac:      %s\n",ether_sprintf(vap->dev_mac));
        printk("---------VAP ESSID:    %s\n",vap->essid);
        printk("---------VAP workmode: %d\n",vap->work_mode);
        printk("---------VAP is_up:    %d\n",vap->is_up);
        printk("---------VAP channel:  %d\n",vap->channel);
        printk("---------VAP txpower:  %d\n",vap->txpower);
        printk("---------VAP txpower:  %d\n",vap->user_cnt);
    }
    if(memcmp(own_base_mac, NULL_MAC, 6) == 0)
    {       
        memcpy(own_base_mac,base_mac,6);
    }
    dev_index = find_own_dev(vap->dev_mac);
    if(dev_index == -1)
    {
        if(sync_debug)
            printk("%s Can't found neighbour ap[%s] dev[%s]!\n",__func__,ether_sprintf(base_mac),ether_sprintf(vap->dev_mac));
        return;
    }
    memcpy(own_vaps[dev_index].essid,vap->essid,32);
    own_vaps[dev_index].work_mode = vap->work_mode;
    own_vaps[dev_index].is_up = vap->is_up;
    own_vaps[dev_index].channel = vap->channel;
    own_vaps[dev_index].txpower = vap->txpower;
    own_vaps[dev_index].user_cnt= vap->user_cnt;
    return;
}


void update_user_info(char * base_mac, struct sync_userinfo_table_tlv *user)
{
    int ap_index = -1;
    int user_index = user->index;
    int new = 0;
    struct sync_userinfo_table * sync_user = NULL;
    struct userinfo_table * local_user = NULL;
    if(sync_debug)
    {
        printk("---------%s\n",__func__);
        printk("---------base_mac :   %s\n",ether_sprintf(base_mac));
        printk("---------sta index:   %d\n",user->index);
        printk("---------sta mac:     %s\n",ether_sprintf(user->sta_mac));
        printk("---------sta workcap: %x\n",user->work_cap);
        printk("---------sta is_asso: %d\n",user->is_assoc);
        printk("---------sta avgrssi: %d\n",user->avg_mgmt_rssi);      
        printk("---------sta assoc_cnt: %d\n",user->assoc_cnt);
    }
    ap_index = find_neighbour_ap(base_mac);
    if(ap_index == -1)
    {
        if(sync_debug)
            printk("%s Can't found neighbour ap in ap_list! base_mac[%s]\n",__func__,ether_sprintf(base_mac));
        return;
    }
    sync_user = find_neighbour_user(ap_index,user->sta_mac);
    if(sync_user == NULL)
    {
        sync_user = create_sync_user(ap_index,user->sta_mac);
        new = 1;
    }
    if(sync_user == NULL)
        return;
    if(new)
    {
        local_user = find_local_user(user->sta_mac);
        if(local_user != NULL)
        {
            TAILQ_INSERT_HEAD(&(local_user->user_list_head), sync_user, user_list_hash);			
        }
    }
    ap_list[ap_index].active_time = jiffies_to_msecs(jiffies);
    sync_user->index = user_index;
    memcpy(sync_user->sta_mac,user->sta_mac,6);	
    memcpy(sync_user->ap_mac,base_mac,6);
    sync_user->work_cap = user->work_cap;
    sync_user->is_assoc = user->is_assoc;
    sync_user->assoc_cnt= user->assoc_cnt;
    sync_user->avg_mgmt_rssi = user->avg_mgmt_rssi;
    sync_user->update_time = jiffies_to_msecs(jiffies);
    return;

}

void sync_clean_table(char * base_mac)
{
    int i = 0;
    int ap_index;	
    struct userinfo_table * local_user = NULL;
    struct sync_userinfo_table * user = NULL;
    struct sync_userinfo_table * user_next = NULL;
    ap_index = find_neighbour_ap(base_mac);
    if(ap_index == -1)
    {
        return;
    }
    ap_list[ap_index].use = 0;
    ap_list[ap_index].active_time = 0;
    memset(ap_list[ap_index].ap_base_mac,0,6);
    memset(ap_list[ap_index].vaps,0,sizeof(ap_list[ap_index].vaps));
    memset(ap_list[ap_index].stations,0,sizeof(ap_list[ap_index].stations));
    for(i = 0; i < MAX_USERINFO_HASH; i++)
    {
        TAILQ_FOREACH_SAFE(user, &(ap_list[ap_index].sync_user_info[i]), sync_userinfo_hash,user_next)
        {
            local_user = find_local_user(user->sta_mac);
            if(local_user != NULL)
            {
                TAILQ_REMOVE(&(local_user->user_list_head), user, user_list_hash);
            }
            TAILQ_REMOVE(&(ap_list[ap_index].sync_user_info[i]), user, sync_userinfo_hash);
            kfree(user);
        }
    }
}


void local_table_aging(void)
{
    int i = 0;	
    int hash_cnt = 0;	
    //u_int32_t cur_time = jiffies_to_msecs(jiffies);
    struct userinfo_table * user = NULL;
    struct userinfo_table * user_next = NULL;
    
    for(i = 0; i < MAX_USERINFO_HASH; i++)
    {
        hash_cnt = 0;
        TAILQ_FOREACH_SAFE(user, &(local_user_info[i]), userinfo_hash,user_next) 
        {
            if(user->avg_mgmt_rssi > 10)
                continue;
            
            if(calc_update_time(user->stamp_time) >= agingtime_thr)
            {
                TAILQ_REMOVE(&(local_user_info[i]), user, userinfo_hash);
                send_sync_info_single(user,SYNC_DELETE_INFO);
                kfree(user);
                local_userinfo_cnt--;
            }
        }
    }
}

void neighbour_table_aging(void)
{
    int i = 0;
    int ap_index = 0;
    int hash_cnt = 0;	
    //u_int32_t cur_time = jiffies_to_msecs(jiffies);
    struct sync_userinfo_table * user = NULL;    
    struct sync_userinfo_table * user_next = NULL;
    struct userinfo_table * local_user = NULL;
    for(ap_index = 0; ap_index < 32; ap_index++)
    {
        for(i = 0; i < MAX_USERINFO_HASH; i++)
        {
            hash_cnt = 0;
            TAILQ_FOREACH_SAFE(user, &(ap_list[ap_index].sync_user_info[i]), sync_userinfo_hash,user_next) {
                if(calc_update_time(user->update_time) >= inactive_time){
                    local_user = find_local_user(user->sta_mac);
                    if(local_user != NULL)
                    {
                        TAILQ_REMOVE(&(local_user->user_list_head), user, user_list_hash);
                    }
                    TAILQ_REMOVE(&(ap_list[ap_index].sync_user_info[i]), user, sync_userinfo_hash);
                    kfree(user);
                }
            }
        }
    }
}

void neighbour_ap_aging(void)
{
    int ap_index = 0;
    //u_int32_t cur_time = jiffies_to_msecs(jiffies);
    for(ap_index = 0; ap_index < MAX_NEIGHBOUR_AP; ap_index++)
    {
        if(ap_list[ap_index].use == 0)
            continue;
        if(calc_update_time(ap_list[ap_index].active_time) > 20000)
        {
            if(sync_debug)
                printk("%s neighbour ap[%s] aging!\n",__func__,ether_sprintf(ap_list[ap_index].ap_base_mac));
            sync_clean_table(ap_list[ap_index].ap_base_mac);
        }
    }
}


