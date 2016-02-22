/************************************************************
Copyright (C), 2006-2013, AUTELAN. Co., Ltd.
FileName: at_connect_ctl.c
Author:Mingzhe Duan 
Version : 1.0
Date:2015-02-03
Description: This file include 5G first,Connect to the beast and User balance
***********************************************************/

#include <ieee80211_var.h>
#include <ath_internal.h>
#include <if_athvar.h>
#include <osif_private.h>
#include "at_connect_ctl.h"
#include "at_sync_info.h"
#define PROCESS 0
#define NOPROCESS 1
#define CONN_DENY 0
#define CONN_ALLOW 1

int max_dv = 3;
int inactive_time = 300000;
int wating_time = 1000;
EXPORT_SYMBOL(wating_time);
int connect_to_best_swith = 1;
EXPORT_SYMBOL(connect_to_best_swith);
int connect_to_best_debug = 0;
EXPORT_SYMBOL(connect_to_best_debug);
int connect_balance_swith = 1;
EXPORT_SYMBOL(connect_balance_swith);

extern TAILQ_HEAD(,userinfo_table) local_user_info[];

void set_connect_to_best(int value)
{
    connect_to_best_swith = value;
}

int get_connect_to_best(void)
{
    return connect_to_best_swith;
}

void set_max_dv(int value)
{
    max_dv = value;
}

int get_max_dv(void)
{
    return max_dv;
}

void set_inactive_time(int value)
{
    inactive_time = value;
}

int get_inactive_time(void)
{
    return inactive_time;
}

void set_wating_time(int value)
{
    wating_time = value;
}

int get_wating_time(void)
{
    return wating_time;
}

void set_connect_to_best_debug(int value)
{
    connect_to_best_debug= value;
}

int get_connect_to_best_debug(void)
{
    return connect_to_best_debug;
}

void set_connect_balance(int value)
{
    connect_balance_swith = value;
}

int get_connect_balance(void)
{
    return connect_balance_swith;
}




int join5g(struct ieee80211com *ic, struct ieee80211vap *vap,struct ieee80211_node * ni, wbuf_t wbuf, struct userinfo_table * user)
{
    int subtype;
    struct ieee80211_frame *wh;
    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    if(user == NULL)
    {
	#if ATOPT_MGMT_DEBUG	
    IEEE80211_NOTE_MGMT_DEBUG(vap, ni, "=====5G Priority: Can't found this station %s.\n",ether_sprintf(wh->i_addr2));		
	#endif
    return 0;
    }
    if(join5g_enable && (IEEE80211_FC0_SUBTYPE_PROBE_REQ == subtype || IEEE80211_FC0_SUBTYPE_AUTH == subtype))
    {
        if(join5g_debug)
        {
            printk("=====5G Priority: Sta[%s]AVG_RSSI: %d, RECV-DEV: %s, SUBTYPE: %s\n",
            ether_sprintf(wh->i_addr2), user->avg_mgmt_rssi,
            IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan)?"5.8G":"2.4G",(IEEE80211_FC0_SUBTYPE_PROBE_REQ == subtype)?"PROBE_REQ":"AUTH");
        }

        if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
        {
			#if ATOPT_MGMT_DEBUG
            IEEE80211_NOTE_MGMT_DEBUG(vap, ni, "=====5G Priority: Sta[%s] AVG_RSSI: %d, RECV-DEV: %s, SUBTYPE: %s\n",
            ether_sprintf(wh->i_addr2), user->avg_mgmt_rssi, 
            IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan)?"5.8G":"2.4G",(IEEE80211_FC0_SUBTYPE_PROBE_REQ == subtype)?"PROBE_REQ":"AUTH");
			#endif
        }

        if(IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan) ||  IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) 
        {
            struct net_device *tmp_dev = NULL;
            if(join5g_debug && IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
            {
                printk("=====5G Priority: 2.4G signal is enough!\r\n");
            }

            if (memcmp(ic->ic_osdev->netdev->name, "wifi0", 5) == 0) 
            {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,22)
                tmp_dev = dev_get_by_name("wifi1");
#else
                tmp_dev = dev_get_by_name(&init_net,"wifi1");
#endif
            }
            else if (memcmp(ic->ic_osdev->netdev->name, "wifi1", 5) == 0)
            {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,22)
                tmp_dev = dev_get_by_name("wifi0");
#else
                tmp_dev = dev_get_by_name(&init_net,"wifi0");
#endif
            }

            if (tmp_dev)
            { 
                unsigned long irq_lock_flags;  /* Temp variable, used for irq lock/unlock parameter. wangjia 2012-10-11 */
                struct ieee80211vap  *vap_tmp = NULL;
                struct ieee80211com  *ic_tmp = (struct ieee80211com *)ath_netdev_priv(tmp_dev); 

                if (ic_tmp)
                {
                /* Begin, Add for the judgement of 5G priority sta threshold. wangjia 2012-10-11 */
                    if((IEEE80211_IS_CHAN_5GHZ(ic_tmp->ic_curchan) && (ic_tmp->ic_sta_assoc < stacount_thr)) ||
                    (IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan) && (ic->ic_sta_assoc < stacount_thr)))
                    {
                            /* End, Add for the judgement of 5G priority sta threshold. wangjia 2012-10-11 */
                        TAILQ_FOREACH(vap_tmp, &ic_tmp->ic_vaps, iv_next)
                        if((vap_tmp->iv_bss->ni_esslen == vap->iv_bss->ni_esslen) &&
                        (memcmp(vap_tmp->iv_bss->ni_essid, vap->iv_bss->ni_essid, vap->iv_bss->ni_esslen) == 0))
                        {
                            u_int32_t current_time;

                            if(subtype == IEEE80211_FC0_SUBTYPE_PROBE_REQ)
                            {
                                current_time = jiffies_to_msecs(jiffies);
                                if(IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
                                {
                                    if(user->identify == 0)
                                    {
                                        /*scantime_thr is identify time. station can be allowed to connect,when satisfied the rule*/
                                        if(current_time - user->stamp_time <= scantime_thr) 
                                        {
                                            /*spin_lock_irqsave/spin_unlock_irqrestore. wangjia 2012-10-11 */ 
                                            spin_lock_irqsave(&(user->userinfo_lock), irq_lock_flags);
                                            user->user_cap |= IEEE80211_TABLE_SUPPORT2G;// set the 2g flag
                                            user->identify_count ++;
                                            if(join5g_debug > 1)
                                            {
                                                printk("=====5G Priority: Sta[%s] drop frame,total is %d\n",
                                                ether_sprintf(wh->i_addr2), user->identify_count);
                                            }
                                            if(user->identify_count >= discard_count)
                                            {
                                                if(join5g_debug > 1)
                                                {
                                                    printk("=====5G Priority: Sta[%s] identify_count(%d) > discard_count(2) identify finish\n",
                                                    ether_sprintf(wh->i_addr2), user->identify_count);
                                                }
                                                user->identify = 1;
                                            }
                                            spin_unlock_irqrestore(&(user->userinfo_lock), irq_lock_flags);
                                            dev_put(tmp_dev); /* Release reference to device. wangjia 2012-10-11 */
                                            return 0;
                                        }
                                        else
                                        {
                                            if(join5g_debug > 1)
                                            {
                                                printk("=====5G Priority: Sta[%s] identify time(%d) > scantime_thr(%d) recounting\n",
                                                ether_sprintf(wh->i_addr2), (current_time - user->stamp_time),scantime_thr);
                                            }
                                            
                                            spin_lock_irqsave(&(user->userinfo_lock), irq_lock_flags);
                                            user->user_cap &= ~(IEEE80211_TABLE_SUPPORT2G | IEEE80211_TABLE_SUPPORT5G);
                                            user->user_cap |= IEEE80211_TABLE_SUPPORT2G;// set the 2g flag
                                            user->identify = 0;
                                            user->identify_count = 0;
                                            spin_unlock_irqrestore(&(user->userinfo_lock), irq_lock_flags);
                                            dev_put(tmp_dev);
                                            return 0;
                                        }
                                    }
                                    else
                                    {
                                        if(user->user_cap & IEEE80211_TABLE_SUPPORT5G)
                                        {
                                            if(join5g_debug > 1)
                                            {
                                                printk("=====5G Priority: Sta[%s] support 5G,drop 2G probe request frame\n",
                                                ether_sprintf(wh->i_addr2));
                                            }
                                            user->user_cap |= IEEE80211_TABLE_SUPPORT2G;
                                            //user->identify = 0;
                                            //user->identify_count = 0;
                                            dev_put(tmp_dev);
                                            return 0;
                                        }
                                        
                                        if(join5g_debug > 1)
                                        {
                                            printk("=====5G Priority: Sta[%s] identify finish,but recv 2G probe req\n",
                                            ether_sprintf(wh->i_addr2),user->identify_count);
                                        }
                                    }
                                }
                                else if(IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan))
                                {
                                    /**
                                                            *spin_lock_irqsave/spin_unlock_irqrestore. wangjia 2012-10-11 
                                                            */ 
                                    spin_lock_irqsave(&(user->userinfo_lock), irq_lock_flags);
                                    user->user_cap |= IEEE80211_TABLE_SUPPORT5G;// set the 5g flag	
                                    user->identify =1;
                                    spin_unlock_irqrestore(&(user->userinfo_lock), irq_lock_flags);
                                }
                            }
                            else if(subtype == IEEE80211_FC0_SUBTYPE_AUTH)	
                            {
                                if(!IEEE80211_ADDR_EQ(((struct ieee80211_frame *)wh)->i_addr1, vap->iv_myaddr) ||  \
                                !IEEE80211_ADDR_EQ(((struct ieee80211_frame *)wh)->i_addr3, (ni)->ni_bssid))
                                {

                                    //IEEE80211_NOTE_MGMT_DEBUG(vap, ni, "=====5G Priority: Recv AUTH, this AUTH is not for me ,mask(%d) count(%d) 2G(pro %d, auth %d) 5G(pro %d, auth %d) CAP = %s\n",
                                    //userinfo_table_t[sta_index].marked,userinfo_table_t[sta_index].count,userinfo_table_t[sta_index].recv_probe_2g,userinfo_table_t[sta_index].recv_auth_2g,userinfo_table_t[sta_index].recv_probe_5g,userinfo_table_t[sta_index].recv_auth_5g,get_user_cap(userinfo_table_t[sta_index].user_cap));
                                    dev_put(tmp_dev);
                                    return 0;
                                }
                                if(user != NULL)
                                {
                                    if(IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
                                    {
                                        //user->recv_auth_2g++;
                                        if(user->identify == 0)
                                        {
											#if ATOPT_MGMT_DEBUG
                                            IEEE80211_NOTE_MGMT_DEBUG(vap, ni, "=====5G Priority: Recv AUTH, but identify did't finish,identify(%d) identify_count(%d) 2G(pro %d, auth %d) 5G(pro %d, auth %d) CAP = %s\n",
                                            user->identify,user->identify_count,user->recv_probe_2g,user->recv_auth_2g,user->recv_probe_5g,user->recv_auth_5g,get_user_cap(user->user_cap));
											#endif
                                            if(join5g_debug)
                                            {
                                                printk("=====5G Priority: Sta[%s] recv AUTH, but identify did't finish,identify(%d) identify_count(%d) 2G(pro %d, auth %d) 5G(pro %d, auth %d) CAP = %s\n",
                                                ether_sprintf(wh->i_addr2),user->identify,user->identify_count,user->recv_probe_2g,user->recv_auth_2g,user->recv_probe_5g,user->recv_auth_5g,get_user_cap(user->user_cap));
                                            }
                                            dev_put(tmp_dev);
                                            return 0;
                                        }
                                        else
                                        {
                                            if(user->user_cap & IEEE80211_TABLE_SUPPORT5G)
                                            { 
												#if ATOPT_MGMT_DEBUG
                                                IEEE80211_NOTE_MGMT_DEBUG(vap, ni, "=====5G Priority: Recv AUTH in 2G,but this station support 5G,identify(%d) identify_count(%d) 2G(pro %d, auth %d) 5G(pro %d, auth %d) allow_2g(%d), drop this frame, CAP = %s\n",
                                                user->identify,user->identify_count,user->recv_probe_2g,user->recv_auth_2g,user->recv_probe_5g,user->recv_auth_5g,
                                                user->allow_2g,get_user_cap(user->user_cap));
												#endif
                                                user->allow_2g++;
                                                if(user->allow_2g < 3)
                                                {
                                                    if(join5g_debug)
                                                    {
                                                        printk("=====5G Priority: Sta[%s] Recv AUTH in 2G,but this station support 5G,identify(%d) identify_count(%d) 2G(pro %d, auth %d) 5G(pro %d, auth %d) allow_2g(%d), drop this frame, CAP = %s\n",
                                                        ether_sprintf(wh->i_addr2),user->identify,user->identify_count,user->recv_probe_2g,user->recv_auth_2g,user->recv_probe_5g,user->recv_auth_5g,user->allow_2g,get_user_cap(user->user_cap));
                                                    }
                                                    dev_put(tmp_dev);
                                                    return 0;
                                                }
                                                else
                                                {
                                                    if(join5g_debug)
                                                    {
                                                        printk("=====5G Priority: Sta[%s] Recv AUTH in 2G,drop this frame (%d) > (%d) ALLOW ACCESS 2G\n",
                                                        ether_sprintf(wh->i_addr2),user->allow_2g,discard_count);
                                                    }
                                                    user->allow_2g = 0;
                                                }
                                            }
                                            else
                                            {
												#if ATOPT_MGMT_DEBUG
                                                IEEE80211_NOTE_MGMT_DEBUG(vap, ni, "=====5G Priority: Recv AUTH in 2G,identify(%d) identify_count(%d) 2G(pro %d, auth %d) 5G(pro %d, auth %d) allow_2g(%d), allow access, CAP = %s\n",
                                                user->identify,user->identify_count,user->recv_probe_2g,user->recv_auth_2g,user->recv_probe_5g,user->recv_auth_5g,
                                                user->allow_2g,get_user_cap(user->user_cap));
												#endif
                                                if(join5g_debug)
                                                {
                                                    printk("=====5G Priority: Sta[%s] Recv AUTH in 2G channel,identify(%d) identify_count(%d) 2G(pro %d, auth %d) 5G(pro %d, auth %d) allow_2g(%d), allow access, CAP = %s\n",
                                                    ether_sprintf(wh->i_addr2),user->identify,user->identify_count,user->recv_probe_2g,user->recv_auth_2g,user->recv_probe_5g,user->recv_auth_5g,user->allow_2g,get_user_cap(user->user_cap));
                                                }
                                            }
                                        }
                                    }
                                    else
                                    {
										#if ATOPT_MGMT_DEBUG
                                        IEEE80211_NOTE_MGMT_DEBUG(vap, ni, "=====5G Priority: Recv AUTH in 5G, 2G(pro %d, auth %d) 5G(pro %d, auth %d),allow access, CAP = %s\n",
                                        user->recv_probe_2g,user->recv_auth_2g,user->recv_probe_5g,user->recv_auth_5g,get_user_cap(user->user_cap));																										
										#endif
                                        if(join5g_debug)
                                        {
                                            printk("=====5G Priority: Sta[%s] Recv AUTH in 5G channel, 2G(pro %d, auth %d) 5G(pro %d, auth %d),allow access, CAP = %s\n",
                                            ether_sprintf(wh->i_addr2),user->recv_probe_2g,user->recv_auth_2g,user->recv_probe_5g,user->recv_auth_5g,get_user_cap(user->user_cap));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else
                    {

                        if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
                        {
                            if(IEEE80211_IS_CHAN_5GHZ(ic_tmp->ic_curchan) && (ic_tmp->ic_sta_assoc < stacount_thr))
                            {
                                TAILQ_FOREACH(vap_tmp, &ic_tmp->ic_vaps, iv_next)
                                if((vap_tmp->iv_bss->ni_esslen == vap->iv_bss->ni_esslen) &&
                                (memcmp(vap_tmp->iv_bss->ni_essid, vap->iv_bss->ni_essid, vap->iv_bss->ni_esslen) == 0))
                                {
									#if ATOPT_MGMT_DEBUG
                                    IEEE80211_NOTE_MGMT_DEBUG(vap_tmp, ni, "=====5G Priority: sta_assoc_count %d , allow access!\n",ic_tmp->ic_sta_assoc);
									#endif
                                    if(join5g_debug)
                                    {
                                        printk("=====5G Priority: Sta[%s] sta_assoc_count %d , allow access!\n",
                                        ether_sprintf(wh->i_addr2),ic_tmp->ic_sta_assoc);
                                    }
                                }
                            }

                            if(IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan) && (ic->ic_sta_assoc < stacount_thr))
                            {
								#if ATOPT_MGMT_DEBUG
                                IEEE80211_NOTE_MGMT_DEBUG(vap, ni, "=====5G Priority: sta_assoc_count %d , allow access!\n",ic->ic_sta_assoc);
								#endif
                                if(join5g_debug)
                                {
                                    printk("=====5G Priority: Sta[%s] sta_assoc_count %d , allow access!\n",
                                    ether_sprintf(wh->i_addr2),ic->ic_sta_assoc);
                                }
                            }
                        }
                    }
                }	
                dev_put(tmp_dev); /* Release reference to device. wangjia 2012-10-11 */
            }
        }
        else if(join5g_debug)
        {
            printk("2.4G signal is NOT enough!\r\n");
        }
    }
    return 1;
}


/*Check the probe frame is unicast?*/
int check_probe(struct ieee80211_node *ni, wbuf_t wbuf, int subtype)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;
    u_int8_t *ssid;

#if ATH_SUPPORT_AP_WDS_COMBO
    if (vap->iv_opmode == IEEE80211_M_STA || !ieee80211_vap_ready_is_set(vap) || vap->iv_no_beacon)
#else
    if (vap->iv_opmode == IEEE80211_M_STA || !ieee80211_vap_ready_is_set(vap))
#endif
    {
        return NOPROCESS;
    }

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    if (IEEE80211_IS_MULTICAST(wh->i_addr2)) {
        /* frame must be directed */
        return NOPROCESS;
    }

    /*
     * prreq frame format
     *  [tlv] ssid
     */
    ssid = NULL;
    while (((frm+1) < efrm) && (frm + frm[1] + 1 < efrm)) {
        switch (*frm) {
        case IEEE80211_ELEMID_SSID:
            ssid = frm;
            /*If IE ssid len is not zero, this is a unicase probe*/
            if (*(ssid+1) != 0) {
                return PROCESS;
            }
            break;
        }
        frm += frm[1] + 2;
    }
    return NOPROCESS;

}

int check_best_rssi(int my_rssi,u_int32_t my_assoc_cnt,int other_rssi,u_int32_t other_assoc_cnt,u_int32_t local_vap_user_cnt, u_int32_t neighbor_vap_user_cnt,int subtype)
{
    int dv = my_rssi - other_rssi;

    /*Claculation rssi difference value between my_rssi and other AP's rssi */
    if((-max_dv <= dv) && (dv <= max_dv))
    {
    
        /*If balance switch is open*/
        if(connect_balance_swith)
        {
        
            /*If other ap user cnt > local cnt, guiding station connect to other ap*/
            if(other_assoc_cnt > my_assoc_cnt)
            {
            
                if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
                {
                    if(connect_to_best_debug){
                        printk("%s my_assoc_cnt(%d) < other_assoc_cnt(%d) DENY\n",__func__,my_assoc_cnt,other_assoc_cnt);
                    }
                }
                return CONN_DENY;
            }
            else if(other_assoc_cnt < my_assoc_cnt)
            {

                /*If this station connnect to other AP times less than local, allow connect*/
                if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
                {
                    if(connect_to_best_debug){
                        printk("%s my_assoc_cnt(%d) > other_assoc_cnt(%d) ALLOW\n",__func__,my_assoc_cnt,other_assoc_cnt);
                    }
                }
                return CONN_ALLOW;
            }
            /*When other_assoc_cnt == my_assoc_cnt trigger connect balance*/
            if(local_vap_user_cnt > neighbor_vap_user_cnt)
            {
            
                if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
                {
                    if(connect_to_best_debug){
                        printk("%s Connect balance:local_vap_user_cnt(%d) > neighbor_vap_user_cnt(%d) DENY\n",__func__,local_vap_user_cnt,neighbor_vap_user_cnt);
                    }
                }
                return CONN_DENY;
            }
            else
            {
                if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
                {
                    if(connect_to_best_debug){
                        printk("%s Connect balance:local_vap_user_cnt(%d) < neighbor_vap_user_cnt(%d) ALLOW\n",__func__,local_vap_user_cnt,neighbor_vap_user_cnt);
                    }
                }
            }
        }
        else
        {
            /*If balance switch is CLOSE and this station connnect to other AP 
                       times greater than local,guiding station connect to other ap*/
            if(other_assoc_cnt > my_assoc_cnt)
            {
                return CONN_DENY;
            }
        }
    }
    else
    {
        if(other_rssi > my_rssi)
        {
            if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
            {
                if(connect_to_best_debug)
                    printk("%s my_rssi(%d) < other_rssi(%d) DENY\n",__func__,my_rssi,other_rssi);
            }
            return CONN_DENY;
        }
        
        if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
        {
            if(connect_to_best_debug)
                printk("%s my_rssi(%d) > other_rssi(%d) ALLOW\n",__func__,my_rssi,other_rssi);
        }
    }
    return CONN_ALLOW;
}

void check_slow_connect(wbuf_t wbuf,struct userinfo_table * user)
{
    int is_mcast = 0;
    int dir = 0;
    struct ieee80211_frame *wh = NULL;
    u_int32_t time = 0;
    u_int32_t overturn = -1;
    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    dir = wh->i_fc[1] & IEEE80211_FC1_DIR_MASK;	
    is_mcast = (dir == IEEE80211_FC1_DIR_DSTODS ||
    dir == IEEE80211_FC1_DIR_TODS ) ?
    IEEE80211_IS_MULTICAST(IEEE80211_WH4(wh)->i_addr3) :
    IEEE80211_IS_MULTICAST(wh->i_addr1);
    if(user == NULL)
        return;

    if(user->stamp_time >= user->prev_stamp_time)
    {
        time = (user->stamp_time - user->prev_stamp_time);
    }
    else
    {
        time = (overturn - user->prev_stamp_time) + user->stamp_time;
    }
    if(time > inactive_time)
    {
        user->slow_connect = 1;
        user->slow_stamp_time = user->stamp_time;
        send_sync_info_single(user,SYNC_USER_INFO);
    }

}

int connect_to_best(wbuf_t wbuf,struct ieee80211vap *vap,struct ieee80211_node * ni,struct userinfo_table * user)
{
    int ret = CONN_ALLOW;
    int dev_index = 0;    
    int have_dev = 0;
    u_int8_t NULL_MAC[6] = {0};
    int subtype;
    int ap_index = -1;
    struct sync_userinfo_table * sync_user = NULL;
    struct ieee80211_frame *wh;	
    u_int32_t local_vap_user_cnt = 0,neighbor_vap_user_cnt = 0;
    //u_int32_t cur_time = jiffies_to_msecs(jiffies);
    //unsigned long irq_lock_flags;
    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    if(connect_to_best_swith == 0)
        return ret;
    /*If can't found this sta in local table, allow it pass*/
    if(user == NULL)
    {
        if(connect_to_best_debug)
            printk("%s can't found sta in local table\n",__func__);
        return ret;
    }

    switch(subtype)
    {
        case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
            /*Check this is a unicase probe?*/
            if(check_probe(ni,wbuf,subtype) == NOPROCESS)
            {
                /*Only process unicase probe, other type allow it pass.*/
                return CONN_ALLOW;
            }
            break;
        case IEEE80211_FC0_SUBTYPE_AUTH:
            /*Check this auth is for me? if not drop it!*/
            if(!IEEE80211_ADDR_EQ(((struct ieee80211_frame *)wh)->i_addr1, vap->iv_myaddr) ||  \
            !IEEE80211_ADDR_EQ(((struct ieee80211_frame *)wh)->i_addr3, (ni)->ni_bssid))
            {
                return CONN_DENY;
            }
            break;
        default:
            return ret;
    }

    if(user->slow_connect)
    {

        if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
        {
            if(connect_to_best_debug)
                printk("%s sta[%s] trigger slow connect rule\n",__func__,ether_sprintf(user->user_mac));
        }
    
        if(calc_update_time(user->slow_stamp_time) < wating_time)
        {
        
            if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
            {
                if(connect_to_best_debug)
                    printk("inactive time(%d), drop this frame(%02x)!\n",calc_update_time(user->slow_stamp_time),subtype);
            }
            return CONN_DENY;
        }

        if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
        {
            if(connect_to_best_debug)
                printk("active time(%d), pass this frame(%02x)!\n",calc_update_time(user->slow_stamp_time),subtype);
        }
        
        user->slow_connect = 0;
    }
    
    if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
    {
        if(connect_to_best_debug)
        {
            printk("Checking sta[%s] connect rule start!\n",ether_sprintf(user->user_mac));
        }
    }

    /*Calc local vap user count(wifi0+wifi1)*/
    for(dev_index = 0; dev_index < MAX_DEV; dev_index++)
    {
        if(memcmp(own_vaps[dev_index].dev_mac, NULL_MAC, 6) == 0)
        {        
            continue;
        }
        if(memcmp(vap->iv_bss->ni_essid,own_vaps[dev_index].essid,vap->iv_bss->ni_esslen) == 0)
        {
            local_vap_user_cnt += own_vaps[dev_index].user_cnt;
        }
    }

    /*Loop all neighbor user and check connect rule*/
    TAILQ_FOREACH(sync_user, &(user->user_list_head), user_list_hash) {
        if(sync_user != NULL)
        {
            //spin_lock_irqsave(&(sync_user->sync_userinfo_lock), irq_lock_flags);
            /*If this user in inactive status, ignore it*/
            if(calc_update_time(sync_user->update_time) > inactive_time)
            {

                if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
                {
                    if(connect_to_best_debug)
                        printk("%s This sta[%s]",__func__,ether_sprintf(sync_user->sta_mac));
                        printk("inactive in neighbor ap[%s]!\n",ether_sprintf(sync_user->ap_mac));
                }
                continue;
            }

            /*Find neighbor ap through neighbor user*/
            ap_index = find_neighbour_ap(sync_user->ap_mac);
            if(ap_index == -1)
            {
                continue;
            }
            neighbor_vap_user_cnt = 0;
            have_dev = 0;
            
            /*Check neighbor ap have same ESSID?*/
            for(dev_index = 0; dev_index < MAX_DEV; dev_index++)
            {
                if(memcmp(ap_list[ap_index].vaps[dev_index].dev_mac, NULL_MAC, 6) == 0)
                {        
                    continue;
                }
                if(memcmp(vap->iv_bss->ni_essid,ap_list[ap_index].vaps[dev_index].essid,vap->iv_bss->ni_esslen) == 0)
                {
                    have_dev = 1;                    
                    /*Calc same ESSID user count(wifi0+wifi1)*/
                    neighbor_vap_user_cnt += ap_list[ap_index].vaps[dev_index].user_cnt;
                    if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
                    {
                        if(connect_to_best_debug)
                            printk("Found this essid[%s] mode[%d] user_cnt[%d] in neighbor ap[%s]\n",\
                            vap->iv_bss->ni_essid,ap_list[ap_index].vaps[dev_index].work_mode,\
                            ap_list[ap_index].vaps[dev_index].user_cnt,ether_sprintf(ap_list[ap_index].ap_base_mac));
                    }
                }
            }

            /*Can find same essid in neighbor ap? if not continue*/
            if(have_dev == 0)
            {
                if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
                {
                    if(connect_to_best_debug)
                        printk("Can't found this essid[%s] in neighbor ap[%s]\n",\
                        vap->iv_bss->ni_essid,ether_sprintf(ap_list[ap_index].ap_base_mac));
                }
                continue;
            }

            /*connect rule, compare rssi,user connect count and AP user count*/
            if(check_best_rssi(user->avg_mgmt_rssi,user->assoc_cnt,sync_user->avg_mgmt_rssi,sync_user->assoc_cnt,local_vap_user_cnt,neighbor_vap_user_cnt,subtype) == CONN_DENY)
            {
                if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
                {
                    if(connect_to_best_debug){
                        printk("     STA[%s] rssi(%d) assoc_cnt(%d) user_cnt(%d)\n",ether_sprintf(user->user_mac),user->avg_mgmt_rssi,user->assoc_cnt,local_vap_user_cnt);
                        printk("Neigbhor[%s] rssi(%d) assoc_cnt(%d) user_cnt(%d), CONNECT DENY!\n",ether_sprintf(sync_user->ap_mac),sync_user->avg_mgmt_rssi,sync_user->assoc_cnt,neighbor_vap_user_cnt);
                        printk("Checked station connect rule finish! sta[%s]\n",ether_sprintf(user->user_mac));
                    }
                }
                return CONN_DENY;
            }
            else
            {
                if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
                {
                    if(connect_to_best_debug){
                        printk("     STA[%s] rssi(%d) assoc_cnt(%d) user_cnt(%d)\n",ether_sprintf(user->user_mac),user->avg_mgmt_rssi,user->assoc_cnt,local_vap_user_cnt);
                        printk("Neigbhor[%s] rssi(%d) assoc_cnt(%d) user_cnt(%d),CONNECT ALLOW!\n",ether_sprintf(sync_user->ap_mac),sync_user->avg_mgmt_rssi,sync_user->assoc_cnt,neighbor_vap_user_cnt);
                    }
                }
            }
            //spin_unlock_irqrestore(&(sync_user->sync_userinfo_lock), irq_lock_flags);	
        }
    }
    if(IEEE80211_FC0_SUBTYPE_AUTH == subtype)
    {
        if(connect_to_best_debug)
        {
            printk("\nSTA[%s] rssi(%d) CONNECT ALLOW!\n",ether_sprintf(user->user_mac),user->avg_mgmt_rssi);
            printk("Checked station connect rule finish! sta[%s]\n",ether_sprintf(user->user_mac));
        }
    }
    return ret;
}


int get_sta_mgmt_behavior(wbuf_t wbuf,struct ieee80211com *ic,struct userinfo_table *user)
{
    int subtype = 0;   
    struct ieee80211_frame *wh;	
    
    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    if(IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan))
    {
        if(subtype == IEEE80211_FC0_SUBTYPE_PROBE_REQ)
        {
            user->recv_probe_5g ++;
        }
        else if(subtype == IEEE80211_FC0_SUBTYPE_AUTH)
        {
            user->recv_auth_5g ++;
        }
    }
    else if(IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
    {
        if(subtype == IEEE80211_FC0_SUBTYPE_PROBE_REQ)
        {
            user->recv_probe_2g ++;
        }
        else if(subtype == IEEE80211_FC0_SUBTYPE_AUTH)
        {
            user->recv_auth_2g ++;
        }
    }

    return 0;
}

