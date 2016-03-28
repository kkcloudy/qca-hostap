/*
*pengdecai added for han private wmm.
*/

#ifndef __IGMP_SNOOPING_H
#define __IGMP_SNOOPING_H

#include <linux/types.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/list.h>
#include <ieee80211_var.h>
#include <han_ioctl.h>
#include "han_command.h"


extern int
ieee80211_han_ioctl_igmp_snooping(struct net_device *dev,struct han_ioctl_priv_args *a,struct iwreq *iwr);
extern void ieee80211_me_SnoopListUpdate(struct MC_LIST_UPDATE* list_entry);
extern void send_igmp_snooping_sta_leave(struct ieee80211_node *ni);
#if ATH_PERF_PWR_OFFLOAD
extern int ol_ieee80211_me_SnoopConvert(struct ieee80211vap *vap, wbuf_t wbuf);
#endif

extern void ieee80211_me_SnoopListUpdate(struct MC_LIST_UPDATE* list_entry);
extern void ieee80211_me_SnoopWDSNodeCleanup(struct ieee80211_node *ni);
extern uint8_t ieee80211_me_SnoopListGetMember(struct ieee80211vap* vap, uint8_t* grp_addr, u_int32_t grp_ipaddr, 
                          u_int32_t src_ip_addr,uint8_t* table, int table_len);
extern int ieee80211_me_SnoopIsDenied(struct ieee80211vap *vap, u_int32_t grpaddr);
extern void ol_igmp_send_skb_fast(struct ieee80211vap *vap,struct sk_buff *skb);

#endif

