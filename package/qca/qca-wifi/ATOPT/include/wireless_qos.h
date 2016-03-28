/*
*pengdecai added for han private wmm.
*/

#ifndef __WIRELESS_QOS_H
#define __WIRELESS_QOS_H

#include <linux/types.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/list.h>
#include <ieee80211_var.h>
#include <han_ioctl.h>
#include "han_command.h"

#define IP_DSCP_MAP_LEN 64
#define WMM_ETHERTYPE_VLAN    0x8100
#define WMM_VLAN_PRI_SHIFT    (13)
#define WMM_VLAN_MASK         (7)
#define WMM_VLAN_LEN            (4)   /* VLAN header length */
#define WMM_ETHR_HDR_LEN        (14)  /* 802.3 header length */
#define WMM_VLANID_MASK      (0x0FFF)
#define WMM_VLANPRI_MASK      (0xE000)

extern int ieee80211_priv_wmm_init(struct ieee80211vap *vap);
extern int 	ieee80211_ioctl_wireless_qos(struct net_device *dev,struct han_ioctl_priv_args *a,struct iwreq *iwr);
extern u_int8_t dscp_to_wmm(struct ieee80211vap *vap,u_int8_t dscp);
extern u_int8_t ieee80211_dscp_to_wmm(struct ieee80211vap *vap, wbuf_t wbuf);
extern u_int8_t ieee80211_vlan_priv_to_wmm(struct ieee80211vap *vap,u_int8_t v_priv);
extern u_int8_t ieee80211_do_wmm_to_dscp(struct ieee80211vap *vap, wbuf_t wbuf);
extern u_int8_t ieee80211_wmm_to_vlan(struct ieee80211vap *vap, u_int8_t ac);
extern int ol_do_vlan_to_wmm(struct ieee80211vap *vap,struct sk_buff *skb);
extern void ol_ieee80211_do_wmm_to_dscp_vlan(os_if_t osif, struct sk_buff *skb,u_int8_t tid);
extern int ol_set_dscp_to_wmm(struct ieee80211vap *vap);
extern int ieee80211_han_ioctl_igmp_snooping(struct net_device *dev,struct han_ioctl_priv_args *a,struct iwreq *iwr);

#endif
