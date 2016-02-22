#ifndef _AT_THINAP_OL_H_
#define _AT_THINAP_OL_H_

#define THINAP_PASS 1
#define THINAP_DROP 0

int dhcp_detect_eth(struct ieee80211vap *vap, struct sk_buff *skb);
int pppoe_detect_eth(struct ieee80211vap *vap, struct sk_buff *skb);
int at_thinap_input_ol(wlan_if_t vap,struct sk_buff *wbuf,u_int8_t tid,u_int8_t frm_type,u_int8_t is_authorize);
#endif
