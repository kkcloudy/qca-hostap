#ifndef _AT_THINAP_H_
#define _AT_THINAP_H_

#define THINAP_PASS 1
#define THINAP_DROP 0
int dhcp_detect_wh(struct ieee80211vap *vap,struct sk_buff *skb);
int dhcp_detect_eth(struct ieee80211vap *vap, struct sk_buff *skb);
int pppoe_detect_wh(struct ieee80211vap *vap, struct sk_buff *skb);
int pppoe_detect_eth(struct ieee80211vap *vap, struct sk_buff *skb);
int dns_detect_wh(struct ieee80211vap *vap, struct sk_buff *skb);
int arp_detect_wh(struct ieee80211vap *vap,struct sk_buff *skb);
int at_thinap_input(wbuf_t wbuf,struct ieee80211_node *ni);
#endif

