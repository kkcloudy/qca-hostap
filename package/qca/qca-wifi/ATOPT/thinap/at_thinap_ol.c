#include <ieee80211_var.h>
#include <ol_if_athvar.h>
#include <ol_txrx_types.h>
#include "ol_tx_desc.h"
#include <if_upperproto.h>
#include "osif_private.h"
#include "at_thinap_ol.h"

int
dhcp_detect_eth(struct ieee80211vap *vap, struct sk_buff *skb)
{
    u_int8_t *eh = skb->data;
    int ip_len = sizeof(struct iphdr);

    if ((skb->len > (ETH_HLEN + ip_len)) &&
        ((*(eh + ETH_HLEN + ip_len + 1) == 67 && *(eh + ETH_HLEN + ip_len + 3) == 68) ||
        (*(eh + ETH_HLEN + ip_len + 1) == 68 && *(eh + ETH_HLEN + ip_len + 3) == 67)))
        return 1;
    else 
        return 0;
}

int
pppoe_detect_eth(struct ieee80211vap *vap, struct sk_buff *skb)
{
    struct ether_header *eh = (struct ether_header *)skb->data;

    if ((eh->ether_type == __constant_htons(ETH_P_PPP_DISC)) ||
        (eh->ether_type == __constant_htons(ETH_P_PPP_SES)))
        return 1;
}

u_int16_t 
get_ether_type(void *buf)
{
    return ((struct ether_header *)buf)->ether_type;
}

int at_thinap_input_ol(wlan_if_t vap,struct sk_buff *wbuf,u_int8_t tid,u_int8_t frm_type,u_int8_t is_authorize)
{
    struct net_device *dev = OSIF_TO_NETDEV(vap->iv_ifp);
    wbuf_t wbuf_capture = NULL;
    u_int16_t frametype = 0;
    u_int8_t packet_type = 0; 
    u_int32_t tunnel_local_state = -1; // 1 means tunnel,0 means local

    /*get the frametype*/

    if(frm_type == wlan_frm_fmt_802_3){
        frametype = get_ether_type(__adf_nbuf_data(wbuf));
    }

    tunnel_local_state = vap->vap_splitmac;
    if (tunnel_local_state == 2)
    {
       /********************************************
            When the node is unauthorized in some conditions we
            need to transmit packets to kernel or AC.
            1. Frame type is EAP or WAI 
            2. This is a PPPoE Frame
            3. This is a DHCP Frame
            *********************************************/
        #if 0
        if (frametype == __constant_htons(ETHERTYPE_PAE) 
            || frametype == __constant_htons(ETHERTYPE_PRE_PAE) 
            || frametype == __constant_htons(ETHERTYPE_WAI))
        {
            wbuf = autelan_transcap_8023_to_80211(vap,wbuf_capture,frametype);
            if(wbuf == NULL) 
                goto bad;
        
            wbuf->protocol = __constant_htons(0x0030); 
        }
        else 
        #endif
        {
            if ((is_authorize == 1) || dhcp_detect_eth(vap, wbuf) || pppoe_detect_eth(vap, wbuf)) { /*caizhibang modify for dhcp and pppoe function*/
                wbuf->protocol = __constant_htons(0x0030);
            } else {
                return THINAP_DROP;
            }
        }
        /*Skip decap 802.11 head and encap 802.3 head directly send to AC when sendtowtpd == 1*/
        return THINAP_PASS;
    }

    if (is_authorize == 0)
    {
        if (dhcp_detect_eth(vap, wbuf) || pppoe_detect_eth(vap,wbuf))
        {
            return THINAP_PASS;
        }
        else
        {
            return THINAP_DROP;
        }
    }
    return THINAP_PASS;
}

