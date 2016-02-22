#include <linux/netdevice.h>
#include <osdep.h>
#include "osif_private.h"
#include "ieee80211_var.h"
#include "if_athvar.h"
#include <if_llc.h>
#include <if_athproto.h>
#include <if_upperproto.h>
#include "ieee80211_defines.h"
#include "at_thinap.h"
#include <linux/module.h>

#ifndef ETHERTYPE_PRE_PAE
#define ETHERTYPE_PRE_PAE 0x88c7/* pre auth eap for wpa2 thinap */
#endif

#if ATOPT_THINAP
/*zhaoyang add for tunnel local ctl by sta state*/
int dhcp_detect_wh(struct ieee80211vap *vap,struct sk_buff *skb)
{
    u_int8_t *wh = skb->data;
    int hdrspace = ieee80211_hdrspace(vap->iv_ic, wh);
    int ip_len = sizeof(struct iphdr);
    if(0)
    {
        int i = 0;
        printk("%s %d\n",__func__,*(wh + hdrspace + LLC_SNAPFRAMELEN + ip_len + 1));
        printk("%s %d\n",__func__,*(wh + hdrspace + LLC_SNAPFRAMELEN + ip_len + 3));
        while(i <= skb->len)
        {
            if((0!=(i%8)) || 0 == i)
            {
                printk("%02x ",skb->data[i]);
                i++;
                continue;
            }
            printk("\n");
            printk("%02x ",skb->data[i]);
            i++;
        }
        printk("skb->len = %d\n",skb->len);
        printk("\n\n");
    }
    if ((skb->len > (hdrspace + LLC_SNAPFRAMELEN + ip_len)) &&
        ((*(wh + hdrspace + LLC_SNAPFRAMELEN + ip_len + 1) == 67 && *(wh + hdrspace + LLC_SNAPFRAMELEN + ip_len + 3) == 68) ||
        (*(wh + hdrspace + LLC_SNAPFRAMELEN + ip_len + 1) == 68 && *(wh + hdrspace + LLC_SNAPFRAMELEN + ip_len + 3) == 67)))
        return 1;       
    else
        return 0;
}

int
pppoe_detect_wh(struct ieee80211vap *vap, struct sk_buff *skb)
{
    struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;

    if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA)
    {
        int hdrspace = ieee80211_hdrspace(vap->iv_ic, wh);
        struct llc *llc_type = (struct llc *)(skb->data + hdrspace);

        if ((llc_type->llc_un.type_snap.ether_type == __constant_htons(ETH_P_PPP_DISC)) ||
            (llc_type->llc_un.type_snap.ether_type == __constant_htons(ETH_P_PPP_SES)))
            return 1;
    }
}


int
dns_detect_wh(struct ieee80211vap *vap, struct sk_buff *skb)
{   
    u_int8_t *wh = skb->data;
    int hdrspace = ieee80211_hdrspace(vap->iv_ic, wh);
    int ip_len = sizeof(struct iphdr);

    if ((skb->len > (hdrspace + LLC_SNAPFRAMELEN + ip_len)) &&
        (*(wh + hdrspace + LLC_SNAPFRAMELEN + ip_len + 1) == 53  ||
        *(wh + hdrspace + LLC_SNAPFRAMELEN + ip_len + 3) == 53))
        return 1;       
    else
        return 0;
}

int 
arp_detect_wh(struct ieee80211vap *vap,struct sk_buff *skb)
{
    u_int8_t *wh = skb->data;
    int hdrspace = ieee80211_hdrspace(vap->iv_ic, wh);

    if(skb->len > (hdrspace + LLC_SNAPFRAMELEN))
    {   
        //arp llc type is 0x0806
        if(*(wh + hdrspace + 6) == 0x08 && *(wh + hdrspace + 7) == 0x06)
            return 1;           
        else 
            return 0;
    }
    else 
        return 0;
}
#endif

int at_thinap_input(wbuf_t wbuf,struct ieee80211_node *ni)
{
    u_int16_t hdrspace;
    u_int16_t frametype = 0;
    struct llc *llc_type = NULL;
    u_int32_t tunnel_local_state = -1; // 1 means tunnel,0 means local    
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;

    if(!thinap)
        return THINAP_PASS;
    
    hdrspace = ieee80211_hdrspace(ic, wbuf_header(wbuf));

    llc_type = (struct llc *)skb_pull(wbuf, hdrspace);

    if (llc_type != NULL)
    {
        if (wbuf->len >= LLC_SNAPFRAMELEN &&
        llc_type->llc_dsap == LLC_SNAP_LSAP && llc_type->llc_ssap == LLC_SNAP_LSAP &&
        llc_type->llc_control == LLC_UI && llc_type->llc_snap.org_code[0] == 0 &&
        llc_type->llc_snap.org_code[1] == 0 && llc_type->llc_snap.org_code[2] == 0) {
            frametype = llc_type->llc_un.type_snap.ether_type;
        }
        skb_push(wbuf, hdrspace);
    }
#if 0
    /*Begin:Modified by lijiyong for shifting down four-way-handshake 2014-03-31*/
    if(vap->iv_eap_in_ap){
        if (frametype == __constant_htons(ETHERTYPE_PAE)) {
            packet_type = *((u_int8_t *)(wbuf->data + hdrspace + LLC_SNAPFRAMELEN + 1));
            if (HANDSHAKE_PAE == packet_type)
            {
                wbuf->protocol = __constant_htons(0x0023);
                goto local_forward;
            }
        }
    }
    /*End:Modified by lijiyong*/
    
    if (vap->vap_splitmac == 3)//ubc mode
    {
        if (!ieee80211_node_is_authorized(ni))
            tunnel_local_state = 2;//tunnel
        else
        {
            if (ni->ni_localflags)
            {
                if (ni->ni_portal_ipaddr[0] == 0)// outer portal server mode
                    tunnel_local_state = 0; //local
                else//inner portal server mode 
                {
                    struct ip_header * ipwh= (struct ip_header *) (wbuf->data + hdrspace + LLC_SNAPFRAMELEN);

                    if (memcmp(&(ipwh->daddr),ni->ni_portal_ipaddr,sizeof(ni->ni_portal_ipaddr)) == 0)// this frame is sent to portal server,so go to tunnel
                    {
                        tunnel_local_state = 2;//tunnel

                    }
                    else
                    {
                        tunnel_local_state = 0;//local
                    }

                }

            }
            else {
                //DHCP,ARP,DNS local ,others tunnel
                if (dhcp_detect_wh(vap,wbuf) || dns_detect_wh(vap,wbuf) || arp_detect_wh(vap,wbuf))
                    tunnel_local_state = 0;//local
                else 
                    tunnel_local_state = 2;//tunnel
            }
        }
    }
    else {
        tunnel_local_state = vap->vap_splitmac;
    }
#endif
    tunnel_local_state = vap->vap_splitmac;

    /*802.3 tunnel*/
    if (tunnel_local_state == 2)
    {
        
        //printk("%s recv a packet in wireless 802.3 tunnel!!!\n",__func__);
        /********************************************
                When the node is unauthorized in some conditions we
                need to transmit packets to kernel or AC.
                1. Frame type is EAP or WAI 
                2. This is a PPPoE Frame               3. This is a DHCP Frame
                *********************************************/
        if (frametype == __constant_htons(ETHERTYPE_PAE) 
            || frametype == __constant_htons(ETHERTYPE_PRE_PAE) 
            || frametype == __constant_htons(ETHERTYPE_WAI))
        {
            wbuf->protocol = __constant_htons(0x0030);
        }
        else
        {
            if (ieee80211_node_is_authorized(ni)|| dhcp_detect_wh(vap, wbuf) || 
                pppoe_detect_wh(vap,wbuf))//gengzongjie transplanted for apv8
            {
                wbuf->protocol = __constant_htons(0x0030);
                //printk("%s recv a dhcp packet in wireless!!!\n",__func__);
            }
            else
            {
                return THINAP_DROP;
            }
        }
        /*Skip decap 802.11 head and encap 802.3 head directly send to AC when sendtowtpd == 1*/
        //goto thinapout;
    }
    else
    {
        //printk("%s recv a in wireless!!!\n",__func__);
        /*local mode*/
    }
    return THINAP_PASS;
}

#define NETDEV_TO_VAP(_dev) (((osif_dev *)netdev_priv(_dev))->os_if)

struct ieee80211vap * get_vap_from_netdev(struct net_device * dev)  
{
    return NETDEV_TO_VAP(dev);
}
EXPORT_SYMBOL(get_vap_from_netdev);

