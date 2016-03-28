/*
*pengdecai added for han private wmm.
*/
#include <han_netlink.h>
#include <ah.h>
#include <ieee80211_defines.h>
#include <osif_private.h>
#include <osapi_linux.h>
#include <uapi/linux/if_vlan.h> 
#include "igmp_snooping.h"
#include "ieee80211_ique.h"
#include "ieee80211_me_priv.h"
#include <ol_txrx_api.h>

//#include <wlan_opts.h>
#include <ieee80211_var.h>
//#include <ieee80211_extap.h>
#include "if_athvar.h"
#include "ieee80211_aponly.h"
//#include <ieee80211_acfg.h>
//#include <acfg_drv_if.h>
//#include <adf_net.h>
//#include <adf_os_perf.h>
//#include <ieee80211_nl.h>
//#include <adf_nbuf.h> /* adf_nbuf_map_single */
#include "if_athproto.h"
#if ATH_PERF_PWR_OFFLOAD
#include "ol_cfg.h"
#endif

/*Begin:pengdecai for han private wmm*/   
#if ATOPT_WIRELESS_QOS
#include <wireless_qos.h>
#endif
/*End:pengdecai for han private wmm*/   

#if ATH_PERF_PWR_OFFLOAD && ATH_SUPPORT_DSCP_OVERRIDE
extern int ol_ath_set_vap_dscp_tid_map(struct ieee80211vap *vap);
#endif

#define IGMP_SNP_TYPE_OPTION 0x00
#define IGMP_SNP_TYPE_GROUP_IP 0x01
#define IGMP_SNP_TYPE_STA_MAC 0x02

//tlv message define
#define TLV_MSG_TYPE_LEN 1
#define TLV_MSG_LENGTH_LEN 1

#pragma pack(push, 1)
struct IGMP_TLV {
	u_int8_t t_op;
	u_int8_t l_op;
	u_int8_t v_op;
	u_int8_t t_group_ip;
	u_int8_t l_group_ip;
	u_int32_t v_group_ip;
	u_int8_t t_sta_mac;
	u_int8_t l_sta_mac;
	u_int8_t v_sta_mac[6];
};

struct igmp_snp_list{
	u_int8_t member_num;
	struct IGMP_TLV tlv;
};
#pragma pack(pop)


#define WMM_STORE_INFO_USER_TO_DRIVER(vap,arg,ac){\
	int i;\
	memset(vap->priv_wmm.ac.priority,0x0,PRI_MAX_NUM);\
	for (i = 0; i < arg->u.wmm.arg_num; i ++){\
		vap->priv_wmm.ac.priority[i] = arg->u.wmm.wmm_args.ac[i];\
		}\
	vap->priv_wmm.ac.num = arg->u.wmm.arg_num;\
}
static void parse_igmpsnp_info(char * buf,struct MC_LIST_UPDATE* list_entry)
{	
	u_int16_t tmp_len = 0;
	u_int16_t tmp_total_len = 0;
	u_int8_t type = 0,cmd=0;
	int igmp_len = sizeof(struct IGMP_TLV);

	  	while(tmp_total_len < igmp_len){ 
    		switch(*buf){
    			case IGMP_SNP_TYPE_GROUP_IP:
    			buf ++;
    			tmp_len = *buf;
    			buf ++;
    			list_entry->grpaddr = *((u_int32_t*)buf);
    			break;
    			case IGMP_SNP_TYPE_STA_MAC:
    			buf ++;
    			tmp_len = *buf;
    			buf ++;
    			IEEE80211_ADDR_COPY(list_entry->grp_member,buf);	
    			break;
    			case IGMP_SNP_TYPE_OPTION:
    			buf ++;
    			tmp_len = *buf;
    			buf ++;
				if(*buf == 3){
    				list_entry->cmd = IGMP_SNOOP_CMD_ADD_INC_LIST;
				}else if(*buf == 4){
					list_entry->cmd = IGMP_SNOOP_CMD_ADD_EXC_LIST;
				}else {
					printk("driver: receive option error!\n");
					list_entry->cmd = IGMP_SNOOP_CMD_OTHER;
				}
				
    			break;
    		}
			buf += tmp_len;
			tmp_total_len += (TLV_MSG_TYPE_LEN + TLV_MSG_LENGTH_LEN + tmp_len);
    	}	
}

struct ieee80211_node_table *
get_node_table(const char* dev_name) 
{
	struct ath_softc_net80211 *scn = NULL;
	struct ieee80211com *ic = NULL;
	struct net_device *dev = NULL;


#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
			dev = dev_get_by_name(&init_net,dev_name);
#else
			dev = dev_get_by_name(dev_name);
#endif

	if (!dev) {
		printk("%s: device %s not Found! \n", __func__, dev_name);
		return NULL;
	}

	scn = ath_netdev_priv(dev);
	if (scn == NULL)  {
		return NULL;
	}

	ic = &scn->sc_ic;
	if (ic == NULL) {
		return NULL;
	}
	
	return &ic->ic_sta;

}

struct ieee80211_node *
find_ni_node_by_mac(char* mac)
{
	struct ieee80211_node_table  *nt = NULL;
	struct ieee80211_node *ni = NULL;

	nt = get_node_table("wifi0");
	ni = ieee80211_find_node(nt,mac);
	
	if(ni != NULL)
		return ni;
	
	nt = get_node_table("wifi1");
	ni = ieee80211_find_node(nt,mac);
	
	if(ni != NULL)
		return ni;
	printk("igmpsnp:cannot find the node!\n");
	return NULL;

}

static int 
set_igmp_other_entry(struct MC_LIST_UPDATE* list_entry)
{
	 int ret = 0;
	 u_int32_t	groupAddr = 0;
	 u_int8_t	groupAddrL2[IEEE80211_ADDR_LEN]; /*group multicast mac address*/
	 groupAddr = list_entry->grpaddr;

	 list_entry->ni = find_ni_node_by_mac(list_entry->grp_member);
	 if(NULL == list_entry->ni){
		return -1;
	 }
	 list_entry->vap = list_entry->ni->ni_vap;
	 
	 /* Init multicast group address conversion */
     groupAddrL2[0] = 0x01;
     groupAddrL2[1] = 0x00;
     groupAddrL2[2] = 0x5e;
	 groupAddrL2[3] = (groupAddr >> 16) & 0x7f;
     groupAddrL2[4] = (groupAddr >>  8) & 0xff;
     groupAddrL2[5] = (groupAddr >>  0) & 0xff;
	 IEEE80211_ADDR_COPY(list_entry->grp_addr,groupAddrL2);
	 list_entry->timestamp = OS_GET_TIMESTAMP();

	 return ret;
}

void recv_igmp_snooping_list(char * data)
{
	struct igmp_snp_list *list = (struct igmp_snp_list *)data;
    struct IGMP_TLV * tlv = &list->tlv;
	struct MC_LIST_UPDATE  list_entry;
	u_int8_t type = 0;

	int i = 0;
	u_int8_t num = list->member_num;
    data ++;
	for (i = 0;i < num; i ++){
		memset(&list_entry,0x0,sizeof(struct MC_LIST_UPDATE));
		parse_igmpsnp_info(data,&list_entry);
		
		if(set_igmp_other_entry(&list_entry))
			continue;
		
		ieee80211_me_SnoopListUpdate(&list_entry);
		data += sizeof(struct IGMP_TLV);
	}
}

static struct MC_GRP_MEMBER_LIST* 
find_group_member_by_mac(struct ieee80211_node *ni)
{
	struct ieee80211vap* vap = ni->ni_vap;
	struct MC_SNOOP_LIST *snp_list = &(vap->iv_me->ieee80211_me_snooplist);
	struct MC_GROUP_LIST_ENTRY* grp_list;
	struct MC_GRP_MEMBER_LIST* grp_member_list;
	rwlock_state_t lock_state;
	
	if(vap->iv_opmode == IEEE80211_M_HOSTAP &&
		   vap->iv_me->mc_snoop_enable &&
		   snp_list != NULL)
	{
		TAILQ_FOREACH(grp_list,&snp_list->msl_node,grp_list){
			TAILQ_FOREACH(grp_member_list, &grp_list->src_list,member_list){
				  if(IEEE80211_ADDR_EQ(grp_member_list->grp_member_addr,ni->ni_macaddr)){
					  return(grp_member_list);
				  }
			   }
		}
	}
	if(vap->iv_me->me_debug == 3){
		printk("igmp driver:the sta is not a member of the vap mc group");
	}
	return(NULL);
}


void send_igmp_snooping_sta_leave(struct ieee80211_node *ni)
{
	struct igmp_snp_list list; 
	struct IGMP_TLV *tlv = &list.tlv;
	struct MC_GRP_MEMBER_LIST* grp_member_list;
	memset(&list,0x0,sizeof(struct igmp_snp_list));
	
	grp_member_list = find_group_member_by_mac(ni);
	if(grp_member_list == NULL)
		return ;
	
	list.member_num = 1;
	tlv->t_op = IGMP_SNP_TYPE_OPTION;
	tlv->l_op = sizeof(tlv->v_op);
	tlv->v_op = 4;//4 delete member,3 add member.
	tlv->t_sta_mac = IGMP_SNP_TYPE_STA_MAC;
	tlv->l_sta_mac = 6;
	tlv->t_group_ip = IGMP_SNP_TYPE_GROUP_IP;
	tlv->l_group_ip = sizeof(tlv->v_group_ip);
	tlv->v_group_ip = grp_member_list->grpaddr;
	
	IEEE80211_ADDR_COPY(tlv->v_sta_mac,ni->ni_macaddr);
	ieee80211_han_netlink_send(&list,sizeof(struct igmp_snp_list),HAN_NETLINK_IGMP_PORT_ID);
}

/* print all the group entries */
static void
han_ieee80211_me_SnoopListDump(struct ieee80211vap* vap)
{
    struct MC_SNOOP_LIST *snp_list = &(vap->iv_me->ieee80211_me_snooplist);
    struct MC_GROUP_LIST_ENTRY* grp_list;
    struct MC_GRP_MEMBER_LIST* grp_member_list;
    rwlock_state_t lock_state;

    if(vap->iv_opmode == IEEE80211_M_HOSTAP &&
        vap->iv_me->mc_snoop_enable &&
        snp_list != NULL)
    {
        IEEE80211_SNOOP_LOCK(snp_list,&lock_state);
        TAILQ_FOREACH(grp_list,&snp_list->msl_node,grp_list){
            printk("group addr %x:%x:%x:%x:%x:%x \n",grp_list->group_addr[0],
                                                     grp_list->group_addr[1],
                                                     grp_list->group_addr[2],
                                                     grp_list->group_addr[3],
                                                     grp_list->group_addr[4],
                                                     grp_list->group_addr[5]);
             
            TAILQ_FOREACH(grp_member_list, &grp_list->src_list,member_list){
                printk("    src_ip_addr %d:%d:%d:%d \n",((grp_member_list->src_ip_addr >> 24) & 0xff),
                                                        ((grp_member_list->src_ip_addr >> 16) & 0xff),
                                                        ((grp_member_list->src_ip_addr >>  8) & 0xff),
                                                        ((grp_member_list->src_ip_addr) & 0xff));
                printk("    member addr %x:%x:%x:%x:%x:%x\n",grp_member_list->grp_member_addr[0],
                                                             grp_member_list->grp_member_addr[1],
                                                             grp_member_list->grp_member_addr[2],
                                                             grp_member_list->grp_member_addr[3],
                                                             grp_member_list->grp_member_addr[4],
                                                             grp_member_list->grp_member_addr[5]);

                printk("    Mode %d \n",grp_member_list->mode); 
            }
        }
        IEEE80211_SNOOP_UNLOCK(snp_list, &lock_state);
    }
}


int
ieee80211_han_ioctl_igmp_snooping(struct net_device *dev,struct han_ioctl_priv_args *a,struct iwreq *iwr)
{
	int retv = 0;
	osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
	
	switch (a->u.igmp.subtype) {
		case HAN_IOCTL_IGMPSNP_ENABLE:
			if(OP_SET == a->u.igmp.op){
			    vap->iv_me->mc_snoop_enable = a->u.igmp.value;
			} else if(OP_GET == a->u.igmp.op){
				a->u.igmp.value = vap->iv_me->mc_snoop_enable;
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_IGMPSNP_MUTOUN:
			if(OP_SET == a->u.igmp.op){
				vap->iv_me->mc_mcast_enable = a->u.igmp.value;
			}else if(OP_GET == a->u.igmp.op){
				a->u.igmp.value = vap->iv_me->mc_mcast_enable;
			}else {
				retv = ENETRESET;
			}
			
			break;
		case HAN_IOCTL_IGMPSNP_STATUS:
			han_ieee80211_me_SnoopListDump(vap);
			printk("count:\n");
			printk("start = %d\n",vap->iv_me->me_convert_start);
			printk("loop_start = %d\n",vap->iv_me->me_convert_loops);
			printk("success = %d\n",vap->iv_me->me_convert_success);
			break;
		case HAN_IOCTL_IGMPSNP_DEBUG:
			if(OP_SET == a->u.igmp.op){
				vap->iv_me->me_debug = a->u.igmp.value; 
				if(a->u.igmp.value == 2){
					netlink_debug = 1;
				}else {
					netlink_debug = 0;
				}
			}else if(OP_GET == a->u.igmp.op){
				a->u.igmp.value = vap->iv_me->me_debug;
			}else {
				retv = ENETRESET;
			}

			
			break;
	}
	
	if(OP_GET == a->u.igmp.op){
		copy_to_user(iwr->u.data.pointer, a, sizeof(struct han_ioctl_priv_args));
	}
	
	return retv;
}

#if ATH_PERF_PWR_OFFLOAD
#if QCA_OL_VLAN_WAR
static int encap_eth2_to_dot3(adf_nbuf_t msdu);
#define LEN_FIELD_SIZE     2
static void transcap_dot3_to_eth2(struct sk_buff *skb)
{
    struct vlan_ethhdr *veh, veth_hdr;
    veh = (struct vlan_ethhdr *)skb->data;

    if (veh->h_vlan_encapsulated_proto > IEEE8023_MAX_LEN)
        return;

    adf_os_mem_copy(&veth_hdr, veh, sizeof(veth_hdr));
    adf_nbuf_pull_head(skb, LEN_FIELD_SIZE);

    veh = (struct vlan_ethhdr *)skb->data;

    adf_os_mem_copy(veh, &veth_hdr, (sizeof(veth_hdr) - LEN_FIELD_SIZE));
}
static inline  int
_ol_tx_vlan_war(struct sk_buff *skb){
    struct ether_header *eh = (struct ether_header *)skb->data;
    skb = skb_unshare(skb, GFP_ATOMIC);
    if (skb == NULL) {
        return 1;
    }
    if ((htons(eh->ether_type) == ETH_P_8021Q)) {
        if (encap_eth2_to_dot3(skb)){
            return 1;
        }
    }
    return 0;
}
#define  OL_TX_VLAN_WAR(_skb)  _ol_tx_vlan_war(_skb)
#else
#define  OL_TX_VLAN_WAR(_skb)  0
#endif

struct sk_buff *
ol_igmp_send_skb(struct ieee80211vap *vap,struct sk_buff *skb)
{
	  osif_dev  *osdev = (osif_dev *)vap->iv_ifp;

#define OFFCHAN_EXT_TID_NONPAUSE    19

		u_int8_t tidno = wbuf_get_tid(skb);
		if (tidno == OFFCHAN_EXT_TID_NONPAUSE)
			printk("%s: Send offchan packet with NONPAUSE_TID\n", __func__);
		/*
		 * Zero out the cb part of the sk_buff, so it can be used
		 * by the driver.
		 */
		memset(skb->cb, 0x0, sizeof(skb->cb));
		
		if(OL_TX_VLAN_WAR(skb))
				return skb;

		/*
		 * DMA mapping is done within the OS shim prior to sending
		 * the frame to the driver.
		 */
		adf_nbuf_map_single(
			vap->iv_ic->ic_adf_dev, (adf_nbuf_t) skb, ADF_OS_DMA_TO_DEVICE);
		/* terminate the (single-element) list of tx frames */
		skb->next = NULL;
		
	/*Begin:pengdecai for han private wmm*/ 
#ifdef ATOPT_WIRELESS_QOS
		if(vap->priv_wmm.vlan_flag && ieee80211_vap_wme_is_set(vap))
		ol_do_vlan_to_wmm(vap,skb);
#endif
	/*End:pengdecai for han private wmm*/

		if (tidno != OFFCHAN_EXT_TID_NONPAUSE)
			skb = osdev->iv_vap_send(osdev->iv_txrx_handle, skb);
		else {
			/* frames with NONPAUSE_TID should be raw format */
			enum ol_txrx_osif_tx_spec tx_spec = ol_txrx_osif_tx_spec_raw |
						   ol_txrx_osif_tx_spec_no_aggr |
						   ol_txrx_osif_tx_spec_no_encrypt;

			skb = osdev->iv_vap_send_non_std(osdev->iv_txrx_handle,
											 OFFCHAN_EXT_TID_NONPAUSE,
											 tx_spec,
											 skb);
		}
		/*
		 * Check whether all tx frames were accepted by the txrx stack.
		 * If the txrx stack cannot accept all the provided tx frames,
		 * it will return a linked list of tx frames it couldn't handle.
		 * Drop these overflowed tx frames.
		 */
		while (skb) {
			struct sk_buff *next = skb->next;
			adf_nbuf_unmap_single(
				vap->iv_ic->ic_adf_dev, (adf_nbuf_t) skb, ADF_OS_DMA_TO_DEVICE);
			dev_kfree_skb(skb);
			skb = next;
		}
		return NULL;


}
/*Begin:pengdecai for han igmpsnp*/
#ifdef ATOPT_IGMP_SNP
void ol_igmp_send_skb_fast(struct ieee80211vap *vap,struct sk_buff *skb)

{
	 osif_dev  *osdev = (osif_dev *)vap->iv_ifp;
	 OL_TX_LL_WRAPPER(osdev->iv_txrx_handle, skb, vap->iv_ic->ic_adf_dev);
}
#endif
/*End:pengdecai for han igmpsnp*/



/*******************************************************************
 * !
 * \brief Mcast enhancement option 1: Tunneling, or option 2: Translate
 *
 * Add an IEEE802.3 header to the mcast packet using node's MAC address
 * as the destination address
 *
 * \param 
 *             vap Pointer to the virtual AP
 *             wbuf Pointer to the wbuf
 *
 * \return number of packets converted and transmitted, or 0 if failed
 */
int
ol_ieee80211_me_SnoopConvert(struct ieee80211vap *vap, wbuf_t wbuf)
{
    struct ieee80211_node *ni = NULL;
    struct ether_header *eh;
    u_int8_t *dstmac;                           /* reference to frame dst addr */
    u_int32_t src_ip_addr;
    u_int32_t grp_addr = 0;
    u_int8_t srcmac[IEEE80211_ADDR_LEN];    /* copy of original frame src addr */
    u_int8_t grpmac[IEEE80211_ADDR_LEN];    /* copy of original frame group addr */
                                            /* table of tunnel group dest mac addrs */
    u_int8_t empty_entry_mac[IEEE80211_ADDR_LEN];
    u_int8_t newmac[MAX_SNOOP_ENTRIES][IEEE80211_ADDR_LEN];
    uint8_t newmaccnt = 0;                        /* count of entries in newmac */
    uint8_t newmacidx = 0;                        /* local index into newmac */
    int xmited = 0;                            /* Number of packets converted and xmited */
    struct ether_header *eh2;                /* eth hdr of tunnelled frame */
    struct athl2p_tunnel_hdr *tunHdr;        /* tunnel header */
    wbuf_t wbuf1 = NULL;                    /* cloned wbuf if necessary */

    if ( (vap->iv_me->mc_snoop_enable == 0 ) || ( wbuf == NULL ) ) {
        /*
         * if snoop is disabled return -1 to indicate 
         * that the frame's not been transmitted and continue the 
         * regular xmit path in wlan_vap_send
         */
        return -1;
    }
 
    vap->iv_me->me_convert_start ++;
	
    eh = (struct ether_header *)wbuf_header(wbuf);

    src_ip_addr = 0;
    /*  Extract the source ip address from the list*/
    if (vap->iv_opmode == IEEE80211_M_HOSTAP ) {
        if (IEEE80211_IS_MULTICAST(eh->ether_dhost) &&
            !IEEE80211_IS_BROADCAST(eh->ether_dhost)){
            if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
                const struct ip_header *ip = (struct ip_header *)
                    (wbuf_header(wbuf) + sizeof (struct ether_header));
                    src_ip_addr = ntohl(ip->saddr);
                    grp_addr = ntohl(ip->daddr);
            }
            else{
                return -1;  /*ether_type is not equal to 0x0800,instead of dropping packets sending as multicast*/
            }
        }
    }
    /* if grp address is in denied list then don't send process it here*/
    if(ieee80211_me_SnoopIsDenied(vap, grp_addr))
    {
        return -1;
    }
    
    /* Get members of this group */
    /* save original frame's src addr once */
    IEEE80211_ADDR_COPY(srcmac, eh->ether_shost);
    IEEE80211_ADDR_COPY(grpmac, eh->ether_dhost);
    OS_MEMSET(empty_entry_mac, 0, IEEE80211_ADDR_LEN);
    dstmac = eh->ether_dhost;

    newmaccnt = ieee80211_me_SnoopListGetMember(vap, grpmac, grp_addr,
            src_ip_addr, newmac[0], MAX_SNOOP_ENTRIES);

    /* save original frame's src addr once */
    /*
     * If newmaccnt is 0: no member intrested in this group
     *                 1: mc in table, only one dest, skb cloning not needed
     *                >1: multiple mc in table, skb cloned for each entry past
     *                    first one.
     */

    /* Maitain the original wbuf avoid being modified.
     */
    if (newmaccnt > 0 && vap->iv_me->mc_mcast_enable == 0)
    {
        /* We have members intrested in this group and no enhancement is required, send true multicast */
        return -1;
    } else if(newmaccnt == 0) {
        /* no members is intrested, no need to send, just drop it */
            wbuf_complete(wbuf);
        return 1;
    } else if(newmaccnt > MAX_SNOOP_ENTRIES) {
        /* Number of entries is more than supported, send true multicast */
        return -1;
    }

    wbuf1 = wbuf_copy(wbuf);
    wbuf_complete(wbuf);
    wbuf = wbuf1;
    wbuf1 = NULL;
	
	vap->iv_me->me_convert_loops ++;
	
    /* loop start */
    do {    
        if(wbuf == NULL)
            goto bad;

        if (newmaccnt > 0) {    
            /* reference new dst mac addr */
            dstmac = &newmac[newmacidx][0];
            

            /*
             * Note - cloned here pre-tunnel due to the way ieee80211_classify()
             * currently works. This is not efficient.  Better to split 
             * ieee80211_classify() functionality into per node and per frame,
             * then clone the post-tunnelled copy.
             * Currently, the priority must be determined based on original frame,
             * before tunnelling.
             */
            if (newmaccnt > 1) {
                wbuf1 = wbuf_copy(wbuf);
                if(wbuf1 != NULL) {
                    wbuf_clear_flags(wbuf1);
                }
            }
        } else {
            goto bad;
        }
        
        /* In case of loop */
        if(IEEE80211_ADDR_EQ(dstmac, srcmac)) {
            goto bad;
        }
        
        /* In case the entry is an empty one, it indicates that
         * at least one STA joined the group and then left. For this
         * case, if mc_discard_mcast is enabled, this mcast frame will
         * be discarded to save the bandwidth for other ucast streaming 
         */
        if (IEEE80211_ADDR_EQ(dstmac, empty_entry_mac)) {
            if (newmaccnt > 1 || vap->iv_me->mc_discard_mcast) {   
                goto bad;
            } else {
                /*
                 * If empty entry AND not to discard the mcast frames,
                 * restore dstmac to the mcast address
                 */    
                newmaccnt = 0;
                dstmac = eh->ether_dhost;
            }
        }

        /* Look up destination */
        ni = ieee80211_find_txnode(vap, dstmac);
        /* Drop frame if dest not found in tx table */
        if (ni == NULL) {
            goto bad2;
        }

        /* Drop frame if dest sta not associated */
        if (ni->ni_associd == 0 && ni != vap->iv_bss) {
            /* the node hasn't been associated */

            if(ni != NULL) {
                ieee80211_free_node(ni);
            }
            
            if (newmaccnt > 0) {
                ieee80211_me_SnoopWDSNodeCleanup(ni);
            }
            goto bad;
        }


        /* Insert tunnel header
         * eh is the pointer to the ethernet header of the original frame.
         * eh2 is the pointer to the ethernet header of the encapsulated frame.
         *
         */
        if (newmaccnt > 0 /*&& vap->iv_me->mc_mcast_enable*/) {
            /*Option 1: Tunneling*/
            if (vap->iv_me->mc_mcast_enable & 1) {
                /* Encapsulation */
                tunHdr = (struct athl2p_tunnel_hdr *) wbuf_push(wbuf, sizeof(struct athl2p_tunnel_hdr));
                eh2 = (struct ether_header *) wbuf_push(wbuf, sizeof(struct ether_header));
        
                /* ATH_ETH_TYPE protocol subtype */
                tunHdr->proto = 17;
            
                /* copy original src addr */
                IEEE80211_ADDR_COPY(&eh2->ether_shost[0], srcmac);
    
                /* copy new ethertype */
                eh2->ether_type = htons(ATH_ETH_TYPE);

            } else if (vap->iv_me->mc_mcast_enable & 2) {/*Option 2: Translating*/
               eh2 = (struct ether_header *)wbuf_header(wbuf);
            } else {/* no tunnel and no-translate, just multicast */
                eh2 = (struct ether_header *)wbuf_header(wbuf);
            }

            /* copy new dest addr */
            IEEE80211_ADDR_COPY(&eh2->ether_dhost[0], &newmac[newmacidx][0]);

            /*
             *  Headline block removal: if the state machine is in
             *  BLOCKING or PROBING state, transmision of UDP data frames
             *  are blocked untill swtiches back to ACTIVE state.
             */
            if (vap->iv_ique_ops.hbr_dropblocked) {
                if (vap->iv_ique_ops.hbr_dropblocked(vap, ni, wbuf)) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IQUE,
                                     "%s: packet dropped coz it blocks the headline\n",
                                     __func__);
                    goto bad2;
                }
            }
        }
        if (!ieee80211_vap_ready_is_set(vap)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_OUTPUT,
                              "%s: ignore data packet, vap is not active\n",
                              __func__);
            goto bad2;
        }
#ifdef IEEE80211_WDS
        if (vap->iv_opmode == IEEE80211_M_WDS)
            wbuf_set_wdsframe(wbuf);
        else
            wbuf_clear_wdsframe(wbuf);
#endif
        
#if QCA_OL_11AC_FAST_PATH			
		ol_igmp_send_skb_fast(vap,wbuf);
#else		
        if(ol_igmp_send_skb(vap,wbuf))
			goto bad2;
#endif

        /* ieee80211_send_wbuf will increase refcnt for frame to be sent, so decrease refcnt here for the increase by find_txnode. */
        ieee80211_free_node(ni); 
        goto loop_end;

    bad2:
        if (ni != NULL) {
            ieee80211_free_node(ni);
        } 
    bad:
        if (wbuf != NULL) {
            wbuf_complete(wbuf);
        }
         
        if (IEEE80211_IS_MULTICAST(dstmac))
            vap->iv_multicast_stats.ims_tx_discard++;
        else
            vap->iv_unicast_stats.ims_tx_discard++;
        
    
    loop_end:
		vap->iv_me->me_convert_success ++;
        /* loop end */
        if (wbuf1 != NULL) {
            wbuf = wbuf1;
        }
        wbuf1 = NULL;
        newmacidx++;
        xmited ++;
        if(newmaccnt)
            newmaccnt--;
    } while (newmaccnt > 0 && vap->iv_me->mc_snoop_enable); 
    return xmited;
}
#endif




