/*
*pengdecai added for han private wmm.
*/
#include <wireless_qos.h>
#include <ah.h>
#include <ieee80211_defines.h>
#include <osif_private.h>
#include <osapi_linux.h>
#include <uapi/linux/if_vlan.h> 

#if ATH_PERF_PWR_OFFLOAD && ATH_SUPPORT_DSCP_OVERRIDE
extern int ol_ath_set_vap_dscp_tid_map(struct ieee80211vap *vap);
#endif

typedef PREPACK struct {
    u_int16_t vlan_tci;
    u_int16_t vlan_encap_p;
} POSTPACK vlan_hdr_t;



#define WMM_STORE_INFO_USER_TO_DRIVER(vap,arg,ac){\
	int i;\
	memset(vap->priv_wmm.ac.priority,0x0,PRI_MAX_NUM);\
	for (i = 0; i < arg->u.wmm.arg_num; i ++){\
		vap->priv_wmm.ac.priority[i] = arg->u.wmm.wmm_args.ac[i];\
		}\
	vap->priv_wmm.ac.num = arg->u.wmm.arg_num;\
}

#define WMM_STORE_INFO_DRIVER_TO_USER(vap,arg,ac){\
	int i;\
	for (i = 0; i < vap->priv_wmm.ac.num ; i ++){\
		arg->u.wmm.wmm_args.ac[i] = vap->priv_wmm.ac.priority[i];\
		}\
	arg->u.wmm.arg_num = vap->priv_wmm.ac.num;\
}

#define SET_DSCP_TO_WMM_AMP(vap,ac,WME_AC){\
	int i;\
	unsigned char dscp =0;\
	for (i = 0;i < vap->priv_wmm.ac.num; i++){\
		dscp = vap->priv_wmm.ac.priority[i];\
		vap->priv_wmm.dscp_to_wmm_map[dscp] = WME_AC;\
	}\
}

#define SET_VLAN_TO_WMM_AMP(vap,ac,WME_AC){\
	int i;\
	unsigned char vlan = 0;\
	for (i = 0;i < vap->priv_wmm.ac.num; i++){\
		vlan = vap->priv_wmm.ac.priority[i];\
		vap->priv_wmm.vlan_to_wmm_map[vlan] = WME_AC;\
	}\
}

int ieee80211_priv_wmm_init(struct ieee80211vap *vap)
{
    int retv =0;
	memset(&vap->priv_wmm,0x0,sizeof(struct	han_wmm));
	vap->priv_wmm.wmm_flag = 1;
	
	retv = wlan_set_param(vap, IEEE80211_FEATURE_WMM, vap->priv_wmm.wmm_flag);
	if(vap->iv_ic->ic_is_mode_offload(vap->iv_ic)) {
        /* For offload interface the AMPDU parameter corresponds to
         * number of subframes in AMPDU
         */
        if (vap->priv_wmm.wmm_flag) {
            /* WMM is enabled - reset number of subframes in AMPDU
             * to 64
             */
            wlan_set_param(vap, IEEE80211_FEATURE_AMPDU, 64);
        }
        else {
            wlan_set_param(vap, IEEE80211_FEATURE_AMPDU, 0);
        }
    } else {
        wlan_set_param(vap, IEEE80211_FEATURE_AMPDU, vap->priv_wmm.wmm_flag);
    } 
	
	//vap->priv_wmm.
	return retv;
}
u_int8_t print_dscp_to_wmm_map(struct ieee80211vap *vap)
{
	int i;
	
    for (i = 0;i < 64;i ++){
		printk("dscp = %d-> wmm = %d\n",i,vap->priv_wmm.dscp_to_wmm_map[i]);
    }
	return 0;
}
u_int8_t print_8021p_to_wmm_map(struct ieee80211vap *vap)
{
	int i;
		
	for (i = 0;i < 8;i ++){
		printk("8021P = %d-> wmm = %d\n",i,vap->priv_wmm.vlan_to_wmm_map[i]);
	}
	return 0;
}

u_int8_t dscp_to_wmm(struct ieee80211vap *vap,u_int8_t dscp)
{
	u_int8_t ac =  WME_AC_BE;
	if( dscp > 63 ){
		vap->priv_wmm.dscp_to_wmm_error++;
		return 0;
	}
	vap->priv_wmm.dscp_to_wmm_ok ++;
	ac = vap->priv_wmm.dscp_to_wmm_map[dscp];
	if(vap->priv_wmm.debug == 1){
		printk("DSCP->WMM:set(2/4): dscp =%d -> WMM_AC=%d\n",dscp,ac);
	}
	
	return ac;
}

int
ieee80211_ioctl_wireless_qos(struct net_device *dev,struct han_ioctl_priv_args *a,struct iwreq *iwr)
{
	int retv = 0;
	osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
	int i;
	
	switch (a->u.wmm.subtype) {
		case HAN_IOCTL_WMM_ENABLE:
			if(OP_SET == a->u.wmm.op){
				vap->priv_wmm.wmm_flag = a->u.wmm.wmm_args.wmm_enable;
				
				retv = wlan_set_param(vap, IEEE80211_FEATURE_WMM, vap->priv_wmm.wmm_flag);
	            if(osifp->osif_is_mode_offload) {
		            /* For offload interface the AMPDU parameter corresponds to
		             * number of subframes in AMPDU
		             */
		            if (vap->priv_wmm.wmm_flag) {
		                /* WMM is enabled - reset number of subframes in AMPDU
		                 * to 64
		                 */
		                wlan_set_param(vap, IEEE80211_FEATURE_AMPDU, 64);
		            }
		            else {
		                wlan_set_param(vap, IEEE80211_FEATURE_AMPDU, 0);
		            }
		        } else {
		            wlan_set_param(vap, IEEE80211_FEATURE_AMPDU, vap->priv_wmm.wmm_flag);
		        }
		        if (retv == EOK) {
		            retv = ENETRESET;
		        }
			}else if(OP_GET == a->u.wmm.op){
				a->u.wmm.wmm_args.wmm_enable = vap->priv_wmm.wmm_flag;
			}else {
				retv = ENETRESET;
			}
			break;
			
		case HAN_IOCTL_WMM_DSCP_ENABLE:
			if(OP_SET == a->u.wmm.op){
				vap->priv_wmm.dscp_flag= a->u.wmm.wmm_args.dscp_enable;
				if(osifp->osif_is_mode_offload) {
					vap->iv_override_dscp = vap->priv_wmm.dscp_flag;
				}
			}else if(OP_GET == a->u.wmm.op){
				a->u.wmm.wmm_args.dscp_enable = vap->priv_wmm.dscp_flag;
			}else {
				retv = ENETRESET;
			}
			break;
			
		case HAN_IOCTL_WMM_8021P_ENABLE:
			if(OP_SET == a->u.wmm.op){
				vap->priv_wmm.vlan_flag = a->u.wmm.wmm_args.vlan_enable;
				
			}else if(OP_GET == a->u.wmm.op){
				a->u.wmm.wmm_args.vlan_enable = vap->priv_wmm.vlan_flag;
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_DEBUG:
			if(OP_SET == a->u.wmm.op){
				vap->priv_wmm.debug= a->u.wmm.wmm_args.debug;
				if(vap->priv_wmm.debug == 3){
					print_dscp_to_wmm_map(vap);
				}else if(vap->priv_wmm.debug == 4){
					print_8021p_to_wmm_map(vap);
				}
			}else if(OP_GET == a->u.wmm.op){
				a->u.wmm.wmm_args.debug= vap->priv_wmm.debug;
			}else {
				retv = ENETRESET;
			}
				break;
		case HAN_IOCTL_WMM_DSCP_TO_BK:
			if(OP_SET == a->u.wmm.op){
				WMM_STORE_INFO_USER_TO_DRIVER(vap,a,dscp_to_bk);
				SET_DSCP_TO_WMM_AMP(vap,dscp_to_bk,WME_AC_BK);
				if(osifp->osif_is_mode_offload) {
					ol_set_dscp_to_wmm(vap);
				}
		    }else if(OP_GET == a->u.wmm.op){
				WMM_STORE_INFO_DRIVER_TO_USER(vap,a,dscp_to_bk);
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_DSCP_TO_BE:
			if(OP_SET == a->u.wmm.op){
				WMM_STORE_INFO_USER_TO_DRIVER(vap,a,dscp_to_be);
				SET_DSCP_TO_WMM_AMP(vap,dscp_to_be,WME_AC_BE);
				if(osifp->osif_is_mode_offload) {
					ol_set_dscp_to_wmm(vap);
				}
		    }else if(OP_GET == a->u.wmm.op){
				WMM_STORE_INFO_DRIVER_TO_USER(vap,a,dscp_to_be);
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_DSCP_TO_VI:
			if(OP_SET == a->u.wmm.op){
				WMM_STORE_INFO_USER_TO_DRIVER(vap,a,dscp_to_vi);
				SET_DSCP_TO_WMM_AMP(vap,dscp_to_vi,WME_AC_VI);
				if(osifp->osif_is_mode_offload) {
					ol_set_dscp_to_wmm(vap);
				}
		    }else if(OP_GET == a->u.wmm.op){
				WMM_STORE_INFO_DRIVER_TO_USER(vap,a,dscp_to_vi);
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_DSCP_TO_VO:
			if(OP_SET == a->u.wmm.op){
				WMM_STORE_INFO_USER_TO_DRIVER(vap,a,dscp_to_vo);
				SET_DSCP_TO_WMM_AMP(vap,dscp_to_vo,WME_AC_VO);
				if(osifp->osif_is_mode_offload) {
					ol_set_dscp_to_wmm(vap);
				}
		    }else if(OP_GET == a->u.wmm.op){
				WMM_STORE_INFO_DRIVER_TO_USER(vap,a,dscp_to_vo);
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_BK_TO_DSCP:
			if(OP_SET == a->u.wmm.op){
				vap->priv_wmm.wmm_to_dscp_map[WME_AC_BK] = a->u.wmm.wmm_args.bk_to_dscp;
			}else if(OP_GET == a->u.wmm.op){
				a->u.wmm.wmm_args.bk_to_dscp = vap->priv_wmm.wmm_to_dscp_map[WME_AC_BK];
			}else {
				retv = ENETRESET;
			} 
			break;
		case HAN_IOCTL_WMM_BE_TO_DSCP:
			if(OP_SET == a->u.wmm.op){
				vap->priv_wmm.wmm_to_dscp_map[WME_AC_BE] = a->u.wmm.wmm_args.be_to_dscp;
			}else if(OP_GET == a->u.wmm.op){
				a->u.wmm.wmm_args.be_to_dscp = vap->priv_wmm.wmm_to_dscp_map[WME_AC_BE];
			}else {
				retv = ENETRESET;
			} 
			
			break;
		case HAN_IOCTL_WMM_VI_TO_DSCP:
			if(OP_SET == a->u.wmm.op){
				vap->priv_wmm.wmm_to_dscp_map[WME_AC_VI] = a->u.wmm.wmm_args.vi_to_dscp;
			}else if(OP_GET == a->u.wmm.op){
				a->u.wmm.wmm_args.vi_to_dscp = vap->priv_wmm.wmm_to_dscp_map[WME_AC_VI];
			}else {
				retv = ENETRESET;
			} 
			break;
		case HAN_IOCTL_WMM_VO_TO_DSCP:
			if(OP_SET == a->u.wmm.op){
			vap->priv_wmm.wmm_to_dscp_map[WME_AC_VO] = a->u.wmm.wmm_args.vo_to_dscp;
			
			}else if(OP_GET == a->u.wmm.op){
			a->u.wmm.wmm_args.vo_to_dscp = vap->priv_wmm.wmm_to_dscp_map[WME_AC_VO];
			}else {
				retv = ENETRESET;
			} 
			break;
		case HAN_IOCTL_WMM_8021P_TO_BK:
			if(OP_SET == a->u.wmm.op){
				WMM_STORE_INFO_USER_TO_DRIVER(vap,a,vlan_to_bk);
				SET_VLAN_TO_WMM_AMP(vap,vlan_to_bk,WME_AC_BK);
				
		    }else if(OP_GET == a->u.wmm.op){
				WMM_STORE_INFO_DRIVER_TO_USER(vap,a,vlan_to_bk);
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_8021P_TO_BE:
			if(OP_SET == a->u.wmm.op){
				WMM_STORE_INFO_USER_TO_DRIVER(vap,a,vlan_to_be);
				SET_VLAN_TO_WMM_AMP(vap,vlan_to_be,WME_AC_BE);
		    }else if(OP_GET == a->u.wmm.op){
				WMM_STORE_INFO_DRIVER_TO_USER(vap,a,vlan_to_be);
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_8021P_TO_VI:
			if(OP_SET == a->u.wmm.op){
				WMM_STORE_INFO_USER_TO_DRIVER(vap,a,vlan_to_vi);
				SET_VLAN_TO_WMM_AMP(vap,vlan_to_vi,WME_AC_VI);
		    }else if(OP_GET == a->u.wmm.op){
				WMM_STORE_INFO_DRIVER_TO_USER(vap,a,vlan_to_vi);
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_8021P_TO_VO:
			if(OP_SET == a->u.wmm.op){
				WMM_STORE_INFO_USER_TO_DRIVER(vap,a,vlan_to_vo);
				SET_VLAN_TO_WMM_AMP(vap,vlan_to_vo,WME_AC_VO);
		    }else if(OP_GET == a->u.wmm.op){
				WMM_STORE_INFO_DRIVER_TO_USER(vap,a,vlan_to_vo);
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_BK_TO_8021P:
			if(OP_SET == a->u.wmm.op){
				vap->priv_wmm.wmm_to_vlan_map[WME_AC_BK] = a->u.wmm.wmm_args.bk_to_vlan;
			}else if(OP_GET == a->u.wmm.op){
				a->u.wmm.wmm_args.bk_to_vlan = vap->priv_wmm.wmm_to_vlan_map[WME_AC_BK];
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_BE_TO_8021P:
			if(OP_SET == a->u.wmm.op){
				vap->priv_wmm.wmm_to_vlan_map[WME_AC_BE] = a->u.wmm.wmm_args.be_to_vlan;
			}else if(OP_GET == a->u.wmm.op){
				a->u.wmm.wmm_args.be_to_vlan = vap->priv_wmm.wmm_to_vlan_map[WME_AC_BE] ;
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_VI_TO_8021P:
			if(OP_SET == a->u.wmm.op){
				vap->priv_wmm.wmm_to_vlan_map[WME_AC_VI] = a->u.wmm.wmm_args.vi_to_vlan;
			}else if(OP_GET == a->u.wmm.op){
			   a->u.wmm.wmm_args.vi_to_vlan = vap->priv_wmm.wmm_to_vlan_map[WME_AC_VI];
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_VO_TO_8021P:
			if(OP_SET == a->u.wmm.op){
				vap->priv_wmm.wmm_to_vlan_map[WME_AC_VO] = a->u.wmm.wmm_args.vo_to_vlan;
			}else if(OP_GET == a->u.wmm.op){
				a->u.wmm.wmm_args.vo_to_vlan = vap->priv_wmm.wmm_to_vlan_map[WME_AC_VO];
			}else {
				retv = ENETRESET;
			}
			break;
		case HAN_IOCTL_WMM_STATISTICS:
			a->u.wmm.wmm_stat.wmm_enable = vap->priv_wmm.wmm_flag;
			a->u.wmm.wmm_stat.dscp_enable = vap->priv_wmm.dscp_flag;
			a->u.wmm.wmm_stat.vlan_enable = vap->priv_wmm.vlan_flag;
			a->u.wmm.wmm_stat.dscp_to_wmm_packets_ok = vap->priv_wmm.dscp_to_wmm_ok;
			a->u.wmm.wmm_stat.dscp_to_wmm_packets_error = vap->priv_wmm.dscp_to_wmm_error;
			a->u.wmm.wmm_stat.wmm_to_dscp_packets_ok = vap->priv_wmm.wmm_to_dscp_ok;
			a->u.wmm.wmm_stat.wmm_to_dscp_packets_error = vap->priv_wmm.wmm_to_dscp_error;
			a->u.wmm.wmm_stat.vlan_to_wmm_packets_ok = vap->priv_wmm.vlan_to_wmm_ok;
			a->u.wmm.wmm_stat.vlan_to_wmm_packets_error = vap->priv_wmm.vlan_to_wmm_error;
			a->u.wmm.wmm_stat.wmm_to_vlan_packets_ok = vap->priv_wmm.wmm_to_vlan_ok;
			a->u.wmm.wmm_stat.wmm_to_vlan_packets_error = vap->priv_wmm.wmm_to_vlan_error;
			break;
		default:
			return -EFAULT;		
	}

	if(OP_GET == a->u.wmm.op){
		copy_to_user(iwr->u.data.pointer, a, sizeof(struct han_ioctl_priv_args));
	}
	
	return retv;
}


u_int8_t 
ieee80211_dscp_to_wmm(struct ieee80211vap *vap, wbuf_t wbuf)
{
	struct ether_header *eh = (struct ether_header *)wbuf->data;
	u_int8_t ac = WME_AC_BE;
	u_int8_t tid = 0;
	
	if(vap->priv_wmm.debug == 1){
		printk("DSCP->WMM:set(1/4): start \n");
	}
	
	if (eh->ether_type == __constant_htons(ETHERTYPE_IP)) {
		const struct iphdr *ip = (struct iphdr *)
		(wbuf->data + sizeof (struct ether_header));
		ac = dscp_to_wmm(vap,(ip->tos >> 2));

	}
	else if(eh->ether_type == __constant_htons(ETHERTYPE_IPV6))
	{
		struct ipv6hdr * ipv6h = (struct ipv6hdr*)(wbuf->data + sizeof(struct ether_header));
		unsigned char tos = 0;		
		tos = ipv6h->priority;
		tos = tos << 4;
		tos |= (ipv6h->flow_lbl[0] >> 4);
		tid = dscp_to_wmm(vap,(tos >> 2));
		ac = TID_TO_WME_AC(tid);
	}
	
	return ac;
}

/*return ac */
u_int8_t 
ieee80211_vlan_priv_to_wmm(struct ieee80211vap *vap,u_int8_t v_priv)
{	
	u_int8_t ac = WME_AC_BE;

    if( v_priv > 7){
		vap->priv_wmm.vlan_to_wmm_error ++;
		return WME_AC_BE;
	}
	vap->priv_wmm.vlan_to_wmm_ok ++;
	ac = vap->priv_wmm.vlan_to_wmm_map[v_priv];
	if(vap->priv_wmm.debug == 2){
		printk("802.1P->WMM:step(1/3): 802.1P = %d -> WMM_AC = %d\n",v_priv,ac);
	}  
	return ac;
}

u_int8_t 
ieee80211_wmm_to_dscp(struct ieee80211vap *vap, u_int8_t ac)
{	
	u_int8_t dscp = 0;
	if(ac > WME_AC_VO){
		vap->priv_wmm.wmm_to_dscp_error++;
		return 0;
	}
	vap->priv_wmm.wmm_to_dscp_ok ++;
	dscp = vap->priv_wmm.wmm_to_dscp_map[ac];
	
	if(vap->priv_wmm.debug == 1){
		printk("WMM->DSCP:step(2/2): WMM_AC = %d -> DSCP = %d\n",ac,dscp);
	}  
	
	return dscp;
}

u_int8_t 
ieee80211_wmm_to_vlan(struct ieee80211vap *vap, u_int8_t ac)
{
    u_int8_t vlan = 0;
	if(ac > 3){
		
		vap->priv_wmm.wmm_to_vlan_error++;
		return 0;
	}
	vap->priv_wmm.wmm_to_vlan_ok ++;
	vlan = 	vap->priv_wmm.wmm_to_vlan_map[ac];
	
	if(vap->priv_wmm.debug == 2){
		printk("WMM->802.1P:step(2/3):WMM_AC = % -> 8021P = %d ",ac,vlan);
	}  
	return vlan;
}


u_int8_t 
ieee80211_do_wmm_to_dscp(struct ieee80211vap *vap, wbuf_t wbuf)
{
	u_int32_t hdrspace = 0;
	u_int16_t frametype = 0;
	struct ieee80211_frame * wh ;
    struct llc *llc_type = NULL;
	
	wh= (struct ieee80211_frame *) wbuf_header(wbuf);
	hdrspace = ieee80211_hdrspace(vap->iv_ic, wbuf_header(wbuf));
	llc_type = (struct llc *)skb_pull(wbuf, hdrspace);
	
	if(vap->priv_wmm.debug == 1){
			printk("WMM->DSCP:set(1/2): start\n");
	}   
	
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

	if ((frametype == __constant_htons(ETHERTYPE_IP)\
		|| frametype == __constant_htons(ETHERTYPE_IPV6)))
		{
			u_int8_t tid = ((struct ieee80211_qosframe *)wh)->i_qos[0] & IEEE80211_QOS_TID;
			struct iphdr *iph = (struct iphdr *)(wbuf->data + hdrspace + LLC_SNAPFRAMELEN);
		    
			if(4 == iph->version)
			{
				iph->tos = ieee80211_wmm_to_dscp(vap,TID_TO_WME_AC(tid)) << 2;
				iph->check = 0;
				iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
			}
			else if(6 == iph->version)
			{
				unsigned char tos = 0;
				struct ipv6hdr * ipv6h = (struct ipv6hdr*)(wbuf->data + hdrspace + LLC_SNAPFRAMELEN);
				tos =  ieee80211_wmm_to_dscp(vap,TID_TO_WME_AC(tid)) << 2;
				ipv6h->priority = tos >> 4;
				ipv6h->flow_lbl[0] |= ((tos <<4) & 0xf0);
			}

	}
	return 0;
}

int ol_set_dscp_to_wmm(struct ieee80211vap *vap)
{
	int i = 0;
	u_int8_t tid = 0;
	
#if ATH_SUPPORT_DSCP_OVERRIDE	
	for (i = 0; i < IP_DSCP_MAP_LEN ; i ++){
	    tid = WME_AC_TO_TID(vap->priv_wmm.dscp_to_wmm_map[i]);
	    vap->iv_dscp_tid_map[i]= tid;
	}

	ol_ath_set_vap_dscp_tid_map(vap);
#endif
	return 0;
}

int ol_do_vlan_to_wmm(struct ieee80211vap *vap,struct sk_buff *skb)
{
    struct vlan_ethhdr *veth = (struct vlan_ethhdr *) skb->data;
	u_int8_t tos, ac;
	u_int16_t vlan_tci;
	/*
	** Determine if this is an 802.1p frame, and get the proper
	** priority information as required
	*/

	if (veth->h_vlan_proto == __constant_htons(ETH_P_8021Q) )
	{
		vlan_tci =__constant_ntohs(veth->h_vlan_TCI);
		tos = (vlan_tci >> VLAN_PRI_SHIFT) & VLAN_PRI_MASK;
		ac = ieee80211_vlan_priv_to_wmm(vap,tos);
		tos = WME_AC_TO_TID(ac);
		vlan_tci &= (VLAN_PRI_MASK << VLAN_PRI_SHIFT);
		vlan_tci |= ((tos & VLAN_PRI_MASK) << VLAN_PRI_SHIFT);
		veth->h_vlan_TCI = __constant_htons(vlan_tci);
	}
	if(vap->priv_wmm.debug == 2){

		printk("802.1P->WMM:step(2/3)5G-end: vlan_tci = %d\n",vlan_tci);
	}  
	return 0;
}




static int 
ol_ieee80211_do_wmm_to_dscp(struct ieee80211vap *vap,struct sk_buff *skb,u_int8_t tid)
{
    u_int8_t *ethertype;
	u_int16_t typeorlength = 0;
//	u_int8_t ac = WME_AC_BE;
	u_int8_t hdr_len = 0;
//	u_int16_t vlan = 0;
	u_int16_t frametype = 0;

	hdr_len = WMM_ETHR_HDR_LEN;
	frametype = ((struct ether_header *) skb->data)->ether_type;	
	if (frametype == __constant_htons(ETHERTYPE_VLAN)) {
		hdr_len += WMM_VLAN_LEN;
	} 
	
	if(vap->priv_wmm.debug == 1){
			printk("WMM->DSCP:set(1/2): start\n");
	} 
	
	if (frametype == __constant_htons(ETHERTYPE_IP)\
		|| frametype == __constant_htons(ETHERTYPE_IPV6))
		{
	        struct iphdr *iph = (struct iphdr *)(skb->data + hdr_len);
			
			if(4 == iph->version)
			{
				iph->tos = ieee80211_wmm_to_dscp(vap,TID_TO_WME_AC(tid)) << 2;
				iph->check = 0;
				iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
			}
			else if(6 == iph->version)
			{
				unsigned char tos = 0;
				struct ipv6hdr * ipv6h = (struct ipv6hdr*)(skb->data + hdr_len);
				tos =  ieee80211_wmm_to_dscp(vap,TID_TO_WME_AC(tid)) << 2;
				ipv6h->priority = tos >> 4;
				ipv6h->flow_lbl[0] |= ((tos <<4) & 0xf0);
			}
	}
	return 0;
}
static int 
ol_ieee80211_do_wmm_to_vlan(struct ieee80211vap *vap,struct sk_buff *skb,u_int8_t tid)
{
	u_int8_t vlan = 0;
	
	if(vap->priv_wmm.debug == 2){
		 printk("WMM->802.1P:step(1/3):start tid = %d",tid);
	} 
	vlan = ieee80211_wmm_to_vlan(vap,TID_TO_WME_AC(tid));
	
	wbuf_set_qosframe(skb);
	wbuf_set_priority(skb,vlan);
	if(vap->priv_wmm.debug == 2){
		printk("WMM->802.1P:step(3/3):End:WMM_AC = %d , 802.1P = %d",TID_TO_WME_AC(tid),wbuf_get_priority(skb));
	} 
	return 0;
}

void
ol_ieee80211_do_wmm_to_dscp_vlan(os_if_t osif, struct sk_buff *skb,u_int8_t tid)
{
	//osif_dev  *osdev = (osif_dev *)osif;
	wlan_if_t vap = ((osif_dev *)osif)->os_if;
	
	if(ieee80211_vap_wme_is_set(vap)){
			if(vap->priv_wmm.dscp_flag){
			    ol_ieee80211_do_wmm_to_dscp(vap,skb,tid);
			}else if(vap->priv_wmm.vlan_flag){
				ol_ieee80211_do_wmm_to_vlan(vap,skb,tid);
			}
	}
	return ;
}



