#ifndef __HAN_NETLINK_H
#define __HAN_NETLINK_H

#define HAN_NETLINK_ATHEROS     (NETLINK_GENERIC + 8)
#define OS_NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define OS_NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))

#define HAN_NETLINK_SYNC_PORT_ID  0X01
#define HAN_NETLINK_IGMP_PORT_ID  0X02


#define OS_NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define OS_NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))


extern int netlink_debug;


#define MAC_ADDR_LEN           6 
typedef struct ath_netlink_event {
	u_int32_t type;
	u_int8_t mac[MAC_ADDR_LEN];
	u_int32_t datalen;
} ath_netlink_event_t;

extern int han_netlink_init(void);
extern int han_netlink_delete(void);

extern void ieee80211_han_netlink_send(unsigned char * message,int buf_len,u_int32_t port_id); 


/*AUTELAN-Added-Begin:Added by pengdecai for wifi scan locate function*/
#pragma pack(1)

#pragma pack()
/*AUTELAN-Added-end:Added by pengdecai for wifi scan locate function*/
/* End: gengzj added end */


#endif
