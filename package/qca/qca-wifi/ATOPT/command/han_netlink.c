/************************************************************
Copyright (C), 2006-2013, AUTELAN. Co., Ltd.
FileName: at_netlink.c
Author:Mingzhe Duan 
Version : 1.0
Date:2015-02-03
Description: This file help driver communicates to applications 
                  through a netlink msg.
***********************************************************/

#include "linux/if.h"
#include "linux/socket.h"
#include "linux/netlink.h"
#include <net/sock.h>

#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/cache.h>
#include <linux/proc_fs.h>

#include "han_netlink.h"
#include "sys/queue.h"
#include "han_command.h"
#include "igmp_snooping.h"

struct sock *han_nl_sock = NULL;
static u32 pid=0;
int netlink_debug = 0;

#define MAX_MSGSIZE 1400
//extern void recv_sync_info(char * data);
extern void recv_igmpsnp_info(char * data);
extern void recv_igmp_snooping_list(char * data);

void parse_netlink_frame(u_int32_t port_id, char * data)
{
	switch(port_id){
		case HAN_NETLINK_SYNC_PORT_ID:
			//printk("Driver recv frame from 0x001\n");
			//recv_sync_info(data);
			break;
		case HAN_NETLINK_IGMP_PORT_ID:
			recv_igmp_snooping_list(data);
			break;
		default:
			break;
	}
}

static void printk_netlink_data(unsigned char *data)
{

   int i = 0;
   struct nlmsghdr* hdr = (struct nlmsghdr *) data;
   for(i = 0; i < hdr->nlmsg_len; i ++){
	  if(i && i%20 ==0) printf("\n");
	  printk("%02x ", ((unsigned char*)data)[i]);
   }
}

static INLINE void OS_SET_NETLINK_HEADER_LOCATE(
    void *nlmsghdr, u32 nlmsg_len, u16 nlmsg_type, u16 nlmsg_flags,
    u32 nlmsg_seq, u32 nlmsg_pid)
{
    struct nlmsghdr* hdr = (struct nlmsghdr *) nlmsghdr;
    hdr->nlmsg_len   = nlmsg_len;
    hdr->nlmsg_type  = nlmsg_type;
    hdr->nlmsg_flags = nlmsg_flags;
    hdr->nlmsg_seq   = nlmsg_seq;
    hdr->nlmsg_pid   = nlmsg_pid;
}

void ieee80211_han_netlink_send(unsigned char * message,int buf_len,u_int32_t port_id) 
{
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  int len = OS_NLMSG_SPACE(buf_len);
  int ret = 0;
  if((!message) || (!han_nl_sock) || (port_id == 0)){
      return;
  }

  // malloc sk_buffer
  skb = alloc_skb(len, GFP_KERNEL);
  if(!skb){
      printk(KERN_ERR "[kernel space] my_net_link: alloc_skb Error.\n");
      return;
  }

  nlh = nlmsg_put(skb, 0, 0, 0, buf_len, 0);

  //set netlink header
  OS_SET_NETLINK_HEADER_LOCATE(nlh, NLMSG_LENGTH(buf_len),
					   0,0,0,port_id) ;
  
  // set Netlink control body
  //NETLINK_CB(skb).pid = 0; // id of msg sender, use 0 if it is kernel
  NETLINK_CB(skb).portid = 0; /* from kernel */
  NETLINK_CB(skb).dst_group = 0; //if dest team is kernle or one process, set it to 0

  //message[slen] = '\0';
  memcpy(OS_NLMSG_DATA(nlh), message, buf_len);

//  printk("Send msg to application, PID is %d\n",port_id);
  //use netlink_unicast(), send msg to process appoint by dstPID in user space
  
  if(netlink_debug){
  	   int i;
	   printk("driver:netlink send pid = %d\n",port_id);
	   printk_netlink_data(nlh);
  }
  ret = netlink_unicast(han_nl_sock, skb, port_id, MSG_DONTWAIT);
  if( ret < 0){
      //printk(KERN_ERR "[kernel space] net_link: can not unicast skb. pid = %d  ret = %d\n",pid,ret);
      return;
  }
  return;

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
static void han_netlink_receive(struct sk_buff *skb)
#else
static void han_netlink_receive(struct sock *sk, int len)
#endif
{ 
   struct nlmsghdr *nlh;
   unsigned char *data;
   if (skb->len >= NLMSG_SPACE(0)) {
       nlh = (struct nlmsghdr *)skb->data;
       data = (char *)NLMSG_DATA(nlh);
       if( pid == 0 ) 
       {
          printk("\n[kernel space] Pid == 0 %d \n ",pid);
       }
       pid = nlh->nlmsg_pid;  //get process pid
       if(netlink_debug){
	   	    printk("driver:netlink receive pid = %d\n",pid);
			printk_netlink_data(skb->data);
	   }
       parse_netlink_frame(nlh->nlmsg_pid,data);
   }
   return;

}

int han_netlink_init(void)
{
	printk("netlink driver:%s HAN_NETLINK_ATHEROS=%d",__func__,HAN_NETLINK_ATHEROS);
    if (han_nl_sock == NULL) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION (3,10,49)
		struct netlink_kernel_cfg cfg = {
			.groups = 1,
			.input = &han_netlink_receive,
			.cb_mutex = NULL,
		};

		han_nl_sock = (struct sock *)netlink_kernel_create(&init_net, HAN_NETLINK_ATHEROS, &cfg);
		
		printk("netlink driver:han_nl_sock = %p",han_nl_sock);
		
#elif LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
        han_nl_sock = (struct sock *)netlink_kernel_create(&init_net, HAN_NETLINK_ATHEROS,
                                   1, &han_netlink_receive, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,22)
        han_nl_sock = (struct sock *)netlink_kernel_create(HAN_NETLINK_ATHEROS,
                                   1, &han_netlink_receive, (struct mutex *) NULL, THIS_MODULE);
#else
        han_nl_sock = (struct sock *)netlink_kernel_create(HAN_NETLINK_ATHEROS,
                                   1, &han_netlink_receive, THIS_MODULE);
#endif

        if (han_nl_sock == NULL) {
            printk("%s NETLINK_KERNEL_CREATE FAILED\n", __func__);
            return -ENODEV;
        }
        printk("%s NETLINK_KERNEL_CREATE OK\n", __func__);
    }
    return 0;
}

int han_netlink_delete(void)
{
    if (han_nl_sock) {
        sock_release(han_nl_sock->sk_socket);
        han_nl_sock = NULL;
    }

    return 0;
}
EXPORT_SYMBOL(han_netlink_init);
EXPORT_SYMBOL(han_netlink_delete);
EXPORT_SYMBOL(ieee80211_han_netlink_send);
