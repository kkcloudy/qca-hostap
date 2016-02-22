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

#include "ath_netlink.h"
#include "sys/queue.h"

struct sock *sync_nl_sock = NULL;
static u32 pid=0;
#define MAX_MSGSIZE 1400
#define NETLINK_SYNC_EVENT 23
extern void recv_sync_info(char * data);

void sync_netlink_send(unsigned char * message,int buf_len) 
{
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  int len = NLMSG_SPACE(buf_len);
  int ret = 0;
  if((!message) || (!sync_nl_sock) || (pid == 0)){
      return;
  }

  // malloc sk_buffer
  skb = alloc_skb(len, GFP_KERNEL);
  if(!skb){
      printk(KERN_ERR "[kernel space] my_net_link: alloc_skb Error.\n");
      return;
  }

  nlh = nlmsg_put(skb, 0, 0, 0, buf_len, 0);

  // set Netlink control body
  //NETLINK_CB(skb).pid = 0; // id of msg sender, use 0 if it is kernel
  NETLINK_CB(skb).portid = 0; /* from kernel */
  NETLINK_CB(skb).dst_group = 0; //if dest team is kernle or one process, set it to 0

  //message[slen] = '\0';
  memcpy(NLMSG_DATA(nlh), message, buf_len);

  //use netlink_unicast(), send msg to process appoint by dstPID in user space
  ret = netlink_unicast(sync_nl_sock, skb, pid, MSG_DONTWAIT);
  if( ret < 0){
      //printk(KERN_ERR "[kernel space] net_link: can not unicast skb. pid = %d  ret = %d\n",pid,ret);
      return;
  }
  return;

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
static void sync_netlink_receive(struct sk_buff *skb)
#else
static void sync_netlink_receive(struct sock *sk, int len)
#endif
{ 
   struct nlmsghdr *nlh;
   unsigned char *msg;
   //int i = 0;
   if (skb->len >= NLMSG_SPACE(0)) {
       nlh = (struct nlmsghdr *)skb->data;
       msg = (char *)NLMSG_DATA(nlh);
       if( pid == 0 ) 
       {
          printk("\n[kernel space] Pid == 0 %d \n ",pid);
       }
       pid = nlh->nlmsg_pid;  //get process pid
       recv_sync_info(msg);
       //kfree_skb(skb);
   }
   return;

}
int sync_netlink_init(void)
{
    if (sync_nl_sock == NULL) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION (3,10,49)
		struct netlink_kernel_cfg cfg = {
			.groups = 1,
			.input = &sync_netlink_receive,
			.cb_mutex = NULL,
		};

		sync_nl_sock = (struct sock *)netlink_kernel_create(&init_net, NETLINK_SYNC_EVENT, &cfg);
		
#elif LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
        sync_nl_sock = (struct sock *)netlink_kernel_create(&init_net, NETLINK_SYNC_EVENT,
                                   1, &sync_netlink_receive, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,22)
        sync_nl_sock = (struct sock *)netlink_kernel_create(NETLINK_SYNC_EVENT,
                                   1, &sync_netlink_receive, (struct mutex *) NULL, THIS_MODULE);
#else
        sync_nl_sock = (struct sock *)netlink_kernel_create(NETLINK_SYNC_EVENT,
                                   1, &sync_netlink_receive, THIS_MODULE);
#endif
        if (sync_nl_sock == NULL) {
            printk("%s NETLINK_KERNEL_CREATE FAILED\n", __func__);
            return -ENODEV;
        }
        printk("%s NETLINK_KERNEL_CREATE OK\n", __func__);
    }
    return 0;
}

int sync_netlink_delete(void)
{
    if (sync_nl_sock) {
        sock_release(sync_nl_sock->sk_socket);
        sync_nl_sock = NULL;
    }

    return 0;
}
EXPORT_SYMBOL(sync_netlink_init);
EXPORT_SYMBOL(sync_netlink_delete);
EXPORT_SYMBOL(sync_netlink_send);
