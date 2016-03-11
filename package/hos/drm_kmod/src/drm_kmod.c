/******************************************************************************
  File Name    : drm_kmod.c
  Author       : lhc
  Date         : 20160302
  Description  : kernel proc msg
******************************************************************************/
#include <linux/types.h>
#include <net/sock.h>
#include <net/netlink.h> 
#include <linux/ip.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/kobject.h>

#include "drm_kmod.h"

#define KDRM_ON               0
#define KDRM_OFF              1
#define KDRM_UDP_PROTOCOL     17
#define DRM_DNS_PROTOCOL      53
#define APURLLEN              128

DEFINE_SPINLOCK(drm_lock);

static int g_drmpid = -1;
static int kdrm_switch = KDRM_ON;
static struct sock *kdrm_sockfd = NULL;
char g_ap_mgmt_url[APURLLEN];

extern void (*kdrm_filter_packet_cb)(struct sk_buff *skb);

/******************************************************************************
  Function Name    : kdrm_sendmsg
  Author           : lhc
  Date             : 20160302
  Description      : drm kernel mod send msg
  Param            : const void *data     send date
                     int datelen          date len
  return Code      : 
******************************************************************************/
static void kdrm_sendmsg(const void *data, int datelen)
{
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlmhdr = NULL;
    unsigned int len = 0;
    int sendret = 0;

    if (NULL == kdrm_sockfd || NULL == data)
    {
        return;
    }

    len = datelen + sizeof(struct nlmsghdr);
    skb = alloc_skb(len, GFP_KERNEL);
    if (NULL == skb)
    {
        printk(KERN_WARNING "[drm kmod]: skb Malloc Failed!\r\n");
        return;
    }

    nlmhdr = nlmsg_put(skb, 0, 0, 0, len - sizeof(struct nlmsghdr), 0);
    NETLINK_CB(skb).portid = g_drmpid;
    NETLINK_CB(skb).dst_group = 0;
    memcpy(nlmsg_data(nlmhdr), data, datelen);
    sendret = netlink_unicast(kdrm_sockfd, skb, g_drmpid, MSG_DONTWAIT);
    
    return;
}

/******************************************************************************
  Function Name    : kdrm_filter_packet
  Author           : lhc
  Date             : 20160302
  Description      : drm kernel filter packet
  Param            : struct sk_buff  *skb          network packet struct
  return Code      : 
******************************************************************************/
void kdrm_filter_packet(struct sk_buff *skb)
{
    if (KDRM_ON != kdrm_switch)
    {
        return;
    }

    struct iphdr *ipptr = NULL;
    struct udpstruct *udpptr;
    unsigned char *buf;
    
    if (NULL == skb)
    {
        return;
    }

    if (skb->len < sizeof(struct iphdr))
    {
        return;
    }
    
    ipptr = (struct iphdr *)(skb->data);
    if (KDRM_UDP_PROTOCOL != ipptr->protocol)
    {
        return;
    }
    
    udpptr = (struct udpstruct *)(skb->data + sizeof(struct iphdr));

    if (skb->len - sizeof(struct iphdr) < sizeof(struct udpstruct))
    {
        return;
    }

    if (DRM_DNS_PROTOCOL != (int)(udpptr->dstport))
    {
        return;
    }
    
    buf = (unsigned char *)(skb->data + sizeof(struct iphdr) + sizeof(struct udpstruct));
    if (0 != (*(buf + 2) >> 7))
    {
        return;
    }

    if (0 != strcmp(g_ap_mgmt_url, buf + 12))
    {
        return;
    }
    printk(KERN_DEBUG "[drm kmod]: strcmp url sucess %s\r\n", buf + 12);
    
    kdrm_sendmsg(skb->data, skb->len);

    ///test
    *buf = 0;
    *(buf + 1) = 1;
    ///end

    return;
}

/******************************************************************************
  Function Name    : kdrm_receive_skb
  Author           : lhc
  Date             : 20160302
  Description      : drm kernel mod recv msg
  Param            : struct sk_buff  *skb          network packet struct
  return Code      : 
******************************************************************************/
static void kdrm_receive_skb(struct sk_buff  *skb)
{
    struct nlmsghdr *nlmhdr = NULL;
    char *ap_mgmt_url = NULL;
    
    if (skb->len >= 0)
    {
        nlmhdr = nlmsg_hdr(skb);
        g_drmpid = NETLINK_CB(skb).portid;
        
        ap_mgmt_url = nlmsg_data(nlmhdr);
        spin_lock(&drm_lock);
        memcpy(g_ap_mgmt_url, ap_mgmt_url, APURLLEN);
        printk(KERN_DEBUG "[drm kmod]: kdrm_receive_skb %s\r\n", g_ap_mgmt_url);
        spin_unlock(&drm_lock);
    }
    
    return;
}

/******************************************************************************
  Function Name    : kdrm_receive
  Author           : lhc
  Date             : 20160302
  Description      : drm kernel mod recv msg
  Param            : struct sk_buff  *skb          network packet struct
  return Code      : 
******************************************************************************/
static void kdrm_receive(struct sk_buff  *skb)
{
	kdrm_receive_skb(skb);

    return;
}

/******************************************************************************
  Function Name    : kdrm_switchshow
  Author           : lhc
  Date             : 20160302
  Description      : drm kernel mod switct value show
  Param            : struct kobject *kobj 
                     struct kobj_attribute 
  return Code      : 
******************************************************************************/
static ssize_t kdrm_switchshow(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%u\r\n", kdrm_switch);
}

/******************************************************************************
  Function Name    : kdrm_switchset
  Author           : lhc
  Date             : 20160302
  Description      : drm kernel mod switct set
  Param            : struct kobject *kobj 
                     struct kobj_attribute *attr 
                     size_t size 
                     const char *buf                set value
  return Code      :
******************************************************************************/
static ssize_t kdrm_switchset(struct kobject *kobj, struct device_attribute *attr, const char *buf, size_t size)
{
    unsigned int state;
    unsigned long ret;
 	ret = kstrtoul(buf, 10, &state);
    if (ret == 0)
    {
        kdrm_switch = state;
    }

    return 1;
}

static struct kobj_attribute kdrm_state = __ATTR(kdrm_disable, 0644, kdrm_switchshow, kdrm_switchset); 
static struct attribute *kdrm_control[] = {
    &kdrm_state.attr,
    NULL,
};
static struct attribute_group kdrm_group = {
    .attrs = kdrm_control,
};

static int sysfs_status = 0 ;
struct kobject *soc_kobj = NULL;
/******************************************************************************
  Function Name    : kdrm_switch_init
  Author           : lhc
  Date             : 20160302
  Description      : drm kernel mod switct exit
  Param            : 
  return Code      : == 0  init suc
                     != 0   init fail
******************************************************************************/
int kdrm_switch_init(void)
{
    int ret = 0;
    
    soc_kobj = kobject_create_and_add("kdrm_control", NULL);
    if (0 == soc_kobj)
    {
        return -1;
    }
    
    ret = sysfs_create_group(soc_kobj, &kdrm_group);
    if (0 != ret)
    {
        sysfs_remove_group(soc_kobj, &kdrm_group);
        kobject_put(soc_kobj);
        return -1;
    }
    
    sysfs_status = 1;
    
    return 0;
}


/******************************************************************************
  Function Name    : kdrm_switch_exit
  Author           : lhc
  Date             : 20160302
  Description      : drm kernel mod switct exit
  Param            : 
  return Code      :
******************************************************************************/
void kdrm_switch_exit(void)
{
    sysfs_remove_group(soc_kobj, &kdrm_group);
    kobject_put(soc_kobj);
       
    return;
}

/******************************************************************************
  Function Name    : kdrm_init
  Author           : lhc
  Date             : 20160302
  Description      : drm kernel mod init
  Param            : 
  return Code      : == 0  init suc
                     != 0   init fail
******************************************************************************/
static int __init kdrm_init(void)
{
 	struct netlink_kernel_cfg cfg = {
		.input	= kdrm_receive,
	};

    if (0 != kdrm_switch_init())
    {
        printk(KERN_ERR "[drm kmod]: mod switch init failed, kmod exit\r\n");
        return -1;
    }
    
    kdrm_sockfd = netlink_kernel_create(&init_net, NETLINK_DRM, &cfg);
    if (NULL == kdrm_sockfd)
    {
        kdrm_switch_exit();
        printk(KERN_ERR "[drm kmod]: netlink create failed, kmod exit\r\n");
        return -1;
    }

    kdrm_filter_packet_cb = kdrm_filter_packet;

    return 0;
}

/******************************************************************************
  Function Name    : kdrm_exit
  Author           : lhc
  Date             : 20160302
  Description      : drm kernel mod exit
  Param            :
  return Code      :
******************************************************************************/
static void __exit kdrm_exit(void)
{
    if (NULL != kdrm_sockfd)
    {
        netlink_kernel_release(kdrm_sockfd);
    }
    
    kdrm_switch_exit();
    
    kdrm_filter_packet_cb = NULL;
}

subsys_initcall(kdrm_init);
module_exit(kdrm_exit);
MODULE_LICENSE("GPL");
