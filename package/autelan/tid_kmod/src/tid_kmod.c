/******************************************************************************
  文 件 名   : kernel_tid.c
  作    者   : wenjue
  生成日期   : 2014年11月19日
  功能描述   : 终端识别模块解析相应报文并将设备信息发送给UM模块
******************************************************************************/
#include <linux/types.h>
#include <net/sock.h>
#include <net/netlink.h> 
#include <linux/ip.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include "tid_kmod.h"

#define KTID_IP 0X800
#define KTID_ON 0
#define KTID_OFF 1

#define KTID_HTTP_PROTOCOL 1
#define KTID_DHCP_PROTOCOL 2
#define KTID_NETBIOS_PROTOCOL 3
#define KTID_BONJOUR_PROTOCOL 4

#define KTID_TCP_PROTOCOL     6
#define KTID_UDP_PROTOCOL     17
#define KTID_HTTPSERVER_PORT  80
#define KTID_DHCPSERVER_PORT  67
#define KTID_DHCPCLIENT_PORT  68
#define KTID_NETBIOSSERVER_PORT  138
#define KTID_BONJOURSERVER_PORT  5353

#define KTID_BONJOUR_RESPONSE 33792 /*0X8400*/
#define KTID_NETBIOS_REQUEST  17
#define KTID_BONJOUR_HINFOMSG 13
#define KTID_NETBIOS_MSGLEN   168
#define KTID_NETBIOS_COMMANDTYPE 2

static int g_tidpid = -1;
static int ktid_switch = KTID_ON;
static struct timer_list ktid_timer;
static struct sock *ktid_sockfd = NULL;
static struct tidtablehead g_sttidtabhd = {
    .next = NULL,
};

extern void (*ktid_filter_packet_cb)(struct sk_buff *skb);
DEFINE_SPINLOCK(tid_lock);

struct tidmachdr{
    unsigned char mac[6];
    unsigned short portocoltype;
    unsigned int datalen;
};

/*****************************************************************************
 函 数 名  : ktid_set_flag
 功能描述  : 设置过滤表项中节点需过滤的协议类型
 输入参数  : char flagtype, 需过滤的协议类型标识
 输出参数  : struct tidtable *psttidtabnode, 需要设置过滤标识的节点
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static void ktid_set_flag(struct tidtable *psttidtabnode, char flagtype)
{
    if (KTID_HTTP_PROTOCOL == flagtype)
    {
        psttidtabnode->httpflag = 1;
    }
    if (KTID_NETBIOS_PROTOCOL == flagtype)
    {
        psttidtabnode->netbiosflag = 1;
    }
    if (KTID_BONJOUR_PROTOCOL == flagtype)
    {
        psttidtabnode->bonjourflag = 1;
    }

    return;
}

/*****************************************************************************
 函 数 名  : ktid_get_httpflag
 功能描述  : 获取终端http协议的过滤标识
 输入参数  : const char *mac, 标识终端的mac地址
 输出参数  : 无
 返 回 值  : == 0 不需要过滤, 此报文发送给用户空间
             != 0 需要过滤, 此报文不发送给用户空间
 作   者   : wenjue
*****************************************************************************/
static unsigned char ktid_get_httpflag(const char *mac)
{
    struct tidtable *psttidtabnode = NULL;
    unsigned char httpflag = 0;
    
    if (NULL == mac)
    {
        return 1;
    }

    psttidtabnode = g_sttidtabhd.next;
    while (NULL != psttidtabnode)
    {
        if (0 == memcmp(psttidtabnode->mac, mac, sizeof(psttidtabnode->mac)))
        {
            httpflag = psttidtabnode->httpflag;
            break;
        }
        psttidtabnode = psttidtabnode->next;
    }
    
    return httpflag;
}

/*****************************************************************************
 函 数 名  : ktid_get_netbiosflag
 功能描述  : 获取终端netbios协议的过滤标识
 输入参数  : const char *mac, 标识终端的mac地址
 输出参数  : 无
 返 回 值  : == 0 不需要过滤, 此报文发送给用户空间
             != 0 需要过滤, 此报文不发送给用户空间
 作   者   : wenjue
*****************************************************************************/
static unsigned char ktid_get_netbiosflag(const char *mac)
{
    struct tidtable *psttidtabnode = NULL;
    unsigned char netbiosflag = 0;
    
    if (NULL == mac)
    {
        return netbiosflag;
    }

    psttidtabnode = g_sttidtabhd.next;
    while (NULL != psttidtabnode)
    {
        if (0 == memcmp(psttidtabnode->mac, mac, sizeof(psttidtabnode->mac)))
        {
            netbiosflag = psttidtabnode->netbiosflag;
            break;
        }
        psttidtabnode = psttidtabnode->next;
    }
    
    return netbiosflag;
}

/*****************************************************************************
 函 数 名  : ktid_get_bonjourflag
 功能描述  : 获取终端bonjour协议的过滤标识
 输入参数  : const char *mac, 标识终端的mac地址
 输出参数  : 无
 返 回 值  : == 0 不需要过滤, 此报文发送给用户空间
             != 0 需要过滤, 此报文不发送给用户空间
 作   者   : wenjue
*****************************************************************************/
static unsigned char ktid_get_bonjourflag(const char *mac)
{
    struct tidtable *psttidtabnode = NULL;
    unsigned char bonjourflag = 0;
    
    if (NULL == mac)
    {
        return bonjourflag;
    }

    psttidtabnode = g_sttidtabhd.next;
    while (NULL != psttidtabnode)
    {
        if (0 == memcmp(psttidtabnode->mac, mac, sizeof(psttidtabnode->mac)))
        {
            bonjourflag = psttidtabnode->bonjourflag;
            break;
        }
        psttidtabnode = psttidtabnode->next;
    }
    
    return bonjourflag;
}

/*****************************************************************************
 函 数 名  : ktid_destroy_table
 功能描述  : 删除过滤表项, tid_kmod会定时调用
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static void ktid_destroy_table(void)
{
    struct tidtable *pstcurnode = NULL;
    struct tidtable *pstnextnode = NULL;

    pstcurnode = g_sttidtabhd.next;
    while (NULL != pstcurnode)
    {   
        pstnextnode = pstcurnode->next;
        kfree(pstcurnode);
        pstcurnode = pstnextnode;
    }
    g_sttidtabhd.next = NULL;
}

/*****************************************************************************
 函 数 名  : ktid_update_table
 功能描述  : 定时更新过滤表项, 此函数根据定时时间反复调用
 输入参数  : unsigned long data, 与定时器执行的处理函数兼容, 此处并无意义
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static void ktid_update_table(unsigned long data)
{
    spin_lock(&tid_lock);
    ktid_destroy_table();
    spin_unlock(&tid_lock);
    ktid_timer.expires = jiffies + 10*HZ;
    add_timer(&ktid_timer);
    
    return;
}

/*****************************************************************************
 函 数 名  : ktid_modify_tablenode
 功能描述  : 修改过滤表项中的过滤条件
 输入参数  : const char *mac, 标识过滤表项中终端节点的mac地址
             char flagtype, 需要修改的过滤协议类型标识
 输出参数  : 无
 返 回 值  : == 0, 成功修改过滤条件
             != 0, 未找到修改的节点, 需要将增加此mac标识的过滤节点
 作   者   : wenjue
*****************************************************************************/
static int ktid_modify_tablenode(const char *mac, char flagtype)
{
    struct tidtable *psttidtabnode = NULL;
    int ret = -1;

    if (NULL == mac)
    {
        return ret;
    }
    
    psttidtabnode = g_sttidtabhd.next;
    while (NULL != psttidtabnode)
    {
        if (0 == memcmp(psttidtabnode->mac, mac, sizeof(psttidtabnode->mac)))
        {
            ktid_set_flag(psttidtabnode, flagtype);
            ret = 0;
            break;
        }
        psttidtabnode = psttidtabnode->next;
    }

    return ret;
}

/*****************************************************************************
 函 数 名  : ktid_add_tablenode
 功能描述  : 新增过滤节点
 输入参数  : const char *mac, 标识过滤终端节点的mac地址
             char flagtype, 需要过滤的协议类型标识
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static void ktid_add_tablenode(const char *mac, char flagtype)
{
    struct tidtable *psttidtabnode = NULL;
    
    if (NULL == mac)
    {
        return;
    }

    psttidtabnode = kmalloc(sizeof(struct tidtable), GFP_KERNEL);
    if (NULL == psttidtabnode)
    {
        printk(KERN_ERR "[tid_kmod]: unable to allocate memory for tidfilternode");
        
        return;
    }
    memset(psttidtabnode, 0, sizeof(struct tidtable));
    memcpy(psttidtabnode->mac, mac, sizeof(psttidtabnode->mac));
    ktid_set_flag(psttidtabnode, flagtype);
    psttidtabnode->next = g_sttidtabhd.next;
    g_sttidtabhd.next = psttidtabnode;

    return;
}

/*****************************************************************************
 函 数 名  : ktid_get_httpmsglen
 功能描述  : 获取http报文首部长度
 输入参数  : const unsigned char *data, 指向http报文头
             int maxlen, 此报文最大长度, 防止访问越界
 输出参数  : 无
 返 回 值  : unsigned int 获取得到的报文首部长度
 作   者   : wenjue
*****************************************************************************/
static unsigned int ktid_get_httpmsglen(const unsigned char *data, int maxlen)
{
    unsigned int len = 0;

    if (0 != memcmp(data, "GET ", 4))
    {
        return len;
    }
    while (1)
    {
        /*judge httpmsg prelude ending*/
        if ((*(data + len) == 13) && (*(data + len + 2) == 13))
        {
            break;
        }
        len++;
        if (len + 4 > maxlen)
        {
            return 0;
        }
    }
    len += 4;

    return len;
}

/*****************************************************************************
 函 数 名  : ktid_filter_tcppacket
 功能描述  : tcp包处理函数
 输入参数  : const char *data, 指向tcp包头
             int len, 此报文最大长度, 防止访问越界
 输出参数  : struct tidmachdr *pstmachdr, tid模块定义的以太网首部, 此处获取的报文长度
 返 回 值  : == 0, 此报文需要发送至用户空间
             != 0, 此报文已被过滤,不需要发往用户空间
 作   者   : wenjue
*****************************************************************************/
static int ktid_filter_tcppacket(struct tidmachdr *pstmachdr, const char *data, int len)
{
    int ret = -1;
    struct tcphead *tcpptr = NULL;

    if (len < sizeof(struct tcphead))
    {
        return ret;
    }
    
    tcpptr = (struct tcphead *)data;
    if (len < tcpptr->headlen / 4)/*tcpotr->headlen << 2*/
    {
        return ret;
    }
    if (KTID_HTTPSERVER_PORT == tcpptr->dstport)
    {   
        pstmachdr->datalen = ktid_get_httpmsglen(data + tcpptr->headlen / 4, len - tcpptr->headlen / 4);   
    }
    if (0 != pstmachdr->datalen)
    {         
        spin_lock(&tid_lock);
        ret = ktid_get_httpflag(pstmachdr->mac);
        spin_unlock(&tid_lock);
        pstmachdr->portocoltype = KTID_HTTP_PROTOCOL;
    }  
    pstmachdr->datalen += tcpptr->headlen / 4;

    return ret;
}

/*****************************************************************************
 函 数 名  : ktid_ishinfomsg
 功能描述  : bonjour报文处理函数
 输入参数  : const char *data, 指向bonjour报文头
             int maxlen, 此报文最大长度, 防止访问越界
 输出参数  : 无
 返 回 值  : == 0, 此报文需要发送至用户空间
             != 0, 此报文已被过滤,不需要发往用户空间
 作   者   : wenjue
*****************************************************************************/
static int ktid_ishinfomsg(const char *data, int maxlen)
{
    int i = 0;
    struct bonjourhead bonjourhd;

    memset(&bonjourhd, 0, sizeof(bonjourhd));
    if (maxlen < sizeof(bonjourhd))
    {
        return -1;
    }

    if (KTID_BONJOUR_RESPONSE != *((unsigned short *)(data + 2)))
    {
        return -1;
    }
    i += sizeof(bonjourhd);
    while (0 != *(data + i))
    {
        i++;
        if (maxlen < i + 1)
        {
            return -1;
        }
    }
    if (KTID_BONJOUR_HINFOMSG == *((unsigned short *)(data + 1 + i)))
    {
        return 0;
    }

    return -1;
}

/*****************************************************************************
 函 数 名  : ktid_isconnetreq
 功能描述  : netbios报文处理函数
 输入参数  : const char *data, 指向netbios报文头
             int maxlen, 此报文最大长度, 防止访问越界
 输出参数  : 无
 返 回 值  : == 0, 此报文需要发送至用户空间
             != 0, 此报文已被过滤,不需要发往用户空间
 作   者   : wenjue
*****************************************************************************/
static int ktid_isconnetreq(const unsigned char *data, int maxlen)
{
    if (maxlen < KTID_NETBIOS_MSGLEN)
    {
        return -1;
    }
    
    if ((KTID_NETBIOS_REQUEST == *data) && (KTID_NETBIOS_COMMANDTYPE == *(data + KTID_NETBIOS_MSGLEN)))
    {
        return 0;
    }

    return -1;
}

/*****************************************************************************
 函 数 名  : ktid_filter_udppacket
 功能描述  : udp包处理函数
 输入参数  : const char *data, 指向包头
             int len, 此报文最大长度, 防止访问越界
 输出参数  : 无
 返 回 值  : == 0, 此报文需要发送至用户空间
             != 0, 此报文已被过滤,不需要发往用户空间
 作   者   : wenjue
*****************************************************************************/
static int ktid_filter_udppacket(unsigned int len, struct tidmachdr *pstmachdr, const char *data)
{
    int ret = -1;
    struct udpstruct *udpptr = (struct udpstruct *)data;

    if (len < sizeof(struct udpstruct))
    {
        return ret;
    }

    if (KTID_NETBIOSSERVER_PORT == udpptr->dstport)
    {    
        if (0 == ktid_isconnetreq(data + sizeof(struct udpstruct), len - sizeof(struct udpstruct)))
        {
            spin_lock(&tid_lock);
            ret = ktid_get_netbiosflag(pstmachdr->mac);
            spin_unlock(&tid_lock);
            pstmachdr->portocoltype = KTID_NETBIOS_PROTOCOL;
        }
    }
    if (KTID_BONJOURSERVER_PORT == udpptr->dstport)
    {   
        if (0 == ktid_ishinfomsg(data + sizeof(struct udpstruct), len - sizeof(struct udpstruct)))
        {   spin_lock(&tid_lock);
            ret = ktid_get_bonjourflag(pstmachdr->mac);
            spin_unlock(&tid_lock);
            pstmachdr->portocoltype = KTID_BONJOUR_PROTOCOL;
        }
    }
    if (KTID_DHCPSERVER_PORT == udpptr->dstport)
    {
        ret = 0;
        pstmachdr->portocoltype = KTID_DHCP_PROTOCOL;
    }
    if (KTID_DHCPCLIENT_PORT == udpptr->dstport)
    {
        ret = 0;
        pstmachdr->portocoltype = KTID_DHCP_PROTOCOL;
    }

    return ret;
}

/*****************************************************************************
 函 数 名  : ktid_sendmsg
 功能描述  : tid_kmod至用户空间的封装、发送函数
 输入参数  : const char *data, 此处是一个ip包
             const struct tidmachdr *pstmachdr, tid_kmod自定义封装的mac头
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static void ktid_sendmsg(const void *data, const struct tidmachdr *pstmachdr)
{
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlmhdr = NULL;
    unsigned int len = 0;
    int sendret = 0;

    if (NULL == ktid_sockfd || NULL == data || NULL == pstmachdr)
    {
        return;
    }

    len = pstmachdr->datalen + sizeof(struct tidmachdr) + sizeof(struct nlmsghdr);
    skb = alloc_skb(len, GFP_KERNEL);
    if (NULL == skb)
    {
        printk(KERN_WARNING "[tid_kmod]: skb Malloc Failed!\r\n");
        return;
    }

    nlmhdr = nlmsg_put(skb, 0, 0, 0, len - sizeof(struct nlmsghdr), 0);
    NETLINK_CB(skb).portid = g_tidpid;
    NETLINK_CB(skb).dst_group = 0;
    memcpy(nlmsg_data(nlmhdr), pstmachdr, sizeof(struct tidmachdr));
    memcpy(nlmsg_data(nlmhdr) + sizeof(struct tidmachdr), data, pstmachdr->datalen);
    sendret = netlink_unicast(ktid_sockfd, skb, g_tidpid, MSG_DONTWAIT);
    
    return;
}

/*****************************************************************************
 函 数 名  : ktid_filter_packet
 功能描述  : 钩子函数, 用于从数据链路层钩出包含ip包、802.3以太网头的skb网络数据包
             并对此网络包进行处理(并不进行修改、仅仅进行读取、判断、拷贝操作)
 输入参数  : struct sk_buff *skb, 钩子函数钩出的网络数据包
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
void ktid_filter_packet(struct sk_buff *skb)
{
    if (KTID_ON != ktid_switch)
    {
        return;
    }

    struct machead *macptr = NULL;
    struct iphdr *ipptr = NULL;
    int flag = -1;
    unsigned char mac[6] = {0};
    unsigned char broadcastmsg[6] = {255, 255, 255, 255, 255, 255};
    struct tidmachdr stmachdr;

    if (NULL == skb)
    {
        return;
    }

    macptr = (struct machead *)(skb->mac_header);
    memset(&stmachdr, 0, sizeof(stmachdr));

    if ((0 == strncmp(skb->dev->name, "wlan", 4)) || (0 == strncmp(skb->dev->name, "ath", 3)))
    {
        memcpy(stmachdr.mac, macptr->src_mac, 6);
    }
    else
    {
        memcpy(stmachdr.mac, macptr->dst_mac, 6);
    }
    if (0 == strncmp(stmachdr.mac, broadcastmsg, 6))
    {
        return;
    }
    
    if (skb->len < sizeof(struct iphdr))
    {
        return;
    }
    
    ipptr = (struct iphdr *)(skb->data);
    if (KTID_TCP_PROTOCOL == ipptr->protocol)
    {
        flag = ktid_filter_tcppacket(&stmachdr, (const char *)(skb->data + sizeof(struct iphdr)), skb->len - sizeof(struct iphdr));
        stmachdr.datalen = stmachdr.datalen + sizeof(struct iphdr);
    }
    else if (KTID_UDP_PROTOCOL == ipptr->protocol)
    {
        flag = ktid_filter_udppacket(skb->len - sizeof(struct iphdr), &stmachdr, (const char *)(skb->data + sizeof(struct iphdr)));
        stmachdr.datalen = skb->len;
    }
    else
    {
        return;
    }

    if (0 == flag)
    {
        ktid_sendmsg(skb->data, &stmachdr);
    }

    return;
}

/*****************************************************************************
 函 数 名  : ktid_receive_skb
 功能描述  : tid_kmod处理接收到的用户空间发送的netlink消息
 输入参数  : struct sk_buff  *skb, 接收到的数据指针
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static void ktid_receive_skb(struct sk_buff  *skb)
{
    struct nlmsghdr *nlmhdr = NULL;
    struct tidmachdr *machdr = NULL;

    if (skb->len >= 0)
    {
        nlmhdr = nlmsg_hdr(skb);
        g_tidpid = NETLINK_CB(skb).portid;
        machdr = nlmsg_data(nlmhdr);
        spin_lock(&tid_lock);
        if(ktid_modify_tablenode(machdr->mac, machdr->portocoltype) < 0)
        {
            ktid_add_tablenode(machdr->mac, machdr->portocoltype);
        }
        spin_unlock(&tid_lock);
    }
    
    return;
}

/*****************************************************************************
 函 数 名  : ktid_receive
 功能描述  : tid_kmod处理用户空间netlink消息的函数指针
 输入参数  : struct sk_buff  *skb, 接收到的数据指针
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static void ktid_receive(struct sk_buff  *skb)
{
	ktid_receive_skb(skb);

    return;
}

/*****************************************************************************
 函 数 名  : ktid_init_timer
 功能描述  : 定时器初始化函数
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static void ktid_init_timer(void)
{
    init_timer(&ktid_timer);
    ktid_timer.function = ktid_update_table;
    ktid_timer.expires = jiffies + 10*HZ;
    add_timer(&ktid_timer);

    return;
}

/*****************************************************************************
 函 数 名  : ktid_switchshow
 功能描述  : ktid_switch内核变量的show方法
 输入参数  : struct kobject *kobj, 兼容函数接口, 此处并无意义
             struct kobj_attribute *attr, 兼容函数接口, 此处并无意义
 输出参数  : char *buf, 输出缓冲区
 返 回 值  : ssize_t, 兼容函数接口, 此处并无意义
 作   者   : wenjue
*****************************************************************************/
static ssize_t ktid_switchshow(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%u\r\n", ktid_switch);
}

/*****************************************************************************
 函 数 名  : ktid_switchset
 功能描述  : ktid_switch内核变量的store方法
 输入参数  : struct kobject *kobj, 兼容函数接口, 此处并无意义
             struct kobj_attribute *attr, 兼容函数接口, 此处并无意义
             size_t size, 兼容函数接口, 此处并无意义
             const char *buf, 修改的内核变量值
 输出参数  : 无
 返 回 值  : ssize_t, 兼容函数接口, 此处并无意义
 作   者   : wenjue
*****************************************************************************/
static ssize_t ktid_switchset(struct kobject *kobj, struct device_attribute *attr, const char *buf, size_t size)
{
    unsigned int state;
    int ret;
 	ret = kstrtoul(buf, 10, &state);
    if (ret == 0)
    {
        ktid_switch = state;
    }

    return 1;
}

static struct kobj_attribute ktid_state = __ATTR(ktid_disable, 0644, ktid_switchshow, ktid_switchset); 
static struct attribute *ktid_control[] = {
    &ktid_state.attr,
    NULL,
};
static struct attribute_group ktid_group = {
    .attrs = ktid_control,
};

static int sysfs_status = 0 ;
struct kobject *soc_kobj = NULL;
/*****************************************************************************
 函 数 名  : tid_switch_init
 功能描述  : 提供给用户空间开启关闭tid_kmod功能的开关初始化
 输入参数  : 无
 输出参数  : 无
 返 回 值  : == 0, 初始化成功
             != 0, 初始化失败
 作   者   : wenjue
*****************************************************************************/
int tid_switch_init(void)
{
    int ret = 0;
    soc_kobj = kobject_create_and_add("ktid_control", NULL);
    if (0 == soc_kobj)
    {
        return -1;
    }
    ret = sysfs_create_group(soc_kobj, &ktid_group);
    if (0 != ret)
    {
        sysfs_remove_group(soc_kobj, &ktid_group);
        kobject_put(soc_kobj);
        return -1;
    }
    sysfs_status = 1;
    return 0;
}

/*****************************************************************************
 函 数 名  : tid_switch_exit
 功能描述  : 提供给用户空间开启关闭tid_kmod功能的开关去初始化
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
void tid_switch_exit(void)
{
    sysfs_remove_group(soc_kobj, &ktid_group);
    kobject_put(soc_kobj);
       
    return;
}

/*****************************************************************************
 函 数 名  : ktid_init
 功能描述  : tid_kmod初始化函数
 输入参数  : 无
 输出参数  : 无
 返 回 值  : == 0, 初始化成功
             != 0, 初始化失败
 作   者   : wenjue
*****************************************************************************/
static int __init ktid_init(void)
{

 	struct netlink_kernel_cfg cfg = {
		.input	= ktid_receive,
	};

    if (0 != tid_switch_init())
    {
        printk(KERN_ERR "[tid_kmod]: mod switch init failed, kmod exit\r\n");
        return -1;
    }
    ktid_sockfd = netlink_kernel_create(&init_net, NETLINK_TID, &cfg);
    if (NULL == ktid_sockfd)
    {
        tid_switch_exit();
        printk(KERN_ERR "[tid_kmod]: netlink create failed, kmod exit\r\n");
        return -1;
    }

    ktid_init_timer();
    ktid_filter_packet_cb = ktid_filter_packet;

    return 0;
}

/*****************************************************************************
 函 数 名  : ktid_exit
 功能描述  : tid_kmod去初始化函数
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static void __exit ktid_exit(void)
{
    if (NULL != ktid_sockfd)
    {
        netlink_kernel_release(ktid_sockfd);
    }
    tid_switch_exit();
    del_timer(&ktid_timer);
    spin_lock(&tid_lock);
    ktid_destroy_table();
    spin_unlock(&tid_lock);
    ktid_filter_packet_cb = NULL;
}

subsys_initcall(ktid_init);
module_exit(ktid_exit);
MODULE_LICENSE("GPL");
