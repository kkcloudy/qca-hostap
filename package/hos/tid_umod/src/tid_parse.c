/******************************************************************************
  文 件 名   : tid_parse.c
  作    者   : wenjue
  生成日期   : 2014年11月19日
  功能描述   : 终端识别模块解析相应报文并将设备信息发送给UM模块
******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <unistd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>

#include "tid_parse.h"
#include "tid_debug.h"

#define TID_PORT 5600
#define TID_CMD_MAX_LEN 128
#define TID_HOSTIP_MAX_LEN 20
#define TID_USER_AGENT_MAXLEN 128
#define ITD_HTTP_METHOD_MAXLEN 8

#define TID_HTTP_PROTOCOL 1
#define TID_DHCP_PROTOCOL 2
#define TID_NETBIOS_PROTOCOL 3
#define TID_BONJOUR_PROTOCOL 4

/*****************************************************************************
 函 数 名  : create_client
 功能描述  : 创建udp socket客户端、用于跟UM模块通信、
             注意, 每个线程均需注册一个客户端
 输入参数  : 无
 输出参数  : struct sockaddr_in *serv_addr
 返 回 值  : int >= 0 返回成功、返回成功注册的socket描述符
                 <  0 返回失败
 作   者   : wenjue
*****************************************************************************/
int create_client(struct sockaddr_in *serv_addr)
{
    int socketfd = -1;

    socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd < 0)
    {
        tid_debug_error("[tid]: socket client failed!");
        return -1;
    }
    
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr->sin_port = htons(TID_PORT);

    return socketfd;
}

/*****************************************************************************
 函 数 名  : parse_dhcp_callback
 功能描述  : 传递给libpcap接口用户处理数据包的回调函数
             用来解析dhcp报文，获取设备主机名、MAC地址信息
             并将解析得到的数据发送给UM模块
 输入参数  : u_char *userless, 包含用于与UM模块通信的udp socket
                               服务端的端口号及地址信息
             const struct pcap_pkthdr *pkthdr, 回调函数参数、此处无意义
             const u_char *packet, dhcp链路层数据包
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static int tid_parse_dhcpmsg(const void *packet, struct usrtidmachdr *machdr, struct socket_clientinfo *socket)
{
    struct dhcphead *dhcphdr = NULL;
    struct devinfo stdevinfo;
    char *dataoption = NULL;
    int datalen = 0;
    int sendret = -1;
    int len = 0;
    int i = 0; 
 
    if (packet == NULL || NULL == machdr || NULL == socket)
    {
        return -1;
    }

    len += sizeof(struct iphdr);
    len += sizeof(struct udpstruct);
    dhcphdr = (struct dhcphead *)(packet + len);
    memset(&stdevinfo, 0, sizeof(stdevinfo));
    i = 0;
    sprintf(stdevinfo.mac, "%02x", dhcphdr->clientmac[i]);
    while (i < 5)
    {
        i++;
        sprintf(stdevinfo.mac, "%s:%02x", stdevinfo.mac, dhcphdr->clientmac[i]);
    }

    if (2 == dhcphdr->messagetype)
    {
        i = 0;
        sprintf(stdevinfo.ipaddr, "%d", dhcphdr->yourip[i]);
        while (i < 3)
        {
            i++;
            sprintf(stdevinfo.ipaddr, "%s.%d", stdevinfo.ipaddr, dhcphdr->yourip[i]);
        }
        sendret = sendto(socket->socketfd, (void *)&stdevinfo, sizeof(stdevinfo), 0,
               (struct sockaddr*)&socket->serv_addr, sizeof(socket->serv_addr));
    }
    else if (1 != dhcphdr->messagetype)
    {
        return -1;
    }

    len += sizeof(struct dhcphead);
    dataoption = (char *)(packet + len);
    while (0 != *dataoption)
    {
        if (12 == *dataoption)
        {
            dataoption += 1;
            datalen = *dataoption;
            dataoption += 1;
            memcpy(stdevinfo.hostname, dataoption, datalen);
            sendret = sendto(socket->socketfd, (void *)&stdevinfo, sizeof(stdevinfo), 0,
                      (struct sockaddr*)&socket->serv_addr, sizeof(socket->serv_addr));
            break;
        }
        dataoption += 1;
        datalen += 2;
        datalen += *dataoption;
        dataoption += *dataoption;
        dataoption += 1;
    }
    if (sendret == sizeof(stdevinfo))
    {
        tid_debug_trace("[tid]: send devinfo to um success!");
    }
    
    return sendret;
}

/*****************************************************************************
 函 数 名  : tid_parse_devstr
 功能描述  : 解析http报文的User-Agent字段、获取设备信息
 输入参数  : const char *devstr，User-Agent字段字符串
 输出参数  : struct devinfo *devinfo, 用来存储设备信息的缓存,需调用者提供空间
 返 回 值  : int == 0 解析成功
                 != 0 解析失败
 作   者   : wenjue
*****************************************************************************/
static int tid_parse_devstr(struct devinfo *devinfo, const char *devstr)
{
    char tmp[TID_USER_AGENT_MAXLEN] = {0};
    char *option = NULL;
    
    if (devstr == NULL || devinfo == NULL)
    {
        return -1;
    }

    memcpy(tmp, devstr, sizeof(tmp) - 1);
    option = strtok(tmp, " ");
    if (NULL == option)
    {
        return -1;
    }

    if (0 == strncasecmp(option, "iphone;", strlen(option)))
    {
        memcpy(devinfo->devtype, "iphone", sizeof(devinfo->devtype));
        memcpy(devinfo->ostype, "IOS", sizeof(devinfo->ostype));
        return 0;
    }
    if (0 == strncasecmp(option, "ipad;", strlen(option)))
    {
        memcpy(devinfo->devtype, "ipad", sizeof(devinfo->devtype));
        memcpy(devinfo->ostype, "IOS", sizeof(devinfo->ostype));
        return 0;
    }
    if (0 == strncasecmp(option, "Linux;", strlen(option)))
    {
        if (NULL != strstr(devstr, "Android"))
        {
            if (NULL != strstr(devstr, "MI"))
            {
                memcpy(devinfo->devmodel, "MI", sizeof(devinfo->devmodel));
                memcpy(devinfo->devtype, "MI", sizeof(devinfo->devtype));
            }
            memcpy(devinfo->ostype, "android", sizeof(devinfo->ostype));
            return 0;
        }
    }
    if (0 == strncasecmp(option, "X11;", strlen(option)))
    {
        option = strtok(NULL, ";");
        if (NULL != option)
        {
            memcpy(devinfo->ostype, option, sizeof(devinfo->ostype));
            memcpy(devinfo->devtype, "PC", sizeof(devinfo->devtype));
            return 0;
        }
    }
    if (0 == strncasecmp(option, "Windows", strlen(option)))
    {
        memcpy(devinfo->ostype, "windows", sizeof(devinfo->ostype));
        memcpy(devinfo->devtype, "PC", sizeof(devinfo->devtype));
        return 0;
    }
    if (0 == strncasecmp(option, "Macintosh;", strlen(option)))
    {
        memcpy(devinfo->devtype, "Mac PC", sizeof(devinfo->devtype));
        memcpy(devinfo->ostype, "Mac OS", sizeof(devinfo->ostype));
        return 0;
    }

    return -1;
}

/*****************************************************************************
 函 数 名  : tid_parse_useragent
 功能描述  : 从数据包中拆分出User-Agent字段
 输入参数  : const char *ua, 包含User-Agent字段的数据包
 输出参数  : struct devinfo *devinfo, 用来存储设备信息的缓存,需调用者提供空间
 返 回 值  : int == 0 解析成功
                 != 0 解析失败
 作   者   : wenjue
*****************************************************************************/
static int tid_parse_useragent(struct devinfo *devinfo, const char *ua)
{
    char tmp[TID_USER_AGENT_MAXLEN] = {0};
    char *devstr = NULL;
    if (ua == NULL || devinfo == NULL)
    {
        return -1;
    }

    memcpy(tmp, ua, sizeof(tmp) - 1);
    devstr = strtok(tmp, "(");
    if (devstr == NULL)
    {
        return -1;
    }
    devstr = strtok(NULL, ")");
    if (devstr == NULL)
    {
        return -1;    
    }

    return tid_parse_devstr(devinfo, devstr);
}

/*****************************************************************************
 函 数 名  : tid_parse_ishttptail
 功能描述  : 用于判断http报文是否已经解析到结尾,避免访问非法内存
 输入参数  : const char *data, http数据包
 输出参数  : 无
 返 回 值  : int == 1 已到达结尾
                 == 0 未到达结尾
 作   者   : wenjue
*****************************************************************************/
static int tid_parse_ishttptail(const char *data)
{
    int i = 0;
    int istail = 0;

    while (i <= 10)
    {
        if ((10 == *(data + i)) && (10 == *(data + i + 2)))
        {
            istail = 1;
            break;
        }
        i ++;
    }

    return istail;
}

/*****************************************************************************
 函 数 名  : parse_http_callback
 功能描述  : 传递给libpcap接口用户处理数据包的回调函数
             用来解析http报文，获取设备形态(PC、iphone、ipad等)、MAC地址
             并将解析得到的数据发送给UM模块
 输入参数  : u_char *userless, 包含用于与UM模块通信的udp socket
                               服务端的端口号及地址信息
             const struct pcap_pkthdr *pkthdr, 回调函数参数、此处无意义
             const u_char *packet, http链路层数据包
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static int tid_parse_httpmsg(const void *packet, struct usrtidmachdr *machdr, struct socket_clientinfo *socket)
{
    struct tcphead *tcpptr = NULL;
    struct devinfo stdevinfo;
    struct iphdr *ipptr = NULL;
    char reqmethod[ITD_HTTP_METHOD_MAXLEN] = {0};
    char *data = NULL;
    unsigned int ipaddr = 0;
    int ret = -1;
    int sendret = -1;
    int len = 0;
    int i = 0;

    if (packet == NULL || NULL == machdr || NULL == socket)
    {
        return -1;
    }

    memset(&stdevinfo, 0, sizeof(stdevinfo));
    i = 0;
    sprintf(stdevinfo.mac, "%02x", machdr->mac[i]);
    while (i < 5)
    {
        i++;
        sprintf(stdevinfo.mac, "%s:%02x", stdevinfo.mac, machdr->mac[i]);
    }
    ipptr = (struct iphdr *)(packet + len);
    i = 0;
    ipaddr = ntohl(ipptr->saddr);
    sprintf(stdevinfo.ipaddr, "%d", *((unsigned char *)&ipaddr));
    while (i < 3)
    {
        i++;
        sprintf(stdevinfo.ipaddr, "%s.%d", stdevinfo.ipaddr, *(((unsigned char *)&ipaddr) + i));
    }
    len += sizeof(struct iphdr);
    data = (char *)(packet + len);
    tcpptr = (struct tcphead *)data;
    len += tcpptr->headlen/4;
    
    data = (char *)(packet + len);
    memcpy(reqmethod, data, 4);
    if (0 != strncasecmp(reqmethod, "GET ", 4))
    {
        return -1;
    }
    
    i = 0;
    while(1)
    {
        if (*(data + i) == 10)
        {
            if (0 == strncasecmp(data + i + 1, "User-Agent:", 11))
            {
                ret = tid_parse_useragent(&stdevinfo, data + i + 13);
                break;
            }
        }
        if (tid_parse_ishttptail(data + i))
        {
            break;
        }
        i++;
    }
    if (0 == ret)
    {
        sendret = sendto(socket->socketfd, (void *)&stdevinfo, sizeof(stdevinfo), 0,
               (struct sockaddr*)&socket->serv_addr, sizeof(socket->serv_addr));
    }
    if (sendret == sizeof(stdevinfo))
    {
        tid_debug_trace("[tid]: send devinfo to um success!");
    }
  
    return sendret;
}

/*****************************************************************************
 函 数 名  : parse_netbios_callback
 功能描述  : 传递给libpcap接口用户处理数据包的回调函数
             用来解析netbios报文，获取设备操作系统、主机名、MAC地址
             并将解析得到的数据发送给UM模块
 输入参数  : u_char *userless, 包含用于与UM模块通信的udp socket
                               服务端的端口号及地址信息
             const struct pcap_pkthdr *pkthdr, 回调函数参数、此处无意义
             const u_char *packet, netbios链路层数据包
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static int tid_parse_netbiosmsg(const void *packet, struct usrtidmachdr *machdr, struct socket_clientinfo *socket)
{
    struct iphdr *ipptr = NULL;
    struct mwbpreq *mwbpptr = NULL;
    struct devinfo stdevinfo;
    unsigned char *data = NULL;
    unsigned int ipaddr = 0;
    int len = 0;
    int sendret = -1;
    int i = 0;
 
    if (packet == NULL || NULL == machdr || NULL == socket)
    {
        return -1;
    }

    memset(&stdevinfo, 0, sizeof(stdevinfo)); 
    i = 0;
    sprintf(stdevinfo.mac, "%02x", machdr->mac[i]);
    while (i < 5)
    {
        i++;
        sprintf(stdevinfo.mac, "%s:%02x", stdevinfo.mac, machdr->mac[i]);
    }
    
    ipptr = (struct iphdr *)(packet + len);
    i = 0;
    ipaddr = ntohl(ipptr->saddr);
    sprintf(stdevinfo.ipaddr, "%d", *((unsigned char *)&ipaddr));
    while (i < 3)
    {
        i++;
        sprintf(stdevinfo.ipaddr, "%s.%d", stdevinfo.ipaddr, *(((unsigned char *)&ipaddr) + i));
    }
    len += sizeof(struct iphdr);
    len += sizeof(struct udpstruct);
    data = (unsigned char *)(packet + len);
    if (*data != 17)
    {
        return -1;
    }
    len += 168;
    
    mwbpptr = (struct mwbpreq*)(packet + len);
    if (2 == mwbpptr->commondtype)
    {
        memcpy(stdevinfo.hostname, mwbpptr->hostname, sizeof(stdevinfo.hostname));
        memcpy(stdevinfo.devtype, "PC", sizeof(stdevinfo.devtype));
        sendret = sendto(socket->socketfd, (void *)&stdevinfo, sizeof(stdevinfo), 0,
               (struct sockaddr*)&socket->serv_addr, sizeof(socket->serv_addr));
    }
    if (sendret == sizeof(stdevinfo))
    {
        tid_debug_trace("[tid]: send devinfo to um success!");
    }
    
    return sendret;
}

/*****************************************************************************
 函 数 名  : tid_parse_hostinfo
 功能描述  : 用来解析bonjour报文中包含设备信息的字段 
 输入参数  : const char *deviceinfo,包含设备信息的字段
 输出参数  : struct devinfo *hostinfo,解析得到的设备信息缓存、需调用者开辟空间
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static void tid_parse_hostinfo(struct devinfo *hostinfo, const char *deviceinfo)
{
    unsigned char modelen = 0;
    const char *modeinfo = NULL;
    unsigned short len = 0;

    modelen = *(deviceinfo + len);
    modeinfo = deviceinfo + len + 1;
    memcpy(hostinfo->cputype, modeinfo, modelen);
    len += modelen + 1;
    modelen = *(deviceinfo + len);
    modeinfo = deviceinfo + len + 1;
    memcpy(hostinfo->ostype, modeinfo, modelen);

    return;
}

/*****************************************************************************
 函 数 名  : parse_bonjour_callback
 功能描述  : 传递给libpcap接口用户处理数据包的回调函数
             用来解析bonjour报文，获取设备操作系统、CPU类型、MAC地址
             并将解析得到的数据发送给UM模块
 输入参数  : u_char *userless, 包含用于与UM模块通信的udp socket
                               服务端的端口号及地址信息
             const struct pcap_pkthdr *pkthdr, 回调函数参数、此处无意义
             const u_char *packet, bonjour链路层数据包
 输出参数  : 无
 返 回 值  : 无
 作   者   : wenjue
*****************************************************************************/
static int tid_parse_bonjourmsg(const void *packet, struct usrtidmachdr *machdr, struct socket_clientinfo *socket)
{
    unsigned short *devinfolen = NULL;
    unsigned short *answertype = NULL;
    struct dnsmsghead *dptr = NULL;
    struct iphdr *ipptr = NULL;
    struct devinfo stdevinfo;
    char hostname[TID_HOSTNAME_MAXLEN] = {0};
    char *deviceinfo = NULL;
    char *data = NULL;  
    char hostnamelen = 0;
    unsigned int ipaddr = 0;
    int sendret = -1;
    int len = 0;
    int i = 0;
 
    if (NULL == packet || NULL == machdr || NULL == socket)
    {
        return -1;
    }
    
    memset(&stdevinfo, 0, sizeof(stdevinfo));
    i = 0;
    sprintf(stdevinfo.mac, "%02x", machdr->mac[i]);
    while (i < 5)
    {
        i++;
        sprintf(stdevinfo.mac, "%s:%02x", stdevinfo.mac, machdr->mac[i]);
    }
    
    ipptr = (struct iphdr *)(packet + len);
    i = 0;
    ipaddr = ntohl(ipptr->saddr);
    sprintf(stdevinfo.ipaddr, "%d", *((unsigned char *)&ipaddr));
    while (i < 3)
    {
        i++;
        sprintf(stdevinfo.ipaddr, "%s.%d", stdevinfo.ipaddr, *(((unsigned char *)&ipaddr) + i));
    }
    len += sizeof(struct iphdr);
    len += sizeof(struct udpstruct);
    dptr = (struct dnsmsghead *)(packet + len);
    if (33792 != dptr->flag)
    {
        return -1;
    }
    
    len += sizeof(struct dnsmsghead);
    data = (char *)(packet + len);
    hostnamelen = *data;
    if (hostnamelen > TID_HOSTNAME_MAXLEN - 1)
    {
        hostnamelen = TID_HOSTNAME_MAXLEN - 1;
    }
    
    i = 1;
    while (0 != *(data + i))
    {
        if (i <= hostnamelen)
        {
            sprintf(hostname, "%s%c", hostname, *(data + i));
        }
        i++;
    };
    i++;   
    
    len += i;
    answertype = (unsigned short *)(packet + len);

    len += 8;
    devinfolen = (unsigned short *)(packet + len);
    len += 2;
    data = (char *)(packet + len);
    deviceinfo = malloc((*devinfolen) + 1);
    if (NULL == deviceinfo)
    {
        return -1;
    }
    snprintf(deviceinfo, *devinfolen + 1, "%s", data);

    if (13 == *answertype)
    {
        memcpy(stdevinfo.hostname, hostname, hostnamelen);
        tid_parse_hostinfo(&stdevinfo, deviceinfo);
        sendret = sendto(socket->socketfd, (void *)&stdevinfo, sizeof(stdevinfo), 0,
                  (struct sockaddr*)&socket->serv_addr, sizeof(socket->serv_addr));
    }
    
    free(deviceinfo);
    deviceinfo = NULL;
    if (sendret == sizeof(stdevinfo))
    {
        tid_debug_trace("[tid]: send devinfo to um success!");
    }
    
    return sendret;
}

static void tid_parse_packet(const void *packet, struct usrtidmachdr *machdr, struct socket_clientinfo *socket)
{
    int ret = -1;

    if (TID_HTTP_PROTOCOL == machdr->portocoltype)
    {
        ret = tid_parse_httpmsg(packet, machdr, socket);
    }
    else if (TID_DHCP_PROTOCOL == machdr->portocoltype)
    {
        ret = tid_parse_dhcpmsg(packet, machdr, socket);
    }
    else if (TID_NETBIOS_PROTOCOL == machdr->portocoltype)
    {
        ret = tid_parse_netbiosmsg(packet, machdr, socket);
    }
    else if (TID_BONJOUR_PROTOCOL == machdr->portocoltype)
    {
        ret = tid_parse_bonjourmsg(packet, machdr, socket);
    }
    
    if (ret > 0)
    {
        tid_sendmsg(sock, machdr);    
    }
    
    return;
}

void tid_recvmsg(struct socket_clientinfo *udpsocket, int socketfd)
{   
    socklen_t len;
    int ret;
    char buf[4096]= {0};
    struct sockaddr_nl src_addr;
    struct usrtidmachdr *machdr = NULL;

    ret = recvfrom(socketfd, buf, sizeof(buf), 0, (struct sockaddr *)&src_addr, &len);
    if (ret < 0 || ret >= sizeof(buf))
    {
        tid_debug_waring("[tid]: recv msg from tid_kmod error");

        return;
    }

    tid_debug_trace("[tid]: recv msg from tid_kmod success");
    machdr = (struct usrtidmachdr *)(buf + sizeof(struct nlmsghdr));
    tid_parse_packet(buf + sizeof(struct nlmsghdr) + sizeof(struct usrtidmachdr), machdr, udpsocket);

    return;
}

void tid_sendmsg(int socketfd, void *data)
{
    struct sockaddr_nl dst_addr;
    struct msghdr msg;
    struct iovec iov;
    struct nlmsghdr *nlh = NULL;
    int datalen = 0;
    int sendlen = 0;

    datalen += sizeof(struct nlmsghdr);
    datalen += sizeof(struct usrtidmachdr);
    nlh = malloc(datalen);
    if (NULL == nlh)
    {
        tid_debug_waring("[tid]: unable to allocate memory for nlh");

        return;
    }
    
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid = 0;
    dst_addr.nl_groups = 0;

    nlh->nlmsg_len = datalen;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    memcpy(NLMSG_DATA(nlh), data, sizeof(struct usrtidmachdr));

    iov.iov_base = (void *)nlh;
    iov.iov_len = datalen;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dst_addr;
    msg.msg_namelen = sizeof(dst_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendlen = sendmsg(socketfd, &msg, 0);
    if (sendlen > 0)
    {
        tid_debug_trace("[tid]: send msg to tid_kmod success");
    }
    free(nlh);

    return;
}
