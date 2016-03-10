/******************************************************************************
  File Name    : drm_phase.c
  Author       : lhc
  Date         : 20160302
  Description  : proc msg
******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
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
#include <malloc.h>

#include "drm_parse.h"
#include "drm_debug.h"
/*
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__u16	check;
	__be32	saddr;
	__be32	daddr;
};
struct udphdr {
	__u16	source;
	__u16	dest;
	__u16	len;
	__u16	check;
};
*/

/******************************************************************************
  Function Name    : checksum
  Author           : lhc
  Date             : 20160302
  Description      : add udp checknum
  Param            : unsigned short *buffer 
                     int size
  return Code      :
******************************************************************************/
unsigned short checksum(unsigned short *buffer, int size)
{
    unsigned long cksum = 0;
    
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);   
    }
    
    if (size)
    {
        cksum += *(unsigned char *)buffer;   
    }
    
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);

    return (unsigned short)(~cksum); 
}

/******************************************************************************
  Function Name    : CalculateCheckSum
  Author           : lhc
  Date             : 20160302
  Description      : add udp checknum
  Param            : void *iphdr 
                     struct udphdr *udphdr 
                     unsigned char *payload 
                     int payloadlen
  return Code      :
******************************************************************************/
void CalculateCheckSum(void *iphdr, struct udphdr *udphdr, unsigned char *payload, int payloadlen)
{   
    int chksumlen = 0;
    int i = 0;
    struct iphdr   *v4hdr = NULL;
    unsigned long  zero = 0;
    unsigned char  buf[1000];
    unsigned char  *ptr = NULL;
    
    ptr = buf;
    v4hdr = (struct iphdr *)iphdr;
    
    // Include the source and destination IP addresses
    memcpy(ptr, &v4hdr->saddr,  sizeof(v4hdr->saddr));  
    ptr += sizeof(v4hdr->saddr);
    chksumlen += sizeof(v4hdr->saddr);
    memcpy(ptr, &v4hdr->daddr, sizeof(v4hdr->daddr)); 
    ptr += sizeof(v4hdr->daddr);
    chksumlen += sizeof(v4hdr->daddr);
    
    // Include the 8 bit zero field
    memcpy(ptr, &zero, 1);
    ptr++;
    chksumlen += 1;
    
    // Protocol
    memcpy(ptr, &v4hdr->protocol, sizeof(v4hdr->protocol)); 
    ptr += sizeof(v4hdr->protocol);
    chksumlen += sizeof(v4hdr->protocol);
    
    // UDP length
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len)); 
    ptr += sizeof(udphdr->len);
    chksumlen += sizeof(udphdr->len);
    
    // UDP source port
    memcpy(ptr, &udphdr->source, sizeof(udphdr->source)); 
    ptr += sizeof(udphdr->source);
    chksumlen += sizeof(udphdr->source);
    
    // UDP destination port
    memcpy(ptr, &udphdr->dest, sizeof(udphdr->dest)); 
    ptr += sizeof(udphdr->dest);
    chksumlen += sizeof(udphdr->dest);
    
    // UDP length again
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len)); 
    ptr += sizeof(udphdr->len);
    chksumlen += sizeof(udphdr->len);
   
    // 16-bit UDP checksum, zero 
    memcpy(ptr, &zero, sizeof(unsigned short));
    ptr += sizeof(unsigned short);
    chksumlen += sizeof(unsigned short);
    
    // payload
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;
    
    // pad to next 16-bit boundary
    for(i=0 ; i < payloadlen%2 ; i++, ptr++)
    {
        drm_debug_error("[DRM]: udp checknum pad one byte");
        *ptr = 0;
        ptr++;
        chksumlen++;
    }
    
    // Compute the checksum and put it in the UDP header
    udphdr->check = checksum((unsigned short *)buf, chksumlen);
    
    return;
}

/******************************************************************************
  Function Name    : drm_send_response
  Author           : lhc
  Date             : 20160302
  Description      : drm send response
  Param            : unsigned char *buffer    send date
                     int buffer_size          date len
                     struct iphdr *ip         
                     struct udphdr *udp 
  return Code      :
******************************************************************************/
static void drm_send_response(unsigned char *buffer, int buffer_size, struct iphdr *ip, struct udphdr *udp)
{
    int sock = -1;
    int ret = -1;
    int flag = 0;

    /* creat sock_row socket */
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0)
    {
        drm_debug_error("[DRM]: creat socket(SOCK_RAW) fail");
        return;
    }

    /* set sock opt */
    flag = 1;
    ret = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag));
    if (ret < 0)
    {
        drm_debug_error("[DRM]: set socket opt(IP) fail");
        close(sock);
        return;
    }

    /* send msg */
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = udp->source;
    addr.sin_addr.s_addr = ip->saddr;
    ret = sendto(sock, buffer, buffer_size, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
    if (ret < 0) 
    {
        drm_debug_error("[DRM]: send dns response fail");
    }
    else
    {
        drm_debug_error("[DRM]: send dns response sucess");
    }

    close(sock);

    return;
}

/******************************************************************************
  Function Name    : drm_assemble_response_ip
  Author           : lhc
  Date             : 20160302
  Description      : drm assemble response ip    
  Param            : struct iphdr *response_ip   response packet ip head point
                     int response_buf_len        response buf len
                     struct iphdr *query_ip      query packet ip head point
  return Code      :
******************************************************************************/
static void drm_assemble_response_ip(struct iphdr *response_ip, int response_buf_len, struct iphdr *query_ip)
{
    response_ip->version = 4;
    response_ip->ihl = 5;
    response_ip->tot_len = response_buf_len;
    response_ip->id = htonl(random());
    response_ip->ttl = 255;
    response_ip->protocol = IPPROTO_UDP;
    response_ip->check = 0;
    response_ip->saddr = query_ip->daddr;
    response_ip->daddr = query_ip->saddr;

    return;
}

/******************************************************************************
  Function Name    : drm_assemble_response_udp
  Author           : lhc
  Date             : 20160302
  Description      : drm assemble response udp
  Param            : struct udphdr *response_udp  response packet udp head point
                     int response_buf_len         response buf len 
                     struct udphdr *query_udp     query packet udp head point
  return Code      :
******************************************************************************/
static void drm_assemble_response_udp(struct udphdr *response_udp, int response_buf_len, struct udphdr *query_udp)
{
    response_udp->source = query_udp->dest;
    response_udp->dest = query_udp->source;
    response_udp->len = htons(response_buf_len - sizeof(struct iphdr));
    response_udp->check = 0;

    return;
}

/******************************************************************************
  Function Name    : drm_assemble_response_dns
  Author           : lhc
  Date             : 20160302
  Description      : drm assemble response dns
  Param            : unsigned char *response_dns    dns response packet 
                     unsigned char *query_dns       dns query packet
                     int query_dns_len              query packet dns part len
  return Code      :
******************************************************************************/
static void drm_assemble_response_dns(unsigned char *response_dns, unsigned char *query_dns, int query_dns_len)
{
    struct dnsmsghead dnsmsg_head;
    struct dnsmsganswear dnsmsg_answear;
    unsigned char *dnsmsg_queries = NULL;
    int dnsmsg_queries_len = 0;
    
    /* dns head */
    memset(&dnsmsg_head, 0, sizeof(dnsmsg_head));
    dnsmsg_head.transid = *((unsigned short *)query_dns);
    dnsmsg_head.flag = 0x8580;
    dnsmsg_head.questcont = 0x0001;
    dnsmsg_head.answercont = 0x0001;

    /* dns queries */
    dnsmsg_queries = query_dns + sizeof(dnsmsg_head);
    dnsmsg_queries_len = query_dns_len - sizeof(dnsmsg_head);

    /* dns answears */
    memset(&dnsmsg_answear, 0, sizeof(dnsmsg_answear));
    dnsmsg_answear.name = 0xc00c;
    dnsmsg_answear.type = 0x0001;
    dnsmsg_answear.Class = 0x0001;
    dnsmsg_answear.time1 = 0;
    dnsmsg_answear.time2 = 0x018b;
    dnsmsg_answear.datelen = 0x0004;
    dnsmsg_answear.addr = 0x707c0ba3;

    memcpy(response_dns, &dnsmsg_head, sizeof(dnsmsg_head));
    memcpy(response_dns + sizeof(dnsmsg_head), dnsmsg_queries, dnsmsg_queries_len);
    memcpy(response_dns + sizeof(dnsmsg_head) + dnsmsg_queries_len, &dnsmsg_answear, sizeof(dnsmsg_answear));

    return;
}

/******************************************************************************
  Function Name    : Drm_recvmsg_form_kernel
  Author           : lhc
  Date             : 20160302
  Description      : drm reply qurery
  Param            : const void *packet    dns packet
  return Code      :
******************************************************************************/
static void drm_reply_qurery(const void *packet)
{
    struct iphdr  *query_ip;
    struct udphdr *query_udp;
    unsigned char *query_dns = NULL;
    int query_dns_len = 0;
    struct iphdr  *response_ip;
    struct udphdr *response_udp;
    unsigned char *response_dns = NULL;
    unsigned char *response_buf = NULL;
    int response_dns_len = 0;
    int response_buf_len = 0;
    
    if (NULL == packet)
    {
        return;
    }

    /* parse query */
    query_ip = (struct iphdr *)(packet);
    query_udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    query_dns = (unsigned char *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));
    query_dns_len = query_udp->len - sizeof(struct udphdr);
    
    /* creat response */
    //response_dns_len = sizeof(struct dnsmsghead) + strlen(query_dns + 12) + 1 + 2 + 2 + sizeof(struct dnsmsganswear);
    response_dns_len = query_dns_len + sizeof(struct dnsmsganswear);
    response_buf_len = sizeof(struct iphdr) + sizeof(struct udphdr) + response_dns_len;
    response_buf = malloc(response_buf_len);
    if (NULL == response_buf)
    {
        drm_debug_error("[DRM]: unable to allocate memory for buf");
        return;
    }
    memset(response_buf, 0, response_buf_len);

    /* assemble response ip */
    response_ip = (struct iphdr *)response_buf;
    drm_assemble_response_ip(response_ip, response_buf_len, query_ip);
    
    /* assemble response udp */
    response_udp = (struct udphdr *)(response_buf + sizeof(struct iphdr));
    drm_assemble_response_udp(response_udp, response_buf_len, query_udp);

    /* assemble response udp */
    response_dns = response_buf + sizeof(struct iphdr) + sizeof(struct udphdr);
    drm_assemble_response_dns(response_dns, query_dns, query_dns_len);

    /* CheckSum response */
    CalculateCheckSum(response_ip, response_udp, response_dns, response_dns_len);

    /* send response */
    drm_send_response(response_buf, response_buf_len, response_ip, response_udp);

    /* destory response */
    free(response_buf);
    
    return;
}

/******************************************************************************
  Function Name    : Drm_recvmsg_form_kernel
  Author           : lhc
  Date             : 20160302
  Description      : Drm recv msg_form kernel
  Param            : socketfd  netlink socket
  return Code      :
******************************************************************************/
void Drm_recvmsg_form_kernel(int socketfd)
{   
    socklen_t len = 0;
    int ret = -1;
    unsigned char buf[4096]= {0};
    struct sockaddr_nl src_addr;

    /* recv msg from kernel */
    ret = recvfrom(socketfd, buf, sizeof(buf), 0, (struct sockaddr *)&src_addr, &len);
    if (ret < 0 || ret >= sizeof(buf))
    {
        drm_debug_error("[DRM]: recv msg from drm_kmod error");

        return;
    }

    drm_debug_trace("[DRM]: recv msg from drm_kmod success");

    /* reply qurery */
    drm_reply_qurery(buf + sizeof(struct nlmsghdr));

    return;
}

/******************************************************************************
  Function Name    : Drm_sendmsg_to_kernel
  Author           : lhc
  Date             : 20160302
  Description      : Drm send msg to kernel
  Param            : int socketfd    netlink socket
                     void *data      send date
                     int date_len    date len
  return Code      : ret = 0         send date sucess
                     ret != 0        send date fail
******************************************************************************/
int Drm_sendmsg_to_kernel(int socketfd, void *data, int date_len)
{
    int msg_len = 0;
    int sendlen = 0;
    int ret= -1;
    struct sockaddr_nl dst_addr;
    struct msghdr msg;
    struct iovec iov;
    struct nlmsghdr *nlh = NULL;

    /* malloc nlmsghdr */
    msg_len += sizeof(struct nlmsghdr);
    msg_len += date_len;
    nlh = malloc(msg_len);
    if (NULL == nlh)
    {
        drm_debug_error("[DRM]: unable to allocate memory for nlh");
        return -1;
    }

    /* init nlmsghdr */
    nlh->nlmsg_len = msg_len;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    memcpy(NLMSG_DATA(nlh), data, date_len);

    /* init iov */
    iov.iov_base = (void *)nlh;
    iov.iov_len = msg_len;

    /* init sockaddr_nl */
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid = 0;
    dst_addr.nl_groups = 0;

    /* init msg */
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dst_addr;
    msg.msg_namelen = sizeof(dst_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    /* send msg */
    sendlen = sendmsg(socketfd, &msg, 0);
    if (sendlen < 0)
    {
        drm_debug_trace("[DRM]: send msg to drm_kmod success");
        ret = -1;
    }
    else
    {
        drm_debug_trace("[DRM]: send msg to drm_kmod success");
        ret = 0;
    }
    
    free(nlh);

    return ret;
}
