/******************************************************************************
  文 件 名   : parse.h
  作    者   : wenjue
  生成日期   : 2014年11月19日
  功能描述   : parse.c的头文件
******************************************************************************/
#ifndef _TID_PARSE_H_
#define _TID_PARSE_H_

#define TID_MAC_MAXLEN       20
#define TID_HOSTNAME_MAXLEN  128
#define TID_OSTYPE_MAXLEN    32
#define TID_CPUTYPE_MAXLEN   32
#define TID_DEVTYPE_MAXLEN   8
#define TID_DEVMODEL_MAXLEN   16
#define TID_IPADDR_MAXLEN   16

struct udpstruct {
    unsigned short srcport;
    unsigned short dstport;
    unsigned short length;
    unsigned short chechsum;
};

struct dhcphead {
    unsigned char messagetype;
    unsigned char hardwaretype;
    unsigned char hardwarelen;
    unsigned char hopcount;
    unsigned int eventid;
    unsigned short sec;
    unsigned short flag;
    unsigned int clientip;
    unsigned char yourip[4];
    unsigned int serverip;
    unsigned int getwayid;
    unsigned char clientmac[6];
    unsigned char clientmacpadding[10];
    char servername[64];
    char guidename[128];
    unsigned int magiccookie;
};

struct tcphead {
    unsigned short srcport;
    unsigned short dstport;
    unsigned int sn;
    unsigned int acksn;
    unsigned char headlen;
    unsigned char flags;
    unsigned short windowsize;
    unsigned short checksum;
};

struct mwbpreq {
    unsigned char commondtype;
    unsigned char flag;
    char hostname[16];
};

struct dnsmsghead {
    unsigned short transid;
    unsigned short flag;
    unsigned short questcont;
    unsigned short answercont;
    unsigned short authorcont;
    unsigned short addcont;
};

struct devinfo{
    char hostname[TID_HOSTNAME_MAXLEN];
    char mac[TID_MAC_MAXLEN];
    char ostype[TID_OSTYPE_MAXLEN];
    char cputype[TID_CPUTYPE_MAXLEN];
    char devmodel[TID_DEVMODEL_MAXLEN];
    char devtype[TID_DEVTYPE_MAXLEN];
    char ipaddr[TID_IPADDR_MAXLEN];
};

struct socket_clientinfo{
    int socketfd;
    struct sockaddr_in serv_addr;
};

struct usrtidmachdr{
    unsigned char mac[6];
    unsigned short portocoltype;
    unsigned int datalen;
};

extern int sock;
void tid_recvmsg(struct socket_clientinfo *udpsocket, int socketfd);
void tid_sendmsg(int socketfd, void *data);
int create_client(struct sockaddr_in *serv_addr);
int tid_uci_load(void);

#endif
