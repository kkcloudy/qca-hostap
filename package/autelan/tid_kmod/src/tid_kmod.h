#ifndef _KERNEL_TID_PARSE_H_
#define _KERNEL_TID_PARSE_H_

struct machead {
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short packettype;
};

struct udpstruct {
    unsigned short srcport;
    unsigned short dstport;
    unsigned short length;
    unsigned short chechsum;
};

struct bonjourhead {
    unsigned short trsportid;
    unsigned short msgflag;
    unsigned short questioncnt;
    unsigned short answercnt;
    unsigned short authorcnt;
    unsigned short additioncnt;
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

struct tidtable{
    unsigned char mac[6];
    unsigned char httpflag;
    unsigned char netbiosflag;
    unsigned char bonjourflag;
    struct tidtable *next;
};

struct tidtablehead{
    struct tidtable *next;
};

void ktid_filter_packet(struct sk_buff *skb);

#endif
