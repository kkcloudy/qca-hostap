/******************************************************************************
  File Name    : dnsrd_kmod.h
  Author       : lhc
  Date         : 20160302
  Description  : dnsrd_kmod.c
******************************************************************************/

#ifndef _KERNEL_DNSRD_KMOD_H_
#define _KERNEL_DNSRD_KMOD_H_

struct udpstruct {
    unsigned short srcport;
    unsigned short dstport;
    unsigned short length;
    unsigned short chechsum;
};

void kdrm_filter_packet(struct sk_buff *skb);

#endif
