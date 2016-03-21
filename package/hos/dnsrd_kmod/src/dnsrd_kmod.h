/******************************************************************************
  File Name    : drm_kmod.h
  Author       : lhc
  Date         : 20160302
  Description  : drm_kmod.c
******************************************************************************/

#ifndef _KERNEL_DRM_PARSE_H_
#define _KERNEL_DRM_PARSE_H_

struct udpstruct {
    unsigned short srcport;
    unsigned short dstport;
    unsigned short length;
    unsigned short chechsum;
};

void kdrm_filter_packet(struct sk_buff *skb);

#endif
