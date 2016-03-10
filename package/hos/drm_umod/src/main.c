/******************************************************************************
  File Name    : main.c
  Author       : lhc
  Date         : 20160302
  Description  : drm main fun
******************************************************************************/
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <netinet/in.h>

#include "drm_parse.h"
#include "drm_debug.h"

#define NETLINK_DRM 23
#define APURLLEN 128
unsigned char drm_debug_level = 3;

/******************************************************************************
  Function Name    : main
  Author           : lhc
  Date             : 20160302
  Description      : drm main fun
  Param            :
  return Code      :
******************************************************************************/
int main(int argc, char **argv)
{
    int  netlink_sock = -1;
    int  ret = -1;
    unsigned char ap_mgmt_url[APURLLEN];
    struct sockaddr_nl src_addr;
    
    /* load DRM cfg */
    //url:myhap.han-networks.com
    memset(ap_mgmt_url, 0, APURLLEN); 
    ap_mgmt_url[0] = 5;
    ap_mgmt_url[1] = 'm';
    ap_mgmt_url[2] = 'y';
    ap_mgmt_url[3] = 'h';
    ap_mgmt_url[4] = 'a';
    ap_mgmt_url[5] = 'p';
    ap_mgmt_url[6] = 12;
    ap_mgmt_url[7] = 'h';
    ap_mgmt_url[8] = 'a';
    ap_mgmt_url[9] = 'n';
    ap_mgmt_url[10] = '-';
    ap_mgmt_url[11] = 'n';
    ap_mgmt_url[12] = 'e';
    ap_mgmt_url[13] = 't';
    ap_mgmt_url[14] = 'w';
    ap_mgmt_url[15] = 'o';
    ap_mgmt_url[16] = 'r';
    ap_mgmt_url[17] = 'k';
    ap_mgmt_url[18] = 's';
    ap_mgmt_url[19] = 3;
    ap_mgmt_url[20] = 'c';
    ap_mgmt_url[21] = 'o';
    ap_mgmt_url[22] = 'm';
    ap_mgmt_url[23] = 0;
    drm_debug_error("[DRM]: load cfg  %s\n", ap_mgmt_url);
    /*
    ret = DRM_cfg_load(ap_mgmt_url);
    if (0 != ret)
    {
        drm_debug_error("[DRM]: load cfg failed");
        return -1;
    }
    */
    
    /* creat socket */
    netlink_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_DRM);
	if (netlink_sock < 0)
	{
	    drm_debug_error("[DRM]: netlink socket creat failed");
        return -1;
	}

	/* bind */
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;
    ret = bind(netlink_sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
	if (ret < 0) 
	{
        drm_debug_error("[DRM]: netlink bind failed");
        close(netlink_sock);
        return -1;
	}

    /* send cfg to KDRM */
    ret = Drm_sendmsg_to_kernel(netlink_sock, ap_mgmt_url, APURLLEN);
    if (ret < 0) 
	{
        drm_debug_error("[DRM]: send cfg to KDRM failed");
        close(netlink_sock);
        return -1;
	}
	
    /* process msg */
    while(1)
    {
        Drm_recvmsg_form_kernel(netlink_sock);
    }

    close(netlink_sock);
    
    return 0;
}
