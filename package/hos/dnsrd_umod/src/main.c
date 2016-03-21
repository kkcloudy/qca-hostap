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

#include "dnsrd_parse.h"
#include "dnsrd_debug.h"

#define NETLINK_DRM 23
#define DRM_APURLLEN 128
#define DRM_SHOWCFGURL "showurlinfo"

unsigned char drm_debug_level = 3;

/******************************************************************************
  Function Name    : replace_domain
  Author           : lhc
  Date             : 20160302
  Description      : replace domain
  Param            : char *output_url            output url
                     char *input_url             input url
  return Code      : ret = 0   success 
                     ret != 0  fail
******************************************************************************/
static int replace_domain(char *buf_output, char *buf_input)
{
    char *token = NULL;
    int buf_len = 0;
    int tmp_len = 0;
    int tmp_flag = 0;

    /* rm \n */
    buf_len = strlen(buf_input);
    if ('\n' == buf_input[buf_len - 1])
    {
        buf_input[buf_len - 1] = 0;
    }

    /* replace domain */
    token = strtok(buf_input, ".");
    if (NULL == token)
    {
        drm_debug_error("[DRM]: replace url info fail");
        return -1;
    }
    
    while (NULL != token)
    {
        tmp_len = strlen(token);
        buf_output[tmp_flag] = (char)tmp_len;
        tmp_flag++;
        memcpy(buf_output + tmp_flag, token, tmp_len);
        tmp_flag += tmp_len;
        
        token = strtok(NULL, ".");
    }
    
    return 0;
}

/******************************************************************************
  Function Name    : DRM_cfg_load
  Author           : lhc
  Date             : 20160302
  Description      : load url from system
  Param            : char *ap_mgmt_url            url buf
  return Code      : ret = 0   success
                     ret != 0  fail
******************************************************************************/
static int DRM_cfg_load(char *ap_mgmt_url)
{
    FILE *url_file;
    int ret = -1;
    char tmp_url[DRM_APURLLEN];
    
    memset(tmp_url, 0, DRM_APURLLEN);

    /* open pipe */
    url_file = popen(DRM_SHOWCFGURL, "r");
    if (NULL == url_file) 
    {
        drm_debug_error("[DRM]: show url info fail");
        return -1;
    }

    /* get url */
    if (NULL == fgets(tmp_url, DRM_APURLLEN, url_file)) 
    {
        drm_debug_error("[DRM]: load url info fail");
        pclose(url_file);
        return -1;
    }

    /* replace url */
    ret = replace_domain(ap_mgmt_url, tmp_url);
    if (0 == ret)
    {
        /*
        int i;
        for (i=0; i<DRM_APURLLEN; i++)
        {
            printf("%d ", ap_mgmt_url[i], ap_mgmt_url[i]);
            if (i%10==0)
            printf("\n");
        }
        */
        drm_debug_error("[DRM]: load url info %s len %d\n", ap_mgmt_url, strlen(ap_mgmt_url));
    }

    /* close pipe */
    pclose(url_file);

    return ret;
}

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
    char ap_mgmt_url[DRM_APURLLEN];
    struct sockaddr_nl src_addr;
    
    /* load DRM cfg */
    memset(ap_mgmt_url, 0, DRM_APURLLEN); 
    ret = DRM_cfg_load(ap_mgmt_url);
    if (0 != ret)
    {
        drm_debug_error("[DRM]: load cfg failed");
        return -1;
    }
    
    /* creat socket */
    netlink_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_DRM);
	if (netlink_sock < 0)
	{
	    drm_debug_error("[DRM]: creat netlink socket failed");
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
        drm_debug_error("[DRM]: bind netlink failed");
        close(netlink_sock);
        return -1;
	}

    /* send cfg to KDRM */
    ret = Drm_sendmsg_to_kernel(netlink_sock, ap_mgmt_url, DRM_APURLLEN);
    if (ret < 0) 
	{
        drm_debug_error("[DRM]: send cfg to drm_kmod failed");
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
