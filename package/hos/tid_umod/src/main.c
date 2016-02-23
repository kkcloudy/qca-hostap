/******************************************************************************
  文 件 名   : main.c
  作    者   : wenjue
  生成日期   : 2014年11月19日
  功能描述   : 终端识别模块入口
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

#include "tid_parse.h"
#include "tid_debug.h"

#define NETLINK_TID 22

int sock = -1;
int main(int argc, char **argv)
{
    struct socket_clientinfo udpsocket;
    struct sockaddr_nl src_addr;
    struct usrtidmachdr machdr;

    tid_uci_load();
    sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_TID);
	if (sock < 0)
	{
	    tid_debug_error("[tid]: netlink socket creat failed");
        return -1;
	}
	
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;
    
	if (bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) 
	{
        tid_debug_error("[tid]: tid bind failed");
        close(sock);
        return -1;
	}

    memset(&machdr, 0, sizeof(machdr));
    tid_sendmsg(sock, &machdr);

    memset(&udpsocket, 0, sizeof(udpsocket));
    udpsocket.socketfd = create_client(&udpsocket.serv_addr);
    if (udpsocket.socketfd < 0)
    {
        close(sock);
        return -1;
    }

    tid_debug_trace("[tid]: recv msg begain");
    while(1)
    {
        tid_recvmsg(&udpsocket, sock);
    }

    close(udpsocket.socketfd);
    close(sock);
    
    return 0;
}
