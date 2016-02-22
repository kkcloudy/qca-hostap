/*
 * Copyright (c) 2011 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
#include <sys/select.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include "ieee80211_wpc.h"
#include "wpc_mgr.h"
#include "wpc_rtte_me.h"
#define PRIN_LOG(format, args...) printf(format "", ## args)

#define EXTRA_BUFFER    1000 // this is because reading a file some times exceeds the buffer. 
int main(int argc, char *argv[])
{
    int i;
    while(argc < 1){
        printf("Error: format is ./wpc_rtte nRxChains \n");
        return 0;
    }
    u_int16_t w_Nu = 7;
    u_int32_t q_N = 1 << w_Nu;
    wpc_probe_data *ppd;
    u_int16_t nRxChains = 2; //(u_int32_t) atoi(argv[1]);
    remove("cir.txt");
    ppd = (wpc_probe_data *) malloc(sizeof(wpc_probe_data)+EXTRA_BUFFER); 
    wpc_rtte_readinput(ppd->cd);
    ppd->toa = 433;
    ppd->tod = 0;

    /* Calculating twiddle factor and bit rever sequence (One time effort) */
    //wpc_init_rtte();
    /* Calculating ftoa */
    wpc_rtte_calculate_ftoa(ppd, nRxChains);
    PRIN_LOG(" **************** \n");

    return 0;
}
