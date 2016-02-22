ifneq ($(strip $(TOOLPREFIX)),)
CROSS:=$(TOOLPREFIX)
endif

CC= $(CROSS)gcc

ifndef ATHEROSPATH
ATHEROSPATH := ../../../drivers/wlan
endif

OS_INC_PATH := $(ATHEROSPATH)/os/linux/include
HAL_PATH := $(ATHEROSPATH)/hal
ADF_PATH := $(ATHEROSPATH)/adf
ASF_PATH := $(ATHEROSPATH)/asf
LMAC_PATH := $(ATHEROSPATH)/lmac
UMAC_PATH := $(ATHEROSPATH)/umac
WPC_MGR_PATH := ../wpc
INCS+= -I${OS_INC_PATH} -I${HAL_PATH} -I${WPC_MGR_PATH} -I${ATHEROSPATH} -I.

CFLAGS= ${INCS} -MMD -O2 -Wall -g -lm -c 

ALL= wpc_rtte_me wpc_rtte_me.o wpc_rtte_me.d wpcrttetest 
LIBALL= libwpcrtteme.a 

all:    ${ALL}

wpc_rtte_me: 
	$(CC) ${CFLAGS} wpc_rtte_me.c
	ar rvs libwpcrtteme.a wpc_rtte_me.o
	cp libwpcrtteme.a ${WPC_MGR_PATH}
	$(CC) ${INCS} -g -DATH_WPC_ME_DEBUG=1 -DATH_WPC_ME_DEBUG_FFT=1 wpc_rtte_main.c wpc_rtte_me.c -lm -o wpcrttetest 

    
clean:
	rm -f $(ALL)
	rm -f $(LIBALL)
