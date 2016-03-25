#CC=mips-openwrt-linux-uclibc-gcc
#AR=mips-openwrt-linux-uclibc-ar
#OBJCOPY=mips-openwrt-linux-uclibc-objcopy
CFLAGS= -Wall -g -ffunction-sections
RANLIB=ranlib


INCLUDE += -I $(STAGING_DIR)/usr/include
INCLUDE += -I ../../../../../staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/include

XML_LIB = $(LD_PATH) -lz
LDFLAGS += $(XML_LIB)
LDFLAGS += -L$(STAGING_DIR)/usr/lib
LIBS_DEPEND=-lcrypto -lssl -lblobmsg_json -luci -lubox -lubus -lpthread -ldl 
#LDFLAGS += -L ../../../../../staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/lib
LDFLAGS += -L$(LIBS_DEPEND)
#soruces := $(shell ls *.c|grep -v main|grep -v radius|grep -v portal|grep -v redir|grep -v eag_ins|grep -v eag_thread)
#iptcsource = ../../../../../build_dir/target-mips_34kc_uClibc-0.9.33.2/linux-ar71xx_generic/iptables-1.4.21/libiptc/.libs/lib*.a
iptcsource = $(BUILD_DIR)/linux-ar71xx_generic/iptables-1.4.21/libiptc/.libs/lib*.a
opensslsource = $(STAGING_DIR)/usr/lib/libssl.*
libcrypto = $(STAGING_DIR)/usr/lib/libcrypto.*
#opensslsource = ../../../../../staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/lib/libssl.*
#libcrypto = ../../../../../staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/lib/libcrypto.*
publicsources = eag_log.o eag_blkmem.o  eag_thread.o eag_errcode.o eag_time.o hashtable.o eag_util.o eag_ifipaddr.o \
		nmp_process.o md5.o portal_packet.o radius_packet.o

eagsources =  eag_main.o eag_radius.o eag_redir.o eag_portal.o eag_stamsg.o \
		eag_captive.o appconn.o  eag_license.o eag_wireless.o  \
		eag_authorize.o eag_conf.o \
		eag_ins.o  eag_ipinfo.o eag_statistics.o eag_iptables.o \
	    eag_coa.o  eag_macauth.o eag_arp.o



all: eag eag_cli
#	[ -d ${AUTEWAREFS_DIR}/files/opt/bin/ ] || mkdir -p ${AUTEWAREFS_DIR}/files/opt/bin/
	
#	cp eag ${AUTEWAREFS_DIR}/files/opt/bin/


eag:$(publicsources) $(eagsources)
	$(CC) $^ $(iptcsource) $(opensslsource) $(libcrypto) $(LDFLAGS) -ldl -o $@

eag_cli:eag_cli.o
	$(CC) $^ $(LDFLAGS)  -o $@

.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@ 


space:
	df|grep sdb2 > aaa
	awk '{printf $$4}' aaa > space
	
codeformat:
	space=$(shell df|grep sdb2|awk '{print $$4}');
	echo $(space);
	if [ $$(space) -gt 10000 ];then \
		ls *.h | xargs indent -kr -i8 -ts8 -sob -l80 -ss -bs -psl; \
		echo "yyy";\
		ls *.c | xargs indent -kr -i8 -ts8 -sob -l80 -ss -bs -psl; \
	fi)

%.test:%.c
	$(CC) -D$(<:.c=_test)=1  $(CFLAGS) $(INCLUDE) $< -o $@ 
#	./$@; \
#	if [ $$? -eq 0 ];	then \
#		echo $(<:.c=_test_ok);\
#	else \
#		echo $(<:.c=_test_failed_failed_failed);\
#	fi;\
	rm $@;\
	

%.d:%.c
	set -e; rm -f $@;\
	$(CC) -MM $(CFLAGS) $(INCLUDE) $< > $@.$$$$;\
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@;\
	rm -f $@.$$$$;



clean:
	rm -f *.o *.d *.test $(TARGET) eag 
