CFLAGS += -Wall -g -O0

RM = /bin/rm -f

DNSRD_OBJS = main.o dnsrd_parse.o

DNSRD_SRCS = $(DNSRD_OBJS:.o=.c)

DNSRD_DEPS := $(DNSRD_OBJS:.o=.d)

DNSRD_APP = dnsrd

$(DNSRD_APP): $(DNSRD_OBJS) 

	$(CC) $(DNSRD_OBJS) $(CFLAGS) -luci -o $(DNSRD_APP)

%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@

install:
	cp dnsrd ../../res
clean: 
	$(RM) $(DNSRD_APP) $(DNSRD_OBJS) $(DNSRD_DEPS)

clean_deps:
	$(DNSRD_DEPS)
	
-include $(DNSRD_DEPS)
