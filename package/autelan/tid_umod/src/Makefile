CFLAGS += -Wall -g -O0

RM = /bin/rm -f

TID_OBJS = main.o tid_parse.o tid_uci.o

TID_SRCS = $(TID_OBJS:.o=.c)

TID_DEPS := $(TID_OBJS:.o=.d)

TID_APP = tid

$(TID_APP): $(TID_OBJS) 

	$(CC) $(TID_OBJS) $(CFLAGS) -luci -o $(TID_APP)

%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@

install:
	cp tid ../../res
clean: 
	$(RM) $(TID_APP) $(TID_OBJS) $(TID_DEPS)

clean_deps:
	$(TID_DEPS)
	
-include $(TID_DEPS)
