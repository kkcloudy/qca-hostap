
OBJS=um.o user.o l2user.o l3user.o uci.o ubus.o tid.o um_delay.o
__TARGET=um
TARGET=$(__TARGET)
LIBS_DEPEND=-lubacktrace -lhos-appkey -luci -lubus -lubox -lblobmsg_json -lpthread

.PHONY:all
all:$(TARGET)

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

$(TARGET):$(OBJS)
	${CC} ${CFLAGS} ${LDFLAGS} $(LIBS_DEPEND) -o $(TARGET) $(OBJS)
	echo $(OBJS) > $(FILENO_PATH)/$(__TARGET).fileno
%.o:%.c
	${CC} -c ${CFLAGS} -D__THIS_FILE=$(shell $(FILENO_BIN) $@ $(OBJS)) $< -o $@