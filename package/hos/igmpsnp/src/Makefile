
LIBS_DEPEND=-lpthread

OBJS=igmpsnp.o igmpsnp_com.o igmpsnp_log.o
__TARGET=igmpsnp
TARGET=$(__TARGET)
INC = -I./igmpsnpcom

.PHONY:all
all:$(TARGET)

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

$(TARGET):$(OBJS)
	${CC} ${CFLAGS} ${LDFLAGS} ${LIBS_DEPEND} -o $(TARGET) $(OBJS)
%.o:%.c
	#${CC} -c ${CFLAGS} ${INC} $< -o $@
	${CC} -c ${CFLAGS} $< -o $@


