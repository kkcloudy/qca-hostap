CFLAGS += -Wall -g -O0

RM = /bin/rm -f

DRM_OBJS = main.o drm_parse.o

DRM_SRCS = $(DRM_OBJS:.o=.c)

DRM_DEPS := $(DRM_OBJS:.o=.d)

DRM_APP = drm

$(DRM_APP): $(DRM_OBJS) 

	$(CC) $(DRM_OBJS) $(CFLAGS) -luci -o $(DRM_APP)

%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@

install:
	cp drm ../../res
clean: 
	$(RM) $(DRM_APP) $(DRM_OBJS) $(DRM_DEPS)

clean_deps:
	$(DRM_DEPS)
	
-include $(DRM_DEPS)
