#
# @@-COPYRIGHT-START-@@
#
# Copyright (c) 2014 Qualcomm Atheros, Inc.
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#
# @@-COPYRIGHT-END-@@
#

TOP_SRCDIR = ../../
include $(TOP_SRCDIR)/Makefile.defs

# Need to add an explicit include directory as steerexec is circularly
# dependent on bandmon (and thus the header file is not installed since
# it is built before bandmon).
CFLAGS += -I$(TOP_SRCDIR)/libs/bandmon

INSTALLHEADERS = steerexec.h
TARGET_LIB = libsteerexec.a
TARGET_OBJECTS = steerexec.$(OBJEXT) steerexecImpl.$(OBJEXT)

all: $(TARGET_LIB) install

$(TARGET_LIB): $(TARGET_OBJECTS)
	@rm -f $(TARGET_LIB)
	$(AR) $(ARFLAGS) $(TARGET_LIB) $(TARGET_OBJECTS)
	$(RANLIB) $(TARGET_LIB)

.c.o:
	$(COMPILE) $(CFLAGS) -c $<

install: $(TARGET_LIB)
	@cp -a -f $(TARGET_LIB) $(LBLIB_STATIC)/.
	@for file in $(INSTALLHEADERS) ; do ln -s -f `pwd`/$$file $(LBINCLUDE)/. ; done

clean:
	@rm -f *.o $(TARGET_LIB) *~

.PHONY: all clean
