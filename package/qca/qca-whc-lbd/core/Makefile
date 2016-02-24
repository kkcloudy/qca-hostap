# @@-COPYRIGHT-START-@@
#
# Copyright (c) 2011,2014 Qualcomm Atheros, Inc.
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#
# @@-COPYRIGHT-END-@@
#

TOP_SRCDIR = ../
include $(TOP_SRCDIR)/Makefile.defs

TARGET_LIB = liblbdcore.a
INSTALLHEADERS := $(shell ls *.h 2> /dev/null)
CFLAGS += -I$(TOP_SRCDIR)/services/tdService -I$(TOP_SRCDIR)/managers/wlanManager

TARGET_OBJECTS = module.$(OBJEXT) config.$(OBJEXT) profile.$(OBJEXT) internal.$(OBJEXT)

all: $(TARGET_LIB) install

$(TARGET_LIB): $(TARGET_OBJECTS)
	@rm -f $(TARGET_LIB)
	@$(AR) $(ARFLAGS) $(TARGET_LIB) $(TARGET_OBJECTS)
	@$(RANLIB) $(TARGET_LIB)

.c.o:
	@$(COMPILE) $(CFLAGS) -c $<

install: $(TARGET_LIB)
	@cp -a -f $(TARGET_LIB) $(LBLIB_STATIC)/.
	@for file in $(INSTALLHEADERS) ; do ln -s -f `pwd`/$$file $(LBINCLUDE)/. ; done

clean:
	@rm -rf *.o $(TARGET_LIB) *~ *.d

.PHONY: all clean

