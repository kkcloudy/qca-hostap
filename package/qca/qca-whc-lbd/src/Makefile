#
# @@-COPYRIGHT-START-@@
#
# Copyright (c) 2011,2014 Qualcomm Atheros, Inc.
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#
# @@-COPYRIGHT-END-@@
#

TOP_SRCDIR = ..
include $(TOP_SRCDIR)/Makefile.defs

LIBS += -lpthread

TARTGET_OBJECTS = lbdMain.$(OBJEXT)

LBD_LIBS = -lwlanif -lsteerexec -lstadb -lbandmon -lsteeralg -lstamon -lestimator -llbdcore -ldiaglog

LBD_OPTIMIZE := -Wl,--gc-sections -fwhole-program -Wl,--sort-section,alignment -Wl,--sort-common

LIBS += $(LBD_LIBS)

all: lbd$(EXEEXT) install

lbd$(EXEEXT): $(TARTGET_OBJECTS) $(LBD_LIBS)
	$(LINK) -o $@ $(TARTGET_OBJECTS) -Xlinker --start-group $(LIBS) -Xlinker --end-group

.c.o:
	$(COMPILE) -c $<

install:
	@cp lbd$(EXEEXT) $(INSTALL_ROOT)/sbin

clean:
	@rm -f *.o *~ lbd$(EXEEXT)


.PHONY: all clean install

