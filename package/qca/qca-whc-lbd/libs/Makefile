#
# @@-COPYRIGHT-START-@@
#
# Copyright (c) 2012,2014 Qualcomm Atheros, Inc.
# All rights reserved.
# Qualcomm Atheros Confidential and Proprietary.
#
# @@-COPYRIGHT-END-@@
#

TOP_SRCDIR = ..
include $(TOP_SRCDIR)/Makefile.defs

SRCDIRS = diaglog \
          wlanif \
          stadb \
          steerexec \
          estimator \
          bandmon \
          steeralg \
          stamon

all:
	@for dir in $(SRCDIRS) ; do (cd $$dir && $(MAKE) all) || exit 1; done

clean:
	@for dir in $(SRCDIRS)  ; do (cd $$dir && $(MAKE) clean) || exit 1; done


.PHONY: all clean
