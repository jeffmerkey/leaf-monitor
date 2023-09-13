#***************************************************************************
#
#	Copyright (c) 1997-2019 Jeffrey Vernon Merkey
#	All Rights Reserved.
#
#**************************************************************************

INCLUDES=cworthy.h netware-screensaver.h srv_stats.h
UTILFILES=libcworthy.so libcworthy.a leafmon 

# user utility build flags
U_CC = gcc
U_CCP = g++
U_CFLAGSP = -g -O3
U_CFLAGS_LIBP = -g -c -O3 
LD = ld
AR = ar

all : utilities

libcworthy.so: cworthy.o netware-screensaver.o
	$(LD) -shared -lc -o libcworthy.so cworthy.o netware-screensaver.o 

libcworthy.a: cworthy.o netware-screensaver.o
	$(AR) r libcworthy.a cworthy.o netware-screensaver.o 

cworthy.o: cworthy.c $(INCLUDES)
	$(U_CCP) $(U_CFLAGS_LIBP) -fPIC -Wall cworthy.c 

netware-screensaver.o: netware-screensaver.c $(INCLUDES)
	$(U_CCP) $(U_CFLAGS_LIBP) -fPIC -Wall netware-screensaver.c 

leafmon: leafmon.c libcworthy.so libcworthy.a $(INCLUDES)
	$(U_CCP) $(U_CFLAGSP) leafmon.c -Wall -o leafmon -lncursesw -lpthread libcworthy.a -lrt -lpthread -lz -lm -ldl -lssl -lcrypto 

clean:
	rm -rf *.o $(UTILFILES)

utilities: $(UTILFILES)

install: utilities
	install -m 0755 leafmon $(DESTDIR)/usr/bin

uninstall: 
	rm -vf $(DESTDIR)/usr/bin/leafmon


