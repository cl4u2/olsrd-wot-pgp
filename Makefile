#
# OLSR ad-hoc routing table management protocol
# Copyright (C) 2003-2004 Andreas T�nnesen (andreto@ifi.uio.no)
#
# This file is part of the olsr.org OLSR daemon.
#
# olsr.org is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# olsr.org is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with olsr.org; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#
# $Id: Makefile,v 1.18 2004/11/05 20:58:09 tlopatic Exp $
#

#OS ?=		linux
#OS =		fbsd
#OS =		win32
#OS =		osx

CC ?= 		gcc

PREFIX ?=

STRIP ?=	strip

BISON ?=	bison
FLEX ?=		flex
CFGDIR =	src/cfgparser

DEPFILE =	.depend
DEPBAK =	.depend.bak
DEPEND =	makedepend -f $(DEPFILE)

all:		olsrd

SRCS =		$(wildcard src/*.c) \
		$(CFGDIR)/oparse.c $(CFGDIR)/oscan.c $(CFGDIR)/olsrd_conf.c

HDRS =		$(wildcard src/*.h) \
		$(CFGDIR)/oparse.h $(CFGDIR)/olsrd_conf.h

OBJS =		$(patsubst %.c,%.o,$(wildcard src/*.c)) \
		$(CFGDIR)/oparse.o $(CFGDIR)/oscan.o $(CFGDIR)/olsrd_conf.o

ifeq ($(OS), linux)

SRCS += 	$(wildcard src/linux/*.c) $(wildcard src/unix/*.c)

HDRS +=		$(wildcard src/linux/*.h) $(wildcard src/unix/*.h)

OBJS +=		$(patsubst %.c,%.o,$(wildcard src/linux/*.c)) \
		$(patsubst %.c,%.o,$(wildcard src/unix/*.c))

CFLAGS ?=	-Isrc -Wall -Wmissing-prototypes -Wstrict-prototypes \
		-O2 -g -Dlinux #-pg -DDEBUG #-march=i686

LIBS =		-lpthread -lm -ldl

$(DEPFILE):	$(SRCS) $(HDRS)
		@echo '# olsrd dependency file. AUTOGENERATED' > $(DEPFILE)
		$(DEPEND) -Y $(CFLAGS) $(SRCS) >/dev/null 2>&1

olsrd:		$(OBJS)
		$(CC) -o bin/$@ $(OBJS) $(LIBS)

else
ifeq ($(OS), fbsd)

SRCS +=		$(wildcard src/bsd/*.c) $(wildcard src/unix/*.c)

HDRS +=		$(wildcard src/bsd/*.h) $(wildcard src/unix/*.h)

OBJS +=		$(patsubst %.c,%.o,$(wildcard src/bsd/*.c)) \
		$(patsubst %.c,%.o,$(wildcard src/unix/*.c))

CFLAGS ?=	-Isrc -Wall -Wmissing-prototypes -Wstrict-prototypes \
		-O2 -g

LIBS =		-pthread -lm

$(DEPFILE):	$(SRCS) $(HDRS)
		@echo '# olsrd dependency file. AUTOGENERATED' > $(DEPFILE)
		$(DEPEND) $(CFLAGS) $(SRCS)

olsrd:		$(OBJS)
		$(CC) -o bin/$@ $(OBJS) $(LIBS)

else
ifeq ($(OS), win32)

SRCS +=		$(wildcard src/win32/*.c)

HDRS +=		$(wildcard src/win32/*.h)

OBJS +=		$(patsubst %.c,%.o,$(wildcard src/win32/*.c))

CFLAGS ?=	-Isrc -Isrc/win32 -Wall -Wmissing-prototypes \
		-Wstrict-prototypes -mno-cygwin -O2 -g -DWIN32

LIBS =		-mno-cygwin -lws2_32 -liphlpapi

$(DEPFILE):	$(SRCS) $(HDRS)
		@echo '# olsrd dependency file. AUTOGENERATED' > $(DEPFILE)
		$(DEPEND) $(CFLAGS) $(SRCS)

olsrd:		$(OBJS)
		$(CC) -o bin/$@ $(OBJS) $(LIBS)

else
ifeq ($(OS), osx)

SRCS +=		$(wildcard src/bsd/*.c) $(wildcard src/unix/*.c)

HDRS +=		$(wildcard src/bsd/*.h) $(wildcard src/unix/*.h)

OBJS +=		$(patsubst %.c,%.o,$(wildcard src/bsd/*.c)) \
		$(patsubst %.c,%.o,$(wildcard src/unix/*.c))

CFLAGS ?=	-D__MacOSX__ -Isrc -Wall -Wmissing-prototypes \
		-Wstrict-prototypes -O2 -g 

LIBS =		-lm -ldl

$(DEPFILE):	$(SRCS) $(HDRS)
		@echo '# olsrd dependency file. AUTOGENERATED' > $(DEPFILE)
		$(DEPEND) $(CFLAGS) $(SRCS)

olsrd:		$(OBJS)
		$(CC) -o bin/$@ $(OBJS) $(LIBS)


else

olsrd:
	@echo
	@echo '***** olsr.org olsr daemon Make ****'
	@echo ' You must provide a valid target OS '
	@echo ' by setting the OS variable! Valid  '
	@echo ' target OSes are:                   '
	@echo ' ---------------------------------  '
	@echo ' linux - GNU/Linux                  '
	@echo ' win32 - Windows NT family(2k/XP)   '
	@echo ' fbsd  - FreeBSD                    '
	@echo ' osx   - Mac OS X                   '
	@echo ' ---------------------------------  '
	@echo ' Example - build for windows:       '
	@echo ' make OS=win32                      '
	@echo ' If you are developing olsrd code,  '
	@echo ' exporting the OS variable might    '
	@echo ' be a good idea :-) Have fun!       '
	@echo '************************************'
	@echo
endif
endif
endif
endif

depend:		$(DEPFILE)

$(CFGDIR)/oparse.c: \
		$(CFGDIR)/oparse.y $(CFGDIR)/olsrd_conf.h
		$(BISON) -d -o$(CFGDIR)/oparse.c $(CFGDIR)/oparse.y

$(CFGDIR)/oparse.h: \
		$(CFGDIR)/oparse.c

$(CFGDIR)/oscan.c: \
		$(CFGDIR)/oscan.lex $(CFGDIR)/oparse.h $(CFGDIR)/olsrd_conf.h
		$(FLEX) -o$(CFGDIR)/oscan.c $(CFGDIR)/oscan.lex

libs: 
		for i in lib/*; do \
			$(MAKE) -C $$i; \
		done; 

clean_libs: 
		for i in lib/*; do \
			$(MAKE) -C $$i clean; \
		done; 

.PHONY:		clean

clean:
		rm -f $(OBJS)

uberclean:
		rm -f $(OBJS) $(DEPFILE) $(DEPBAK)
		rm -f $(CFGDIR)/oscan.c $(CFGDIR)/oparse.h $(CFGDIR)/oparse.c
		rm -f bin/olsrd bin/olsrd.exe
		rm -f src/*~ src/linux/*~ src/unix/*~ src/win32/*~
		rm -f src/bsd/*~ src/cfgparser/*~

install_libs:
		for i in lib/*; do \
			$(MAKE) -C $$i LIBDIR=$(PREFIX)/usr/lib install; \
		done; 	

install_bin:
		$(STRIP) bin/olsrd
		install -D -m 755 bin/olsrd $(PREFIX)/usr/sbin/olsrd

install:	install_bin
		@echo olsrd uses the configfile $(PREFIX)/etc/olsr.conf
		@echo a default configfile. A sample configfile
		@echo can be installed
		mkdir -p $(PREFIX)/etc
		cp -i files/olsrd.conf.default $(PREFIX)/etc/olsrd.conf
		@echo -------------------------------------------
		@echo Edit $(PREFIX)/etc/olsrd.conf before running olsrd!!
		@echo -------------------------------------------
		mkdir -p $(PREFIX)/usr/share/man/man8/
		cp files/olsrd.8.gz $(PREFIX)/usr/share/man/man8/olsrd.8.gz

sinclude	$(DEPFILE)

