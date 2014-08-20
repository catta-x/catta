# This file is part of avahi.
#
# avahi is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# avahi is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with avahi; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA.

AM_CFLAGS=-I$(top_srcdir)

# This cool debug trap works on i386/gcc only
AM_CFLAGS+='-DDEBUG_TRAP=__asm__("int $$3")'

avahiincludedir = $(top_srcdir)/avahi

avahiinclude_HEADERS = \
	strlst.h \
	address.h \
	alternative.h \
	domain.h \
	cdecl.h \
	defs.h \
	malloc.h \
	watch.h \
	timeval.h \
	simple-watch.h \
	thread-watch.h \
	gccmacro.h \
	error.h \
	llist.h \
	rlist.h \
	core.h \
	log.h \
	rr.h \
	publish.h \
	lookup.h

lib_LTLIBRARIES = libavahi.la

libavahi_la_SOURCES = \
	malloc.c malloc.h \
	address.c address.h \
	alternative.c alternative.h \
	error.c error.h \
	strlst.c strlst.h \
	domain.c domain.h \
	timeval.c timeval.h \
	simple-watch.c simple-watch.h \
	thread-watch.c thread-watch.h \
	watch.h gccmacro.h \
	rlist.h rlist.c \
	utf8.c utf8.h \
	i18n.c i18n.h \
	timeeventq.c timeeventq.h\
	iface.c iface.h \
	server.c internal.h entry.c \
	prioq.c prioq.h \
	cache.c cache.h \
	socket.c socket.h \
	response-sched.c response-sched.h \
	query-sched.c query-sched.h \
	probe-sched.c probe-sched.h \
	announce.c announce.h \
	browse.c browse.h \
	rrlist.c rrlist.h \
	resolve-host-name.c \
	resolve-address.c \
	browse-domain.c \
	browse-service-type.c \
	browse-service.c \
	resolve-service.c \
	dns.c dns.h \
	rr.c rr.h rr-util.h \
	core.h lookup.h publish.h \
	log.c log.h \
	browse-dns-server.c \
	fdutil.h fdutil.c \
	util.c util.h \
	hashmap.c hashmap.h \
	wide-area.c wide-area.h \
	multicast-lookup.c multicast-lookup.h \
	querier.c querier.h \
	addr-util.h addr-util.c \
	domain-util.h domain-util.c \
	dns-srv-rr.h

if HAVE_NETLINK
libavahi_la_SOURCES += \
       iface-linux.c iface-linux.h \
       netlink.c netlink.h
else
if HAVE_PF_ROUTE
libavahi_la_SOURCES += \
	iface-pfroute.c iface-pfroute.h
else
libavahi_la_SOURCES += \
	iface-none.c
endif
endif

libavahi_la_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS) -DAVAHI_LOCALEDIR=\"$(avahilocaledir)\"
libavahi_la_LIBADD = $(AM_LDADD) $(PTHREAD_CFLAGS) $(PTHREAD_LIBS) $(INTLLIBS)
libavahi_la_LDFLAGS = $(AM_LDFLAGS)  -version-info $(LIBAVAHI_VERSION_INFO)
