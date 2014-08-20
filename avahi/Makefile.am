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

avahiincludedir=$(includedir)/src

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

if ENABLE_TESTS
noinst_PROGRAMS = \
	strlst-test \
	domain-test \
	alternative-test \
	timeval-test \
	watch-test \
	watch-test-thread \
	utf8-test \
	prioq-test \
	avahi-test \
	conformance-test \
	avahi-reflector \
	dns-test \
	dns-spin-test \
	timeeventq-test \
	hashmap-test \
	querier-test \
	update-test

TESTS = \
	dns-spin-test \
	dns-test \
	hashmap-test
endif

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

strlst_test_SOURCES = strlst-test.c
strlst_test_CFLAGS = $(AM_CFLAGS)
strlst_test_LDADD = $(AM_LDADD) libavahi.la

alternative_test_SOURCES = alternative-test.c
alternative_test_CFLAGS = $(AM_CFLAGS)
alternative_test_LDADD = $(AM_LDADD) libavahi.la

domain_test_SOURCES = domain-test.c
domain_test_CFLAGS = $(AM_CFLAGS)
domain_test_LDADD = $(AM_LDADD) libavahi.la

watch_test_SOURCES = watch-test.c
watch_test_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS)
watch_test_LDADD = $(AM_LDADD) $(PTHREAD_LIBS) $(PTHREAD_CFLAGS) libavahi.la

watch_test_thread_SOURCES = $(watch_test_SOURCES)
watch_test_thread_CFLAGS = $(watch_test_CFLAGS) -DUSE_THREAD
watch_test_thread_LDADD = $(watch_test_LDADD) libavahi.la

timeval_test_SOURCES = timeval-test.c
timeval_test_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS)
timeval_test_LDADD = $(AM_LDADD) $(PTHREAD_LIBS) $(PTHREAD_CFLAGS) libavahi.la

utf8_test_SOURCES = utf8-test.c
utf8_test_CFLAGS = $(AM_CFLAGS)
utf8_test_LDADD = $(AM_LDADD) libavahi.la

prioq_test_SOURCES = prioq-test.c
prioq_test_CFLAGS = $(AM_CFLAGS)
prioq_test_LDADD = $(AM_LDADD) libavahi.la

avahi_test_SOURCES = avahi-test.c
avahi_test_CFLAGS = $(AM_CFLAGS)
avahi_test_LDADD = $(AM_LDADD) libavahi.la

update_test_SOURCES = update-test.c
update_test_CFLAGS = $(AM_CFLAGS)
update_test_LDADD = $(AM_LDADD) libavahi.la

querier_test_SOURCES = querier-test.c
querier_test_CFLAGS = $(AM_CFLAGS)
querier_test_LDADD = $(AM_LDADD) libavahi.la

conformance_test_SOURCES = conformance-test.c
conformance_test_CFLAGS = $(AM_CFLAGS)
conformance_test_LDADD = $(AM_LDADD) libavahi.la

avahi_reflector_SOURCES = avahi-reflector.c
avahi_reflector_CFLAGS = $(AM_CFLAGS)
avahi_reflector_LDADD = $(AM_LDADD) libavahi.la

dns_test_SOURCES = dns-test.c
dns_test_CFLAGS = $(AM_CFLAGS)
dns_test_LDADD = $(AM_LDADD) libavahi.la

dns_spin_test_SOURCES = dns-spin-test.c
dns_spin_test_CFLAGS = $(AM_CFLAGS)
dns_spin_test_LDADD = $(AM_LDADD) libavahi.la

timeeventq_test_SOURCES = timeeventq-test.c
timeeventq_test_CFLAGS = $(AM_CFLAGS)
timeeventq_test_LDADD = $(AM_LDADD) libavahi.la

hashmap_test_SOURCES = hashmap-test.c
hashmap_test_CFLAGS = $(AM_CFLAGS)
hashmap_test_LDADD = $(AM_LDADD) libavahi.la

valgrind: avahi-test
	libtool --mode=execute valgrind ./avahi-test

gdb: avahi-test
	libtool --mode=execute gdb ./avahi-test
