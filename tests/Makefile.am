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
AM_LDADD=$(top_srcdir)/avahi/libavahi.la

# This cool debug trap works on i386/gcc only
AM_CFLAGS+='-DDEBUG_TRAP=__asm__("int $$3")'

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


strlst_test_SOURCES = strlst-test.c
strlst_test_CFLAGS = $(AM_CFLAGS)
strlst_test_LDADD = $(AM_LDADD)

alternative_test_SOURCES = alternative-test.c
alternative_test_CFLAGS = $(AM_CFLAGS)
alternative_test_LDADD = $(AM_LDADD)

domain_test_SOURCES = domain-test.c
domain_test_CFLAGS = $(AM_CFLAGS)
domain_test_LDADD = $(AM_LDADD)

watch_test_SOURCES = watch-test.c
watch_test_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS)
watch_test_LDADD = $(AM_LDADD) $(PTHREAD_LIBS) $(PTHREAD_CFLAGS)

watch_test_thread_SOURCES = $(watch_test_SOURCES)
watch_test_thread_CFLAGS = $(watch_test_CFLAGS) -DUSE_THREAD
watch_test_thread_LDADD = $(watch_test_LDADD)

timeval_test_SOURCES = timeval-test.c
timeval_test_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS)
timeval_test_LDADD = $(AM_LDADD) $(PTHREAD_LIBS) $(PTHREAD_CFLAGS)

utf8_test_SOURCES = utf8-test.c
utf8_test_CFLAGS = $(AM_CFLAGS)
utf8_test_LDADD = $(AM_LDADD)

prioq_test_SOURCES = prioq-test.c
prioq_test_CFLAGS = $(AM_CFLAGS)
prioq_test_LDADD = $(AM_LDADD)

avahi_test_SOURCES = avahi-test.c
avahi_test_CFLAGS = $(AM_CFLAGS)
avahi_test_LDADD = $(AM_LDADD)

update_test_SOURCES = update-test.c
update_test_CFLAGS = $(AM_CFLAGS)
update_test_LDADD = $(AM_LDADD)

querier_test_SOURCES = querier-test.c
querier_test_CFLAGS = $(AM_CFLAGS)
querier_test_LDADD = $(AM_LDADD)

conformance_test_SOURCES = conformance-test.c
conformance_test_CFLAGS = $(AM_CFLAGS)
conformance_test_LDADD = $(AM_LDADD)

avahi_reflector_SOURCES = avahi-reflector.c
avahi_reflector_CFLAGS = $(AM_CFLAGS)
avahi_reflector_LDADD = $(AM_LDADD)

dns_test_SOURCES = dns-test.c
dns_test_CFLAGS = $(AM_CFLAGS)
dns_test_LDADD = $(AM_LDADD)

dns_spin_test_SOURCES = dns-spin-test.c
dns_spin_test_CFLAGS = $(AM_CFLAGS)
dns_spin_test_LDADD = $(AM_LDADD)

timeeventq_test_SOURCES = timeeventq-test.c
timeeventq_test_CFLAGS = $(AM_CFLAGS)
timeeventq_test_LDADD = $(AM_LDADD)

hashmap_test_SOURCES = hashmap-test.c
hashmap_test_CFLAGS = $(AM_CFLAGS)
hashmap_test_LDADD = $(AM_LDADD)

valgrind: avahi-test
	libtool --mode=execute valgrind ./avahi-test

gdb: avahi-test
	libtool --mode=execute gdb ./avahi-test
