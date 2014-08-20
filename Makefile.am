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

ACLOCAL_AMFLAGS = -I m4

include $(srcdir)/m4/doxygen.mk

EXTRA_DIST = \
	LICENSE \
	$(DX_CONFIG) \
	docs/INSTALL \
	docs/TODO \
	docs/NEWS \
	docs/README \
	docs/DBUS-API \
	docs/AUTHORS \
	docs/HACKING \
	docs/API-CHANGES-0.6 \
	docs/COMPAT-LAYERS \
	docs/MALLOC \
	docs/overview.dia \
	docs/server-states.dia \
	docs/avahi-poll.dia \
	avahi.pc.in \
	doxygen_to_devhelp.xsl

SUBDIRS = \
	m4 \
	src \
    include \
	tests \
	examples

DX_INPUT = \
	$(srcdir)/include/avahi/address.h \
	$(srcdir)/include/avahi/malloc.h \
	$(srcdir)/include/avahi/strlst.h \
	$(srcdir)/include/avahi/alternative.h \
	$(srcdir)/include/avahi/defs.h \
	$(srcdir)/include/avahi/error.h \
	$(srcdir)/include/avahi/domain.h \
	$(srcdir)/include/avahi/watch.h \
	$(srcdir)/include/avahi/simple-watch.h \
	$(srcdir)/include/avahi/thread-watch.h \
	$(srcdir)/include/avahi/core.h \
	$(srcdir)/include/avahi/lookup.h \
	$(srcdir)/include/avahi/publish.h \
	$(srcdir)/include/avahi/rr.h \
	$(srcdir)/include/avahi/log.h

DX_EXAMPLE_PATH = $(srcdir)/examples
DX_EXAMPLE_PATTERNS = *.c

pkgconfigdir = $(libdir)/pkgconfig

%.pc: %.pc.in
	$(AM_V_GEN)sed -e 's,@prefix\@,$(prefix),g' \
	    -e 's,@libdir\@,$(libdir),g' \
	    -e 's,@PACKAGE_VERSION\@,$(PACKAGE_VERSION),g' $< > $@

pkgconfig_DATA = avahi.pc
CLEANFILES = avahi.pc
CLEANFILES += avahi.devhelp

avahi.devhelp: doxygen-run
	xsltproc -o $@ doxygen_to_devhelp.xsl doxygen/xml/index.xml

MOSTLYCLEANFILES = $(DX_CLEANFILES)
