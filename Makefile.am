# This file is part of catta.
#
# catta is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# catta is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with catta; if not, write to the Free Software
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
	catta.pc.in \
	doxygen_to_devhelp.xsl

SUBDIRS = \
	m4 \
	src \
    include \
	tests \
	examples

DX_INPUT = \
	$(srcdir)/include/catta/address.h \
	$(srcdir)/include/catta/malloc.h \
	$(srcdir)/include/catta/strlst.h \
	$(srcdir)/include/catta/alternative.h \
	$(srcdir)/include/catta/defs.h \
	$(srcdir)/include/catta/error.h \
	$(srcdir)/include/catta/domain.h \
	$(srcdir)/include/catta/watch.h \
	$(srcdir)/include/catta/simple-watch.h \
	$(srcdir)/include/catta/thread-watch.h \
	$(srcdir)/include/catta/core.h \
	$(srcdir)/include/catta/lookup.h \
	$(srcdir)/include/catta/publish.h \
	$(srcdir)/include/catta/rr.h \
	$(srcdir)/include/catta/log.h

DX_EXAMPLE_PATH = $(srcdir)/examples
DX_EXAMPLE_PATTERNS = *.c

pkgconfigdir = $(libdir)/pkgconfig

%.pc: %.pc.in
	$(AM_V_GEN)sed -e 's,@prefix\@,$(prefix),g' \
	    -e 's,@libdir\@,$(libdir),g' \
	    -e 's,@PACKAGE_VERSION\@,$(PACKAGE_VERSION),g' $< > $@

pkgconfig_DATA = catta.pc
CLEANFILES = catta.pc
CLEANFILES += catta.devhelp

catta.devhelp: doxygen-run
	xsltproc -o $@ doxygen_to_devhelp.xsl doxygen/xml/index.xml

MOSTLYCLEANFILES = $(DX_CLEANFILES)
