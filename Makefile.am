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

ACLOCAL_AMFLAGS = -I common

include $(srcdir)/common/doxygen.mk

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
	common \
	avahi \
	tests \
	examples

DX_INPUT = \
	$(srcdir)/avahi/address.h \
	$(srcdir)/avahi/malloc.h \
	$(srcdir)/avahi/strlst.h \
	$(srcdir)/avahi/alternative.h \
	$(srcdir)/avahi/defs.h \
	$(srcdir)/avahi/error.h \
	$(srcdir)/avahi/domain.h \
	$(srcdir)/avahi/watch.h \
	$(srcdir)/avahi/simple-watch.h \
	$(srcdir)/avahi/thread-watch.h \
	$(srcdir)/avahi/core.h \
	$(srcdir)/avahi/lookup.h \
	$(srcdir)/avahi/publish.h \
	$(srcdir)/avahi/rr.h \
	$(srcdir)/avahi/log.h

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
