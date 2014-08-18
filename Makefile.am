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
	autogen.sh \
	bootstrap.sh \
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
	avahi-core.pc.in \
	doxygen_to_devhelp.xsl \
        common/introspection.m4

SUBDIRS = \
	common \
	avahi-common \
	avahi-core \
	examples \
	po

DX_INPUT = \
	$(srcdir)/avahi-common/address.h \
	$(srcdir)/avahi-common/malloc.h \
	$(srcdir)/avahi-common/strlst.h \
	$(srcdir)/avahi-common/alternative.h \
	$(srcdir)/avahi-common/defs.h \
	$(srcdir)/avahi-common/error.h \
	$(srcdir)/avahi-common/domain.h \
	$(srcdir)/avahi-common/watch.h \
	$(srcdir)/avahi-common/simple-watch.h \
	$(srcdir)/avahi-common/thread-watch.h

DX_EXAMPLE_PATH = $(srcdir)/examples
DX_EXAMPLE_PATTERNS = *.c

if ENABLE_CORE_DOCS
DX_INPUT += \
	$(srcdir)/avahi-core/core.h \
	$(srcdir)/avahi-core/lookup.h \
	$(srcdir)/avahi-core/publish.h \
	$(srcdir)/avahi-core/rr.h \
	$(srcdir)/avahi-core/log.h
endif

pkgconfigdir = $(libdir)/pkgconfig

%.pc: %.pc.in
	$(AM_V_GEN)sed -e 's,@prefix\@,$(prefix),g' \
	    -e 's,@libdir\@,$(libdir),g' \
	    -e 's,@HOWL_COMPAT_VERSION\@,$(HOWL_COMPAT_VERSION),g' \
	    -e 's,@PACKAGE_VERSION\@,$(PACKAGE_VERSION),g' $< > $@

pkgconfig_DATA = avahi-core.pc
CLEANFILES = avahi-core.pc
CLEANFILES += avahi.devhelp

avahi.devhelp: doxygen-run
	xsltproc -o $@ doxygen_to_devhelp.xsl doxygen/xml/index.xml

MOSTLYCLEANFILES = $(DX_CLEANFILES)

DISTCHECK_CONFIGURE_FLAGS = \
	--disable-monodoc \
	--enable-introspection \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

DISTCLEANFILES = \
	po/.intltool-merge-cache
