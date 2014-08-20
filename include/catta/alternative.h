#ifndef fooalternativehfoo
#define fooalternativehfoo

/***
  This file is part of catta.

  catta is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  catta is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
  Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with catta; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

/** \file alternative.h Functions to find alternative names for hosts and services in the case of name collision */

#include <catta/cdecl.h>

CATTA_C_DECL_BEGIN

/** Find an alternative for the specified host name. If called with an
 * original host name, "-2" is appended, afterwards the number is
 * increased on each call. (i.e. "foo" becomes "foo-2" becomes "foo-3"
 * and so on.) catta_free() the result. */
char *catta_alternative_host_name(const char *s);

/** Find an alternative for the specified service name. If called with
 * an original service name, " #2" is appended. Afterwards the number
 * is increased on each call (i.e. "foo" becomes "foo #2" becomes "foo
 * #3" and so on.) catta_free() the result. */
char *catta_alternative_service_name(const char *s);

CATTA_C_DECL_END

#endif
