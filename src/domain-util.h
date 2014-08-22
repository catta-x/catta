#ifndef foodomainutilhfoo
#define foodomainutilhfoo

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

#include <inttypes.h>
#include <sys/types.h>

#include <catta/cdecl.h>
#include <catta/domain.h>

CATTA_C_DECL_BEGIN

/** Return the local host name. */
char *catta_get_host_name(char *ret_s, size_t size);

/** Return the local host name. catta_free() the result! */
char *catta_get_host_name_strdup(void);

/** Do a binary comparison of to specified domain names, return -1, 0, or 1, depending on the order. */
int catta_binary_domain_cmp(const char *a, const char *b);

/** Returns 1 if the the end labels of domain are eqal to suffix */
int catta_domain_ends_with(const char *domain, const char *suffix);

CATTA_C_DECL_END

#endif
