#ifndef fooutilhfoo
#define fooutilhfoo

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

#include <catta/cdecl.h>

CATTA_C_DECL_BEGIN

void catta_hexdump(const void *p, size_t size);

char *catta_format_mac_address(char *t, size_t l, const uint8_t* mac, size_t size);

/** Change every character in the string to upper case (ASCII), return a pointer to the string */
char *catta_strup(char *s);

/** Change every character in the string to lower case (ASCII), return a pointer to the string */
char *catta_strdown(char *s);

CATTA_C_DECL_END

#endif
