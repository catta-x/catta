#ifndef foorrutilhfoo
#define foorrutilhfoo

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

#include <catta/rr.h>

CATTA_C_DECL_BEGIN

/** Creaze new CattaKey object based on an existing key but replaceing the type by CNAME */
CattaKey *catta_key_new_cname(CattaKey *key);

/** Match a key to a key pattern. The pattern has a type of
CATTA_DNS_CLASS_ANY, the classes are taken to be equal. Same for the
type. If the pattern has neither class nor type with ANY constants,
this function is identical to catta_key_equal(). In contrast to
catta_equal() this function is not commutative. */
int catta_key_pattern_match(const CattaKey *pattern, const CattaKey *k);

/** Check whether a key is a pattern key, i.e. the class/type has a
 * value of CATTA_DNS_CLASS_ANY/CATTA_DNS_TYPE_ANY */
int catta_key_is_pattern(const CattaKey *k);

/** Returns a maximum estimate for the space that is needed to store
 * this key in a DNS packet. */
size_t catta_key_get_estimate_size(CattaKey *k);

/** Returns a maximum estimate for the space that is needed to store
 * the record in a DNS packet. */
size_t catta_record_get_estimate_size(CattaRecord *r);

/** Do a mDNS spec conforming lexicographical comparison of the two
 * records. Return a negative value if a < b, a positive if a > b,
 * zero if equal. */
int catta_record_lexicographical_compare(CattaRecord *a, CattaRecord *b);

/** Return 1 if the specified record is an mDNS goodbye record. i.e. TTL is zero. */
int catta_record_is_goodbye(CattaRecord *r);

/** Make a deep copy of an CattaRecord object */
CattaRecord *catta_record_copy(CattaRecord *r);

CATTA_C_DECL_END

#endif
