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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#include <catta/domain.h>
#include <catta/malloc.h>

#include "../src/hashmap.h"
#include "../src/util.h"

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char *argv[]) {
    unsigned n;
    CattaHashmap *m;
    const char *t;

    m = catta_hashmap_new(catta_string_hash, catta_string_equal, catta_free, catta_free);

    catta_hashmap_insert(m, catta_strdup("bla"), catta_strdup("#1"));
    catta_hashmap_insert(m, catta_strdup("bla2"), catta_strdup("asdf"));
    catta_hashmap_insert(m, catta_strdup("gurke"), catta_strdup("ffsdf"));
    catta_hashmap_insert(m, catta_strdup("blubb"), catta_strdup("sadfsd"));
    catta_hashmap_insert(m, catta_strdup("bla"), catta_strdup("#2"));

    for (n = 0; n < 1000; n ++)
        catta_hashmap_insert(m, catta_strdup_printf("key %u", n), catta_strdup_printf("value %u", n));

    printf("%s\n", (const char*) catta_hashmap_lookup(m, "bla"));

    catta_hashmap_replace(m, catta_strdup("bla"), catta_strdup("#3"));

    printf("%s\n", (const char*) catta_hashmap_lookup(m, "bla"));

    catta_hashmap_remove(m, "bla");

    t = (const char*) catta_hashmap_lookup(m, "bla");
    printf("%s\n", t ? t : "(null)");

    catta_hashmap_free(m);

    return 0;
}
