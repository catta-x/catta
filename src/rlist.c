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

#include <stdlib.h>

#include <catta/rlist.h>
#include <catta/malloc.h>

CattaRList* catta_rlist_prepend(CattaRList *r, void *data) {
    CattaRList *n;

    if (!(n = catta_new(CattaRList, 1)))
        return NULL;

    n->data = data;

    CATTA_LLIST_PREPEND(CattaRList, rlist, r, n);
    return r;
}

CattaRList* catta_rlist_remove(CattaRList *r, void *data) {
    CattaRList *n;

    for (n = r; n; n = n->rlist_next)

        if (n->data == data) {
            CATTA_LLIST_REMOVE(CattaRList, rlist, r, n);
            catta_free(n);
            break;
        }

    return r;
}

CattaRList* catta_rlist_remove_by_link(CattaRList *r, CattaRList *n) {
    assert(n);

    CATTA_LLIST_REMOVE(CattaRList, rlist, r, n);
    catta_free(n);

    return r;
}
