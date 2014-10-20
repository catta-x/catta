#ifndef foorlistfoo
#define foorlistfoo

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

/** \file rlist.h A simple linked list implementation */

#include "llist.h"

CATTA_C_DECL_BEGIN

/** A doubly linked list type */
typedef struct CattaRList CattaRList;

/** A doubly linked list type */
struct CattaRList {
    CATTA_LLIST_FIELDS(CattaRList, rlist);
    void *data;
};

/** Prepend a new item to the beginning of the list and return the new beginning */
CattaRList* catta_rlist_prepend(CattaRList *r, void *data);

/** Remove the first occurence of the specified item from the list and return the new beginning */
CattaRList* catta_rlist_remove(CattaRList *r, void *data);

/** Remove the specified item from the list and return the new beginning */
CattaRList* catta_rlist_remove_by_link(CattaRList *r, CattaRList *n);

CATTA_C_DECL_END

#endif
