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
#include <assert.h>

#include <catta/llist.h>
#include <catta/malloc.h>

#include "rrlist.h"
#include <catta/log.h>

typedef struct CattaRecordListItem CattaRecordListItem;

struct CattaRecordListItem {
    int read;
    CattaRecord *record;
    int unicast_response;
    int flush_cache;
    int auxiliary;
    CATTA_LLIST_FIELDS(CattaRecordListItem, items);
};

struct CattaRecordList {
    CATTA_LLIST_HEAD(CattaRecordListItem, read);
    CATTA_LLIST_HEAD(CattaRecordListItem, unread);

    int all_flush_cache;
};

CattaRecordList *catta_record_list_new(void) {
    CattaRecordList *l;

    if (!(l = catta_new(CattaRecordList, 1))) {
        catta_log_error("catta_new() failed.");
        return NULL;
    }

    CATTA_LLIST_HEAD_INIT(CattaRecordListItem, l->read);
    CATTA_LLIST_HEAD_INIT(CattaRecordListItem, l->unread);

    l->all_flush_cache = 1;
    return l;
}

void catta_record_list_free(CattaRecordList *l) {
    assert(l);

    catta_record_list_flush(l);
    catta_free(l);
}

static void item_free(CattaRecordList *l, CattaRecordListItem *i) {
    assert(l);
    assert(i);

    if (i->read)
        CATTA_LLIST_REMOVE(CattaRecordListItem, items, l->read, i);
    else
        CATTA_LLIST_REMOVE(CattaRecordListItem, items, l->unread, i);

    catta_record_unref(i->record);
    catta_free(i);
}

void catta_record_list_flush(CattaRecordList *l) {
    assert(l);

    while (l->read)
        item_free(l, l->read);
    while (l->unread)
        item_free(l, l->unread);

    l->all_flush_cache = 1;
}

CattaRecord* catta_record_list_next(CattaRecordList *l, int *ret_flush_cache, int *ret_unicast_response, int *ret_auxiliary) {
    CattaRecord *r;
    CattaRecordListItem *i;

    if (!(i = l->unread))
        return NULL;

    assert(!i->read);

    r = catta_record_ref(i->record);
    if (ret_unicast_response)
        *ret_unicast_response = i->unicast_response;
    if (ret_flush_cache)
        *ret_flush_cache = i->flush_cache;
    if (ret_auxiliary)
        *ret_auxiliary = i->auxiliary;

    CATTA_LLIST_REMOVE(CattaRecordListItem, items, l->unread, i);
    CATTA_LLIST_PREPEND(CattaRecordListItem, items, l->read, i);

    i->read = 1;

    return r;
}

static CattaRecordListItem *get(CattaRecordList *l, CattaRecord *r) {
    CattaRecordListItem *i;

    assert(l);
    assert(r);

    for (i = l->read; i; i = i->items_next)
        if (catta_record_equal_no_ttl(i->record, r))
            return i;

    for (i = l->unread; i; i = i->items_next)
        if (catta_record_equal_no_ttl(i->record, r))
            return i;

    return NULL;
}

void catta_record_list_push(CattaRecordList *l, CattaRecord *r, int flush_cache, int unicast_response, int auxiliary) {
    CattaRecordListItem *i;

    assert(l);
    assert(r);

    if (get(l, r))
        return;

    if (!(i = catta_new(CattaRecordListItem, 1))) {
        catta_log_error("catta_new() failed.");
        return;
    }

    i->unicast_response = unicast_response;
    i->flush_cache = flush_cache;
    i->auxiliary = auxiliary;
    i->record = catta_record_ref(r);
    i->read = 0;

    l->all_flush_cache = l->all_flush_cache && flush_cache;

    CATTA_LLIST_PREPEND(CattaRecordListItem, items, l->unread, i);
}

void catta_record_list_drop(CattaRecordList *l, CattaRecord *r) {
    CattaRecordListItem *i;

    assert(l);
    assert(r);

    if (!(i = get(l, r)))
        return;

    item_free(l, i);
}

int catta_record_list_is_empty(CattaRecordList *l) {
    assert(l);

    return !l->unread && !l->read;
}

int catta_record_list_all_flush_cache(CattaRecordList *l) {
    assert(l);

    /* Return TRUE if all entries in this list have flush_cache set */

    return l->all_flush_cache;
}
