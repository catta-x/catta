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
#include <string.h>

#include <catta/llist.h>
#include <catta/domain.h>
#include <catta/malloc.h>

#include "hashmap.h"
#include "util.h"

#define HASH_MAP_SIZE 123

typedef struct Entry Entry;
struct Entry {
    CattaHashmap *hashmap;
    void *key;
    void *value;

    CATTA_LLIST_FIELDS(Entry, bucket);
    CATTA_LLIST_FIELDS(Entry, entries);
};

struct CattaHashmap {
    CattaHashFunc hash_func;
    CattaEqualFunc equal_func;
    CattaFreeFunc key_free_func, value_free_func;

    Entry *entries[HASH_MAP_SIZE];
    CATTA_LLIST_HEAD(Entry, entries_list);
};

static Entry* entry_get(CattaHashmap *m, const void *key) {
    unsigned idx;
    Entry *e;

    idx = m->hash_func(key) % HASH_MAP_SIZE;

    for (e = m->entries[idx]; e; e = e->bucket_next)
        if (m->equal_func(key, e->key))
            return e;

    return NULL;
}

static void entry_free(CattaHashmap *m, Entry *e, int stolen) {
    unsigned idx;
    assert(m);
    assert(e);

    idx = m->hash_func(e->key) % HASH_MAP_SIZE;

    CATTA_LLIST_REMOVE(Entry, bucket, m->entries[idx], e);
    CATTA_LLIST_REMOVE(Entry, entries, m->entries_list, e);

    if (m->key_free_func)
        m->key_free_func(e->key);
    if (m->value_free_func && !stolen)
        m->value_free_func(e->value);

    catta_free(e);
}

CattaHashmap* catta_hashmap_new(CattaHashFunc hash_func, CattaEqualFunc equal_func, CattaFreeFunc key_free_func, CattaFreeFunc value_free_func) {
    CattaHashmap *m;

    assert(hash_func);
    assert(equal_func);

    if (!(m = catta_new0(CattaHashmap, 1)))
        return NULL;

    m->hash_func = hash_func;
    m->equal_func = equal_func;
    m->key_free_func = key_free_func;
    m->value_free_func = value_free_func;

    CATTA_LLIST_HEAD_INIT(Entry, m->entries_list);

    return m;
}

void catta_hashmap_free(CattaHashmap *m) {
    assert(m);

    while (m->entries_list)
        entry_free(m, m->entries_list, 0);

    catta_free(m);
}

void* catta_hashmap_lookup(CattaHashmap *m, const void *key) {
    Entry *e;

    assert(m);

    if (!(e = entry_get(m, key)))
        return NULL;

    return e->value;
}

int catta_hashmap_insert(CattaHashmap *m, void *key, void *value) {
    unsigned idx;
    Entry *e;

    assert(m);

    if ((e = entry_get(m, key))) {
        if (m->key_free_func)
            m->key_free_func(key);
        if (m->value_free_func)
            m->value_free_func(value);

        return 1;
    }

    if (!(e = catta_new(Entry, 1)))
        return -1;

    e->hashmap = m;
    e->key = key;
    e->value = value;

    CATTA_LLIST_PREPEND(Entry, entries, m->entries_list, e);

    idx = m->hash_func(key) % HASH_MAP_SIZE;
    CATTA_LLIST_PREPEND(Entry, bucket, m->entries[idx], e);

    return 0;
}


int catta_hashmap_replace(CattaHashmap *m, void *key, void *value) {
    unsigned idx;
    Entry *e;

    assert(m);

    if ((e = entry_get(m, key))) {
        if (m->key_free_func)
            m->key_free_func(e->key);
        if (m->value_free_func)
            m->value_free_func(e->value);

        e->key = key;
        e->value = value;

        return 1;
    }

    if (!(e = catta_new(Entry, 1)))
        return -1;

    e->hashmap = m;
    e->key = key;
    e->value = value;

    CATTA_LLIST_PREPEND(Entry, entries, m->entries_list, e);

    idx = m->hash_func(key) % HASH_MAP_SIZE;
    CATTA_LLIST_PREPEND(Entry, bucket, m->entries[idx], e);

    return 0;
}

void catta_hashmap_remove(CattaHashmap *m, const void *key) {
    Entry *e;

    assert(m);

    if (!(e = entry_get(m, key)))
        return;

    entry_free(m, e, 0);
}

void catta_hashmap_foreach(CattaHashmap *m, CattaHashmapForeachCallback callback, void *userdata) {
    Entry *e, *next;
    assert(m);
    assert(callback);

    for (e = m->entries_list; e; e = next) {
        next = e->entries_next;

        callback(e->key, e->value, userdata);
    }
}

unsigned catta_string_hash(const void *data) {
    const char *p = data;
    unsigned hash = 0;

    assert(p);

    for (; *p; p++)
        hash = 31 * hash + *p;

    return hash;
}

int catta_string_equal(const void *a, const void *b) {
    const char *p = a, *q = b;

    assert(p);
    assert(q);

    return strcmp(p, q) == 0;
}

unsigned catta_int_hash(const void *data) {
    const int *i = data;

    assert(i);

    return (unsigned) *i;
}

int catta_int_equal(const void *a, const void *b) {
    const int *_a = a, *_b = b;

    assert(_a);
    assert(_b);

    return *_a == *_b;
}
