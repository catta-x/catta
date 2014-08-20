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

#include <catta/malloc.h>
#include <catta/timeval.h>

#include "internal.h"
#include "browse.h"
#include "socket.h"
#include <catta/log.h>
#include "hashmap.h"
#include "multicast-lookup.h"
#include "rr-util.h"

struct CattaMulticastLookup {
    CattaMulticastLookupEngine *engine;
    int dead;

    CattaKey *key, *cname_key;

    CattaMulticastLookupCallback callback;
    void *userdata;

    CattaIfIndex interface;
    CattaProtocol protocol;

    int queriers_added;

    CattaTimeEvent *all_for_now_event;

    CATTA_LLIST_FIELDS(CattaMulticastLookup, lookups);
    CATTA_LLIST_FIELDS(CattaMulticastLookup, by_key);
};

struct CattaMulticastLookupEngine {
    CattaServer *server;

    /* Lookups */
    CATTA_LLIST_HEAD(CattaMulticastLookup, lookups);
    CattaHashmap *lookups_by_key;

    int cleanup_dead;
};

static void all_for_now_callback(CattaTimeEvent *e, void* userdata) {
    CattaMulticastLookup *l = userdata;

    assert(e);
    assert(l);

    catta_time_event_free(l->all_for_now_event);
    l->all_for_now_event = NULL;

    l->callback(l->engine, l->interface, l->protocol, CATTA_BROWSER_ALL_FOR_NOW, CATTA_LOOKUP_RESULT_MULTICAST, NULL, l->userdata);
}

CattaMulticastLookup *catta_multicast_lookup_new(
    CattaMulticastLookupEngine *e,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaKey *key,
    CattaMulticastLookupCallback callback,
    void *userdata) {

    CattaMulticastLookup *l, *t;
    struct timeval tv;

    assert(e);
    assert(CATTA_IF_VALID(interface));
    assert(CATTA_PROTO_VALID(protocol));
    assert(key);
    assert(callback);

    l = catta_new(CattaMulticastLookup, 1);
    l->engine = e;
    l->dead = 0;
    l->key = catta_key_ref(key);
    l->cname_key = catta_key_new_cname(l->key);
    l->callback = callback;
    l->userdata = userdata;
    l->interface = interface;
    l->protocol = protocol;
    l->all_for_now_event = NULL;
    l->queriers_added = 0;

    t = catta_hashmap_lookup(e->lookups_by_key, l->key);
    CATTA_LLIST_PREPEND(CattaMulticastLookup, by_key, t, l);
    catta_hashmap_replace(e->lookups_by_key, catta_key_ref(l->key), t);

    CATTA_LLIST_PREPEND(CattaMulticastLookup, lookups, e->lookups, l);

    catta_querier_add_for_all(e->server, interface, protocol, l->key, &tv);
    l->queriers_added = 1;

    /* Add a second */
    catta_timeval_add(&tv, 1000000);

    /* Issue the ALL_FOR_NOW event one second after the querier was initially created */
    l->all_for_now_event = catta_time_event_new(e->server->time_event_queue, &tv, all_for_now_callback, l);

    return l;
}

static void lookup_stop(CattaMulticastLookup *l) {
    assert(l);

    l->callback = NULL;

    if (l->queriers_added) {
        catta_querier_remove_for_all(l->engine->server, l->interface, l->protocol, l->key);
        l->queriers_added = 0;
    }

    if (l->all_for_now_event) {
        catta_time_event_free(l->all_for_now_event);
        l->all_for_now_event = NULL;
    }
}

static void lookup_destroy(CattaMulticastLookup *l) {
    CattaMulticastLookup *t;
    assert(l);

    lookup_stop(l);

    t = catta_hashmap_lookup(l->engine->lookups_by_key, l->key);
    CATTA_LLIST_REMOVE(CattaMulticastLookup, by_key, t, l);
    if (t)
        catta_hashmap_replace(l->engine->lookups_by_key, catta_key_ref(l->key), t);
    else
        catta_hashmap_remove(l->engine->lookups_by_key, l->key);

    CATTA_LLIST_REMOVE(CattaMulticastLookup, lookups, l->engine->lookups, l);

    if (l->key)
        catta_key_unref(l->key);

    if (l->cname_key)
        catta_key_unref(l->cname_key);

    catta_free(l);
}

void catta_multicast_lookup_free(CattaMulticastLookup *l) {
    assert(l);

    if (l->dead)
        return;

    l->dead = 1;
    l->engine->cleanup_dead = 1;
    lookup_stop(l);
}

void catta_multicast_lookup_engine_cleanup(CattaMulticastLookupEngine *e) {
    CattaMulticastLookup *l, *n;
    assert(e);

    while (e->cleanup_dead) {
        e->cleanup_dead = 0;

        for (l = e->lookups; l; l = n) {
            n = l->lookups_next;

            if (l->dead)
                lookup_destroy(l);
        }
    }
}

struct cbdata {
    CattaMulticastLookupEngine *engine;
    CattaMulticastLookupCallback callback;
    void *userdata;
    CattaKey *key, *cname_key;
    CattaInterface *interface;
    unsigned n_found;
};

static void* scan_cache_callback(CattaCache *c, CattaKey *pattern, CattaCacheEntry *e, void* userdata) {
    struct cbdata *cbdata = userdata;

    assert(c);
    assert(pattern);
    assert(e);
    assert(cbdata);

    cbdata->callback(
        cbdata->engine,
        cbdata->interface->hardware->index,
        cbdata->interface->protocol,
        CATTA_BROWSER_NEW,
        CATTA_LOOKUP_RESULT_CACHED|CATTA_LOOKUP_RESULT_MULTICAST,
        e->record,
        cbdata->userdata);

    cbdata->n_found ++;

    return NULL;
}

static void scan_interface_callback(CattaInterfaceMonitor *m, CattaInterface *i, void* userdata) {
    struct cbdata *cbdata = userdata;

    assert(m);
    assert(i);
    assert(cbdata);

    cbdata->interface = i;

    catta_cache_walk(i->cache, cbdata->key, scan_cache_callback, cbdata);

    if (cbdata->cname_key)
        catta_cache_walk(i->cache, cbdata->cname_key, scan_cache_callback, cbdata);

    cbdata->interface = NULL;
}

unsigned catta_multicast_lookup_engine_scan_cache(
    CattaMulticastLookupEngine *e,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaKey *key,
    CattaMulticastLookupCallback callback,
    void *userdata) {

    struct cbdata cbdata;

    assert(e);
    assert(key);
    assert(callback);

    assert(CATTA_IF_VALID(interface));
    assert(CATTA_PROTO_VALID(protocol));

    cbdata.engine = e;
    cbdata.key = key;
    cbdata.cname_key = catta_key_new_cname(key);
    cbdata.callback = callback;
    cbdata.userdata = userdata;
    cbdata.interface = NULL;
    cbdata.n_found = 0;

    catta_interface_monitor_walk(e->server->monitor, interface, protocol, scan_interface_callback, &cbdata);

    if (cbdata.cname_key)
        catta_key_unref(cbdata.cname_key);

    return cbdata.n_found;
}

void catta_multicast_lookup_engine_new_interface(CattaMulticastLookupEngine *e, CattaInterface *i) {
    CattaMulticastLookup *l;

    assert(e);
    assert(i);

    for (l = e->lookups; l; l = l->lookups_next) {

        if (l->dead || !l->callback)
            continue;

        if (l->queriers_added && catta_interface_match(i, l->interface, l->protocol))
            catta_querier_add(i, l->key, NULL);
    }
}

void catta_multicast_lookup_engine_notify(CattaMulticastLookupEngine *e, CattaInterface *i, CattaRecord *record, CattaBrowserEvent event) {
    CattaMulticastLookup *l;

    assert(e);
    assert(record);
    assert(i);

    for (l = catta_hashmap_lookup(e->lookups_by_key, record->key); l; l = l->by_key_next) {
        if (l->dead || !l->callback)
            continue;

        if (catta_interface_match(i, l->interface, l->protocol))
            l->callback(e, i->hardware->index, i->protocol, event, CATTA_LOOKUP_RESULT_MULTICAST, record, l->userdata);
    }


    if (record->key->clazz == CATTA_DNS_CLASS_IN && record->key->type == CATTA_DNS_TYPE_CNAME) {
        /* It's a CNAME record, so we have to scan the all lookups to see if one matches */

        for (l = e->lookups; l; l = l->lookups_next) {
            CattaKey *key;

            if (l->dead || !l->callback)
                continue;

            if ((key = catta_key_new_cname(l->key))) {
                if (catta_key_equal(record->key, key))
                    l->callback(e, i->hardware->index, i->protocol, event, CATTA_LOOKUP_RESULT_MULTICAST, record, l->userdata);

                catta_key_unref(key);
            }
        }
    }
}

CattaMulticastLookupEngine *catta_multicast_lookup_engine_new(CattaServer *s) {
    CattaMulticastLookupEngine *e;

    assert(s);

    e = catta_new(CattaMulticastLookupEngine, 1);
    e->server = s;
    e->cleanup_dead = 0;

    /* Initialize lookup list */
    e->lookups_by_key = catta_hashmap_new((CattaHashFunc) catta_key_hash, (CattaEqualFunc) catta_key_equal, (CattaFreeFunc) catta_key_unref, NULL);
    CATTA_LLIST_HEAD_INIT(CattaWideAreaLookup, e->lookups);

    return e;
}

void catta_multicast_lookup_engine_free(CattaMulticastLookupEngine *e) {
    assert(e);

    while (e->lookups)
        lookup_destroy(e->lookups);

    catta_hashmap_free(e->lookups_by_key);
    catta_free(e);
}

