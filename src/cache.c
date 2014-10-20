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

#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <catta/timeval.h>
#include <catta/malloc.h>
#include <catta/log.h>

#include "cache.h"
#include "rr-util.h"

static void remove_entry(CattaCache *c, CattaCacheEntry *e) {
    CattaCacheEntry *t;

    assert(c);
    assert(e);

/*     catta_log_debug("removing from cache: %p %p", c, e); */

    /* Remove from hash table */
    t = catta_hashmap_lookup(c->hashmap, e->record->key);
    CATTA_LLIST_REMOVE(CattaCacheEntry, by_key, t, e);
    if (t)
        catta_hashmap_replace(c->hashmap, t->record->key, t);
    else
        catta_hashmap_remove(c->hashmap, e->record->key);

    /* Remove from linked list */
    CATTA_LLIST_REMOVE(CattaCacheEntry, entry, c->entries, e);

    if (e->time_event)
        catta_time_event_free(e->time_event);

    catta_multicast_lookup_engine_notify(c->server->multicast_lookup_engine, c->iface, e->record, CATTA_BROWSER_REMOVE);

    catta_record_unref(e->record);

    catta_free(e);

    assert(c->n_entries >= 1);
    --c->n_entries;
}

CattaCache *catta_cache_new(CattaServer *server, CattaInterface *iface) {
    CattaCache *c;
    assert(server);

    if (!(c = catta_new(CattaCache, 1))) {
        catta_log_error(__FILE__": Out of memory.");
        return NULL; /* OOM */
    }

    c->server = server;
    c->iface = iface;

    if (!(c->hashmap = catta_hashmap_new((CattaHashFunc) catta_key_hash, (CattaEqualFunc) catta_key_equal, NULL, NULL))) {
        catta_log_error(__FILE__": Out of memory.");
        catta_free(c);
        return NULL; /* OOM */
    }

    CATTA_LLIST_HEAD_INIT(CattaCacheEntry, c->entries);
    c->n_entries = 0;

    c->last_rand_timestamp = 0;

    return c;
}

void catta_cache_free(CattaCache *c) {
    assert(c);

    while (c->entries)
        remove_entry(c, c->entries);
    assert(c->n_entries == 0);

    catta_hashmap_free(c->hashmap);

    catta_free(c);
}

static CattaCacheEntry *lookup_key(CattaCache *c, CattaKey *k) {
    assert(c);
    assert(k);

    assert(!catta_key_is_pattern(k));

    return catta_hashmap_lookup(c->hashmap, k);
}

void* catta_cache_walk(CattaCache *c, CattaKey *pattern, CattaCacheWalkCallback cb, void* userdata) {
    void* ret;

    assert(c);
    assert(pattern);
    assert(cb);

    if (catta_key_is_pattern(pattern)) {
        CattaCacheEntry *e, *n;

        for (e = c->entries; e; e = n) {
            n = e->entry_next;

            if (catta_key_pattern_match(pattern, e->record->key))
                if ((ret = cb(c, pattern, e, userdata)))
                    return ret;
        }

    } else {
        CattaCacheEntry *e, *n;

        for (e = lookup_key(c, pattern); e; e = n) {
            n = e->by_key_next;

            if ((ret = cb(c, pattern, e, userdata)))
                return ret;
        }
    }

    return NULL;
}

static void* lookup_record_callback(CattaCache *c, CattaKey *pattern, CattaCacheEntry *e, void *userdata) {
    assert(c);
    assert(pattern);
    assert(e);

    if (catta_record_equal_no_ttl(e->record, userdata))
        return e;

    return NULL;
}

static CattaCacheEntry *lookup_record(CattaCache *c, CattaRecord *r) {
    assert(c);
    assert(r);

    return catta_cache_walk(c, r->key, lookup_record_callback, r);
}

static void next_expiry(CattaCache *c, CattaCacheEntry *e, unsigned percent);

static void elapse_func(CattaTimeEvent *t, void *userdata) {
    CattaCacheEntry *e = userdata;
/*     char *txt; */
    unsigned percent = 0;

    assert(t);
    assert(e);

/*     txt = catta_record_to_string(e->record); */

    switch (e->state) {

        case CATTA_CACHE_EXPIRY_FINAL:
        case CATTA_CACHE_POOF_FINAL:
        case CATTA_CACHE_GOODBYE_FINAL:
        case CATTA_CACHE_REPLACE_FINAL:

            remove_entry(e->cache, e);

            e = NULL;
/*         catta_log_debug("Removing entry from cache due to expiration (%s)", txt); */
            break;

        case CATTA_CACHE_VALID:
        case CATTA_CACHE_POOF:
            e->state = CATTA_CACHE_EXPIRY1;
            percent = 85;
            break;

        case CATTA_CACHE_EXPIRY1:
            e->state = CATTA_CACHE_EXPIRY2;
            percent = 90;
            break;
        case CATTA_CACHE_EXPIRY2:
            e->state = CATTA_CACHE_EXPIRY3;
            percent = 95;
            break;

        case CATTA_CACHE_EXPIRY3:
            e->state = CATTA_CACHE_EXPIRY_FINAL;
            percent = 100;
            break;
    }

    if (e) {

        assert(percent > 0);

        /* Request a cache update if we are subscribed to this entry */
        if (catta_querier_shall_refresh_cache(e->cache->iface, e->record->key))
            catta_interface_post_query(e->cache->iface, e->record->key, 0, NULL);

        /* Check again later */
        next_expiry(e->cache, e, percent);

    }

/*     catta_free(txt); */
}

static void update_time_event(CattaCache *c, CattaCacheEntry *e) {
    assert(c);
    assert(e);

    if (e->time_event)
        catta_time_event_update(e->time_event, &e->expiry);
    else
        e->time_event = catta_time_event_new(c->server->time_event_queue, &e->expiry, elapse_func, e);
}

static void next_expiry(CattaCache *c, CattaCacheEntry *e, unsigned percent) {
    CattaUsec usec, left, right;
    time_t now;

    assert(c);
    assert(e);
    assert(percent > 0 && percent <= 100);

    usec = (CattaUsec) e->record->ttl * 10000;

    left = usec * percent;
    right = usec * (percent+2); /* 2% jitter */

    now = time(NULL);

    if (now >= c->last_rand_timestamp + 10) {
        c->last_rand = rand();
        c->last_rand_timestamp = now;
    }

    usec = left + (CattaUsec) ((double) (right-left) * c->last_rand / (RAND_MAX+1.0));

    e->expiry = e->timestamp;
    catta_timeval_add(&e->expiry, usec);

/*     g_message("wake up in +%lu seconds", e->expiry.tv_sec - e->timestamp.tv_sec); */

    update_time_event(c, e);
}

static void expire_in_one_second(CattaCache *c, CattaCacheEntry *e, CattaCacheEntryState state) {
    assert(c);
    assert(e);

    e->state = state;
    gettimeofday(&e->expiry, NULL);
    catta_timeval_add(&e->expiry, 1000000); /* 1s */
    update_time_event(c, e);
}

void catta_cache_update(CattaCache *c, CattaRecord *r, int cache_flush, const CattaAddress *a) {
/*     char *txt; */

    assert(c);
    assert(r && r->ref >= 1);

/*     txt = catta_record_to_string(r); */

    if (r->ttl == 0) {
        /* This is a goodbye request */

        CattaCacheEntry *e;

        if ((e = lookup_record(c, r)))
            expire_in_one_second(c, e, CATTA_CACHE_GOODBYE_FINAL);

    } else {
        CattaCacheEntry *e = NULL, *first;
        struct timeval now;

        gettimeofday(&now, NULL);

        /* This is an update request */

        if ((first = lookup_key(c, r->key))) {

            if (cache_flush) {

                /* For unique entries drop all entries older than one second */
                for (e = first; e; e = e->by_key_next) {
                    CattaUsec t;

                    t = catta_timeval_diff(&now, &e->timestamp);

                    if (t > 1000000)
                        expire_in_one_second(c, e, CATTA_CACHE_REPLACE_FINAL);
                }
            }

            /* Look for exactly the same entry */
            for (e = first; e; e = e->by_key_next)
                if (catta_record_equal_no_ttl(e->record, r))
                    break;
        }

        if (e) {

/*             catta_log_debug("found matching cache entry");  */

            /* We need to update the hash table key if we replace the
             * record */
            if (e->by_key_prev == NULL)
                catta_hashmap_replace(c->hashmap, r->key, e);

            /* Update the record */
            catta_record_unref(e->record);
            e->record = catta_record_ref(r);

/*             catta_log_debug("cache: updating %s", txt);   */

        } else {
            /* No entry found, therefore we create a new one */

/*             catta_log_debug("cache: couldn't find matching cache entry for %s", txt);   */

            if (c->n_entries >= c->server->config.n_cache_entries_max)
                return;

            if (!(e = catta_new(CattaCacheEntry, 1))) {
                catta_log_error(__FILE__": Out of memory");
                return;
            }

            e->cache = c;
            e->time_event = NULL;
            e->record = catta_record_ref(r);

            /* Append to hash table */
            CATTA_LLIST_PREPEND(CattaCacheEntry, by_key, first, e);
            catta_hashmap_replace(c->hashmap, e->record->key, first);

            /* Append to linked list */
            CATTA_LLIST_PREPEND(CattaCacheEntry, entry, c->entries, e);

            c->n_entries++;

            /* Notify subscribers */
            catta_multicast_lookup_engine_notify(c->server->multicast_lookup_engine, c->iface, e->record, CATTA_BROWSER_NEW);
        }

        e->origin = *a;
        e->timestamp = now;
        next_expiry(c, e, 80);
        e->state = CATTA_CACHE_VALID;
        e->cache_flush = cache_flush;
    }

/*     catta_free(txt);  */
}

struct dump_data {
    CattaDumpCallback callback;
    void* userdata;
};

static void dump_callback(void* key, void* data, void* userdata) {
    CattaCacheEntry *e = data;
    CattaKey *k = key;
    struct dump_data *dump_data = userdata;

    assert(k);
    assert(e);
    assert(data);

    for (; e; e = e->by_key_next) {
        char *t;

        if (!(t = catta_record_to_string(e->record)))
            continue; /* OOM */

        dump_data->callback(t, dump_data->userdata);
        catta_free(t);
    }
}

int catta_cache_dump(CattaCache *c, CattaDumpCallback callback, void* userdata) {
    struct dump_data data;

    assert(c);
    assert(callback);

    callback(";;; CACHE DUMP FOLLOWS ;;;", userdata);

    data.callback = callback;
    data.userdata = userdata;

    catta_hashmap_foreach(c->hashmap, dump_callback, &data);

    return 0;
}

int catta_cache_entry_half_ttl(CattaCache *c, CattaCacheEntry *e) {
    struct timeval now;
    unsigned age;

    assert(c);
    assert(e);

    gettimeofday(&now, NULL);

    age = (unsigned) (catta_timeval_diff(&now, &e->timestamp)/1000000);

/*     catta_log_debug("age: %lli, ttl/2: %u", age, e->record->ttl);  */

    return age >= e->record->ttl/2;
}

void catta_cache_flush(CattaCache *c) {
    assert(c);

    while (c->entries)
        remove_entry(c, c->entries);
}

/*** Passive observation of failure ***/

static void* start_poof_callback(CattaCache *c, CattaKey *pattern, CattaCacheEntry *e, void *userdata) {
    CattaAddress *a = userdata;
    struct timeval now;

    assert(c);
    assert(pattern);
    assert(e);
    assert(a);

    gettimeofday(&now, NULL);

    switch (e->state) {
        case CATTA_CACHE_VALID:

            /* The entry was perfectly valid till, now, so let's enter
             * POOF mode */

            e->state = CATTA_CACHE_POOF;
            e->poof_address = *a;
            e->poof_timestamp = now;
            e->poof_num = 0;

            break;

        case CATTA_CACHE_POOF:
            if (catta_timeval_diff(&now, &e->poof_timestamp) < 1000000)
              break;

            e->poof_timestamp = now;
            e->poof_address = *a;
            e->poof_num ++;

            /* This is the 4th time we got no response, so let's
             * fucking remove this entry. */
            if (e->poof_num > 3)
              expire_in_one_second(c, e, CATTA_CACHE_POOF_FINAL);
            break;

        default:
            ;
    }

    return NULL;
}

void catta_cache_start_poof(CattaCache *c, CattaKey *key, const CattaAddress *a) {
    assert(c);
    assert(key);

    catta_cache_walk(c, key, start_poof_callback, (void*) a);
}

void catta_cache_stop_poof(CattaCache *c, CattaRecord *record, const CattaAddress *a) {
    CattaCacheEntry *e;

    assert(c);
    assert(record);
    assert(a);

    if (!(e = lookup_record(c, record)))
        return;

    /* This function is called for each response suppression
       record. If the matching cache entry is in POOF state and the
       query address is the same, we put it back into valid mode */

    if (e->state == CATTA_CACHE_POOF || e->state == CATTA_CACHE_POOF_FINAL)
        if (catta_address_cmp(a, &e->poof_address) == 0) {
            e->state = CATTA_CACHE_VALID;
            next_expiry(c, e, 80);
        }
}
