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

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>

#include <catta/malloc.h>
#include <catta/error.h>
#include <catta/timeval.h>

#include "internal.h"
#include "browse.h"
#include "socket.h"
#include <catta/log.h>
#include "hashmap.h"
#include "wide-area.h"
#include "addr-util.h"
#include "rr-util.h"

#define CACHE_ENTRIES_MAX 500

typedef struct CattaWideAreaCacheEntry CattaWideAreaCacheEntry;

struct CattaWideAreaCacheEntry {
    CattaWideAreaLookupEngine *engine;

    CattaRecord *record;
    struct timeval timestamp;
    struct timeval expiry;

    CattaTimeEvent *time_event;

    CATTA_LLIST_FIELDS(CattaWideAreaCacheEntry, by_key);
    CATTA_LLIST_FIELDS(CattaWideAreaCacheEntry, cache);
};

struct CattaWideAreaLookup {
    CattaWideAreaLookupEngine *engine;
    int dead;

    uint32_t id;  /* effectively just an uint16_t, but we need it as an index for a hash table */
    CattaTimeEvent *time_event;

    CattaKey *key, *cname_key;

    int n_send;
    CattaDnsPacket *packet;

    CattaWideAreaLookupCallback callback;
    void *userdata;

    CattaAddress dns_server_used;

    CATTA_LLIST_FIELDS(CattaWideAreaLookup, lookups);
    CATTA_LLIST_FIELDS(CattaWideAreaLookup, by_key);
};

struct CattaWideAreaLookupEngine {
    CattaServer *server;

    int fd_ipv4, fd_ipv6;
    CattaWatch *watch_ipv4, *watch_ipv6;

    uint16_t next_id;

    /* Cache */
    CATTA_LLIST_HEAD(CattaWideAreaCacheEntry, cache);
    CattaHashmap *cache_by_key;
    unsigned cache_n_entries;

    /* Lookups */
    CATTA_LLIST_HEAD(CattaWideAreaLookup, lookups);
    CattaHashmap *lookups_by_id;
    CattaHashmap *lookups_by_key;

    int cleanup_dead;

    CattaAddress dns_servers[CATTA_WIDE_AREA_SERVERS_MAX];
    unsigned n_dns_servers;
    unsigned current_dns_server;
};

static CattaWideAreaLookup* find_lookup(CattaWideAreaLookupEngine *e, uint16_t id) {
    CattaWideAreaLookup *l;
    int i = (int) id;

    assert(e);

    if (!(l = catta_hashmap_lookup(e->lookups_by_id, &i)))
        return NULL;

    assert(l->id == id);

    if (l->dead)
        return NULL;

    return l;
}

static int send_to_dns_server(CattaWideAreaLookup *l, CattaDnsPacket *p) {
    CattaAddress *a;

    assert(l);
    assert(p);

    if (l->engine->n_dns_servers <= 0)
        return -1;

    assert(l->engine->current_dns_server < l->engine->n_dns_servers);

    a = &l->engine->dns_servers[l->engine->current_dns_server];
    l->dns_server_used = *a;

    if (a->proto == CATTA_PROTO_INET) {

        if (l->engine->fd_ipv4 < 0)
            return -1;

        return catta_send_dns_packet_ipv4(l->engine->fd_ipv4, CATTA_IF_UNSPEC, p, NULL, &a->data.ipv4, CATTA_DNS_PORT);

    } else {
        assert(a->proto == CATTA_PROTO_INET6);

        if (l->engine->fd_ipv6 < 0)
            return -1;

        return catta_send_dns_packet_ipv6(l->engine->fd_ipv6, CATTA_IF_UNSPEC, p, NULL, &a->data.ipv6, CATTA_DNS_PORT);
    }
}

static void next_dns_server(CattaWideAreaLookupEngine *e) {
    assert(e);

    e->current_dns_server++;

    if (e->current_dns_server >= e->n_dns_servers)
        e->current_dns_server = 0;
}

static void lookup_stop(CattaWideAreaLookup *l) {
    assert(l);

    l->callback = NULL;

    if (l->time_event) {
        catta_time_event_free(l->time_event);
        l->time_event = NULL;
    }
}

static void sender_timeout_callback(CattaTimeEvent *e, void *userdata) {
    CattaWideAreaLookup *l = userdata;
    struct timeval tv;

    assert(l);

    /* Try another DNS server after three retries */
    if (l->n_send >= 3 && catta_address_cmp(&l->engine->dns_servers[l->engine->current_dns_server], &l->dns_server_used) == 0) {
        next_dns_server(l->engine);

        if (catta_address_cmp(&l->engine->dns_servers[l->engine->current_dns_server], &l->dns_server_used) == 0)
            /* There is no other DNS server, fail */
            l->n_send = 1000;
    }

    if (l->n_send >= 6) {
        catta_log_warn(__FILE__": Query timed out.");
        catta_server_set_errno(l->engine->server, CATTA_ERR_TIMEOUT);
        l->callback(l->engine, CATTA_BROWSER_FAILURE, CATTA_LOOKUP_RESULT_WIDE_AREA, NULL, l->userdata);
        lookup_stop(l);
        return;
    }

    assert(l->packet);
    send_to_dns_server(l, l->packet);
    l->n_send++;

    catta_time_event_update(e, catta_elapse_time(&tv, 1000, 0));
}

CattaWideAreaLookup *catta_wide_area_lookup_new(
    CattaWideAreaLookupEngine *e,
    CattaKey *key,
    CattaWideAreaLookupCallback callback,
    void *userdata) {

    struct timeval tv;
    CattaWideAreaLookup *l, *t;
    uint8_t *p;

    assert(e);
    assert(key);
    assert(callback);
    assert(userdata);

    l = catta_new(CattaWideAreaLookup, 1);
    l->engine = e;
    l->dead = 0;
    l->key = catta_key_ref(key);
    l->cname_key = catta_key_new_cname(l->key);
    l->callback = callback;
    l->userdata = userdata;

    /* If more than 65K wide area quries are issued simultaneously,
     * this will break. This should be limited by some higher level */

    for (;; e->next_id++)
        if (!find_lookup(e, e->next_id))
            break; /* This ID is not yet used. */

    l->id = e->next_id++;

    /* We keep the packet around in case we need to repeat our query */
    l->packet = catta_dns_packet_new(0);

    catta_dns_packet_set_field(l->packet, CATTA_DNS_FIELD_ID, (uint16_t) l->id);
    catta_dns_packet_set_field(l->packet, CATTA_DNS_FIELD_FLAGS, CATTA_DNS_FLAGS(0, 0, 0, 0, 1, 0, 0, 0, 0, 0));

    p = catta_dns_packet_append_key(l->packet, key, 0);
    assert(p);

    catta_dns_packet_set_field(l->packet, CATTA_DNS_FIELD_QDCOUNT, 1);

    if (send_to_dns_server(l, l->packet) < 0) {
        catta_log_error(__FILE__": Failed to send packet.");
        catta_dns_packet_free(l->packet);
        catta_key_unref(l->key);
        if (l->cname_key)
            catta_key_unref(l->cname_key);
        catta_free(l);
        return NULL;
    }

    l->n_send = 1;

    l->time_event = catta_time_event_new(e->server->time_event_queue, catta_elapse_time(&tv, 500, 0), sender_timeout_callback, l);

    catta_hashmap_insert(e->lookups_by_id, &l->id, l);

    t = catta_hashmap_lookup(e->lookups_by_key, l->key);
    CATTA_LLIST_PREPEND(CattaWideAreaLookup, by_key, t, l);
    catta_hashmap_replace(e->lookups_by_key, catta_key_ref(l->key), t);

    CATTA_LLIST_PREPEND(CattaWideAreaLookup, lookups, e->lookups, l);

    return l;
}

static void lookup_destroy(CattaWideAreaLookup *l) {
    CattaWideAreaLookup *t;
    assert(l);

    lookup_stop(l);

    t = catta_hashmap_lookup(l->engine->lookups_by_key, l->key);
    CATTA_LLIST_REMOVE(CattaWideAreaLookup, by_key, t, l);
    if (t)
        catta_hashmap_replace(l->engine->lookups_by_key, catta_key_ref(l->key), t);
    else
        catta_hashmap_remove(l->engine->lookups_by_key, l->key);

    CATTA_LLIST_REMOVE(CattaWideAreaLookup, lookups, l->engine->lookups, l);

    catta_hashmap_remove(l->engine->lookups_by_id, &l->id);
    catta_dns_packet_free(l->packet);

    if (l->key)
        catta_key_unref(l->key);

    if (l->cname_key)
        catta_key_unref(l->cname_key);

    catta_free(l);
}

void catta_wide_area_lookup_free(CattaWideAreaLookup *l) {
    assert(l);

    if (l->dead)
        return;

    l->dead = 1;
    l->engine->cleanup_dead = 1;
    lookup_stop(l);
}

void catta_wide_area_cleanup(CattaWideAreaLookupEngine *e) {
    CattaWideAreaLookup *l, *n;
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

static void cache_entry_free(CattaWideAreaCacheEntry *c) {
    CattaWideAreaCacheEntry *t;
    assert(c);

    if (c->time_event)
        catta_time_event_free(c->time_event);

    CATTA_LLIST_REMOVE(CattaWideAreaCacheEntry, cache, c->engine->cache, c);

    t = catta_hashmap_lookup(c->engine->cache_by_key, c->record->key);
    CATTA_LLIST_REMOVE(CattaWideAreaCacheEntry, by_key, t, c);
    if (t)
        catta_hashmap_replace(c->engine->cache_by_key, catta_key_ref(c->record->key), t);
    else
        catta_hashmap_remove(c->engine->cache_by_key, c->record->key);

    c->engine->cache_n_entries --;

    catta_record_unref(c->record);
    catta_free(c);
}

static void expiry_event(CattaTimeEvent *te, void *userdata) {
    CattaWideAreaCacheEntry *e = userdata;

    assert(te);
    assert(e);

    cache_entry_free(e);
}

static CattaWideAreaCacheEntry* find_record_in_cache(CattaWideAreaLookupEngine *e, CattaRecord *r) {
    CattaWideAreaCacheEntry *c;

    assert(e);
    assert(r);

    for (c = catta_hashmap_lookup(e->cache_by_key, r->key); c; c = c->by_key_next)
        if (catta_record_equal_no_ttl(r, c->record))
            return c;

    return NULL;
}

static void run_callbacks(CattaWideAreaLookupEngine *e, CattaRecord *r) {
    CattaWideAreaLookup *l;

    assert(e);
    assert(r);

    for (l = catta_hashmap_lookup(e->lookups_by_key, r->key); l; l = l->by_key_next) {
        if (l->dead || !l->callback)
            continue;

        l->callback(e, CATTA_BROWSER_NEW, CATTA_LOOKUP_RESULT_WIDE_AREA, r, l->userdata);
    }

    if (r->key->clazz == CATTA_DNS_CLASS_IN && r->key->type == CATTA_DNS_TYPE_CNAME) {
        /* It's a CNAME record, so we have to scan the all lookups to see if one matches */

        for (l = e->lookups; l; l = l->lookups_next) {
            CattaKey *key;

            if (l->dead || !l->callback)
                continue;

            if ((key = catta_key_new_cname(l->key))) {
                if (catta_key_equal(r->key, key))
                    l->callback(e, CATTA_BROWSER_NEW, CATTA_LOOKUP_RESULT_WIDE_AREA, r, l->userdata);

                catta_key_unref(key);
            }
        }
    }
}

static void add_to_cache(CattaWideAreaLookupEngine *e, CattaRecord *r) {
    CattaWideAreaCacheEntry *c;
    int is_new;

    assert(e);
    assert(r);

    if ((c = find_record_in_cache(e, r))) {
        is_new = 0;

        /* Update the existing entry */
        catta_record_unref(c->record);
    } else {
        CattaWideAreaCacheEntry *t;

        is_new = 1;

        /* Enforce cache size */
        if (e->cache_n_entries >= CACHE_ENTRIES_MAX)
            /* Eventually we should improve the caching algorithm here */
            goto finish;

        c = catta_new(CattaWideAreaCacheEntry, 1);
        c->engine = e;
        c->time_event = NULL;

        CATTA_LLIST_PREPEND(CattaWideAreaCacheEntry, cache, e->cache, c);

        /* Add the new entry to the cache entry hash table */
        t = catta_hashmap_lookup(e->cache_by_key, r->key);
        CATTA_LLIST_PREPEND(CattaWideAreaCacheEntry, by_key, t, c);
        catta_hashmap_replace(e->cache_by_key, catta_key_ref(r->key), t);

        e->cache_n_entries ++;
    }

    c->record = catta_record_ref(r);

    gettimeofday(&c->timestamp, NULL);
    c->expiry = c->timestamp;
    catta_timeval_add(&c->expiry, r->ttl * 1000000);

    if (c->time_event)
        catta_time_event_update(c->time_event, &c->expiry);
    else
        c->time_event = catta_time_event_new(e->server->time_event_queue, &c->expiry, expiry_event, c);

finish:

    if (is_new)
        run_callbacks(e, r);
}

static int map_dns_error(uint16_t error) {
    static const int table[16] = {
        CATTA_OK,
        CATTA_ERR_DNS_FORMERR,
        CATTA_ERR_DNS_SERVFAIL,
        CATTA_ERR_DNS_NXDOMAIN,
        CATTA_ERR_DNS_NOTIMP,
        CATTA_ERR_DNS_REFUSED,
        CATTA_ERR_DNS_YXDOMAIN,
        CATTA_ERR_DNS_YXRRSET,
        CATTA_ERR_DNS_NXRRSET,
        CATTA_ERR_DNS_NOTAUTH,
        CATTA_ERR_DNS_NOTZONE,
        CATTA_ERR_INVALID_DNS_ERROR,
        CATTA_ERR_INVALID_DNS_ERROR,
        CATTA_ERR_INVALID_DNS_ERROR,
        CATTA_ERR_INVALID_DNS_ERROR,
        CATTA_ERR_INVALID_DNS_ERROR
    };

    assert(error <= 15);

    return table[error];
}

static void handle_packet(CattaWideAreaLookupEngine *e, CattaDnsPacket *p) {
    CattaWideAreaLookup *l = NULL;
    int i, r;

    CattaBrowserEvent final_event = CATTA_BROWSER_ALL_FOR_NOW;

    assert(e);
    assert(p);

    /* Some superficial validity tests */
    if (catta_dns_packet_check_valid(p) < 0 || catta_dns_packet_is_query(p)) {
        catta_log_warn(__FILE__": Ignoring invalid response for wide area datagram.");
        goto finish;
    }

    /* Look for the lookup that issued this query */
    if (!(l = find_lookup(e, catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ID))) || l->dead)
        goto finish;

    /* Check whether this a packet indicating a failure */
    if ((r = catta_dns_packet_get_field(p, CATTA_DNS_FIELD_FLAGS) & 15) != 0 ||
        catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ANCOUNT) == 0) {

        catta_server_set_errno(e->server, r == 0 ? CATTA_ERR_NOT_FOUND : map_dns_error(r));
        /* Tell the user about the failure */
        final_event = CATTA_BROWSER_FAILURE;

        /* We go on here, since some of the records contained in the
           reply might be interesting in some way */
    }

    /* Skip over the question */
    for (i = (int) catta_dns_packet_get_field(p, CATTA_DNS_FIELD_QDCOUNT); i > 0; i--) {
        CattaKey *k;

        if (!(k = catta_dns_packet_consume_key(p, NULL))) {
            catta_log_warn(__FILE__": Wide area response packet too short or invalid while reading question key. (Maybe a UTF-8 problem?)");
            catta_server_set_errno(e->server, CATTA_ERR_INVALID_PACKET);
            final_event = CATTA_BROWSER_FAILURE;
            goto finish;
        }

        catta_key_unref(k);
    }

    /* Process responses */
    for (i = (int) catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ANCOUNT) +
             (int) catta_dns_packet_get_field(p, CATTA_DNS_FIELD_NSCOUNT) +
             (int) catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ARCOUNT); i > 0; i--) {

        CattaRecord *rr;

        if (!(rr = catta_dns_packet_consume_record(p, NULL))) {
            catta_log_warn(__FILE__": Wide area response packet too short or invalid while reading response record. (Maybe a UTF-8 problem?)");
            catta_server_set_errno(e->server, CATTA_ERR_INVALID_PACKET);
            final_event = CATTA_BROWSER_FAILURE;
            goto finish;
        }

        add_to_cache(e, rr);
        catta_record_unref(rr);
    }

finish:

    if (l && !l->dead) {
        if (l->callback)
            l->callback(e, final_event, CATTA_LOOKUP_RESULT_WIDE_AREA, NULL, l->userdata);

        lookup_stop(l);
    }
}

static void socket_event(CATTA_GCC_UNUSED CattaWatch *w, int fd, CATTA_GCC_UNUSED CattaWatchEvent events, void *userdata) {
    CattaWideAreaLookupEngine *e = userdata;
    CattaDnsPacket *p = NULL;

    if (fd == e->fd_ipv4)
        p = catta_recv_dns_packet_ipv4(e->fd_ipv4, NULL, NULL, NULL, NULL, NULL);
    else {
        assert(fd == e->fd_ipv6);
        p = catta_recv_dns_packet_ipv6(e->fd_ipv6, NULL, NULL, NULL, NULL, NULL);
    }

    if (p) {
        handle_packet(e, p);
        catta_dns_packet_free(p);
    }
}

CattaWideAreaLookupEngine *catta_wide_area_engine_new(CattaServer *s) {
    CattaWideAreaLookupEngine *e;

    assert(s);

    e = catta_new(CattaWideAreaLookupEngine, 1);
    e->server = s;
    e->cleanup_dead = 0;

    /* Create sockets */
    e->fd_ipv4 = s->config.use_ipv4 ? catta_open_unicast_socket_ipv4() : -1;
    e->fd_ipv6 = s->config.use_ipv6 ? catta_open_unicast_socket_ipv6() : -1;

    if (e->fd_ipv4 < 0 && e->fd_ipv6 < 0) {
        catta_log_error(__FILE__": Failed to create wide area sockets: %s", strerror(errno));

        if (e->fd_ipv6 >= 0)
            closesocket(e->fd_ipv6);

        if (e->fd_ipv4 >= 0)
            closesocket(e->fd_ipv4);

        catta_free(e);
        return NULL;
    }

    /* Create watches */

    e->watch_ipv4 = e->watch_ipv6 = NULL;

    if (e->fd_ipv4 >= 0)
        e->watch_ipv4 = s->poll_api->watch_new(e->server->poll_api, e->fd_ipv4, CATTA_WATCH_IN, socket_event, e);
    if (e->fd_ipv6 >= 0)
        e->watch_ipv6 = s->poll_api->watch_new(e->server->poll_api, e->fd_ipv6, CATTA_WATCH_IN, socket_event, e);

    e->n_dns_servers = e->current_dns_server = 0;
    e->next_id = (uint16_t) rand();

    /* Initialize cache */
    CATTA_LLIST_HEAD_INIT(CattaWideAreaCacheEntry, e->cache);
    e->cache_by_key = catta_hashmap_new((CattaHashFunc) catta_key_hash, (CattaEqualFunc) catta_key_equal, (CattaFreeFunc) catta_key_unref, NULL);
    e->cache_n_entries = 0;

    /* Initialize lookup list */
    e->lookups_by_id = catta_hashmap_new((CattaHashFunc) catta_int_hash, (CattaEqualFunc) catta_int_equal, NULL, NULL);
    e->lookups_by_key = catta_hashmap_new((CattaHashFunc) catta_key_hash, (CattaEqualFunc) catta_key_equal, (CattaFreeFunc) catta_key_unref, NULL);
    CATTA_LLIST_HEAD_INIT(CattaWideAreaLookup, e->lookups);

    return e;
}

void catta_wide_area_engine_free(CattaWideAreaLookupEngine *e) {
    assert(e);

    catta_wide_area_clear_cache(e);

    while (e->lookups)
        lookup_destroy(e->lookups);

    catta_hashmap_free(e->cache_by_key);
    catta_hashmap_free(e->lookups_by_id);
    catta_hashmap_free(e->lookups_by_key);

    if (e->watch_ipv4)
        e->server->poll_api->watch_free(e->watch_ipv4);

    if (e->watch_ipv6)
        e->server->poll_api->watch_free(e->watch_ipv6);

    if (e->fd_ipv6 >= 0)
        closesocket(e->fd_ipv6);

    if (e->fd_ipv4 >= 0)
        closesocket(e->fd_ipv4);

    catta_free(e);
}

void catta_wide_area_clear_cache(CattaWideAreaLookupEngine *e) {
    assert(e);

    while (e->cache)
        cache_entry_free(e->cache);

    assert(e->cache_n_entries == 0);
}

void catta_wide_area_set_servers(CattaWideAreaLookupEngine *e, const CattaAddress *a, unsigned n) {
    assert(e);

    if (a) {
        for (e->n_dns_servers = 0; n > 0 && e->n_dns_servers < CATTA_WIDE_AREA_SERVERS_MAX; a++, n--)
            if ((a->proto == CATTA_PROTO_INET && e->fd_ipv4 >= 0) || (a->proto == CATTA_PROTO_INET6 && e->fd_ipv6 >= 0))
                e->dns_servers[e->n_dns_servers++] = *a;
    } else {
        assert(n == 0);
        e->n_dns_servers = 0;
    }

    e->current_dns_server = 0;

    catta_wide_area_clear_cache(e);
}

void catta_wide_area_cache_dump(CattaWideAreaLookupEngine *e, CattaDumpCallback callback, void* userdata) {
    CattaWideAreaCacheEntry *c;

    assert(e);
    assert(callback);

    callback(";; WIDE AREA CACHE ;;; ", userdata);

    for (c = e->cache; c; c = c->cache_next) {
        char *t = catta_record_to_string(c->record);
        callback(t, userdata);
        catta_free(t);
    }
}

unsigned catta_wide_area_scan_cache(CattaWideAreaLookupEngine *e, CattaKey *key, CattaWideAreaLookupCallback callback, void *userdata) {
    CattaWideAreaCacheEntry *c;
    CattaKey *cname_key;
    unsigned n = 0;

    assert(e);
    assert(key);
    assert(callback);

    for (c = catta_hashmap_lookup(e->cache_by_key, key); c; c = c->by_key_next) {
        callback(e, CATTA_BROWSER_NEW, CATTA_LOOKUP_RESULT_WIDE_AREA|CATTA_LOOKUP_RESULT_CACHED, c->record, userdata);
        n++;
    }

    if ((cname_key = catta_key_new_cname(key))) {

        for (c = catta_hashmap_lookup(e->cache_by_key, cname_key); c; c = c->by_key_next) {
            callback(e, CATTA_BROWSER_NEW, CATTA_LOOKUP_RESULT_WIDE_AREA|CATTA_LOOKUP_RESULT_CACHED, c->record, userdata);
            n++;
        }

        catta_key_unref(cname_key);
    }

    return n;
}

int catta_wide_area_has_servers(CattaWideAreaLookupEngine *e) {
    assert(e);

    return e->n_dns_servers > 0;
}



