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

#include <catta/timeval.h>
#include <catta/malloc.h>
#include <catta/error.h>
#include <catta/domain.h>
#include <catta/rlist.h>
#include <catta/address.h>
#include <catta/log.h>

#include "browse.h"
#include "querier.h"
#include "domain-util.h"
#include "rr-util.h"

#define CATTA_LOOKUPS_PER_BROWSER_MAX 15

struct CattaSRBLookup {
    CattaSRecordBrowser *record_browser;

    unsigned ref;

    CattaIfIndex iface;
    CattaProtocol protocol;
    CattaLookupFlags flags;

    CattaKey *key;

    CattaWideAreaLookup *wide_area;
    CattaMulticastLookup *multicast;

    CattaRList *cname_lookups;

    CATTA_LLIST_FIELDS(CattaSRBLookup, lookups);
};

static void lookup_handle_cname(CattaSRBLookup *l, CattaIfIndex iface, CattaProtocol protocol, CattaLookupFlags flags, CattaRecord *r);
static void lookup_drop_cname(CattaSRBLookup *l, CattaIfIndex iface, CattaProtocol protocol, CattaLookupFlags flags, CattaRecord *r);

static void transport_flags_from_domain(CattaServer *s, CattaLookupFlags *flags, const char *domain) {
    assert(flags);
    assert(domain);

    assert(!((*flags & CATTA_LOOKUP_USE_MULTICAST) && (*flags & CATTA_LOOKUP_USE_WIDE_AREA)));

    if (*flags & (CATTA_LOOKUP_USE_MULTICAST|CATTA_LOOKUP_USE_WIDE_AREA))
        return;

    if (!s->wide_area_lookup_engine ||
        !catta_wide_area_has_servers(s->wide_area_lookup_engine) ||
        catta_domain_ends_with(domain, CATTA_MDNS_SUFFIX_LOCAL) ||
        catta_domain_ends_with(domain, CATTA_MDNS_SUFFIX_ADDR_IPV4) ||
        catta_domain_ends_with(domain, CATTA_MDNS_SUFFIX_ADDR_IPV6))
        *flags |= CATTA_LOOKUP_USE_MULTICAST;
    else
        *flags |= CATTA_LOOKUP_USE_WIDE_AREA;
}

static CattaSRBLookup* lookup_new(
    CattaSRecordBrowser *b,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaLookupFlags flags,
    CattaKey *key) {

    CattaSRBLookup *l;

    assert(b);
    assert(CATTA_IF_VALID(iface));
    assert(CATTA_PROTO_VALID(protocol));

    if (b->n_lookups >= CATTA_LOOKUPS_PER_BROWSER_MAX)
        /* We don't like cyclic CNAMEs */
        return NULL;

    if (!(l = catta_new(CattaSRBLookup, 1)))
        return NULL;

    l->ref = 1;
    l->record_browser = b;
    l->iface = iface;
    l->protocol = protocol;
    l->key = catta_key_ref(key);
    l->wide_area = NULL;
    l->multicast = NULL;
    l->cname_lookups = NULL;
    l->flags = flags;

    transport_flags_from_domain(b->server, &l->flags, key->name);

    CATTA_LLIST_PREPEND(CattaSRBLookup, lookups, b->lookups, l);

    b->n_lookups ++;

    return l;
}

static void lookup_unref(CattaSRBLookup *l) {
    assert(l);
    assert(l->ref >= 1);

    if (--l->ref >= 1)
        return;

    CATTA_LLIST_REMOVE(CattaSRBLookup, lookups, l->record_browser->lookups, l);
    l->record_browser->n_lookups --;

    if (l->wide_area) {
        catta_wide_area_lookup_free(l->wide_area);
        l->wide_area = NULL;
    }

    if (l->multicast) {
        catta_multicast_lookup_free(l->multicast);
        l->multicast = NULL;
    }

    while (l->cname_lookups) {
        lookup_unref(l->cname_lookups->data);
        l->cname_lookups = catta_rlist_remove_by_link(l->cname_lookups, l->cname_lookups);
    }

    catta_key_unref(l->key);
    catta_free(l);
}

static CattaSRBLookup* lookup_ref(CattaSRBLookup *l) {
    assert(l);
    assert(l->ref >= 1);

    l->ref++;
    return l;
}

static CattaSRBLookup *lookup_find(
    CattaSRecordBrowser *b,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaLookupFlags flags,
    CattaKey *key) {

    CattaSRBLookup *l;

    assert(b);

    for (l = b->lookups; l; l = l->lookups_next) {

        if ((l->iface == CATTA_IF_UNSPEC || l->iface == iface) &&
            (l->iface == CATTA_PROTO_UNSPEC || l->protocol == protocol) &&
            l->flags == flags &&
            catta_key_equal(l->key, key))

            return l;
    }

    return NULL;
}

static void browser_cancel(CattaSRecordBrowser *b) {
    assert(b);

    if (b->root_lookup) {
        lookup_unref(b->root_lookup);
        b->root_lookup = NULL;
    }

    if (b->defer_time_event) {
        catta_time_event_free(b->defer_time_event);
        b->defer_time_event = NULL;
    }
}

static void lookup_wide_area_callback(
    CattaWideAreaLookupEngine *e,
    CattaBrowserEvent event,
    CattaLookupResultFlags flags,
    CattaRecord *r,
    void *userdata) {

    CattaSRBLookup *l = userdata;
    CattaSRecordBrowser *b;

    assert(e);
    assert(l);
    assert(l->ref >= 1);

    b = l->record_browser;

    if (b->dead)
        return;

    lookup_ref(l);

    switch (event) {
        case CATTA_BROWSER_NEW:
            assert(r);

            if (r->key->clazz == CATTA_DNS_CLASS_IN &&
                r->key->type == CATTA_DNS_TYPE_CNAME)
                /* It's a CNAME record, so let's follow it. We only follow it on wide area DNS! */
                lookup_handle_cname(l, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, CATTA_LOOKUP_USE_WIDE_AREA, r);
            else {
                /* It's a normal record, so let's call the user callback */
                assert(catta_key_equal(r->key, l->key));

                b->callback(b, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, event, r, flags, b->userdata);
            }
            break;

        case CATTA_BROWSER_REMOVE:
        case CATTA_BROWSER_CACHE_EXHAUSTED:
            /* Not defined for wide area DNS */
            abort();

        case CATTA_BROWSER_ALL_FOR_NOW:
        case CATTA_BROWSER_FAILURE:

            b->callback(b, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, event, NULL, flags, b->userdata);
            break;
    }

    lookup_unref(l);

}

static void lookup_multicast_callback(
    CattaMulticastLookupEngine *e,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    CattaLookupResultFlags flags,
    CattaRecord *r,
    void *userdata) {

    CattaSRBLookup *l = userdata;
    CattaSRecordBrowser *b;

    assert(e);
    assert(l);

    b = l->record_browser;

    if (b->dead)
        return;

    lookup_ref(l);

    switch (event) {
        case CATTA_BROWSER_NEW:
            assert(r);

            if (r->key->clazz == CATTA_DNS_CLASS_IN &&
                r->key->type == CATTA_DNS_TYPE_CNAME)
                /* It's a CNAME record, so let's follow it. We allow browsing on both multicast and wide area. */
                lookup_handle_cname(l, iface, protocol, b->flags, r);
            else {
                /* It's a normal record, so let's call the user callback */

                if (catta_server_is_record_local(b->server, iface, protocol, r))
                    flags |= CATTA_LOOKUP_RESULT_LOCAL;

                b->callback(b, iface, protocol, event, r, flags, b->userdata);
            }
            break;

        case CATTA_BROWSER_REMOVE:
            assert(r);

            if (r->key->clazz == CATTA_DNS_CLASS_IN &&
                r->key->type == CATTA_DNS_TYPE_CNAME)
                /* It's a CNAME record, so let's drop that query! */
                lookup_drop_cname(l, iface, protocol, 0, r);
            else {
                /* It's a normal record, so let's call the user callback */
                assert(catta_key_equal(b->key, l->key));

                b->callback(b, iface, protocol, event, r, flags, b->userdata);
            }
            break;

        case CATTA_BROWSER_ALL_FOR_NOW:

            b->callback(b, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, event, NULL, flags, b->userdata);
            break;

        case CATTA_BROWSER_CACHE_EXHAUSTED:
        case CATTA_BROWSER_FAILURE:
            /* Not defined for multicast DNS */
            abort();

    }

    lookup_unref(l);
}

static int lookup_start(CattaSRBLookup *l) {
    assert(l);

    assert(!(l->flags & CATTA_LOOKUP_USE_WIDE_AREA) != !(l->flags & CATTA_LOOKUP_USE_MULTICAST));
    assert(!l->wide_area && !l->multicast);

    if (l->flags & CATTA_LOOKUP_USE_WIDE_AREA) {

        if (!(l->wide_area = catta_wide_area_lookup_new(l->record_browser->server->wide_area_lookup_engine, l->key, lookup_wide_area_callback, l)))
            return -1;

    } else {
        assert(l->flags & CATTA_LOOKUP_USE_MULTICAST);

        if (!(l->multicast = catta_multicast_lookup_new(l->record_browser->server->multicast_lookup_engine, l->iface, l->protocol, l->key, lookup_multicast_callback, l)))
            return -1;
    }

    return 0;
}

static int lookup_scan_cache(CattaSRBLookup *l) {
    int n = 0;

    assert(l);

    assert(!(l->flags & CATTA_LOOKUP_USE_WIDE_AREA) != !(l->flags & CATTA_LOOKUP_USE_MULTICAST));


    if (l->flags & CATTA_LOOKUP_USE_WIDE_AREA) {
        n = (int) catta_wide_area_scan_cache(l->record_browser->server->wide_area_lookup_engine, l->key, lookup_wide_area_callback, l);

    } else {
        assert(l->flags & CATTA_LOOKUP_USE_MULTICAST);
        n = (int) catta_multicast_lookup_engine_scan_cache(l->record_browser->server->multicast_lookup_engine, l->iface, l->protocol, l->key, lookup_multicast_callback, l);
    }

    return n;
}

static CattaSRBLookup* lookup_add(CattaSRecordBrowser *b, CattaIfIndex iface, CattaProtocol protocol, CattaLookupFlags flags, CattaKey *key) {
    CattaSRBLookup *l;

    assert(b);
    assert(!b->dead);

    if ((l = lookup_find(b, iface, protocol, flags, key)))
        return lookup_ref(l);

    if (!(l = lookup_new(b, iface, protocol, flags, key)))
        return NULL;

    return l;
}

static int lookup_go(CattaSRBLookup *l) {
    int n = 0;
    assert(l);

    if (l->record_browser->dead)
        return 0;

    lookup_ref(l);

    /* Browse the cache for the root request */
    n = lookup_scan_cache(l);

    /* Start the lookup */
    if (!l->record_browser->dead && l->ref > 1) {

        if ((l->flags & CATTA_LOOKUP_USE_MULTICAST) || n == 0)
            /* We do no start a query if the cache contained entries and we're on wide area */

            if (lookup_start(l) < 0)
                n = -1;
    }

    lookup_unref(l);

    return n;
}

static void lookup_handle_cname(CattaSRBLookup *l, CattaIfIndex iface, CattaProtocol protocol, CattaLookupFlags flags, CattaRecord *r) {
    CattaKey *k;
    CattaSRBLookup *n;

    assert(l);
    assert(r);

    assert(r->key->clazz == CATTA_DNS_CLASS_IN);
    assert(r->key->type == CATTA_DNS_TYPE_CNAME);

    k = catta_key_new(r->data.ptr.name, l->record_browser->key->clazz, l->record_browser->key->type);
    n = lookup_add(l->record_browser, iface, protocol, flags, k);
    catta_key_unref(k);

    if (!n) {
        catta_log_debug(__FILE__": Failed to create SRBLookup.");
        return;
    }

    l->cname_lookups = catta_rlist_prepend(l->cname_lookups, lookup_ref(n));

    lookup_go(n);
    lookup_unref(n);
}

static void lookup_drop_cname(CattaSRBLookup *l, CattaIfIndex iface, CattaProtocol protocol, CattaLookupFlags flags, CattaRecord *r) {
    CattaKey *k;
    CattaSRBLookup *n = NULL;
    CattaRList *rl;

    assert(r->key->clazz == CATTA_DNS_CLASS_IN);
    assert(r->key->type == CATTA_DNS_TYPE_CNAME);

    k = catta_key_new(r->data.ptr.name, l->record_browser->key->clazz, l->record_browser->key->type);

    for (rl = l->cname_lookups; rl; rl = rl->rlist_next) {
        n = rl->data;

        assert(n);

        if ((n->iface == CATTA_IF_UNSPEC || n->iface == iface) &&
            (n->iface == CATTA_PROTO_UNSPEC || n->protocol == protocol) &&
            n->flags == flags &&
            catta_key_equal(n->key, k))
            break;
    }

    catta_key_unref(k);

    if (rl) {
        l->cname_lookups = catta_rlist_remove_by_link(l->cname_lookups, rl);
        lookup_unref(n);
    }
}

static void defer_callback(CATTA_GCC_UNUSED CattaTimeEvent *e, void *userdata) {
    CattaSRecordBrowser *b = userdata;
    int n;

    assert(b);
    assert(!b->dead);

    /* Remove the defer timeout */
    if (b->defer_time_event) {
        catta_time_event_free(b->defer_time_event);
        b->defer_time_event = NULL;
    }

    /* Create initial query */
    assert(!b->root_lookup);
    b->root_lookup = lookup_add(b, b->iface, b->protocol, b->flags, b->key);
    assert(b->root_lookup);

    n = lookup_go(b->root_lookup);

    if (b->dead)
        return;

    if (n < 0) {
        /* sending of the initial query failed */

        catta_server_set_errno(b->server, CATTA_ERR_FAILURE);

        b->callback(
            b, b->iface, b->protocol, CATTA_BROWSER_FAILURE, NULL,
            b->flags & CATTA_LOOKUP_USE_WIDE_AREA ? CATTA_LOOKUP_RESULT_WIDE_AREA : CATTA_LOOKUP_RESULT_MULTICAST,
            b->userdata);

        browser_cancel(b);
        return;
    }

    /* Tell the client that we're done with the cache */
    b->callback(
        b, b->iface, b->protocol, CATTA_BROWSER_CACHE_EXHAUSTED, NULL,
        b->flags & CATTA_LOOKUP_USE_WIDE_AREA ? CATTA_LOOKUP_RESULT_WIDE_AREA : CATTA_LOOKUP_RESULT_MULTICAST,
        b->userdata);

    if (!b->dead && b->root_lookup && b->root_lookup->flags & CATTA_LOOKUP_USE_WIDE_AREA && n > 0) {

        /* If we do wide area lookups and the the cache contained
         * entries, we assume that it is complete, and tell the user
         * so by firing ALL_FOR_NOW. */

        b->callback(b, b->iface, b->protocol, CATTA_BROWSER_ALL_FOR_NOW, NULL, CATTA_LOOKUP_RESULT_WIDE_AREA, b->userdata);
    }
}

void catta_s_record_browser_restart(CattaSRecordBrowser *b) {
    assert(b);
    assert(!b->dead);

    browser_cancel(b);

    /* Request a new iteration of the cache scanning */
    if (!b->defer_time_event) {
        b->defer_time_event = catta_time_event_new(b->server->time_event_queue, NULL, defer_callback, b);
        assert(b->defer_time_event);
    }
}

CattaSRecordBrowser *catta_s_record_browser_new(
    CattaServer *server,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaKey *key,
    CattaLookupFlags flags,
    CattaSRecordBrowserCallback callback,
    void* userdata) {

    CattaSRecordBrowser *b;

    assert(server);
    assert(key);
    assert(callback);

    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_IF_VALID(iface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, !catta_key_is_pattern(key), CATTA_ERR_IS_PATTERN);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, catta_key_is_valid(key), CATTA_ERR_INVALID_KEY);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_FLAGS_VALID(flags, CATTA_LOOKUP_USE_WIDE_AREA|CATTA_LOOKUP_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, !(flags & CATTA_LOOKUP_USE_WIDE_AREA) || !(flags & CATTA_LOOKUP_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);

    if (!(b = catta_new(CattaSRecordBrowser, 1))) {
        catta_server_set_errno(server, CATTA_ERR_NO_MEMORY);
        return NULL;
    }

    b->dead = 0;
    b->server = server;
    b->iface = iface;
    b->protocol = protocol;
    b->key = catta_key_ref(key);
    b->flags = flags;
    b->callback = callback;
    b->userdata = userdata;
    b->n_lookups = 0;
    CATTA_LLIST_HEAD_INIT(CattaSRBLookup, b->lookups);
    b->root_lookup = NULL;

    CATTA_LLIST_PREPEND(CattaSRecordBrowser, browser, server->record_browsers, b);

    /* The currently cached entries are scanned a bit later, and than we will start querying, too */
    b->defer_time_event = catta_time_event_new(server->time_event_queue, NULL, defer_callback, b);
    assert(b->defer_time_event);

    return b;
}

void catta_s_record_browser_free(CattaSRecordBrowser *b) {
    assert(b);
    assert(!b->dead);

    b->dead = 1;
    b->server->need_browser_cleanup = 1;

    browser_cancel(b);
}

void catta_s_record_browser_destroy(CattaSRecordBrowser *b) {
    assert(b);

    browser_cancel(b);

    CATTA_LLIST_REMOVE(CattaSRecordBrowser, browser, b->server->record_browsers, b);

    catta_key_unref(b->key);

    catta_free(b);
}

void catta_browser_cleanup(CattaServer *server) {
    CattaSRecordBrowser *b;
    CattaSRecordBrowser *n;

    assert(server);

    while (server->need_browser_cleanup) {
        server->need_browser_cleanup = 0;

        for (b = server->record_browsers; b; b = n) {
            n = b->browser_next;

            if (b->dead)
                catta_s_record_browser_destroy(b);
        }
    }

    if (server->wide_area_lookup_engine)
        catta_wide_area_cleanup(server->wide_area_lookup_engine);
    catta_multicast_lookup_engine_cleanup(server->multicast_lookup_engine);
}

