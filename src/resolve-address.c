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

#include "browse.h"

#define TIMEOUT_MSEC 5000

struct CattaSAddressResolver {
    CattaServer *server;
    CattaAddress address;

    CattaSRecordBrowser *record_browser;

    CattaSAddressResolverCallback callback;
    void* userdata;

    CattaRecord *ptr_record;
    CattaIfIndex interface;
    CattaProtocol protocol;
    CattaLookupResultFlags flags;

    int retry_with_multicast;
    CattaKey *key;

    CattaTimeEvent *time_event;

    CATTA_LLIST_FIELDS(CattaSAddressResolver, resolver);
};

static void finish(CattaSAddressResolver *r, CattaResolverEvent event) {
    assert(r);

    if (r->time_event) {
        catta_time_event_free(r->time_event);
        r->time_event = NULL;
    }

    switch (event) {
        case CATTA_RESOLVER_FAILURE:
            r->callback(r, r->interface, r->protocol, event, &r->address, NULL, r->flags, r->userdata);
            break;

        case CATTA_RESOLVER_FOUND:
            assert(r->ptr_record);
            r->callback(r, r->interface, r->protocol, event, &r->address, r->ptr_record->data.ptr.name, r->flags, r->userdata);
            break;
    }
}

static void time_event_callback(CattaTimeEvent *e, void *userdata) {
    CattaSAddressResolver *r = userdata;

    assert(e);
    assert(r);

    catta_server_set_errno(r->server, CATTA_ERR_TIMEOUT);
    finish(r, CATTA_RESOLVER_FAILURE);
}

static void start_timeout(CattaSAddressResolver *r) {
    struct timeval tv;
    assert(r);

    if (r->time_event)
        return;

    catta_elapse_time(&tv, TIMEOUT_MSEC, 0);
    r->time_event = catta_time_event_new(r->server->time_event_queue, &tv, time_event_callback, r);
}

static void record_browser_callback(
    CattaSRecordBrowser*rr,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    CattaRecord *record,
    CattaLookupResultFlags flags,
    void* userdata) {

    CattaSAddressResolver *r = userdata;

    assert(rr);
    assert(r);

    switch (event) {
        case CATTA_BROWSER_NEW:
            assert(record);
            assert(record->key->type == CATTA_DNS_TYPE_PTR);

            if (r->interface > 0 && interface != r->interface)
                return;

            if (r->protocol != CATTA_PROTO_UNSPEC && protocol != r->protocol)
                return;

            if (r->interface <= 0)
                r->interface = interface;

            if (r->protocol == CATTA_PROTO_UNSPEC)
                r->protocol = protocol;

            if (!r->ptr_record) {
                r->ptr_record = catta_record_ref(record);
                r->flags = flags;

                finish(r, CATTA_RESOLVER_FOUND);
            }
            break;

        case CATTA_BROWSER_REMOVE:
            assert(record);
            assert(record->key->type == CATTA_DNS_TYPE_PTR);

            if (r->ptr_record && catta_record_equal_no_ttl(record, r->ptr_record)) {
                catta_record_unref(r->ptr_record);
                r->ptr_record = NULL;
                r->flags = flags;

                /** Look for a replacement */
                catta_s_record_browser_restart(r->record_browser);
                start_timeout(r);
            }

            break;

        case CATTA_BROWSER_CACHE_EXHAUSTED:
        case CATTA_BROWSER_ALL_FOR_NOW:
            break;

        case CATTA_BROWSER_FAILURE:

            if (r->retry_with_multicast) {
                r->retry_with_multicast = 0;

                catta_s_record_browser_free(r->record_browser);
                r->record_browser = catta_s_record_browser_new(r->server, r->interface, r->protocol, r->key, CATTA_LOOKUP_USE_MULTICAST, record_browser_callback, r);

                if (r->record_browser) {
                    start_timeout(r);
                    break;
                }
            }

            r->flags = flags;
            finish(r, CATTA_RESOLVER_FAILURE);
            break;
    }
}

CattaSAddressResolver *catta_s_address_resolver_new(
    CattaServer *server,
    CattaIfIndex interface,
    CattaProtocol protocol,
    const CattaAddress *address,
    CattaLookupFlags flags,
    CattaSAddressResolverCallback callback,
    void* userdata) {

    CattaSAddressResolver *r;
    CattaKey *k;
    char n[CATTA_DOMAIN_NAME_MAX];

    assert(server);
    assert(address);
    assert(callback);

    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_IF_VALID(interface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, address->proto == CATTA_PROTO_INET || address->proto == CATTA_PROTO_INET6, CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_FLAGS_VALID(flags, CATTA_LOOKUP_USE_WIDE_AREA|CATTA_LOOKUP_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);

    catta_reverse_lookup_name(address, n, sizeof(n));

    if (!(k = catta_key_new(n, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_PTR))) {
        catta_server_set_errno(server, CATTA_ERR_NO_MEMORY);
        return NULL;
    }

    if (!(r = catta_new(CattaSAddressResolver, 1))) {
        catta_server_set_errno(server, CATTA_ERR_NO_MEMORY);
        catta_key_unref(k);
        return NULL;
    }

    r->server = server;
    r->address = *address;
    r->callback = callback;
    r->userdata = userdata;
    r->ptr_record = NULL;
    r->interface = interface;
    r->protocol = protocol;
    r->flags = 0;
    r->retry_with_multicast = 0;
    r->key = k;

    r->record_browser = NULL;
    CATTA_LLIST_PREPEND(CattaSAddressResolver, resolver, server->address_resolvers, r);

    r->time_event = NULL;

    if (!(flags & (CATTA_LOOKUP_USE_MULTICAST|CATTA_LOOKUP_USE_WIDE_AREA))) {

        if (!server->wide_area_lookup_engine || !catta_wide_area_has_servers(server->wide_area_lookup_engine))
            flags |= CATTA_LOOKUP_USE_MULTICAST;
        else {
            flags |= CATTA_LOOKUP_USE_WIDE_AREA;
            r->retry_with_multicast = 1;
        }
    }

    r->record_browser = catta_s_record_browser_new(server, interface, protocol, k, flags, record_browser_callback, r);

    if (!r->record_browser) {
        catta_s_address_resolver_free(r);
        return NULL;
    }

    start_timeout(r);

    return r;
}

void catta_s_address_resolver_free(CattaSAddressResolver *r) {
    assert(r);

    CATTA_LLIST_REMOVE(CattaSAddressResolver, resolver, r->server->address_resolvers, r);

    if (r->record_browser)
        catta_s_record_browser_free(r->record_browser);

    if (r->time_event)
        catta_time_event_free(r->time_event);

    if (r->ptr_record)
        catta_record_unref(r->ptr_record);

    if (r->key)
        catta_key_unref(r->key);

    catta_free(r);
}
