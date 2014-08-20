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

#include <catta/domain.h>
#include <catta/timeval.h>
#include <catta/malloc.h>
#include <catta/error.h>

#include "browse.h"
#include <catta/log.h>

#define TIMEOUT_MSEC 5000

struct CattaSHostNameResolver {
    CattaServer *server;
    char *host_name;

    CattaSRecordBrowser *record_browser_a;
    CattaSRecordBrowser *record_browser_aaaa;

    CattaSHostNameResolverCallback callback;
    void* userdata;

    CattaRecord *address_record;
    CattaIfIndex interface;
    CattaProtocol protocol;
    CattaLookupResultFlags flags;

    CattaTimeEvent *time_event;

    CATTA_LLIST_FIELDS(CattaSHostNameResolver, resolver);
};

static void finish(CattaSHostNameResolver *r, CattaResolverEvent event) {
    assert(r);

    if (r->time_event) {
        catta_time_event_free(r->time_event);
        r->time_event = NULL;
    }

    switch (event) {
        case CATTA_RESOLVER_FOUND: {
            CattaAddress a;

            assert(r->address_record);

            switch (r->address_record->key->type) {
                case CATTA_DNS_TYPE_A:
                    a.proto = CATTA_PROTO_INET;
                    a.data.ipv4 = r->address_record->data.a.address;
                    break;

                case CATTA_DNS_TYPE_AAAA:
                    a.proto = CATTA_PROTO_INET6;
                    a.data.ipv6 = r->address_record->data.aaaa.address;
                    break;

                default:
                    abort();
            }

            r->callback(r, r->interface, r->protocol, CATTA_RESOLVER_FOUND, r->address_record->key->name, &a, r->flags, r->userdata);
            break;

        }

        case CATTA_RESOLVER_FAILURE:

            r->callback(r, r->interface, r->protocol, event, r->host_name, NULL, r->flags, r->userdata);
            break;
    }
}

static void time_event_callback(CattaTimeEvent *e, void *userdata) {
    CattaSHostNameResolver *r = userdata;

    assert(e);
    assert(r);

    catta_server_set_errno(r->server, CATTA_ERR_TIMEOUT);
    finish(r, CATTA_RESOLVER_FAILURE);
}

static void start_timeout(CattaSHostNameResolver *r) {
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

    CattaSHostNameResolver *r = userdata;

    assert(rr);
    assert(r);


    switch (event) {
        case CATTA_BROWSER_NEW:
            assert(record);
            assert(record->key->type == CATTA_DNS_TYPE_A || record->key->type == CATTA_DNS_TYPE_AAAA);

            if (r->interface > 0 && interface != r->interface)
                return;

            if (r->protocol != CATTA_PROTO_UNSPEC && protocol != r->protocol)
                return;

            if (r->interface <= 0)
                r->interface = interface;

            if (r->protocol == CATTA_PROTO_UNSPEC)
                r->protocol = protocol;

            if (!r->address_record) {
                r->address_record = catta_record_ref(record);
                r->flags = flags;

                finish(r, CATTA_RESOLVER_FOUND);
            }

            break;

        case CATTA_BROWSER_REMOVE:
            assert(record);
            assert(record->key->type == CATTA_DNS_TYPE_A || record->key->type == CATTA_DNS_TYPE_AAAA);

            if (r->address_record && catta_record_equal_no_ttl(record, r->address_record)) {
                catta_record_unref(r->address_record);
                r->address_record = NULL;

                r->flags = flags;


                /** Look for a replacement */
                if (r->record_browser_aaaa)
                    catta_s_record_browser_restart(r->record_browser_aaaa);
                if (r->record_browser_a)
                    catta_s_record_browser_restart(r->record_browser_a);

                start_timeout(r);
            }

            break;

        case CATTA_BROWSER_CACHE_EXHAUSTED:
        case CATTA_BROWSER_ALL_FOR_NOW:
            /* Ignore */
            break;

        case CATTA_BROWSER_FAILURE:

            /* Stop browsers */

            if (r->record_browser_aaaa)
                catta_s_record_browser_free(r->record_browser_aaaa);
            if (r->record_browser_a)
                catta_s_record_browser_free(r->record_browser_a);

            r->record_browser_a = r->record_browser_aaaa = NULL;
            r->flags = flags;

            finish(r, CATTA_RESOLVER_FAILURE);
            break;
    }
}

CattaSHostNameResolver *catta_s_host_name_resolver_new(
    CattaServer *server,
    CattaIfIndex interface,
    CattaProtocol protocol,
    const char *host_name,
    CattaProtocol aprotocol,
    CattaLookupFlags flags,
    CattaSHostNameResolverCallback callback,
    void* userdata) {

    CattaSHostNameResolver *r;
    CattaKey *k;

    assert(server);
    assert(host_name);
    assert(callback);

    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_IF_VALID(interface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, catta_is_valid_fqdn(host_name), CATTA_ERR_INVALID_HOST_NAME);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_PROTO_VALID(aprotocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_FLAGS_VALID(flags, CATTA_LOOKUP_USE_WIDE_AREA|CATTA_LOOKUP_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);

    if (!(r = catta_new(CattaSHostNameResolver, 1))) {
        catta_server_set_errno(server, CATTA_ERR_NO_MEMORY);
        return NULL;
    }

    r->server = server;
    r->host_name = catta_normalize_name_strdup(host_name);
    r->callback = callback;
    r->userdata = userdata;
    r->address_record = NULL;
    r->interface = interface;
    r->protocol = protocol;
    r->flags = 0;

    r->record_browser_a = r->record_browser_aaaa = NULL;

    r->time_event = NULL;

    CATTA_LLIST_PREPEND(CattaSHostNameResolver, resolver, server->host_name_resolvers, r);

    r->record_browser_aaaa = r->record_browser_a = NULL;

    if (aprotocol == CATTA_PROTO_INET || aprotocol == CATTA_PROTO_UNSPEC) {
        k = catta_key_new(host_name, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_A);
        r->record_browser_a = catta_s_record_browser_new(server, interface, protocol, k, flags, record_browser_callback, r);
        catta_key_unref(k);

        if (!r->record_browser_a)
            goto fail;
    }

    if (aprotocol == CATTA_PROTO_INET6 || aprotocol == CATTA_PROTO_UNSPEC) {
        k = catta_key_new(host_name, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_AAAA);
        r->record_browser_aaaa = catta_s_record_browser_new(server, interface, protocol, k, flags, record_browser_callback, r);
        catta_key_unref(k);

        if (!r->record_browser_aaaa)
            goto fail;
    }

    assert(r->record_browser_aaaa || r->record_browser_a);

    start_timeout(r);

    return r;

fail:
    catta_s_host_name_resolver_free(r);
    return NULL;
}

void catta_s_host_name_resolver_free(CattaSHostNameResolver *r) {
    assert(r);

    CATTA_LLIST_REMOVE(CattaSHostNameResolver, resolver, r->server->host_name_resolvers, r);

    if (r->record_browser_a)
        catta_s_record_browser_free(r->record_browser_a);

    if (r->record_browser_aaaa)
        catta_s_record_browser_free(r->record_browser_aaaa);

    if (r->time_event)
        catta_time_event_free(r->time_event);

    if (r->address_record)
        catta_record_unref(r->address_record);

    catta_free(r->host_name);
    catta_free(r);
}
