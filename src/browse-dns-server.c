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

#include <catta/domain.h>
#include <catta/malloc.h>
#include <catta/error.h>

#include "browse.h"
#include <catta/log.h>
#include <catta/rr.h>

typedef struct CattaDNSServerInfo CattaDNSServerInfo;

struct CattaDNSServerInfo {
    CattaSDNSServerBrowser *browser;

    CattaIfIndex iface;
    CattaProtocol protocol;
    CattaRecord *srv_record;
    CattaSHostNameResolver *host_name_resolver;
    CattaAddress address;
    CattaLookupResultFlags flags;

    CATTA_LLIST_FIELDS(CattaDNSServerInfo, info);
};

struct CattaSDNSServerBrowser {
    CattaServer *server;

    CattaSRecordBrowser *record_browser;
    CattaSDNSServerBrowserCallback callback;
    void* userdata;
    CattaProtocol aprotocol;
    CattaLookupFlags user_flags;

    unsigned n_info;

    CATTA_LLIST_FIELDS(CattaSDNSServerBrowser, browser);
    CATTA_LLIST_HEAD(CattaDNSServerInfo, info);
};

static CattaDNSServerInfo* get_server_info(CattaSDNSServerBrowser *b, CattaIfIndex iface, CattaProtocol protocol, CattaRecord *r) {
    CattaDNSServerInfo *i;

    assert(b);
    assert(r);

    for (i = b->info; i; i = i->info_next)
        if (i->iface == iface &&
            i->protocol == protocol &&
            catta_record_equal_no_ttl(r, i->srv_record))
            return i;

    return NULL;
}

static void server_info_free(CattaSDNSServerBrowser *b, CattaDNSServerInfo *i) {
    assert(b);
    assert(i);

    catta_record_unref(i->srv_record);
    if (i->host_name_resolver)
        catta_s_host_name_resolver_free(i->host_name_resolver);

    CATTA_LLIST_REMOVE(CattaDNSServerInfo, info, b->info, i);

    assert(b->n_info >= 1);
    b->n_info--;

    catta_free(i);
}

static void host_name_resolver_callback(
    CattaSHostNameResolver *r,
    CATTA_GCC_UNUSED CattaIfIndex iface,
    CATTA_GCC_UNUSED CattaProtocol protocol,
    CattaResolverEvent event,
    const char *host_name,
    const CattaAddress *a,
    CattaLookupResultFlags flags,
    void* userdata) {

    CattaDNSServerInfo *i = userdata;

    assert(r);
    assert(host_name);
    assert(i);

    switch (event) {
        case CATTA_RESOLVER_FOUND: {
            i->address = *a;

            i->browser->callback(
                i->browser,
                i->iface,
                i->protocol,
                CATTA_BROWSER_NEW,
                i->srv_record->data.srv.name,
                &i->address,
                i->srv_record->data.srv.port,
                i->flags | flags,
                i->browser->userdata);

            break;
        }

        case CATTA_RESOLVER_FAILURE:
            /* Ignore */
            break;
    }

    catta_s_host_name_resolver_free(i->host_name_resolver);
    i->host_name_resolver = NULL;
}

static void record_browser_callback(
    CattaSRecordBrowser*rr,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    CattaRecord *record,
    CattaLookupResultFlags flags,
    void* userdata) {

    CattaSDNSServerBrowser *b = userdata;

    assert(rr);
    assert(b);

    /* Filter flags */
    flags &= CATTA_LOOKUP_RESULT_CACHED | CATTA_LOOKUP_RESULT_MULTICAST | CATTA_LOOKUP_RESULT_WIDE_AREA;

    switch (event) {
        case CATTA_BROWSER_NEW: {
            CattaDNSServerInfo *i;

            assert(record);
            assert(record->key->type == CATTA_DNS_TYPE_SRV);

            if (get_server_info(b, iface, protocol, record))
                return;

            if (b->n_info >= 10)
                return;

            if (!(i = catta_new(CattaDNSServerInfo, 1)))
                return; /* OOM */

            i->browser = b;
            i->iface = iface;
            i->protocol = protocol;
            i->srv_record = catta_record_ref(record);
            i->host_name_resolver = catta_s_host_name_resolver_new(
                b->server,
                iface, protocol,
                record->data.srv.name,
                b->aprotocol,
                b->user_flags,
                host_name_resolver_callback, i);
            i->flags = flags;

            CATTA_LLIST_PREPEND(CattaDNSServerInfo, info, b->info, i);

            b->n_info++;
            break;
        }

        case CATTA_BROWSER_REMOVE: {
            CattaDNSServerInfo *i;

            assert(record);
            assert(record->key->type == CATTA_DNS_TYPE_SRV);

            if (!(i = get_server_info(b, iface, protocol, record)))
                return;

            if (!i->host_name_resolver)
                b->callback(
                    b,
                    iface,
                    protocol,
                    event,
                    i->srv_record->data.srv.name,
                    &i->address,
                    i->srv_record->data.srv.port,
                    i->flags | flags,
                    b->userdata);

            server_info_free(b, i);
            break;
        }

        case CATTA_BROWSER_FAILURE:
        case CATTA_BROWSER_ALL_FOR_NOW:
        case CATTA_BROWSER_CACHE_EXHAUSTED:

            b->callback(
                b,
                iface,
                protocol,
                event,
                NULL,
                NULL,
                0,
                flags,
                b->userdata);

            break;
    }
}

CattaSDNSServerBrowser *catta_s_dns_server_browser_new(
    CattaServer *server,
    CattaIfIndex iface,
    CattaProtocol protocol,
    const char *domain,
    CattaDNSServerType type,
    CattaProtocol aprotocol,
    CattaLookupFlags flags,
    CattaSDNSServerBrowserCallback callback,
    void* userdata) {

    static const char * const type_table[CATTA_DNS_SERVER_MAX] = {
        "_domain._udp",
        "_dns-update._udp"
    };

    CattaSDNSServerBrowser *b;
    CattaKey *k = NULL;
    char n[CATTA_DOMAIN_NAME_MAX];
    int r;

    assert(server);
    assert(callback);

    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_IF_VALID(iface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_PROTO_VALID(aprotocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, !domain || catta_is_valid_domain_name(domain), CATTA_ERR_INVALID_DOMAIN_NAME);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_FLAGS_VALID(flags, CATTA_LOOKUP_USE_WIDE_AREA|CATTA_LOOKUP_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, type < CATTA_DNS_SERVER_MAX, CATTA_ERR_INVALID_FLAGS);

    if (!domain)
        domain = server->domain_name;

    if ((r = catta_service_name_join(n, sizeof(n), NULL, type_table[type], domain)) < 0) {
        catta_server_set_errno(server, r);
        return NULL;
    }

    if (!(b = catta_new(CattaSDNSServerBrowser, 1))) {
        catta_server_set_errno(server, CATTA_ERR_NO_MEMORY);
        return NULL;
    }

    b->server = server;
    b->callback = callback;
    b->userdata = userdata;
    b->aprotocol = aprotocol;
    b->n_info = 0;
    b->user_flags = flags;

    CATTA_LLIST_HEAD_INIT(CattaDNSServerInfo, b->info);
    CATTA_LLIST_PREPEND(CattaSDNSServerBrowser, browser, server->dns_server_browsers, b);

    if (!(k = catta_key_new(n, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_SRV))) {
        catta_server_set_errno(server, CATTA_ERR_NO_MEMORY);
        goto fail;
    }

    if (!(b->record_browser = catta_s_record_browser_new(server, iface, protocol, k, flags, record_browser_callback, b)))
        goto fail;

    catta_key_unref(k);

    return b;

fail:

    if (k)
        catta_key_unref(k);

    catta_s_dns_server_browser_free(b);
    return NULL;
}

void catta_s_dns_server_browser_free(CattaSDNSServerBrowser *b) {
    assert(b);

    while (b->info)
        server_info_free(b, b->info);

    CATTA_LLIST_REMOVE(CattaSDNSServerBrowser, browser, b->server->dns_server_browsers, b);

    if (b->record_browser)
        catta_s_record_browser_free(b->record_browser);

    catta_free(b);
}

