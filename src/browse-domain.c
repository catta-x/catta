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
#include <catta/malloc.h>
#include <catta/error.h>

#include "browse.h"
#include <catta/log.h>

struct CattaSDomainBrowser {
    int ref;

    CattaServer *server;

    CattaSRecordBrowser *record_browser;

    CattaDomainBrowserType type;
    CattaSDomainBrowserCallback callback;
    void* userdata;

    CattaTimeEvent *defer_event;

    int all_for_now_scheduled;

    CATTA_LLIST_FIELDS(CattaSDomainBrowser, browser);
};

static void inc_ref(CattaSDomainBrowser *b) {
    assert(b);
    assert(b->ref >= 1);

    b->ref++;
}

static void record_browser_callback(
    CattaSRecordBrowser*rr,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    CattaRecord *record,
    CattaLookupResultFlags flags,
    void* userdata) {

    CattaSDomainBrowser *b = userdata;
    char *n = NULL;

    assert(rr);
    assert(b);

    if (event == CATTA_BROWSER_ALL_FOR_NOW &&
        b->defer_event) {

        b->all_for_now_scheduled = 1;
        return;
    }

    /* Filter flags */
    flags &= CATTA_LOOKUP_RESULT_CACHED | CATTA_LOOKUP_RESULT_MULTICAST | CATTA_LOOKUP_RESULT_WIDE_AREA;

    if (record) {
        assert(record->key->type == CATTA_DNS_TYPE_PTR);
        n = record->data.ptr.name;

        if (b->type == CATTA_DOMAIN_BROWSER_BROWSE) {
            CattaStringList *l;

            /* Filter out entries defined statically */

            for (l = b->server->config.browse_domains; l; l = l->next)
                if (catta_domain_equal((char*) l->text, n))
                    return;
        }

    }

    b->callback(b, iface, protocol, event, n, flags, b->userdata);
}

static void defer_callback(CattaTimeEvent *e, void *userdata) {
    CattaSDomainBrowser *b = userdata;
    CattaStringList *l;

    assert(e);
    assert(b);

    assert(b->type == CATTA_DOMAIN_BROWSER_BROWSE);

    catta_time_event_free(b->defer_event);
    b->defer_event = NULL;

    /* Increase ref counter */
    inc_ref(b);

    for (l = b->server->config.browse_domains; l; l = l->next) {

        /* Check whether this object still exists outside our own
         * stack frame */
        if (b->ref <= 1)
            break;

        b->callback(b, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, CATTA_BROWSER_NEW, (char*) l->text, CATTA_LOOKUP_RESULT_STATIC, b->userdata);
    }

    if (b->ref > 1) {
        /* If the ALL_FOR_NOW event has already been scheduled, execute it now */

        if (b->all_for_now_scheduled)
            b->callback(b, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, CATTA_BROWSER_ALL_FOR_NOW, NULL, 0, b->userdata);
    }

    /* Decrease ref counter */
    catta_s_domain_browser_free(b);
}

CattaSDomainBrowser *catta_s_domain_browser_new(
    CattaServer *server,
    CattaIfIndex iface,
    CattaProtocol protocol,
    const char *domain,
    CattaDomainBrowserType type,
    CattaLookupFlags flags,
    CattaSDomainBrowserCallback callback,
    void* userdata) {

    static const char * const type_table[CATTA_DOMAIN_BROWSER_MAX] = {
        "b",
        "db",
        "r",
        "dr",
        "lb"
    };

    CattaSDomainBrowser *b;
    CattaKey *k = NULL;
    char n[CATTA_DOMAIN_NAME_MAX];
    int r;

    assert(server);
    assert(callback);

    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_IF_VALID(iface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, type < CATTA_DOMAIN_BROWSER_MAX, CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, !domain || catta_is_valid_domain_name(domain), CATTA_ERR_INVALID_DOMAIN_NAME);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_FLAGS_VALID(flags, CATTA_LOOKUP_USE_WIDE_AREA|CATTA_LOOKUP_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);

    if (!domain)
        domain = server->domain_name;

    if ((r = catta_service_name_join(n, sizeof(n), type_table[type], "_dns-sd._udp", domain)) < 0) {
        catta_server_set_errno(server, r);
        return NULL;
    }

    if (!(b = catta_new(CattaSDomainBrowser, 1))) {
        catta_server_set_errno(server, CATTA_ERR_NO_MEMORY);
        return NULL;
    }

    b->ref = 1;
    b->server = server;
    b->callback = callback;
    b->userdata = userdata;
    b->record_browser = NULL;
    b->type = type;
    b->all_for_now_scheduled = 0;
    b->defer_event = NULL;

    CATTA_LLIST_PREPEND(CattaSDomainBrowser, browser, server->domain_browsers, b);

    if (!(k = catta_key_new(n, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_PTR))) {
        catta_server_set_errno(server, CATTA_ERR_NO_MEMORY);
        goto fail;
    }

    if (!(b->record_browser = catta_s_record_browser_new(server, iface, protocol, k, flags, record_browser_callback, b)))
        goto fail;

    catta_key_unref(k);

    if (type == CATTA_DOMAIN_BROWSER_BROWSE && b->server->config.browse_domains)
        b->defer_event = catta_time_event_new(server->time_event_queue, NULL, defer_callback, b);

    return b;

fail:

    if (k)
        catta_key_unref(k);

    catta_s_domain_browser_free(b);

    return NULL;
}

void catta_s_domain_browser_free(CattaSDomainBrowser *b) {
    assert(b);

    assert(b->ref >= 1);
    if (--b->ref > 0)
        return;

    CATTA_LLIST_REMOVE(CattaSDomainBrowser, browser, b->server->domain_browsers, b);

    if (b->record_browser)
        catta_s_record_browser_free(b->record_browser);

    if (b->defer_event)
        catta_time_event_free(b->defer_event);

    catta_free(b);
}
