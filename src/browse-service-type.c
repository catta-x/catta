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

struct CattaSServiceTypeBrowser {
    CattaServer *server;
    char *domain_name;

    CattaSRecordBrowser *record_browser;

    CattaSServiceTypeBrowserCallback callback;
    void* userdata;

    CATTA_LLIST_FIELDS(CattaSServiceTypeBrowser, browser);
};

static void record_browser_callback(
    CattaSRecordBrowser*rr,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    CattaRecord *record,
    CattaLookupResultFlags flags,
    void* userdata) {

    CattaSServiceTypeBrowser *b = userdata;

    assert(rr);
    assert(b);

    /* Filter flags */
    flags &= CATTA_LOOKUP_RESULT_CACHED | CATTA_LOOKUP_RESULT_MULTICAST | CATTA_LOOKUP_RESULT_WIDE_AREA;

    if (record) {
        char type[CATTA_DOMAIN_NAME_MAX], domain[CATTA_DOMAIN_NAME_MAX];

        assert(record->key->type == CATTA_DNS_TYPE_PTR);

        if (catta_service_name_split(record->data.ptr.name, NULL, 0, type, sizeof(type), domain, sizeof(domain)) < 0) {
            catta_log_warn("Invalid service type '%s'", record->key->name);
            return;
        }

        b->callback(b, iface, protocol, event, type, domain, flags, b->userdata);
    } else
        b->callback(b, iface, protocol, event, NULL, b->domain_name, flags, b->userdata);
}

CattaSServiceTypeBrowser *catta_s_service_type_browser_new(
    CattaServer *server,
    CattaIfIndex iface,
    CattaProtocol protocol,
    const char *domain,
    CattaLookupFlags flags,
    CattaSServiceTypeBrowserCallback callback,
    void* userdata) {

    CattaSServiceTypeBrowser *b;
    CattaKey *k = NULL;
    char n[CATTA_DOMAIN_NAME_MAX];
    int r;

    assert(server);
    assert(callback);

    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_IF_VALID(iface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, !domain || catta_is_valid_domain_name(domain), CATTA_ERR_INVALID_DOMAIN_NAME);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_FLAGS_VALID(flags, CATTA_LOOKUP_USE_WIDE_AREA|CATTA_LOOKUP_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);

    if (!domain)
        domain = server->domain_name;

    if ((r = catta_service_name_join(n, sizeof(n), NULL, "_services._dns-sd._udp", domain)) < 0) {
        catta_server_set_errno(server, r);
        return NULL;
    }

    if (!(b = catta_new(CattaSServiceTypeBrowser, 1))) {
        catta_server_set_errno(server, CATTA_ERR_NO_MEMORY);
        return NULL;
    }

    b->server = server;
    b->callback = callback;
    b->userdata = userdata;
    b->record_browser = NULL;

    CATTA_LLIST_PREPEND(CattaSServiceTypeBrowser, browser, server->service_type_browsers, b);

    if (!(b->domain_name = catta_normalize_name_strdup(domain))) {
        catta_server_set_errno(server, CATTA_ERR_NO_MEMORY);
        goto fail;
    }

    if (!(k = catta_key_new(n, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_PTR))) {
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

    catta_s_service_type_browser_free(b);

    return NULL;
}

void catta_s_service_type_browser_free(CattaSServiceTypeBrowser *b) {
    assert(b);

    CATTA_LLIST_REMOVE(CattaSServiceTypeBrowser, browser, b->server->service_type_browsers, b);

    if (b->record_browser)
        catta_s_record_browser_free(b->record_browser);

    catta_free(b->domain_name);
    catta_free(b);
}


