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

struct CattaSServiceBrowser {
    CattaServer *server;
    char *domain_name;
    char *service_type;

    CattaSRecordBrowser *record_browser;

    CattaSServiceBrowserCallback callback;
    void* userdata;

    CATTA_LLIST_FIELDS(CattaSServiceBrowser, browser);
};

static void record_browser_callback(
    CattaSRecordBrowser*rr,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    CattaRecord *record,
    CattaLookupResultFlags flags,
    void* userdata) {

    CattaSServiceBrowser *b = userdata;

    assert(rr);
    assert(b);

    /* Filter flags */
    flags &= CATTA_LOOKUP_RESULT_CACHED | CATTA_LOOKUP_RESULT_MULTICAST | CATTA_LOOKUP_RESULT_WIDE_AREA;

    if (record) {
        char service[CATTA_LABEL_MAX], type[CATTA_DOMAIN_NAME_MAX], domain[CATTA_DOMAIN_NAME_MAX];

        assert(record->key->type == CATTA_DNS_TYPE_PTR);

        if (event == CATTA_BROWSER_NEW && catta_server_is_service_local(b->server, iface, protocol, record->data.ptr.name))
            flags |= CATTA_LOOKUP_RESULT_LOCAL;

        if (catta_service_name_split(record->data.ptr.name, service, sizeof(service), type, sizeof(type), domain, sizeof(domain)) < 0) {
            catta_log_warn("Failed to split '%s'", record->key->name);
            return;
        }

        b->callback(b, iface, protocol, event, service, type, domain, flags, b->userdata);

    } else
        b->callback(b, iface, protocol, event, NULL, b->service_type, b->domain_name, flags, b->userdata);

}

CattaSServiceBrowser *catta_s_service_browser_new(
    CattaServer *server,
    CattaIfIndex iface,
    CattaProtocol protocol,
    const char *service_type,
    const char *domain,
    CattaLookupFlags flags,
    CattaSServiceBrowserCallback callback,
    void* userdata) {

    CattaSServiceBrowser *b;
    CattaKey *k = NULL;
    char n[CATTA_DOMAIN_NAME_MAX];
    int r;

    assert(server);
    assert(callback);
    assert(service_type);

    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_IF_VALID(iface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, !domain || catta_is_valid_domain_name(domain), CATTA_ERR_INVALID_DOMAIN_NAME);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_FLAGS_VALID(flags, CATTA_LOOKUP_USE_WIDE_AREA|CATTA_LOOKUP_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, catta_is_valid_service_type_generic(service_type), CATTA_ERR_INVALID_SERVICE_TYPE);

    if (!domain)
        domain = server->domain_name;

    if ((r = catta_service_name_join(n, sizeof(n), NULL, service_type, domain)) < 0) {
        catta_server_set_errno(server, r);
        return NULL;
    }

    if (!(b = catta_new(CattaSServiceBrowser, 1))) {
        catta_server_set_errno(server, CATTA_ERR_NO_MEMORY);
        return NULL;
    }

    b->server = server;
    b->domain_name = b->service_type = NULL;
    b->callback = callback;
    b->userdata = userdata;
    b->record_browser = NULL;

    CATTA_LLIST_PREPEND(CattaSServiceBrowser, browser, server->service_browsers, b);

    if (!(b->domain_name = catta_normalize_name_strdup(domain)) ||
        !(b->service_type = catta_normalize_name_strdup(service_type))) {
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

    catta_s_service_browser_free(b);
    return NULL;
}

void catta_s_service_browser_free(CattaSServiceBrowser *b) {
    assert(b);

    CATTA_LLIST_REMOVE(CattaSServiceBrowser, browser, b->server->service_browsers, b);

    if (b->record_browser)
        catta_s_record_browser_free(b->record_browser);

    catta_free(b->domain_name);
    catta_free(b->service_type);
    catta_free(b);
}
