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
#include <stdio.h>
#include <stdlib.h>

#include <catta/domain.h>
#include <catta/timeval.h>
#include <catta/malloc.h>
#include <catta/error.h>

#include "browse.h"
#include <catta/log.h>

#define TIMEOUT_MSEC 5000

struct CattaSServiceResolver {
    CattaServer *server;
    char *service_name;
    char *service_type;
    char *domain_name;
    CattaProtocol address_protocol;

    CattaIfIndex iface;
    CattaProtocol protocol;

    CattaSRecordBrowser *record_browser_srv;
    CattaSRecordBrowser *record_browser_txt;
    CattaSRecordBrowser *record_browser_a;
    CattaSRecordBrowser *record_browser_aaaa;

    CattaRecord *srv_record, *txt_record, *address_record;
    CattaLookupResultFlags srv_flags, txt_flags, address_flags;

    CattaSServiceResolverCallback callback;
    void* userdata;
    CattaLookupFlags user_flags;

    CattaTimeEvent *time_event;

    CATTA_LLIST_FIELDS(CattaSServiceResolver, resolver);
};

static void finish(CattaSServiceResolver *r, CattaResolverEvent event) {
    CattaLookupResultFlags flags;

    assert(r);

    if (r->time_event) {
        catta_time_event_free(r->time_event);
        r->time_event = NULL;
    }

    flags =
        r->txt_flags |
        r->srv_flags |
        r->address_flags;

    switch (event) {
        case CATTA_RESOLVER_FAILURE:

            r->callback(
                r,
                r->iface,
                r->protocol,
                event,
                r->service_name,
                r->service_type,
                r->domain_name,
                NULL,
                NULL,
                0,
                NULL,
                flags,
                r->userdata);

            break;

        case CATTA_RESOLVER_FOUND: {
            CattaAddress a;

            assert(event == CATTA_RESOLVER_FOUND);

            assert(r->srv_record);

            if (r->address_record) {
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
                        assert(0);
                }
            }

            r->callback(
                r,
                r->iface,
                r->protocol,
                event,
                r->service_name,
                r->service_type,
                r->domain_name,
                r->srv_record->data.srv.name,
                r->address_record ? &a : NULL,
                r->srv_record->data.srv.port,
                r->txt_record ? r->txt_record->data.txt.string_list : NULL,
                flags,
                r->userdata);

            break;
        }
    }
}

static void time_event_callback(CattaTimeEvent *e, void *userdata) {
    CattaSServiceResolver *r = userdata;

    assert(e);
    assert(r);

    catta_server_set_errno(r->server, CATTA_ERR_TIMEOUT);
    finish(r, CATTA_RESOLVER_FAILURE);
}

static void start_timeout(CattaSServiceResolver *r) {
    struct timeval tv;
    assert(r);

    if (r->time_event)
        return;

    catta_elapse_time(&tv, TIMEOUT_MSEC, 0);

    r->time_event = catta_time_event_new(r->server->time_event_queue, &tv, time_event_callback, r);
}

static void record_browser_callback(
    CattaSRecordBrowser*rr,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    CattaRecord *record,
    CattaLookupResultFlags flags,
    void* userdata) {

    CattaSServiceResolver *r = userdata;

    assert(rr);
    assert(r);

    if (rr == r->record_browser_aaaa || rr == r->record_browser_a)
        r->address_flags = flags;
    else if (rr == r->record_browser_srv)
        r->srv_flags = flags;
    else if (rr == r->record_browser_txt)
        r->txt_flags = flags;

    switch (event) {

        case CATTA_BROWSER_NEW: {
            int changed = 0;
            assert(record);

            if (r->iface > 0 && iface > 0 &&  iface != r->iface)
                return;

            if (r->protocol != CATTA_PROTO_UNSPEC && protocol != CATTA_PROTO_UNSPEC && protocol != r->protocol)
                return;

            if (r->iface <= 0)
                r->iface = iface;

            if (r->protocol == CATTA_PROTO_UNSPEC)
                r->protocol = protocol;

            switch (record->key->type) {
                case CATTA_DNS_TYPE_SRV:
                    if (!r->srv_record) {
                        r->srv_record = catta_record_ref(record);
                        changed = 1;

                        if (r->record_browser_a) {
                            catta_s_record_browser_free(r->record_browser_a);
                            r->record_browser_a = NULL;
                        }

                        if (r->record_browser_aaaa) {
                            catta_s_record_browser_free(r->record_browser_aaaa);
                            r->record_browser_aaaa = NULL;
                        }

                        if (!(r->user_flags & CATTA_LOOKUP_NO_ADDRESS)) {

                            if (r->address_protocol == CATTA_PROTO_INET || r->address_protocol == CATTA_PROTO_UNSPEC) {
                                CattaKey *k = catta_key_new(r->srv_record->data.srv.name, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_A);
                                r->record_browser_a = catta_s_record_browser_new(r->server, r->iface, r->protocol, k, r->user_flags & ~(CATTA_LOOKUP_NO_TXT|CATTA_LOOKUP_NO_ADDRESS), record_browser_callback, r);
                                catta_key_unref(k);
                            }

                            if (r->address_protocol == CATTA_PROTO_INET6 || r->address_protocol == CATTA_PROTO_UNSPEC) {
                                CattaKey *k = catta_key_new(r->srv_record->data.srv.name, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_AAAA);
                                r->record_browser_aaaa = catta_s_record_browser_new(r->server, r->iface, r->protocol, k, r->user_flags & ~(CATTA_LOOKUP_NO_TXT|CATTA_LOOKUP_NO_ADDRESS), record_browser_callback, r);
                                catta_key_unref(k);
                            }
                        }
                    }
                    break;

                case CATTA_DNS_TYPE_TXT:

                    assert(!(r->user_flags & CATTA_LOOKUP_NO_TXT));

                    if (!r->txt_record) {
                        r->txt_record = catta_record_ref(record);
                        changed = 1;
                    }
                    break;

                case CATTA_DNS_TYPE_A:
                case CATTA_DNS_TYPE_AAAA:

                    assert(!(r->user_flags & CATTA_LOOKUP_NO_ADDRESS));

                    if (!r->address_record) {
                        r->address_record = catta_record_ref(record);
                        changed = 1;
                    }
                    break;

                default:
                    abort();
            }


            if (changed &&
                r->srv_record &&
                (r->txt_record || (r->user_flags & CATTA_LOOKUP_NO_TXT)) &&
                (r->address_record || (r->user_flags & CATTA_LOOKUP_NO_ADDRESS)))
                finish(r, CATTA_RESOLVER_FOUND);

            break;

        }

        case CATTA_BROWSER_REMOVE:

            assert(record);

            switch (record->key->type) {
                case CATTA_DNS_TYPE_SRV:

                    if (r->srv_record && catta_record_equal_no_ttl(record, r->srv_record)) {
                        catta_record_unref(r->srv_record);
                        r->srv_record = NULL;

                        if (r->record_browser_a) {
                            catta_s_record_browser_free(r->record_browser_a);
                            r->record_browser_a = NULL;
                        }

                        if (r->record_browser_aaaa) {
                            catta_s_record_browser_free(r->record_browser_aaaa);
                            r->record_browser_aaaa = NULL;
                        }

                        /** Look for a replacement */
                        catta_s_record_browser_restart(r->record_browser_srv);
                        start_timeout(r);
                    }

                    break;

                case CATTA_DNS_TYPE_TXT:

                    assert(!(r->user_flags & CATTA_LOOKUP_NO_TXT));

                    if (r->txt_record && catta_record_equal_no_ttl(record, r->txt_record)) {
                        catta_record_unref(r->txt_record);
                        r->txt_record = NULL;

                        /** Look for a replacement */
                        catta_s_record_browser_restart(r->record_browser_txt);
                        start_timeout(r);
                    }
                    break;

                case CATTA_DNS_TYPE_A:
                case CATTA_DNS_TYPE_AAAA:

                    assert(!(r->user_flags & CATTA_LOOKUP_NO_ADDRESS));

                    if (r->address_record && catta_record_equal_no_ttl(record, r->address_record)) {
                        catta_record_unref(r->address_record);
                        r->address_record = NULL;

                        /** Look for a replacement */
                        if (r->record_browser_aaaa)
                            catta_s_record_browser_restart(r->record_browser_aaaa);
                        if (r->record_browser_a)
                            catta_s_record_browser_restart(r->record_browser_a);
                        start_timeout(r);
                    }
                    break;

                default:
                    abort();
            }

            break;

        case CATTA_BROWSER_CACHE_EXHAUSTED:
        case CATTA_BROWSER_ALL_FOR_NOW:
            break;

        case CATTA_BROWSER_FAILURE:

            if (rr == r->record_browser_a && r->record_browser_aaaa) {
                /* We were looking for both AAAA and A, and the other query is still living, so we'll not die */
                catta_s_record_browser_free(r->record_browser_a);
                r->record_browser_a = NULL;
                break;
            }

            if (rr == r->record_browser_aaaa && r->record_browser_a) {
                /* We were looking for both AAAA and A, and the other query is still living, so we'll not die */
                catta_s_record_browser_free(r->record_browser_aaaa);
                r->record_browser_aaaa = NULL;
                break;
            }

            /* Hmm, everything's lost, tell the user */

            if (r->record_browser_srv)
                catta_s_record_browser_free(r->record_browser_srv);
            if (r->record_browser_txt)
                catta_s_record_browser_free(r->record_browser_txt);
            if (r->record_browser_a)
                catta_s_record_browser_free(r->record_browser_a);
            if (r->record_browser_aaaa)
                catta_s_record_browser_free(r->record_browser_aaaa);

            r->record_browser_srv = r->record_browser_txt = r->record_browser_a = r->record_browser_aaaa = NULL;

            finish(r, CATTA_RESOLVER_FAILURE);
            break;
    }
}

CattaSServiceResolver *catta_s_service_resolver_new(
    CattaServer *server,
    CattaIfIndex iface,
    CattaProtocol protocol,
    const char *name,
    const char *type,
    const char *domain,
    CattaProtocol aprotocol,
    CattaLookupFlags flags,
    CattaSServiceResolverCallback callback,
    void* userdata) {

    CattaSServiceResolver *r;
    CattaKey *k;
    char n[CATTA_DOMAIN_NAME_MAX];
    int ret;

    assert(server);
    assert(type);
    assert(callback);

    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_IF_VALID(iface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_PROTO_VALID(aprotocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, !domain || catta_is_valid_domain_name(domain), CATTA_ERR_INVALID_DOMAIN_NAME);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, !name || catta_is_valid_service_name(name), CATTA_ERR_INVALID_SERVICE_NAME);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, catta_is_valid_service_type_strict(type), CATTA_ERR_INVALID_SERVICE_TYPE);
    CATTA_CHECK_VALIDITY_RETURN_NULL(server, CATTA_FLAGS_VALID(flags, CATTA_LOOKUP_USE_WIDE_AREA|CATTA_LOOKUP_USE_MULTICAST|CATTA_LOOKUP_NO_TXT|CATTA_LOOKUP_NO_ADDRESS), CATTA_ERR_INVALID_FLAGS);

    if (!domain)
        domain = server->domain_name;

    if ((ret = catta_service_name_join(n, sizeof(n), name, type, domain)) < 0) {
        catta_server_set_errno(server, ret);
        return NULL;
    }

    if (!(r = catta_new(CattaSServiceResolver, 1))) {
        catta_server_set_errno(server, CATTA_ERR_NO_MEMORY);
        return NULL;
    }

    r->server = server;
    r->service_name = catta_strdup(name);
    r->service_type = catta_normalize_name_strdup(type);
    r->domain_name = catta_normalize_name_strdup(domain);
    r->callback = callback;
    r->userdata = userdata;
    r->address_protocol = aprotocol;
    r->srv_record = r->txt_record = r->address_record = NULL;
    r->srv_flags = r->txt_flags = r->address_flags = 0;
    r->iface = iface;
    r->protocol = protocol;
    r->user_flags = flags;
    r->record_browser_a = r->record_browser_aaaa = r->record_browser_srv = r->record_browser_txt = NULL;
    r->time_event = NULL;
    CATTA_LLIST_PREPEND(CattaSServiceResolver, resolver, server->service_resolvers, r);

    k = catta_key_new(n, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_SRV);
    r->record_browser_srv = catta_s_record_browser_new(server, iface, protocol, k, flags & ~(CATTA_LOOKUP_NO_TXT|CATTA_LOOKUP_NO_ADDRESS), record_browser_callback, r);
    catta_key_unref(k);

    if (!r->record_browser_srv) {
        catta_s_service_resolver_free(r);
        return NULL;
    }

    if (!(flags & CATTA_LOOKUP_NO_TXT)) {
        k = catta_key_new(n, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_TXT);
        r->record_browser_txt = catta_s_record_browser_new(server, iface, protocol, k, flags & ~(CATTA_LOOKUP_NO_TXT|CATTA_LOOKUP_NO_ADDRESS),  record_browser_callback, r);
        catta_key_unref(k);

        if (!r->record_browser_txt) {
            catta_s_service_resolver_free(r);
            return NULL;
        }
    }

    start_timeout(r);

    return r;
}

void catta_s_service_resolver_free(CattaSServiceResolver *r) {
    assert(r);

    CATTA_LLIST_REMOVE(CattaSServiceResolver, resolver, r->server->service_resolvers, r);

    if (r->time_event)
        catta_time_event_free(r->time_event);

    if (r->record_browser_srv)
        catta_s_record_browser_free(r->record_browser_srv);
    if (r->record_browser_txt)
        catta_s_record_browser_free(r->record_browser_txt);
    if (r->record_browser_a)
        catta_s_record_browser_free(r->record_browser_a);
    if (r->record_browser_aaaa)
        catta_s_record_browser_free(r->record_browser_aaaa);

    if (r->srv_record)
        catta_record_unref(r->srv_record);
    if (r->txt_record)
        catta_record_unref(r->txt_record);
    if (r->address_record)
        catta_record_unref(r->address_record);

    catta_free(r->service_name);
    catta_free(r->service_type);
    catta_free(r->domain_name);
    catta_free(r);
}
