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
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <catta/domain.h>
#include <catta/timeval.h>
#include <catta/malloc.h>
#include <catta/error.h>
#include <catta/domain.h>
#include <catta/log.h>

#include "internal.h"
#include "iface.h"
#include "socket.h"
#include "browse.h"
#include "util.h"
#include "dns-srv-rr.h"
#include "rr-util.h"
#include "domain-util.h"

static void transport_flags_from_domain(CattaServer *s, CattaPublishFlags *flags, const char *domain) {
    assert(flags);
    assert(domain);

    assert(!((*flags & CATTA_PUBLISH_USE_MULTICAST) && (*flags & CATTA_PUBLISH_USE_WIDE_AREA)));

    if (*flags & (CATTA_PUBLISH_USE_MULTICAST|CATTA_PUBLISH_USE_WIDE_AREA))
        return;

    if (!s->wide_area_lookup_engine ||
        !catta_wide_area_has_servers(s->wide_area_lookup_engine) ||
        catta_domain_ends_with(domain, CATTA_MDNS_SUFFIX_LOCAL) ||
        catta_domain_ends_with(domain, CATTA_MDNS_SUFFIX_ADDR_IPV4) ||
        catta_domain_ends_with(domain, CATTA_MDNS_SUFFIX_ADDR_IPV6))
        *flags |= CATTA_PUBLISH_USE_MULTICAST;
    else
        *flags |= CATTA_PUBLISH_USE_WIDE_AREA;
}

void catta_entry_free(CattaServer*s, CattaEntry *e) {
    CattaEntry *t;

    assert(s);
    assert(e);

    catta_goodbye_entry(s, e, 1, 1);

    /* Remove from linked list */
    CATTA_LLIST_REMOVE(CattaEntry, entries, s->entries, e);

    /* Remove from hash table indexed by name */
    t = catta_hashmap_lookup(s->entries_by_key, e->record->key);
    CATTA_LLIST_REMOVE(CattaEntry, by_key, t, e);
    if (t)
        catta_hashmap_replace(s->entries_by_key, t->record->key, t);
    else
        catta_hashmap_remove(s->entries_by_key, e->record->key);

    /* Remove from associated group */
    if (e->group)
        CATTA_LLIST_REMOVE(CattaEntry, by_group, e->group->entries, e);

    catta_record_unref(e->record);
    catta_free(e);
}

void catta_entry_group_free(CattaServer *s, CattaSEntryGroup *g) {
    assert(s);
    assert(g);

    while (g->entries)
        catta_entry_free(s, g->entries);

    if (g->register_time_event)
        catta_time_event_free(g->register_time_event);

    CATTA_LLIST_REMOVE(CattaSEntryGroup, groups, s->groups, g);
    catta_free(g);
}

void catta_cleanup_dead_entries(CattaServer *s) {
    assert(s);

    if (s->need_group_cleanup) {
        CattaSEntryGroup *g, *next;

        for (g = s->groups; g; g = next) {
            next = g->groups_next;

            if (g->dead)
                catta_entry_group_free(s, g);
        }

        s->need_group_cleanup = 0;
    }

    if (s->need_entry_cleanup) {
        CattaEntry *e, *next;

        for (e = s->entries; e; e = next) {
            next = e->entries_next;

            if (e->dead)
                catta_entry_free(s, e);
        }

        s->need_entry_cleanup = 0;
    }

    if (s->need_browser_cleanup)
        catta_browser_cleanup(s);

    if (s->cleanup_time_event) {
        catta_time_event_free(s->cleanup_time_event);
        s->cleanup_time_event = NULL;
    }
}

static int check_record_conflict(CattaServer *s, CattaIfIndex interface, CattaProtocol protocol, CattaRecord *r, CattaPublishFlags flags) {
    CattaEntry *e;

    assert(s);
    assert(r);

    for (e = catta_hashmap_lookup(s->entries_by_key, r->key); e; e = e->by_key_next) {
        if (e->dead)
            continue;

        if (!(flags & CATTA_PUBLISH_UNIQUE) && !(e->flags & CATTA_PUBLISH_UNIQUE))
            continue;

        if ((flags & CATTA_PUBLISH_ALLOW_MULTIPLE) && (e->flags & CATTA_PUBLISH_ALLOW_MULTIPLE) )
            continue;

        if (catta_record_equal_no_ttl(r, e->record)) {
            /* The records are the same, not a conflict in any case */
            continue;
        }

        if ((interface <= 0 ||
             e->interface <= 0 ||
             e->interface == interface) &&
            (protocol == CATTA_PROTO_UNSPEC ||
             e->protocol == CATTA_PROTO_UNSPEC ||
             e->protocol == protocol))

            return -1;
    }

    return 0;
}

static CattaEntry * server_add_internal(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    CattaRecord *r) {

    CattaEntry *e;

    assert(s);
    assert(r);

    CATTA_CHECK_VALIDITY_RETURN_NULL(s, s->state != CATTA_SERVER_FAILURE && s->state != CATTA_SERVER_INVALID, CATTA_ERR_BAD_STATE);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, CATTA_IF_VALID(interface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, CATTA_FLAGS_VALID(
                                         flags,
                                         CATTA_PUBLISH_NO_ANNOUNCE|
                                         CATTA_PUBLISH_NO_PROBE|
                                         CATTA_PUBLISH_UNIQUE|
                                         CATTA_PUBLISH_ALLOW_MULTIPLE|
                                         CATTA_PUBLISH_UPDATE|
                                         CATTA_PUBLISH_USE_WIDE_AREA|
                                         CATTA_PUBLISH_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, catta_is_valid_domain_name(r->key->name), CATTA_ERR_INVALID_HOST_NAME);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, r->ttl != 0, CATTA_ERR_INVALID_TTL);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, !catta_key_is_pattern(r->key), CATTA_ERR_IS_PATTERN);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, catta_record_is_valid(r), CATTA_ERR_INVALID_RECORD);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, r->key->clazz == CATTA_DNS_CLASS_IN, CATTA_ERR_INVALID_DNS_CLASS);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s,
                                     (r->key->type != 0) &&
                                     (r->key->type != CATTA_DNS_TYPE_ANY) &&
                                     (r->key->type != CATTA_DNS_TYPE_OPT) &&
                                     (r->key->type != CATTA_DNS_TYPE_TKEY) &&
                                     (r->key->type != CATTA_DNS_TYPE_TSIG) &&
                                     (r->key->type != CATTA_DNS_TYPE_IXFR) &&
                                     (r->key->type != CATTA_DNS_TYPE_AXFR), CATTA_ERR_INVALID_DNS_TYPE);

    transport_flags_from_domain(s, &flags, r->key->name);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, flags & CATTA_PUBLISH_USE_MULTICAST, CATTA_ERR_NOT_SUPPORTED);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, !s->config.disable_publishing, CATTA_ERR_NOT_PERMITTED);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s,
                                     !g ||
                                     (g->state != CATTA_ENTRY_GROUP_ESTABLISHED && g->state != CATTA_ENTRY_GROUP_REGISTERING) ||
                                     (flags & CATTA_PUBLISH_UPDATE), CATTA_ERR_BAD_STATE);

    if (flags & CATTA_PUBLISH_UPDATE) {
        CattaRecord *old_record;
        int is_first = 1;

        /* Update and existing record */

        /* Find the first matching entry */
        for (e = catta_hashmap_lookup(s->entries_by_key, r->key); e; e = e->by_key_next) {
            if (!e->dead && e->group == g && e->interface == interface && e->protocol == protocol)
                break;

            is_first = 0;
        }

        /* Hmm, nothing found? */
        if (!e) {
            catta_server_set_errno(s, CATTA_ERR_NOT_FOUND);
            return NULL;
        }

        /* Update the entry */
        old_record = e->record;
        e->record = catta_record_ref(r);
        e->flags = flags;

        /* Announce our changes when needed */
        if (!catta_record_equal_no_ttl(old_record, r) && (!g || g->state != CATTA_ENTRY_GROUP_UNCOMMITED)) {

            /* Remove the old entry from all caches, if needed */
            if (!(e->flags & CATTA_PUBLISH_UNIQUE))
                catta_goodbye_entry(s, e, 1, 0);

            /* Reannounce our updated entry */
            catta_reannounce_entry(s, e);
        }

        /* If we were the first entry in the list, we need to update the key */
        if (is_first)
            catta_hashmap_replace(s->entries_by_key, e->record->key, e);

        catta_record_unref(old_record);

    } else {
        CattaEntry *t;

        /* Add a new record */

        if (check_record_conflict(s, interface, protocol, r, flags) < 0) {
            catta_server_set_errno(s, CATTA_ERR_COLLISION);
            return NULL;
        }

        if (!(e = catta_new(CattaEntry, 1))) {
            catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);
            return NULL;
        }

        e->server = s;
        e->record = catta_record_ref(r);
        e->group = g;
        e->interface = interface;
        e->protocol = protocol;
        e->flags = flags;
        e->dead = 0;

        CATTA_LLIST_HEAD_INIT(CattaAnnouncer, e->announcers);

        CATTA_LLIST_PREPEND(CattaEntry, entries, s->entries, e);

        /* Insert into hash table indexed by name */
        t = catta_hashmap_lookup(s->entries_by_key, e->record->key);
        CATTA_LLIST_PREPEND(CattaEntry, by_key, t, e);
        catta_hashmap_replace(s->entries_by_key, e->record->key, t);

        /* Insert into group list */
        if (g)
            CATTA_LLIST_PREPEND(CattaEntry, by_group, g->entries, e);

        catta_announce_entry(s, e);
    }

    return e;
}

int catta_server_add(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    CattaRecord *r) {

    if (!server_add_internal(s, g, interface, protocol, flags, r))
        return catta_server_errno(s);

    return CATTA_OK;
}

const CattaRecord *catta_server_iterate(CattaServer *s, CattaSEntryGroup *g, void **state) {
    CattaEntry **e = (CattaEntry**) state;
    assert(s);
    assert(e);

    if (!*e)
        *e = g ? g->entries : s->entries;

    while (*e && (*e)->dead)
        *e = g ? (*e)->by_group_next : (*e)->entries_next;

    if (!*e)
        return NULL;

    return catta_record_ref((*e)->record);
}

int catta_server_dump(CattaServer *s, CattaDumpCallback callback, void* userdata) {
    CattaEntry *e;

    assert(s);
    assert(callback);

    callback(";;; ZONE DUMP FOLLOWS ;;;", userdata);

    for (e = s->entries; e; e = e->entries_next) {
        char *t;
        char ln[256];

        if (e->dead)
            continue;

        if (!(t = catta_record_to_string(e->record)))
            return catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);

        snprintf(ln, sizeof(ln), "%s ; iface=%i proto=%i", t, e->interface, e->protocol);
        catta_free(t);

        callback(ln, userdata);
    }

    catta_dump_caches(s->monitor, callback, userdata);

    if (s->wide_area_lookup_engine)
        catta_wide_area_cache_dump(s->wide_area_lookup_engine, callback, userdata);
    return CATTA_OK;
}

static CattaEntry *server_add_ptr_internal(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    uint32_t ttl,
    const char *name,
    const char *dest) {

    CattaRecord *r;
    CattaEntry *e;

    assert(s);
    assert(dest);

    CATTA_CHECK_VALIDITY_RETURN_NULL(s, !name || catta_is_valid_domain_name(name), CATTA_ERR_INVALID_HOST_NAME);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, catta_is_valid_domain_name(dest), CATTA_ERR_INVALID_HOST_NAME);

    if (!name)
        name = s->host_name_fqdn;

    if (!(r = catta_record_new_full(name, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_PTR, ttl))) {
        catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);
        return NULL;
    }

    r->data.ptr.name = catta_normalize_name_strdup(dest);
    e = server_add_internal(s, g, interface, protocol, flags, r);
    catta_record_unref(r);
    return e;
}

int catta_server_add_ptr(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    uint32_t ttl,
    const char *name,
    const char *dest) {

    CattaEntry *e;

    assert(s);

    if (!(e = server_add_ptr_internal(s, g, interface, protocol, flags, ttl, name, dest)))
        return catta_server_errno(s);

    return CATTA_OK;
}

int catta_server_add_address(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,
    CattaAddress *a) {

    char n[CATTA_DOMAIN_NAME_MAX];
    int ret = CATTA_OK;
    CattaEntry *entry = NULL, *reverse = NULL;
    CattaRecord  *r;

    assert(s);
    assert(a);

    CATTA_CHECK_VALIDITY(s, CATTA_IF_VALID(interface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY(s, CATTA_PROTO_VALID(protocol) && CATTA_PROTO_VALID(a->proto), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY(s, CATTA_FLAGS_VALID(flags,
                                              CATTA_PUBLISH_NO_REVERSE|
                                              CATTA_PUBLISH_NO_ANNOUNCE|
                                              CATTA_PUBLISH_NO_PROBE|
                                              CATTA_PUBLISH_UPDATE|
                                              CATTA_PUBLISH_USE_WIDE_AREA|
                                              CATTA_PUBLISH_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY(s, !name || catta_is_valid_fqdn(name), CATTA_ERR_INVALID_HOST_NAME);

    /* Prepare the host naem */

    if (!name)
        name = s->host_name_fqdn;
    else {
        CATTA_ASSERT_TRUE(catta_normalize_name(name, n, sizeof(n)));
        name = n;
    }

    transport_flags_from_domain(s, &flags, name);
    CATTA_CHECK_VALIDITY(s, flags & CATTA_PUBLISH_USE_MULTICAST, CATTA_ERR_NOT_SUPPORTED);

    /* Create the A/AAAA record */

    if (a->proto == CATTA_PROTO_INET) {

        if (!(r = catta_record_new_full(name, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_A, CATTA_DEFAULT_TTL_HOST_NAME))) {
            ret = catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);
            goto finish;
        }

        r->data.a.address = a->data.ipv4;

    } else {
        assert(a->proto == CATTA_PROTO_INET6);

        if (!(r = catta_record_new_full(name, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_AAAA, CATTA_DEFAULT_TTL_HOST_NAME))) {
            ret = catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);
            goto finish;
        }

        r->data.aaaa.address = a->data.ipv6;
    }

    entry = server_add_internal(s, g, interface, protocol, (flags & ~ CATTA_PUBLISH_NO_REVERSE) | CATTA_PUBLISH_UNIQUE | CATTA_PUBLISH_ALLOW_MULTIPLE, r);
    catta_record_unref(r);

    if (!entry) {
        ret = catta_server_errno(s);
        goto finish;
    }

    /* Create the reverse lookup entry */

    if (!(flags & CATTA_PUBLISH_NO_REVERSE)) {
        char reverse_n[CATTA_DOMAIN_NAME_MAX];
        catta_reverse_lookup_name(a, reverse_n, sizeof(reverse_n));

        if (!(reverse = server_add_ptr_internal(s, g, interface, protocol, flags | CATTA_PUBLISH_UNIQUE, CATTA_DEFAULT_TTL_HOST_NAME, reverse_n, name))) {
            ret = catta_server_errno(s);
            goto finish;
        }
    }

finish:

    if (ret != CATTA_OK && !(flags & CATTA_PUBLISH_UPDATE)) {
        if (entry)
            catta_entry_free(s, entry);
        if (reverse)
            catta_entry_free(s, reverse);
    }

    return ret;
}

static CattaEntry *server_add_txt_strlst_nocopy(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    uint32_t ttl,
    const char *name,
    CattaStringList *strlst) {

    CattaRecord *r;
    CattaEntry *e;

    assert(s);

    if (!(r = catta_record_new_full(name ? name : s->host_name_fqdn, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_TXT, ttl))) {
        catta_string_list_free(strlst);
        catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);
        return NULL;
    }

    r->data.txt.string_list = strlst;
    e = server_add_internal(s, g, interface, protocol, flags, r);
    catta_record_unref(r);

    return e;
}

static CattaStringList *add_magic_cookie(
    CattaServer *s,
    CattaStringList *strlst) {

    assert(s);

    if (!s->config.add_service_cookie)
        return strlst;

    if (catta_string_list_find(strlst, CATTA_SERVICE_COOKIE))
        /* This string list already contains a magic cookie */
        return strlst;

    return catta_string_list_add_printf(strlst, CATTA_SERVICE_COOKIE"=%u", s->local_service_cookie);
}

static int server_add_service_strlst_nocopy(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,
    const char *type,
    const char *domain,
    const char *host,
    uint16_t port,
    CattaStringList *strlst) {

    char ptr_name[CATTA_DOMAIN_NAME_MAX], svc_name[CATTA_DOMAIN_NAME_MAX], enum_ptr[CATTA_DOMAIN_NAME_MAX], *h = NULL;
    CattaRecord *r = NULL;
    int ret = CATTA_OK;
    CattaEntry *srv_entry = NULL, *txt_entry = NULL, *ptr_entry = NULL, *enum_entry = NULL;

    assert(s);
    assert(type);
    assert(name);

    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, CATTA_IF_VALID(interface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, CATTA_FLAGS_VALID(flags,
                                                                CATTA_PUBLISH_NO_COOKIE|
                                                                CATTA_PUBLISH_UPDATE|
                                                                CATTA_PUBLISH_USE_WIDE_AREA|
                                                                CATTA_PUBLISH_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, catta_is_valid_service_name(name), CATTA_ERR_INVALID_SERVICE_NAME);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, catta_is_valid_service_type_strict(type), CATTA_ERR_INVALID_SERVICE_TYPE);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, !domain || catta_is_valid_domain_name(domain), CATTA_ERR_INVALID_DOMAIN_NAME);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, !host || catta_is_valid_fqdn(host), CATTA_ERR_INVALID_HOST_NAME);

    if (!domain)
        domain = s->domain_name;

    if (!host)
        host = s->host_name_fqdn;

    transport_flags_from_domain(s, &flags, domain);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, flags & CATTA_PUBLISH_USE_MULTICAST, CATTA_ERR_NOT_SUPPORTED);

    if (!(h = catta_normalize_name_strdup(host))) {
        ret = catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);
        goto fail;
    }

    if ((ret = catta_service_name_join(svc_name, sizeof(svc_name), name, type, domain)) < 0 ||
        (ret = catta_service_name_join(ptr_name, sizeof(ptr_name), NULL, type, domain)) < 0 ||
        (ret = catta_service_name_join(enum_ptr, sizeof(enum_ptr), NULL, "_services._dns-sd._udp", domain)) < 0) {
        catta_server_set_errno(s, ret);
        goto fail;
    }

    /* Add service enumeration PTR record */

    if (!(ptr_entry = server_add_ptr_internal(s, g, interface, protocol, 0, CATTA_DEFAULT_TTL, ptr_name, svc_name))) {
        ret = catta_server_errno(s);
        goto fail;
    }

    /* Add SRV record */

    if (!(r = catta_record_new_full(svc_name, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_SRV, CATTA_DEFAULT_TTL_HOST_NAME))) {
        ret = catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);
        goto fail;
    }

    r->data.srv.priority = 0;
    r->data.srv.weight = 0;
    r->data.srv.port = port;
    r->data.srv.name = h;
    h = NULL;
    srv_entry = server_add_internal(s, g, interface, protocol, CATTA_PUBLISH_UNIQUE, r);
    catta_record_unref(r);

    if (!srv_entry) {
        ret = catta_server_errno(s);
        goto fail;
    }

    /* Add TXT record */

    if (!(flags & CATTA_PUBLISH_NO_COOKIE))
        strlst = add_magic_cookie(s, strlst);

    txt_entry = server_add_txt_strlst_nocopy(s, g, interface, protocol, CATTA_PUBLISH_UNIQUE, CATTA_DEFAULT_TTL, svc_name, strlst);
    strlst = NULL;

    if (!txt_entry) {
        ret = catta_server_errno(s);
        goto fail;
    }

    /* Add service type enumeration record */

    if (!(enum_entry = server_add_ptr_internal(s, g, interface, protocol, 0, CATTA_DEFAULT_TTL, enum_ptr, ptr_name))) {
        ret = catta_server_errno(s);
        goto fail;
    }

fail:
    if (ret != CATTA_OK && !(flags & CATTA_PUBLISH_UPDATE)) {
        if (srv_entry)
            catta_entry_free(s, srv_entry);
        if (txt_entry)
            catta_entry_free(s, txt_entry);
        if (ptr_entry)
            catta_entry_free(s, ptr_entry);
        if (enum_entry)
            catta_entry_free(s, enum_entry);
    }

    catta_string_list_free(strlst);
    catta_free(h);

    return ret;
}

int catta_server_add_service_strlst(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,
    const char *type,
    const char *domain,
    const char *host,
    uint16_t port,
    CattaStringList *strlst) {

    assert(s);
    assert(type);
    assert(name);

    return server_add_service_strlst_nocopy(s, g, interface, protocol, flags, name, type, domain, host, port, catta_string_list_copy(strlst));
}

int catta_server_add_service(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,
    const char *type,
    const char *domain,
    const char *host,
    uint16_t port,
    ... ){

    va_list va;
    int ret;

    va_start(va, port);
    ret = server_add_service_strlst_nocopy(s, g, interface, protocol, flags, name, type, domain, host, port, catta_string_list_new_va(va));
    va_end(va);

    return ret;
}

static int server_update_service_txt_strlst_nocopy(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,
    const char *type,
    const char *domain,
    CattaStringList *strlst) {

    char svc_name[CATTA_DOMAIN_NAME_MAX];
    int ret = CATTA_OK;
    CattaEntry *e;

    assert(s);
    assert(type);
    assert(name);

    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, CATTA_IF_VALID(interface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, CATTA_FLAGS_VALID(flags,
                                                                CATTA_PUBLISH_NO_COOKIE|
                                                                CATTA_PUBLISH_USE_WIDE_AREA|
                                                                CATTA_PUBLISH_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, catta_is_valid_service_name(name), CATTA_ERR_INVALID_SERVICE_NAME);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, catta_is_valid_service_type_strict(type), CATTA_ERR_INVALID_SERVICE_TYPE);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, !domain || catta_is_valid_domain_name(domain), CATTA_ERR_INVALID_DOMAIN_NAME);

    if (!domain)
        domain = s->domain_name;

    transport_flags_from_domain(s, &flags, domain);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, flags & CATTA_PUBLISH_USE_MULTICAST, CATTA_ERR_NOT_SUPPORTED);

    if ((ret = catta_service_name_join(svc_name, sizeof(svc_name), name, type, domain)) < 0) {
        catta_server_set_errno(s, ret);
        goto fail;
    }

    /* Add TXT record */
    if (!(flags & CATTA_PUBLISH_NO_COOKIE))
        strlst = add_magic_cookie(s, strlst);

    e = server_add_txt_strlst_nocopy(s, g, interface, protocol, CATTA_PUBLISH_UNIQUE | CATTA_PUBLISH_UPDATE, CATTA_DEFAULT_TTL, svc_name, strlst);
    strlst = NULL;

    if (!e)
        ret = catta_server_errno(s);

fail:

    catta_string_list_free(strlst);

    return ret;
}

int catta_server_update_service_txt_strlst(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,
    const char *type,
    const char *domain,
    CattaStringList *strlst) {

    return server_update_service_txt_strlst_nocopy(s, g, interface, protocol, flags, name, type, domain, catta_string_list_copy(strlst));
}

/** Update the TXT record for a service with the NULL termonate list of strings */
int catta_server_update_service_txt(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,
    const char *type,
    const char *domain,
    ...) {

    va_list va;
    int ret;

    va_start(va, domain);
    ret = server_update_service_txt_strlst_nocopy(s, g, interface, protocol, flags, name, type, domain, catta_string_list_new_va(va));
    va_end(va);

    return ret;
}

int catta_server_add_service_subtype(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,
    const char *type,
    const char *domain,
    const char *subtype) {

    int ret = CATTA_OK;
    char svc_name[CATTA_DOMAIN_NAME_MAX], ptr_name[CATTA_DOMAIN_NAME_MAX];

    assert(name);
    assert(type);
    assert(subtype);

    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, CATTA_IF_VALID(interface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, CATTA_FLAGS_VALID(flags, CATTA_PUBLISH_USE_MULTICAST|CATTA_PUBLISH_USE_WIDE_AREA), CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, catta_is_valid_service_name(name), CATTA_ERR_INVALID_SERVICE_NAME);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, catta_is_valid_service_type_strict(type), CATTA_ERR_INVALID_SERVICE_TYPE);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, !domain || catta_is_valid_domain_name(domain), CATTA_ERR_INVALID_DOMAIN_NAME);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, catta_is_valid_service_subtype(subtype), CATTA_ERR_INVALID_SERVICE_SUBTYPE);

    if (!domain)
        domain = s->domain_name;

    transport_flags_from_domain(s, &flags, domain);
    CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(s, flags & CATTA_PUBLISH_USE_MULTICAST, CATTA_ERR_NOT_SUPPORTED);

    if ((ret = catta_service_name_join(svc_name, sizeof(svc_name), name, type, domain)) < 0 ||
        (ret = catta_service_name_join(ptr_name, sizeof(ptr_name), NULL, subtype, domain)) < 0) {
        catta_server_set_errno(s, ret);
        goto fail;
    }

    if ((ret = catta_server_add_ptr(s, g, interface, protocol, 0, CATTA_DEFAULT_TTL, ptr_name, svc_name)) < 0)
        goto fail;

fail:

    return ret;
}

static void hexstring(char *s, size_t sl, const void *p, size_t pl) {
    static const char hex[] = "0123456789abcdef";
    int b = 0;
    const uint8_t *k = p;

    while (sl > 1 && pl > 0) {
        *(s++) = hex[(b ? *k : *k >> 4) & 0xF];

        if (b) {
            k++;
            pl--;
        }

        b = !b;

        sl--;
    }

    if (sl > 0)
        *s = 0;
}

static CattaEntry *server_add_dns_server_name(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *domain,
    CattaDNSServerType type,
    const char *name,
    uint16_t port /** should be 53 */) {

    CattaEntry *e;
    char t[CATTA_DOMAIN_NAME_MAX], normalized_d[CATTA_DOMAIN_NAME_MAX], *n;

    CattaRecord *r;

    assert(s);
    assert(name);

    CATTA_CHECK_VALIDITY_RETURN_NULL(s, CATTA_FLAGS_VALID(flags, CATTA_PUBLISH_USE_WIDE_AREA|CATTA_PUBLISH_USE_MULTICAST), CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, type == CATTA_DNS_SERVER_UPDATE || type == CATTA_DNS_SERVER_RESOLVE, CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, port != 0, CATTA_ERR_INVALID_PORT);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, catta_is_valid_fqdn(name), CATTA_ERR_INVALID_HOST_NAME);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, !domain || catta_is_valid_domain_name(domain), CATTA_ERR_INVALID_DOMAIN_NAME);

    if (!domain)
        domain = s->domain_name;

    transport_flags_from_domain(s, &flags, domain);
    CATTA_CHECK_VALIDITY_RETURN_NULL(s, flags & CATTA_PUBLISH_USE_MULTICAST, CATTA_ERR_NOT_SUPPORTED);

    if (!(n = catta_normalize_name_strdup(name))) {
        catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);
        return NULL;
    }

    CATTA_ASSERT_TRUE(catta_normalize_name(domain, normalized_d, sizeof(normalized_d)));

    snprintf(t, sizeof(t), "%s.%s", type == CATTA_DNS_SERVER_RESOLVE ? "_domain._udp" : "_dns-update._udp", normalized_d);

    if (!(r = catta_record_new_full(t, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_SRV, CATTA_DEFAULT_TTL_HOST_NAME))) {
        catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);
        catta_free(n);
        return NULL;
    }

    r->data.srv.priority = 0;
    r->data.srv.weight = 0;
    r->data.srv.port = port;
    r->data.srv.name = n;
    e = server_add_internal(s, g, interface, protocol, 0, r);
    catta_record_unref(r);

    return e;
}

int catta_server_add_dns_server_address(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *domain,
    CattaDNSServerType type,
    const CattaAddress *address,
    uint16_t port /** should be 53 */) {

    CattaRecord *r;
    char n[64], h[64];
    CattaEntry *a_entry, *s_entry;

    assert(s);
    assert(address);

    CATTA_CHECK_VALIDITY(s, CATTA_IF_VALID(interface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY(s, CATTA_PROTO_VALID(protocol) && CATTA_PROTO_VALID(address->proto), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY(s, CATTA_FLAGS_VALID(flags, CATTA_PUBLISH_USE_MULTICAST|CATTA_PUBLISH_USE_WIDE_AREA), CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY(s, type == CATTA_DNS_SERVER_UPDATE || type == CATTA_DNS_SERVER_RESOLVE, CATTA_ERR_INVALID_FLAGS);
    CATTA_CHECK_VALIDITY(s, port != 0, CATTA_ERR_INVALID_PORT);
    CATTA_CHECK_VALIDITY(s, !domain || catta_is_valid_domain_name(domain), CATTA_ERR_INVALID_DOMAIN_NAME);

    if (!domain)
        domain = s->domain_name;

    transport_flags_from_domain(s, &flags, domain);
    CATTA_CHECK_VALIDITY(s, flags & CATTA_PUBLISH_USE_MULTICAST, CATTA_ERR_NOT_SUPPORTED);

    if (address->proto == CATTA_PROTO_INET) {
        hexstring(h, sizeof(h), &address->data, sizeof(CattaIPv4Address));
        snprintf(n, sizeof(n), "ip-%s.%s", h, domain);
        r = catta_record_new_full(n, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_A, CATTA_DEFAULT_TTL_HOST_NAME);
        r->data.a.address = address->data.ipv4;
    } else {
        hexstring(h, sizeof(h), &address->data, sizeof(CattaIPv6Address));
        snprintf(n, sizeof(n), "ip6-%s.%s", h, domain);
        r = catta_record_new_full(n, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_AAAA, CATTA_DEFAULT_TTL_HOST_NAME);
        r->data.aaaa.address = address->data.ipv6;
    }

    if (!r)
        return catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);

    a_entry = server_add_internal(s, g, interface, protocol, CATTA_PUBLISH_UNIQUE | CATTA_PUBLISH_ALLOW_MULTIPLE, r);
    catta_record_unref(r);

    if (!a_entry)
        return catta_server_errno(s);

    if (!(s_entry = server_add_dns_server_name(s, g, interface, protocol, flags, domain, type, n, port))) {
        if (!(flags & CATTA_PUBLISH_UPDATE))
            catta_entry_free(s, a_entry);
        return catta_server_errno(s);
    }

    return CATTA_OK;
}

void catta_s_entry_group_change_state(CattaSEntryGroup *g, CattaEntryGroupState state) {
    assert(g);

    if (g->state == state)
        return;

    assert(state <= CATTA_ENTRY_GROUP_COLLISION);

    if (g->state == CATTA_ENTRY_GROUP_ESTABLISHED) {

        /* If the entry group was established for a time longer then
         * 5s, reset the establishment trial counter */

        if (catta_age(&g->established_at) > 5000000)
            g->n_register_try = 0;
    } else if (g->state == CATTA_ENTRY_GROUP_REGISTERING) {
        if (g->register_time_event) {
            catta_time_event_free(g->register_time_event);
            g->register_time_event = NULL;
        }
    }

    if (state == CATTA_ENTRY_GROUP_ESTABLISHED)

        /* If the entry group is now established, remember the time
         * this happened */

        gettimeofday(&g->established_at, NULL);

    g->state = state;

    if (g->callback)
        g->callback(g->server, g, state, g->userdata);
}

CattaSEntryGroup *catta_s_entry_group_new(CattaServer *s, CattaSEntryGroupCallback callback, void* userdata) {
    CattaSEntryGroup *g;

    assert(s);

    if (!(g = catta_new(CattaSEntryGroup, 1))) {
        catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);
        return NULL;
    }

    g->server = s;
    g->callback = callback;
    g->userdata = userdata;
    g->dead = 0;
    g->state = CATTA_ENTRY_GROUP_UNCOMMITED;
    g->n_probing = 0;
    g->n_register_try = 0;
    g->register_time_event = NULL;
    g->register_time.tv_sec = 0;
    g->register_time.tv_usec = 0;
    CATTA_LLIST_HEAD_INIT(CattaEntry, g->entries);

    CATTA_LLIST_PREPEND(CattaSEntryGroup, groups, s->groups, g);
    return g;
}

static void cleanup_time_event_callback(CATTA_GCC_UNUSED CattaTimeEvent *e, void* userdata) {
    CattaServer *s = userdata;

    assert(s);

    catta_cleanup_dead_entries(s);
}

static void schedule_cleanup(CattaServer *s) {
    struct timeval tv;

    assert(s);

    if (!s->cleanup_time_event)
        s->cleanup_time_event = catta_time_event_new(s->time_event_queue, catta_elapse_time(&tv, 1000, 0), &cleanup_time_event_callback, s);
}

void catta_s_entry_group_free(CattaSEntryGroup *g) {
    CattaEntry *e;

    assert(g);
    assert(g->server);

    for (e = g->entries; e; e = e->by_group_next) {
        if (!e->dead) {
            catta_goodbye_entry(g->server, e, 1, 1);
            e->dead = 1;
        }
    }

    if (g->register_time_event) {
        catta_time_event_free(g->register_time_event);
        g->register_time_event = NULL;
    }

    g->dead = 1;

    g->server->need_group_cleanup = 1;
    g->server->need_entry_cleanup = 1;

    schedule_cleanup(g->server);
}

static void entry_group_commit_real(CattaSEntryGroup *g) {
    assert(g);

    gettimeofday(&g->register_time, NULL);

    catta_s_entry_group_change_state(g, CATTA_ENTRY_GROUP_REGISTERING);

    if (g->dead)
        return;

    catta_announce_group(g->server, g);
    catta_s_entry_group_check_probed(g, 0);
}

static void entry_group_register_time_event_callback(CATTA_GCC_UNUSED CattaTimeEvent *e, void* userdata) {
    CattaSEntryGroup *g = userdata;
    assert(g);

    catta_time_event_free(g->register_time_event);
    g->register_time_event = NULL;

    /* Holdoff time passed, so let's start probing */
    entry_group_commit_real(g);
}

int catta_s_entry_group_commit(CattaSEntryGroup *g) {
    struct timeval now;

    assert(g);
    assert(!g->dead);

    if (g->state != CATTA_ENTRY_GROUP_UNCOMMITED && g->state != CATTA_ENTRY_GROUP_COLLISION)
        return catta_server_set_errno(g->server, CATTA_ERR_BAD_STATE);

    if (catta_s_entry_group_is_empty(g))
        return catta_server_set_errno(g->server, CATTA_ERR_IS_EMPTY);

    g->n_register_try++;

    catta_timeval_add(&g->register_time,
                      1000*(g->n_register_try >= CATTA_RR_RATE_LIMIT_COUNT ?
                            CATTA_RR_HOLDOFF_MSEC_RATE_LIMIT :
                            CATTA_RR_HOLDOFF_MSEC));

    gettimeofday(&now, NULL);

    if (catta_timeval_compare(&g->register_time, &now) <= 0) {

        /* Holdoff time passed, so let's start probing */
        entry_group_commit_real(g);
    } else {

         /* Holdoff time has not yet passed, so let's wait */
        assert(!g->register_time_event);
        g->register_time_event = catta_time_event_new(g->server->time_event_queue, &g->register_time, entry_group_register_time_event_callback, g);

        catta_s_entry_group_change_state(g, CATTA_ENTRY_GROUP_REGISTERING);
    }

    return CATTA_OK;
}

void catta_s_entry_group_reset(CattaSEntryGroup *g) {
    CattaEntry *e;
    assert(g);

    for (e = g->entries; e; e = e->by_group_next) {
        if (!e->dead) {
            catta_goodbye_entry(g->server, e, 1, 1);
            e->dead = 1;
        }
    }
    g->server->need_entry_cleanup = 1;

    g->n_probing = 0;

    catta_s_entry_group_change_state(g, CATTA_ENTRY_GROUP_UNCOMMITED);

    schedule_cleanup(g->server);
}

int catta_entry_is_commited(CattaEntry *e) {
    assert(e);
    assert(!e->dead);

    return !e->group ||
        e->group->state == CATTA_ENTRY_GROUP_REGISTERING ||
        e->group->state == CATTA_ENTRY_GROUP_ESTABLISHED;
}

CattaEntryGroupState catta_s_entry_group_get_state(CattaSEntryGroup *g) {
    assert(g);
    assert(!g->dead);

    return g->state;
}

void catta_s_entry_group_set_data(CattaSEntryGroup *g, void* userdata) {
    assert(g);

    g->userdata = userdata;
}

void* catta_s_entry_group_get_data(CattaSEntryGroup *g) {
    assert(g);

    return g->userdata;
}

int catta_s_entry_group_is_empty(CattaSEntryGroup *g) {
    CattaEntry *e;
    assert(g);

    /* Look for an entry that is not dead */
    for (e = g->entries; e; e = e->by_group_next)
        if (!e->dead)
            return 0;

    return 1;
}
