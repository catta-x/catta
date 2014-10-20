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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <catta/error.h>
#include <catta/malloc.h>
#include <catta/domain.h>
#include <catta/log.h>

#include "iface.h"
#include "dns.h"
#include "socket.h"
#include "announce.h"
#include "util.h"
#include "multicast-lookup.h"
#include "querier.h"

void catta_interface_address_update_rrs(CattaInterfaceAddress *a, int remove_rrs) {
    CattaInterfaceMonitor *m;

    assert(a);
    m = a->monitor;

    if (m->list_complete &&
        catta_interface_address_is_relevant(a) &&
        catta_interface_is_relevant(a->iface) &&
        !remove_rrs &&
        m->server->config.publish_addresses &&
        (m->server->state == CATTA_SERVER_RUNNING ||
        m->server->state == CATTA_SERVER_REGISTERING)) {

        /* Fill the entry group */
        if (!a->entry_group)
            a->entry_group = catta_s_entry_group_new(m->server, catta_host_rr_entry_group_callback, NULL);

        if (!a->entry_group) /* OOM */
            return;

        if (catta_s_entry_group_is_empty(a->entry_group)) {
            char t[CATTA_ADDRESS_STR_MAX];
            CattaProtocol p;

            p = (a->iface->protocol == CATTA_PROTO_INET && m->server->config.publish_a_on_ipv6) ||
                (a->iface->protocol == CATTA_PROTO_INET6 && m->server->config.publish_aaaa_on_ipv4) ? CATTA_PROTO_UNSPEC : a->iface->protocol;

            catta_address_snprint(t, sizeof(t), &a->address);
            catta_log_info("Registering new address record for %s on %s.%s.", t, a->iface->hardware->name, p == CATTA_PROTO_UNSPEC ? "*" : catta_proto_to_string(p));

            if (catta_server_add_address(m->server, a->entry_group, a->iface->hardware->index, p, m->server->config.publish_no_reverse ? CATTA_PUBLISH_NO_REVERSE : 0, NULL, &a->address) < 0) {
                catta_log_warn(__FILE__": catta_server_add_address() failed: %s", catta_strerror(m->server->error));
                catta_s_entry_group_free(a->entry_group);
                a->entry_group = NULL;
                return;
            }

            catta_s_entry_group_commit(a->entry_group);
        }
    } else {

        /* Clear the entry group */

        if (a->entry_group && !catta_s_entry_group_is_empty(a->entry_group)) {
            char t[CATTA_ADDRESS_STR_MAX];
            catta_address_snprint(t, sizeof(t), &a->address);

            catta_log_info("Withdrawing address record for %s on %s.", t, a->iface->hardware->name);

            if (catta_s_entry_group_get_state(a->entry_group) == CATTA_ENTRY_GROUP_REGISTERING &&
                m->server->state == CATTA_SERVER_REGISTERING)
                catta_server_decrease_host_rr_pending(m->server);

            catta_s_entry_group_reset(a->entry_group);
        }
    }
}

void catta_interface_update_rrs(CattaInterface *i, int remove_rrs) {
    CattaInterfaceAddress *a;

    assert(i);

    for (a = i->addresses; a; a = a->address_next)
        catta_interface_address_update_rrs(a, remove_rrs);
}

void catta_hw_interface_update_rrs(CattaHwInterface *hw, int remove_rrs) {
    CattaInterface *i;
    CattaInterfaceMonitor *m;

    assert(hw);
    m = hw->monitor;

    for (i = hw->interfaces; i; i = i->by_hardware_next)
        catta_interface_update_rrs(i, remove_rrs);

    if (m->list_complete &&
        !remove_rrs &&
        m->server->config.publish_workstation &&
        (m->server->state == CATTA_SERVER_RUNNING)) {

        if (!hw->entry_group)
            hw->entry_group = catta_s_entry_group_new(m->server, catta_host_rr_entry_group_callback, NULL);

        if (!hw->entry_group)
            return; /* OOM */

        if (catta_s_entry_group_is_empty(hw->entry_group)) {
            char name[CATTA_LABEL_MAX], unescaped[CATTA_LABEL_MAX], mac[256];
            const char *p = m->server->host_name;

            catta_unescape_label(&p, unescaped, sizeof(unescaped));
            catta_format_mac_address(mac, sizeof(mac), hw->mac_address, hw->mac_address_size);
            snprintf(name, sizeof(name), "%s [%s]", unescaped, mac);

            if (catta_server_add_service(m->server, hw->entry_group, hw->index, CATTA_PROTO_UNSPEC, 0, name, "_workstation._tcp", NULL, NULL, 9, NULL) < 0) {
                catta_log_warn(__FILE__": catta_server_add_service() failed: %s", catta_strerror(m->server->error));
                catta_s_entry_group_free(hw->entry_group);
                hw->entry_group = NULL;
            } else
                catta_s_entry_group_commit(hw->entry_group);
        }

    } else {

        if (hw->entry_group && !catta_s_entry_group_is_empty(hw->entry_group)) {

            catta_log_info("Withdrawing workstation service for %s.", hw->name);

            if (catta_s_entry_group_get_state(hw->entry_group) == CATTA_ENTRY_GROUP_REGISTERING &&
                m->server->state == CATTA_SERVER_REGISTERING)
                catta_server_decrease_host_rr_pending(m->server);

            catta_s_entry_group_reset(hw->entry_group);
        }
    }
}

void catta_interface_monitor_update_rrs(CattaInterfaceMonitor *m, int remove_rrs) {
    CattaHwInterface *hw;

    assert(m);

    for (hw = m->hw_interfaces; hw; hw = hw->hardware_next)
        catta_hw_interface_update_rrs(hw, remove_rrs);
}

static int interface_mdns_mcast_join(CattaInterface *i, int join) {
    char at[CATTA_ADDRESS_STR_MAX];
    int r;
    assert(i);

    if (!!join  == !!i->mcast_joined)
        return 0;

    if ((i->protocol == CATTA_PROTO_INET6 && i->monitor->server->fd_ipv6 < 0) ||
        (i->protocol == CATTA_PROTO_INET && i->monitor->server->fd_ipv4 < 0))
        return -1;

    if (join) {
        CattaInterfaceAddress *a;

        /* Look if there's an address with global scope */
        for (a = i->addresses; a; a = a->address_next)
            if (a->global_scope)
                break;

        /* No address with a global scope has been found, so let's use
         * any. */
        if (!a)
            a = i->addresses;

        /* Hmm, there is no address available. */
        if (!a)
            return -1;

        i->local_mcast_address = a->address;
    }

    catta_log_info("%s mDNS multicast group on interface %s.%s with address %s.",
                   join ? "Joining" : "Leaving",
                   i->hardware->name,
                   catta_proto_to_string(i->protocol),
                   catta_address_snprint(at, sizeof(at), &i->local_mcast_address));

    if (i->protocol == CATTA_PROTO_INET6)
        r = catta_mdns_mcast_join_ipv6(i->monitor->server->fd_ipv6, &i->local_mcast_address.data.ipv6, i->hardware->index, join);
    else {
        assert(i->protocol == CATTA_PROTO_INET);

        r = catta_mdns_mcast_join_ipv4(i->monitor->server->fd_ipv4, &i->local_mcast_address.data.ipv4, i->hardware->index, join);
    }

    if (r < 0)
        i->mcast_joined = 0;
    else
        i->mcast_joined = join;

    return 0;
}

static int interface_mdns_mcast_rejoin(CattaInterface *i) {
    CattaInterfaceAddress *a, *usable = NULL, *found = NULL;
    assert(i);

    if (!i->mcast_joined)
        return 0;

    /* Check whether old address we joined with is still available. If
     * not, rejoin using an other address. */

    for (a = i->addresses; a; a = a->address_next) {
        if (a->global_scope && !usable)
            usable = a;

        if (catta_address_cmp(&a->address, &i->local_mcast_address) == 0) {

            if (a->global_scope)
                /* No action necessary: the address still exists and
                 * has global scope. */
                return 0;

            found = a;
        }
    }

    if (found && !usable)
        /* No action necessary: the address still exists and no better one has been found */
        return 0;

    interface_mdns_mcast_join(i, 0);
    return interface_mdns_mcast_join(i, 1);
}

void catta_interface_address_free(CattaInterfaceAddress *a) {
    assert(a);
    assert(a->iface);

    catta_interface_address_update_rrs(a, 1);
    CATTA_LLIST_REMOVE(CattaInterfaceAddress, address, a->iface->addresses, a);

    if (a->entry_group)
        catta_s_entry_group_free(a->entry_group);

    interface_mdns_mcast_rejoin(a->iface);

    catta_free(a);
}

void catta_interface_free(CattaInterface *i, int send_goodbye) {
    assert(i);

    /* Handle goodbyes and remove announcers */
    catta_goodbye_interface(i->monitor->server, i, send_goodbye, 1);
    catta_response_scheduler_force(i->response_scheduler);
    assert(!i->announcers);

    if (i->mcast_joined)
        interface_mdns_mcast_join(i, 0);

    /* Remove queriers */
    catta_querier_free_all(i);
    catta_hashmap_free(i->queriers_by_key);

    /* Remove local RRs */
    catta_interface_update_rrs(i, 1);

    while (i->addresses)
        catta_interface_address_free(i->addresses);

    catta_response_scheduler_free(i->response_scheduler);
    catta_query_scheduler_free(i->query_scheduler);
    catta_probe_scheduler_free(i->probe_scheduler);
    catta_cache_free(i->cache);

    CATTA_LLIST_REMOVE(CattaInterface, iface, i->monitor->interfaces, i);
    CATTA_LLIST_REMOVE(CattaInterface, by_hardware, i->hardware->interfaces, i);

    catta_free(i);
}

void catta_hw_interface_free(CattaHwInterface *hw, int send_goodbye) {
    assert(hw);

    catta_hw_interface_update_rrs(hw, 1);

    while (hw->interfaces)
        catta_interface_free(hw->interfaces, send_goodbye);

    if (hw->entry_group)
        catta_s_entry_group_free(hw->entry_group);

    CATTA_LLIST_REMOVE(CattaHwInterface, hardware, hw->monitor->hw_interfaces, hw);
    catta_hashmap_remove(hw->monitor->hashmap, &hw->index);

    catta_free(hw->name);
    catta_free(hw);
}

CattaInterface* catta_interface_new(CattaInterfaceMonitor *m, CattaHwInterface *hw, CattaProtocol protocol) {
    CattaInterface *i;

    assert(m);
    assert(hw);
    assert(CATTA_PROTO_VALID(protocol));

    if (!(i = catta_new(CattaInterface, 1)))
        goto fail; /* OOM */

    i->monitor = m;
    i->hardware = hw;
    i->protocol = protocol;
    i->announcing = 0;
    i->mcast_joined = 0;

    CATTA_LLIST_HEAD_INIT(CattaInterfaceAddress, i->addresses);
    CATTA_LLIST_HEAD_INIT(CattaAnnouncer, i->announcers);

    CATTA_LLIST_HEAD_INIT(CattaQuerier, i->queriers);
    i->queriers_by_key = catta_hashmap_new((CattaHashFunc) catta_key_hash, (CattaEqualFunc) catta_key_equal, NULL, NULL);

    i->cache = catta_cache_new(m->server, i);
    i->response_scheduler = catta_response_scheduler_new(i);
    i->query_scheduler = catta_query_scheduler_new(i);
    i->probe_scheduler = catta_probe_scheduler_new(i);

    if (!i->cache || !i->response_scheduler || !i->query_scheduler || !i->probe_scheduler)
        goto fail; /* OOM */

    CATTA_LLIST_PREPEND(CattaInterface, by_hardware, hw->interfaces, i);
    CATTA_LLIST_PREPEND(CattaInterface, iface, m->interfaces, i);

    return i;

fail:

    if (i) {
        if (i->cache)
            catta_cache_free(i->cache);
        if (i->response_scheduler)
            catta_response_scheduler_free(i->response_scheduler);
        if (i->query_scheduler)
            catta_query_scheduler_free(i->query_scheduler);
        if (i->probe_scheduler)
            catta_probe_scheduler_free(i->probe_scheduler);
    }

    return NULL;
}

CattaHwInterface *catta_hw_interface_new(CattaInterfaceMonitor *m, CattaIfIndex idx) {
    CattaHwInterface *hw;

    assert(m);
    assert(CATTA_IF_VALID(idx));

    if  (!(hw = catta_new(CattaHwInterface, 1)))
        return NULL;

    hw->monitor = m;
    hw->name = NULL;
    hw->flags_ok = 0;
    hw->mtu = 1500;
    hw->index = idx;
    hw->mac_address_size = 0;
    hw->entry_group = NULL;
    hw->ratelimit_begin.tv_sec = 0;
    hw->ratelimit_begin.tv_usec = 0;
    hw->ratelimit_counter = 0;

    CATTA_LLIST_HEAD_INIT(CattaInterface, hw->interfaces);
    CATTA_LLIST_PREPEND(CattaHwInterface, hardware, m->hw_interfaces, hw);

    catta_hashmap_insert(m->hashmap, &hw->index, hw);

    if (m->server->fd_ipv4 >= 0 || m->server->config.publish_a_on_ipv6)
        catta_interface_new(m, hw, CATTA_PROTO_INET);
    if (m->server->fd_ipv6 >= 0 || m->server->config.publish_aaaa_on_ipv4)
        catta_interface_new(m, hw, CATTA_PROTO_INET6);

    return hw;
}

CattaInterfaceAddress *catta_interface_address_new(CattaInterfaceMonitor *m, CattaInterface *i, const CattaAddress *addr, unsigned prefix_len) {
    CattaInterfaceAddress *a;

    assert(m);
    assert(i);

    if (!(a = catta_new(CattaInterfaceAddress, 1)))
        return NULL;

    a->iface = i;
    a->monitor = m;
    a->address = *addr;
    a->prefix_len = prefix_len;
    a->global_scope = 0;
    a->deprecated = 0;
    a->entry_group = NULL;

    CATTA_LLIST_PREPEND(CattaInterfaceAddress, address, i->addresses, a);

    return a;
}

void catta_interface_check_relevant(CattaInterface *i) {
    int b;
    CattaInterfaceMonitor *m;

    assert(i);
    m = i->monitor;

    b = catta_interface_is_relevant(i);

    if (m->list_complete && b && !i->announcing) {
        interface_mdns_mcast_join(i, 1);

        if (i->mcast_joined) {
            catta_log_info("New relevant interface %s.%s for mDNS.", i->hardware->name, catta_proto_to_string(i->protocol));

            i->announcing = 1;
            catta_announce_interface(m->server, i);
            catta_multicast_lookup_engine_new_interface(m->server->multicast_lookup_engine, i);
        }

    } else if (!b && i->announcing) {
        catta_log_info("Interface %s.%s no longer relevant for mDNS.", i->hardware->name, catta_proto_to_string(i->protocol));

        interface_mdns_mcast_join(i, 0);

        catta_goodbye_interface(m->server, i, 0, 1);
        catta_querier_free_all(i);

        catta_response_scheduler_clear(i->response_scheduler);
        catta_query_scheduler_clear(i->query_scheduler);
        catta_probe_scheduler_clear(i->probe_scheduler);
        catta_cache_flush(i->cache);

        i->announcing = 0;

    } else
        interface_mdns_mcast_rejoin(i);
}

void catta_hw_interface_check_relevant(CattaHwInterface *hw) {
    CattaInterface *i;

    assert(hw);

    for (i = hw->interfaces; i; i = i->by_hardware_next)
        catta_interface_check_relevant(i);
}

void catta_interface_monitor_check_relevant(CattaInterfaceMonitor *m) {
    CattaInterface *i;

    assert(m);

    for (i = m->interfaces; i; i = i->iface_next)
        catta_interface_check_relevant(i);
}

CattaInterfaceMonitor *catta_interface_monitor_new(CattaServer *s) {
    CattaInterfaceMonitor *m = NULL;

    if (!(m = catta_new0(CattaInterfaceMonitor, 1)))
        return NULL; /* OOM */

    m->server = s;
    m->list_complete = 0;
    m->hashmap = catta_hashmap_new(catta_int_hash, catta_int_equal, NULL, NULL);

    CATTA_LLIST_HEAD_INIT(CattaInterface, m->interfaces);
    CATTA_LLIST_HEAD_INIT(CattaHwInterface, m->hw_interfaces);

    if (catta_interface_monitor_init_osdep(m) < 0)
        goto fail;

    return m;

fail:
    catta_interface_monitor_free(m);
    return NULL;
}

void catta_interface_monitor_free(CattaInterfaceMonitor *m) {
    assert(m);

    while (m->hw_interfaces)
        catta_hw_interface_free(m->hw_interfaces, 1);

    assert(!m->interfaces);

    catta_interface_monitor_free_osdep(m);

    if (m->hashmap)
        catta_hashmap_free(m->hashmap);

    catta_free(m);
}


CattaInterface* catta_interface_monitor_get_interface(CattaInterfaceMonitor *m, CattaIfIndex idx, CattaProtocol protocol) {
    CattaHwInterface *hw;
    CattaInterface *i;

    assert(m);
    assert(idx >= 0);
    assert(protocol != CATTA_PROTO_UNSPEC);

    if (!(hw = catta_interface_monitor_get_hw_interface(m, idx)))
        return NULL;

    for (i = hw->interfaces; i; i = i->by_hardware_next)
        if (i->protocol == protocol)
            return i;

    return NULL;
}

CattaHwInterface* catta_interface_monitor_get_hw_interface(CattaInterfaceMonitor *m, CattaIfIndex idx) {
    assert(m);
    assert(idx >= 0);

    return catta_hashmap_lookup(m->hashmap, &idx);
}

CattaInterfaceAddress* catta_interface_monitor_get_address(CattaInterfaceMonitor *m, CattaInterface *i, const CattaAddress *raddr) {
    CattaInterfaceAddress *ia;

    assert(m);
    assert(i);
    assert(raddr);

    for (ia = i->addresses; ia; ia = ia->address_next)
        if (catta_address_cmp(&ia->address, raddr) == 0)
            return ia;

    return NULL;
}

void catta_interface_send_packet_unicast(CattaInterface *i, CattaDnsPacket *p, const CattaAddress *a, uint16_t port) {
    assert(i);
    assert(p);

    if (!i->announcing)
        return;

    assert(!a || a->proto == i->protocol);

    if (i->monitor->server->config.ratelimit_interval > 0) {
        struct timeval now, end;

        gettimeofday(&now, NULL);

        end = i->hardware->ratelimit_begin;
        catta_timeval_add(&end, i->monitor->server->config.ratelimit_interval);

        if (i->hardware->ratelimit_begin.tv_sec <= 0 ||
            catta_timeval_compare(&end, &now) < 0) {

            i->hardware->ratelimit_begin = now;
            i->hardware->ratelimit_counter = 0;
        }

        if (i->hardware->ratelimit_counter > i->monitor->server->config.ratelimit_burst)
            return;

        i->hardware->ratelimit_counter++;
    }

    if (i->protocol == CATTA_PROTO_INET && i->monitor->server->fd_ipv4 >= 0)
        catta_send_dns_packet_ipv4(i->monitor->server->fd_ipv4, i->hardware->index, p, i->mcast_joined ? &i->local_mcast_address.data.ipv4 : NULL, a ? &a->data.ipv4 : NULL, port);
    else if (i->protocol == CATTA_PROTO_INET6 && i->monitor->server->fd_ipv6 >= 0)
        catta_send_dns_packet_ipv6(i->monitor->server->fd_ipv6, i->hardware->index, p, i->mcast_joined ? &i->local_mcast_address.data.ipv6 : NULL, a ? &a->data.ipv6 : NULL, port);
}

void catta_interface_send_packet(CattaInterface *i, CattaDnsPacket *p) {
    assert(i);
    assert(p);

    catta_interface_send_packet_unicast(i, p, NULL, 0);
}

int catta_interface_post_query(CattaInterface *i, CattaKey *key, int immediately, unsigned *ret_id) {
    assert(i);
    assert(key);

    if (!i->announcing)
        return 0;

    return catta_query_scheduler_post(i->query_scheduler, key, immediately, ret_id);
}

int catta_interface_withraw_query(CattaInterface *i, unsigned id) {

    return catta_query_scheduler_withdraw_by_id(i->query_scheduler, id);
}

int catta_interface_post_response(CattaInterface *i, CattaRecord *record, int flush_cache, const CattaAddress *querier, int immediately) {
    assert(i);
    assert(record);

    if (!i->announcing)
        return 0;

    return catta_response_scheduler_post(i->response_scheduler, record, flush_cache, querier, immediately);
}

int catta_interface_post_probe(CattaInterface *i, CattaRecord *record, int immediately) {
    assert(i);
    assert(record);

    if (!i->announcing)
        return 0;

    return catta_probe_scheduler_post(i->probe_scheduler, record, immediately);
}

int catta_dump_caches(CattaInterfaceMonitor *m, CattaDumpCallback callback, void* userdata) {
    CattaInterface *i;
    assert(m);

    for (i = m->interfaces; i; i = i->iface_next) {
        if (catta_interface_is_relevant(i)) {
            char ln[256];
            snprintf(ln, sizeof(ln), ";;; INTERFACE %s.%s ;;;", i->hardware->name, catta_proto_to_string(i->protocol));
            callback(ln, userdata);
            if (catta_cache_dump(i->cache, callback, userdata) < 0)
                return -1;
        }
    }

    return 0;
}

static int catta_interface_is_relevant_internal(CattaInterface *i) {
    CattaInterfaceAddress *a;

    assert(i);

    if (!i->hardware->flags_ok)
        return 0;

    for (a = i->addresses; a; a = a->address_next)
        if (catta_interface_address_is_relevant(a))
            return 1;

    return 0;
}

int catta_interface_is_relevant(CattaInterface *i) {
    CattaStringList *l;
    assert(i);

    for (l = i->monitor->server->config.deny_interfaces; l; l = l->next)
        if (strcasecmp((char*) l->text, i->hardware->name) == 0)
            return 0;

    if (i->monitor->server->config.allow_interfaces) {

        for (l = i->monitor->server->config.allow_interfaces; l; l = l->next)
            if (strcasecmp((char*) l->text, i->hardware->name) == 0)
                goto good;

        return 0;
    }

good:
    return catta_interface_is_relevant_internal(i);
}

int catta_interface_address_is_relevant(CattaInterfaceAddress *a) {
    CattaInterfaceAddress *b;
    assert(a);

    /* Publish public and non-deprecated IP addresses */
    if (a->global_scope && !a->deprecated)
        return 1;

    /* Publish link-local and deprecated IP addresses only if they are
     * the only ones on the link */
    for (b = a->iface->addresses; b; b = b->address_next) {
        if (b == a)
            continue;

        if (b->global_scope && !b->deprecated)
            return 0;
    }

    return 1;
}

int catta_interface_match(CattaInterface *i, CattaIfIndex idx, CattaProtocol protocol) {
    assert(i);

    if (idx != CATTA_IF_UNSPEC && idx != i->hardware->index)
        return 0;

    if (protocol != CATTA_PROTO_UNSPEC && protocol != i->protocol)
        return 0;

    return 1;
}

void catta_interface_monitor_walk(CattaInterfaceMonitor *m, CattaIfIndex iface, CattaProtocol protocol, CattaInterfaceMonitorWalkCallback callback, void* userdata) {
    assert(m);
    assert(callback);

    if (iface != CATTA_IF_UNSPEC) {
        if (protocol != CATTA_PROTO_UNSPEC) {
            CattaInterface *i;

            if ((i = catta_interface_monitor_get_interface(m, iface, protocol)))
                callback(m, i, userdata);

        } else {
            CattaHwInterface *hw;
            CattaInterface *i;

            if ((hw = catta_interface_monitor_get_hw_interface(m, iface)))
                for (i = hw->interfaces; i; i = i->by_hardware_next)
                    if (catta_interface_match(i, iface, protocol))
                        callback(m, i, userdata);
        }

    } else {
        CattaInterface *i;

        for (i = m->interfaces; i; i = i->iface_next)
            if (catta_interface_match(i, iface, protocol))
                callback(m, i, userdata);
    }
}


int catta_address_is_local(CattaInterfaceMonitor *m, const CattaAddress *a) {
    CattaInterface *i;
    CattaInterfaceAddress *ia;
    assert(m);
    assert(a);

    for (i = m->interfaces; i; i = i->iface_next)
        for (ia = i->addresses; ia; ia = ia->address_next)
            if (catta_address_cmp(a, &ia->address) == 0)
                return 1;

    return 0;
}

int catta_interface_address_on_link(CattaInterface *i, const CattaAddress *a) {
    CattaInterfaceAddress *ia;

    assert(i);
    assert(a);

    if (a->proto != i->protocol)
        return 0;

    for (ia = i->addresses; ia; ia = ia->address_next) {

        if (a->proto == CATTA_PROTO_INET) {
            uint32_t m;

            m = ~(((uint32_t) -1) >> ia->prefix_len);

            if ((ntohl(a->data.ipv4.address) & m) == (ntohl(ia->address.data.ipv4.address) & m))
                return 1;
        } else {
            unsigned j;
            unsigned char pl;
            assert(a->proto == CATTA_PROTO_INET6);

            pl = ia->prefix_len;

            for (j = 0; j < 16; j++) {
                uint8_t m;

                if (pl == 0)
                    return 1;

                if (pl >= 8) {
                    m = 0xFF;
                    pl -= 8;
                } else {
                    m = ~(0xFF >> pl);
                    pl = 0;
                }

                if ((a->data.ipv6.address[j] & m) != (ia->address.data.ipv6.address[j] & m))
                    break;
            }
        }
    }

    return 0;
}

int catta_interface_has_address(CattaInterfaceMonitor *m, CattaIfIndex iface, const CattaAddress *a) {
    CattaInterface *i;
    CattaInterfaceAddress *j;

    assert(m);
    assert(iface != CATTA_IF_UNSPEC);
    assert(a);

    if (!(i = catta_interface_monitor_get_interface(m, iface, a->proto)))
        return 0;

    for (j = i->addresses; j; j = j->address_next)
        if (catta_address_cmp(a, &j->address) == 0)
            return 1;

    return 0;
}

CattaIfIndex catta_find_interface_for_address(CattaInterfaceMonitor *m, const CattaAddress *a) {
    CattaInterface *i;
    assert(m);

    /* Some stupid OS don't support passing the interface index when a
     * packet is received. We have to work around that limitation by
     * looking for an interface that has the incoming address
     * attached. This is sometimes ambiguous, but we have to live with
     * it. */

    for (i = m->interfaces; i; i = i->iface_next) {
        CattaInterfaceAddress *ai;

        if (i->protocol != a->proto)
            continue;

        for (ai = i->addresses; ai; ai = ai->address_next)
            if (catta_address_cmp(a, &ai->address) == 0)
                return i->hardware->index;
    }

    return CATTA_IF_UNSPEC;
}
