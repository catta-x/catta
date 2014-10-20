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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include <catta/domain.h>
#include <catta/timeval.h>
#include <catta/malloc.h>
#include <catta/error.h>
#include <catta/log.h>

#include "internal.h"
#include "iface.h"
#include "socket.h"
#include "browse.h"
#include "util.h"
#include "dns-srv-rr.h"
#include "addr-util.h"
#include "domain-util.h"
#include "rr-util.h"

#define CATTA_DEFAULT_CACHE_ENTRIES_MAX 4096

static void enum_aux_records(CattaServer *s, CattaInterface *i, const char *name, uint16_t type, void (*callback)(CattaServer *s, CattaRecord *r, int flush_cache, void* userdata), void* userdata) {
    assert(s);
    assert(i);
    assert(name);
    assert(callback);

    if (type == CATTA_DNS_TYPE_ANY) {
        CattaEntry *e;

        for (e = s->entries; e; e = e->entries_next)
            if (!e->dead &&
                catta_entry_is_registered(s, e, i) &&
                e->record->key->clazz == CATTA_DNS_CLASS_IN &&
                catta_domain_equal(name, e->record->key->name))
                callback(s, e->record, e->flags & CATTA_PUBLISH_UNIQUE, userdata);

    } else {
        CattaEntry *e;
        CattaKey *k;

        if (!(k = catta_key_new(name, CATTA_DNS_CLASS_IN, type)))
            return; /** OOM */

        for (e = catta_hashmap_lookup(s->entries_by_key, k); e; e = e->by_key_next)
            if (!e->dead && catta_entry_is_registered(s, e, i))
                callback(s, e->record, e->flags & CATTA_PUBLISH_UNIQUE, userdata);

        catta_key_unref(k);
    }
}

void catta_server_enumerate_aux_records(CattaServer *s, CattaInterface *i, CattaRecord *r, void (*callback)(CattaServer *s, CattaRecord *r, int flush_cache, void* userdata), void* userdata) {
    assert(s);
    assert(i);
    assert(r);
    assert(callback);

    /* Call the specified callback far all records referenced by the one specified in *r */

    if (r->key->clazz == CATTA_DNS_CLASS_IN) {
        if (r->key->type == CATTA_DNS_TYPE_PTR) {
            enum_aux_records(s, i, r->data.ptr.name, CATTA_DNS_TYPE_SRV, callback, userdata);
            enum_aux_records(s, i, r->data.ptr.name, CATTA_DNS_TYPE_TXT, callback, userdata);
        } else if (r->key->type == CATTA_DNS_TYPE_SRV) {
            enum_aux_records(s, i, r->data.srv.name, CATTA_DNS_TYPE_A, callback, userdata);
            enum_aux_records(s, i, r->data.srv.name, CATTA_DNS_TYPE_AAAA, callback, userdata);
        } else if (r->key->type == CATTA_DNS_TYPE_CNAME)
            enum_aux_records(s, i, r->data.cname.name, CATTA_DNS_TYPE_ANY, callback, userdata);
    }
}

void catta_server_prepare_response(CattaServer *s, CattaInterface *i, CattaEntry *e, int unicast_response, int auxiliary) {
    assert(s);
    assert(i);
    assert(e);

    catta_record_list_push(s->record_list, e->record, e->flags & CATTA_PUBLISH_UNIQUE, unicast_response, auxiliary);
}

void catta_server_prepare_matching_responses(CattaServer *s, CattaInterface *i, CattaKey *k, int unicast_response) {
    assert(s);
    assert(i);
    assert(k);

    /* Push all records that match the specified key to the record list */

    if (catta_key_is_pattern(k)) {
        CattaEntry *e;

        /* Handle ANY query */

        for (e = s->entries; e; e = e->entries_next)
            if (!e->dead && catta_key_pattern_match(k, e->record->key) && catta_entry_is_registered(s, e, i))
                catta_server_prepare_response(s, i, e, unicast_response, 0);

    } else {
        CattaEntry *e;

        /* Handle all other queries */

        for (e = catta_hashmap_lookup(s->entries_by_key, k); e; e = e->by_key_next)
            if (!e->dead && catta_entry_is_registered(s, e, i))
                catta_server_prepare_response(s, i, e, unicast_response, 0);
    }

    /* Look for CNAME records */

    if ((k->clazz == CATTA_DNS_CLASS_IN || k->clazz == CATTA_DNS_CLASS_ANY)
        && k->type != CATTA_DNS_TYPE_CNAME && k->type != CATTA_DNS_TYPE_ANY) {

        CattaKey *cname_key;

        if (!(cname_key = catta_key_new(k->name, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_CNAME)))
            return;

        catta_server_prepare_matching_responses(s, i, cname_key, unicast_response);
        catta_key_unref(cname_key);
    }
}

static void withdraw_entry(CattaServer *s, CattaEntry *e) {
    assert(s);
    assert(e);

    /* Withdraw the specified entry, and if is part of an entry group,
     * put that into COLLISION state */

    if (e->dead)
        return;

    if (e->group) {
        CattaEntry *k;

        for (k = e->group->entries; k; k = k->by_group_next)
            if (!k->dead) {
                catta_goodbye_entry(s, k, 0, 1);
                k->dead = 1;
            }

        e->group->n_probing = 0;

        catta_s_entry_group_change_state(e->group, CATTA_ENTRY_GROUP_COLLISION);
    } else {
        catta_goodbye_entry(s, e, 0, 1);
        e->dead = 1;
    }

    s->need_entry_cleanup = 1;
}

static void withdraw_rrset(CattaServer *s, CattaKey *key) {
    CattaEntry *e;

    assert(s);
    assert(key);

    /* Withdraw an entry RRSset */

    for (e = catta_hashmap_lookup(s->entries_by_key, key); e; e = e->by_key_next)
        withdraw_entry(s, e);
}

static void incoming_probe(CattaServer *s, CattaRecord *record, CattaInterface *i) {
    CattaEntry *e, *n;
    int ours = 0, won = 0, lost = 0;

    assert(s);
    assert(record);
    assert(i);

    /* Handle incoming probes and check if they conflict our own probes */

    for (e = catta_hashmap_lookup(s->entries_by_key, record->key); e; e = n) {
        int cmp;
        n = e->by_key_next;

        if (e->dead)
            continue;

        if ((cmp = catta_record_lexicographical_compare(e->record, record)) == 0) {
            ours = 1;
            break;
        } else {

            if (catta_entry_is_probing(s, e, i)) {
                if (cmp > 0)
                    won = 1;
                else /* cmp < 0 */
                    lost = 1;
            }
        }
    }

    if (!ours) {
        char *t = catta_record_to_string(record);

        if (won)
            catta_log_debug("Received conflicting probe [%s]. Local host won.", t);
        else if (lost) {
            catta_log_debug("Received conflicting probe [%s]. Local host lost. Withdrawing.", t);
            withdraw_rrset(s, record->key);
        }

        catta_free(t);
    }
}

static int handle_conflict(CattaServer *s, CattaInterface *i, CattaRecord *record, int unique) {
    int valid = 1, ours = 0, conflict = 0, withdraw_immediately = 0;
    CattaEntry *e, *n, *conflicting_entry = NULL;

    assert(s);
    assert(i);
    assert(record);

    /* Check whether an incoming record conflicts with one of our own */

    for (e = catta_hashmap_lookup(s->entries_by_key, record->key); e; e = n) {
        n = e->by_key_next;

        if (e->dead)
            continue;

        /* Check if the incoming is a goodbye record */
        if (catta_record_is_goodbye(record)) {

            if (catta_record_equal_no_ttl(e->record, record)) {
                char *t;

                /* Refresh */
                t = catta_record_to_string(record);
                catta_log_debug("Received goodbye record for one of our records [%s]. Refreshing.", t);
                catta_server_prepare_matching_responses(s, i, e->record->key, 0);

                valid = 0;
                catta_free(t);
                break;
            }

            /* If the goodybe packet doesn't match one of our own RRs, we simply ignore it. */
            continue;
        }

        if (!(e->flags & CATTA_PUBLISH_UNIQUE) && !unique)
            continue;

        /* Either our entry or the other is intended to be unique, so let's check */

        if (catta_record_equal_no_ttl(e->record, record)) {
            ours = 1; /* We have an identical record, so this is no conflict */

            /* Check wheter there is a TTL conflict */
            if (record->ttl <= e->record->ttl/2 &&
                catta_entry_is_registered(s, e, i)) {
                char *t;
                /* Refresh */
                t = catta_record_to_string(record);

                catta_log_debug("Received record with bad TTL [%s]. Refreshing.", t);
                catta_server_prepare_matching_responses(s, i, e->record->key, 0);
                valid = 0;

                catta_free(t);
            }

            /* There's no need to check the other entries of this RRset */
            break;

        } else {

            if (catta_entry_is_registered(s, e, i)) {

                /* A conflict => we have to return to probe mode */
                conflict = 1;
                conflicting_entry = e;

            } else if (catta_entry_is_probing(s, e, i)) {

                /* We are currently registering a matching record, but
                 * someone else already claimed it, so let's
                 * withdraw */
                conflict = 1;
                withdraw_immediately = 1;
            }
        }
    }

    if (!ours && conflict) {
        char *t;

        valid = 0;

        t = catta_record_to_string(record);

        if (withdraw_immediately) {
            catta_log_debug("Received conflicting record [%s] with local record to be. Withdrawing.", t);
            withdraw_rrset(s, record->key);
        } else {
            assert(conflicting_entry);
            catta_log_debug("Received conflicting record [%s]. Resetting our record.", t);
            catta_entry_return_to_initial_state(s, conflicting_entry, i);

            /* Local unique records are returned to probing
             * state. Local shared records are reannounced. */
        }

        catta_free(t);
    }

    return valid;
}

static void append_aux_callback(CattaServer *s, CattaRecord *r, int flush_cache, void* userdata) {
    int *unicast_response = userdata;

    assert(s);
    assert(r);
    assert(unicast_response);

    catta_record_list_push(s->record_list, r, flush_cache, *unicast_response, 1);
}

static void append_aux_records_to_list(CattaServer *s, CattaInterface *i, CattaRecord *r, int unicast_response) {
    assert(s);
    assert(r);

    catta_server_enumerate_aux_records(s, i, r, append_aux_callback, &unicast_response);
}

void catta_server_generate_response(CattaServer *s, CattaInterface *i, CattaDnsPacket *p, const CattaAddress *a, uint16_t port, int legacy_unicast, int immediately) {

    assert(s);
    assert(i);
    assert(!legacy_unicast || (a && port > 0 && p));

    if (legacy_unicast) {
        CattaDnsPacket *reply;
        CattaRecord *r;

        if (!(reply = catta_dns_packet_new_reply(p, 512 + CATTA_DNS_PACKET_EXTRA_SIZE /* unicast DNS maximum packet size is 512 */ , 1, 1)))
            return; /* OOM */

        while ((r = catta_record_list_next(s->record_list, NULL, NULL, NULL))) {

            append_aux_records_to_list(s, i, r, 0);

            if (catta_dns_packet_append_record(reply, r, 0, 10))
                catta_dns_packet_inc_field(reply, CATTA_DNS_FIELD_ANCOUNT);
            else {
                char *t = catta_record_to_string(r);
                catta_log_warn("Record [%s] not fitting in legacy unicast packet, dropping.", t);
                catta_free(t);
            }

            catta_record_unref(r);
        }

        if (catta_dns_packet_get_field(reply, CATTA_DNS_FIELD_ANCOUNT) != 0)
            catta_interface_send_packet_unicast(i, reply, a, port);

        catta_dns_packet_free(reply);

    } else {
        int unicast_response, flush_cache, auxiliary;
        CattaDnsPacket *reply = NULL;
        CattaRecord *r;

        /* In case the query packet was truncated never respond
        immediately, because known answer suppression records might be
        contained in later packets */
        int tc = p && !!(catta_dns_packet_get_field(p, CATTA_DNS_FIELD_FLAGS) & CATTA_DNS_FLAG_TC);

        while ((r = catta_record_list_next(s->record_list, &flush_cache, &unicast_response, &auxiliary))) {

            int im = immediately;

            /* Only send the response immediately if it contains a
             * unique entry AND it is not in reply to a truncated
             * packet AND it is not an auxiliary record AND all other
             * responses for this record are unique too. */

            if (flush_cache && !tc && !auxiliary && catta_record_list_all_flush_cache(s->record_list))
                im = 1;

            if (!catta_interface_post_response(i, r, flush_cache, a, im) && unicast_response) {

                /* Due to some reasons the record has not been scheduled.
                 * The client requested an unicast response in that
                 * case. Therefore we prepare such a response */

                append_aux_records_to_list(s, i, r, unicast_response);

                for (;;) {

                    if (!reply) {
                        assert(p);

                        if (!(reply = catta_dns_packet_new_reply(p, i->hardware->mtu, 0, 0)))
                            break; /* OOM */
                    }

                    if (catta_dns_packet_append_record(reply, r, flush_cache, 0)) {

                        /* Appending this record succeeded, so incremeant
                         * the specific header field, and return to the caller */

                        catta_dns_packet_inc_field(reply, CATTA_DNS_FIELD_ANCOUNT);
                        break;
                    }

                    if (catta_dns_packet_get_field(reply, CATTA_DNS_FIELD_ANCOUNT) == 0) {
                        size_t size;

                        /* The record is too large for one packet, so create a larger packet */

                        catta_dns_packet_free(reply);
                        size = catta_record_get_estimate_size(r) + CATTA_DNS_PACKET_HEADER_SIZE;

                        if (!(reply = catta_dns_packet_new_reply(p, size + CATTA_DNS_PACKET_EXTRA_SIZE, 0, 1)))
                            break; /* OOM */

                        if (catta_dns_packet_append_record(reply, r, flush_cache, 0)) {

                            /* Appending this record succeeded, so incremeant
                             * the specific header field, and return to the caller */

                            catta_dns_packet_inc_field(reply, CATTA_DNS_FIELD_ANCOUNT);
                            break;

                        }  else {

                            /* We completely fucked up, there's
                             * nothing we can do. The RR just doesn't
                             * fit in. Let's ignore it. */

                            char *t;
                            catta_dns_packet_free(reply);
                            reply = NULL;
                            t = catta_record_to_string(r);
                            catta_log_warn("Record [%s] too large, doesn't fit in any packet!", t);
                            catta_free(t);
                            break;
                        }
                    }

                    /* Appending the record didn't succeeed, so let's send this packet, and create a new one */
                    catta_interface_send_packet_unicast(i, reply, a, port);
                    catta_dns_packet_free(reply);
                    reply = NULL;
                }
            }

            catta_record_unref(r);
        }

        if (reply) {
            if (catta_dns_packet_get_field(reply, CATTA_DNS_FIELD_ANCOUNT) != 0)
                catta_interface_send_packet_unicast(i, reply, a, port);
            catta_dns_packet_free(reply);
        }
    }

    catta_record_list_flush(s->record_list);
}

static void reflect_response(CattaServer *s, CattaInterface *i, CattaRecord *r, int flush_cache) {
    CattaInterface *j;

    assert(s);
    assert(i);
    assert(r);

    if (!s->config.enable_reflector)
        return;

    for (j = s->monitor->interfaces; j; j = j->iface_next)
        if (j != i && (s->config.reflect_ipv || j->protocol == i->protocol))
            catta_interface_post_response(j, r, flush_cache, NULL, 1);
}

static void* reflect_cache_walk_callback(CattaCache *c, CattaKey *pattern, CattaCacheEntry *e, void* userdata) {
    CattaServer *s = userdata;
    CattaRecord* r;

    assert(c);
    assert(pattern);
    assert(e);
    assert(s);

    /* Don't reflect cache entry with ipv6 link-local addresses. */
    r = e->record;
    if ((r->key->type == CATTA_DNS_TYPE_AAAA) &&
            (r->data.aaaa.address.address[0] == 0xFE) &&
            (r->data.aaaa.address.address[1] == 0x80))
      return NULL;

    catta_record_list_push(s->record_list, e->record, e->cache_flush, 0, 0);
    return NULL;
}

static void reflect_query(CattaServer *s, CattaInterface *i, CattaKey *k) {
    CattaInterface *j;

    assert(s);
    assert(i);
    assert(k);

    if (!s->config.enable_reflector)
        return;

    for (j = s->monitor->interfaces; j; j = j->iface_next)
        if (j != i && (s->config.reflect_ipv || j->protocol == i->protocol)) {
            /* Post the query to other networks */
            catta_interface_post_query(j, k, 1, NULL);

            /* Reply from caches of other network. This is needed to
             * "work around" known answer suppression. */

            catta_cache_walk(j->cache, k, reflect_cache_walk_callback, s);
        }
}

static void reflect_probe(CattaServer *s, CattaInterface *i, CattaRecord *r) {
    CattaInterface *j;

    assert(s);
    assert(i);
    assert(r);

    if (!s->config.enable_reflector)
        return;

    for (j = s->monitor->interfaces; j; j = j->iface_next)
        if (j != i && (s->config.reflect_ipv || j->protocol == i->protocol))
            catta_interface_post_probe(j, r, 1);
}

static void handle_query_packet(CattaServer *s, CattaDnsPacket *p, CattaInterface *i, const CattaAddress *a, uint16_t port, int legacy_unicast, int from_local_iface) {
    size_t n;
    int is_probe;

    assert(s);
    assert(p);
    assert(i);
    assert(a);

    assert(catta_record_list_is_empty(s->record_list));

    is_probe = catta_dns_packet_get_field(p, CATTA_DNS_FIELD_NSCOUNT) > 0;

    /* Handle the questions */
    for (n = catta_dns_packet_get_field(p, CATTA_DNS_FIELD_QDCOUNT); n > 0; n --) {
        CattaKey *key;
        int unicast_response = 0;

        if (!(key = catta_dns_packet_consume_key(p, &unicast_response))) {
            catta_log_warn(__FILE__": Packet too short or invalid while reading question key. (Maybe a UTF-8 problem?)");
            goto fail;
        }

        if (!legacy_unicast && !from_local_iface) {
            reflect_query(s, i, key);
            if (!unicast_response)
              catta_cache_start_poof(i->cache, key, a);
        }

        if (catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ANCOUNT) == 0 &&
            !(catta_dns_packet_get_field(p, CATTA_DNS_FIELD_FLAGS) & CATTA_DNS_FLAG_TC))
            /* Allow our own queries to be suppressed by incoming
             * queries only when they do not include known answers */
            catta_query_scheduler_incoming(i->query_scheduler, key);

        catta_server_prepare_matching_responses(s, i, key, unicast_response);
        catta_key_unref(key);
    }

    if (!legacy_unicast) {

        /* Known Answer Suppression */
        for (n = catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ANCOUNT); n > 0; n --) {
            CattaRecord *record;
            int unique = 0;

            if (!(record = catta_dns_packet_consume_record(p, &unique))) {
                catta_log_warn(__FILE__": Packet too short or invalid while reading known answer record. (Maybe a UTF-8 problem?)");
                goto fail;
            }

            catta_response_scheduler_suppress(i->response_scheduler, record, a);
            catta_record_list_drop(s->record_list, record);
            catta_cache_stop_poof(i->cache, record, a);

            catta_record_unref(record);
        }

        /* Probe record */
        for (n = catta_dns_packet_get_field(p, CATTA_DNS_FIELD_NSCOUNT); n > 0; n --) {
            CattaRecord *record;
            int unique = 0;

            if (!(record = catta_dns_packet_consume_record(p, &unique))) {
                catta_log_warn(__FILE__": Packet too short or invalid while reading probe record. (Maybe a UTF-8 problem?)");
                goto fail;
            }

            if (!catta_key_is_pattern(record->key)) {
                if (!from_local_iface)
                    reflect_probe(s, i, record);
                incoming_probe(s, record, i);
            }

            catta_record_unref(record);
        }
    }

    if (!catta_record_list_is_empty(s->record_list))
        catta_server_generate_response(s, i, p, a, port, legacy_unicast, is_probe);

    return;

fail:
    catta_record_list_flush(s->record_list);
}

static void handle_response_packet(CattaServer *s, CattaDnsPacket *p, CattaInterface *i, const CattaAddress *a, int from_local_iface) {
    unsigned n;

    assert(s);
    assert(p);
    assert(i);
    assert(a);

    for (n = catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ANCOUNT) +
             catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ARCOUNT); n > 0; n--) {
        CattaRecord *record;
        int cache_flush = 0;

        if (!(record = catta_dns_packet_consume_record(p, &cache_flush))) {
            catta_log_warn(__FILE__": Packet too short or invalid while reading response record. (Maybe a UTF-8 problem?)");
            break;
        }

        if (!catta_key_is_pattern(record->key)) {

            if (handle_conflict(s, i, record, cache_flush)) {
                if (!from_local_iface && !catta_record_is_link_local_address(record))
                    reflect_response(s, i, record, cache_flush);
                catta_cache_update(i->cache, record, cache_flush, a);
                catta_response_scheduler_incoming(i->response_scheduler, record, cache_flush);
            }
        }

        catta_record_unref(record);
    }

    /* If the incoming response contained a conflicting record, some
       records have been scheduled for sending. We need to flush them
       here. */
    if (!catta_record_list_is_empty(s->record_list))
        catta_server_generate_response(s, i, NULL, NULL, 0, 0, 1);
}

static CattaLegacyUnicastReflectSlot* allocate_slot(CattaServer *s) {
    unsigned n, idx = (unsigned) -1;
    CattaLegacyUnicastReflectSlot *slot;

    assert(s);

    if (!s->legacy_unicast_reflect_slots)
        s->legacy_unicast_reflect_slots = catta_new0(CattaLegacyUnicastReflectSlot*, CATTA_LEGACY_UNICAST_REFLECT_SLOTS_MAX);

    for (n = 0; n < CATTA_LEGACY_UNICAST_REFLECT_SLOTS_MAX; n++, s->legacy_unicast_reflect_id++) {
        idx = s->legacy_unicast_reflect_id % CATTA_LEGACY_UNICAST_REFLECT_SLOTS_MAX;

        if (!s->legacy_unicast_reflect_slots[idx])
            break;
    }

    if (idx == (unsigned) -1 || s->legacy_unicast_reflect_slots[idx])
        return NULL;

    if (!(slot = catta_new(CattaLegacyUnicastReflectSlot, 1)))
        return NULL; /* OOM */

    s->legacy_unicast_reflect_slots[idx] = slot;
    slot->id = s->legacy_unicast_reflect_id++;
    slot->server = s;

    return slot;
}

static void deallocate_slot(CattaServer *s, CattaLegacyUnicastReflectSlot *slot) {
    unsigned idx;

    assert(s);
    assert(slot);

    idx = slot->id % CATTA_LEGACY_UNICAST_REFLECT_SLOTS_MAX;

    assert(s->legacy_unicast_reflect_slots[idx] == slot);

    catta_time_event_free(slot->time_event);

    catta_free(slot);
    s->legacy_unicast_reflect_slots[idx] = NULL;
}

static void free_slots(CattaServer *s) {
    unsigned idx;
    assert(s);

    if (!s->legacy_unicast_reflect_slots)
        return;

    for (idx = 0; idx < CATTA_LEGACY_UNICAST_REFLECT_SLOTS_MAX; idx ++)
        if (s->legacy_unicast_reflect_slots[idx])
            deallocate_slot(s, s->legacy_unicast_reflect_slots[idx]);

    catta_free(s->legacy_unicast_reflect_slots);
    s->legacy_unicast_reflect_slots = NULL;
}

static CattaLegacyUnicastReflectSlot* find_slot(CattaServer *s, uint16_t id) {
    unsigned idx;

    assert(s);

    if (!s->legacy_unicast_reflect_slots)
        return NULL;

    idx = id % CATTA_LEGACY_UNICAST_REFLECT_SLOTS_MAX;

    if (!s->legacy_unicast_reflect_slots[idx] || s->legacy_unicast_reflect_slots[idx]->id != id)
        return NULL;

    return s->legacy_unicast_reflect_slots[idx];
}

static void legacy_unicast_reflect_slot_timeout(CattaTimeEvent *e, void *userdata) {
    CattaLegacyUnicastReflectSlot *slot = userdata;

    assert(e);
    assert(slot);
    assert(slot->time_event == e);

    deallocate_slot(slot->server, slot);
}

static void reflect_legacy_unicast_query_packet(CattaServer *s, CattaDnsPacket *p, CattaInterface *i, const CattaAddress *a, uint16_t port) {
    CattaLegacyUnicastReflectSlot *slot;
    CattaInterface *j;

    assert(s);
    assert(p);
    assert(i);
    assert(a);
    assert(port > 0);
    assert(i->protocol == a->proto);

    if (!s->config.enable_reflector)
        return;

    /* Reflecting legacy unicast queries is a little more complicated
       than reflecting normal queries, since we must route the
       responses back to the right client. Therefore we must store
       some information for finding the right client contact data for
       response packets. In contrast to normal queries legacy
       unicast query and response packets are reflected untouched and
       are not reassembled into larger packets */

    if (!(slot = allocate_slot(s))) {
        /* No slot available, we drop this legacy unicast query */
        catta_log_warn("No slot available for legacy unicast reflection, dropping query packet.");
        return;
    }

    slot->original_id = catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ID);
    slot->address = *a;
    slot->port = port;
    slot->iface = i->hardware->index;

    catta_elapse_time(&slot->elapse_time, 2000, 0);
    slot->time_event = catta_time_event_new(s->time_event_queue, &slot->elapse_time, legacy_unicast_reflect_slot_timeout, slot);

    /* Patch the packet with our new locally generatet id */
    catta_dns_packet_set_field(p, CATTA_DNS_FIELD_ID, slot->id);

    for (j = s->monitor->interfaces; j; j = j->iface_next)
        if (j->announcing &&
            j != i &&
            (s->config.reflect_ipv || j->protocol == i->protocol)) {

            if (j->protocol == CATTA_PROTO_INET && s->fd_legacy_unicast_ipv4 >= 0) {
                catta_send_dns_packet_ipv4(s->fd_legacy_unicast_ipv4, j->hardware->index, p, NULL, NULL, 0);
            } else if (j->protocol == CATTA_PROTO_INET6 && s->fd_legacy_unicast_ipv6 >= 0)
                catta_send_dns_packet_ipv6(s->fd_legacy_unicast_ipv6, j->hardware->index, p, NULL, NULL, 0);
        }

    /* Reset the id */
    catta_dns_packet_set_field(p, CATTA_DNS_FIELD_ID, slot->original_id);
}

static int originates_from_local_legacy_unicast_socket(CattaServer *s, const CattaAddress *address, uint16_t port) {
    assert(s);
    assert(address);
    assert(port > 0);

    if (!s->config.enable_reflector)
        return 0;

    if (!catta_address_is_local(s->monitor, address))
        return 0;

    if (address->proto == CATTA_PROTO_INET && s->fd_legacy_unicast_ipv4 >= 0) {
        struct sockaddr_in lsa;
        socklen_t l = sizeof(lsa);

        if (getsockname(s->fd_legacy_unicast_ipv4, (struct sockaddr*) &lsa, &l) != 0)
            catta_log_warn("getsockname(): %s", errnostrsocket());
        else
            return catta_port_from_sockaddr((struct sockaddr*) &lsa) == port;

    }

    if (address->proto == CATTA_PROTO_INET6 && s->fd_legacy_unicast_ipv6 >= 0) {
        struct sockaddr_in6 lsa;
        socklen_t l = sizeof(lsa);

        if (getsockname(s->fd_legacy_unicast_ipv6, (struct sockaddr*) &lsa, &l) != 0)
            catta_log_warn("getsockname(): %s", errnostrsocket());
        else
            return catta_port_from_sockaddr((struct sockaddr*) &lsa) == port;
    }

    return 0;
}

static int is_mdns_mcast_address(const CattaAddress *a) {
    CattaAddress b;
    assert(a);

    catta_address_parse(a->proto == CATTA_PROTO_INET ? CATTA_IPV4_MCAST_GROUP : CATTA_IPV6_MCAST_GROUP, a->proto, &b);
    return catta_address_cmp(a, &b) == 0;
}

static int originates_from_local_iface(CattaServer *s, CattaIfIndex iface, const CattaAddress *a, uint16_t port) {
    assert(s);
    assert(iface != CATTA_IF_UNSPEC);
    assert(a);

    /* If it isn't the MDNS port it can't be generated by us */
    if (port != CATTA_MDNS_PORT)
        return 0;

    return catta_interface_has_address(s->monitor, iface, a);
}

static void dispatch_packet(CattaServer *s, CattaDnsPacket *p, const CattaAddress *src_address, uint16_t port, const CattaAddress *dst_address, CattaIfIndex iface, int ttl) {
    CattaInterface *i;
    int from_local_iface = 0;

    assert(s);
    assert(p);
    assert(src_address);
    assert(dst_address);
    assert(iface > 0);
    assert(src_address->proto == dst_address->proto);

    if (!(i = catta_interface_monitor_get_interface(s->monitor, iface, src_address->proto))) {
        catta_log_warn("Received packet from unrecognized interface (%d).", iface);
        return;
    }
    if (!i->announcing) {
        catta_log_warn("Received packet from invalid interface %d (not announcing).", iface);
        return;
    }

    if (port <= 0) {
        /* This fixes RHBZ #475394 */
        catta_log_warn("Received packet from invalid source port %u.", (unsigned) port);
        return;
    }

    if (catta_address_is_ipv4_in_ipv6(src_address))
        /* This is an IPv4 address encapsulated in IPv6, so let's ignore it. */
        return;

    if (originates_from_local_legacy_unicast_socket(s, src_address, port))
        /* This originates from our local reflector, so let's ignore it */
        return;

    /* We don't want to reflect local traffic, so we check if this packet is generated locally. */
    if (s->config.enable_reflector)
        from_local_iface = originates_from_local_iface(s, iface, src_address, port);

    if (catta_dns_packet_check_valid_multicast(p) < 0) {
        catta_log_warn("Received invalid packet.");
        return;
    }

    if (catta_dns_packet_is_query(p)) {
        int legacy_unicast = 0;

        /* For queries EDNS0 might allow ARCOUNT != 0. We ignore the
         * AR section completely here, so far. Until the day we add
         * EDNS0 support. */

        if (port != CATTA_MDNS_PORT) {
            /* Legacy Unicast */

            if ((catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ANCOUNT) != 0 ||
                 catta_dns_packet_get_field(p, CATTA_DNS_FIELD_NSCOUNT) != 0)) {
                catta_log_warn("Invalid legacy unicast query packet.");
                return;
            }

            legacy_unicast = 1;
        }

        if (legacy_unicast)
            reflect_legacy_unicast_query_packet(s, p, i, src_address, port);

        handle_query_packet(s, p, i, src_address, port, legacy_unicast, from_local_iface);

    } else {
        char t[CATTA_ADDRESS_STR_MAX];

        if (port != CATTA_MDNS_PORT) {
            catta_log_warn("Received response from host %s with invalid source port %u on interface '%s.%i'", catta_address_snprint(t, sizeof(t), src_address), port, i->hardware->name, i->protocol);
            return;
        }

        if (ttl != 255 && s->config.check_response_ttl) {
            catta_log_warn("Received response from host %s with invalid TTL %u on interface '%s.%i'.", catta_address_snprint(t, sizeof(t), src_address), ttl, i->hardware->name, i->protocol);
            return;
        }

        if (!is_mdns_mcast_address(dst_address) &&
            !catta_interface_address_on_link(i, src_address)) {

            catta_log_warn("Received non-local response from host %s on interface '%s.%i'.", catta_address_snprint(t, sizeof(t), src_address), i->hardware->name, i->protocol);
            return;
        }

        if (catta_dns_packet_get_field(p, CATTA_DNS_FIELD_QDCOUNT) != 0 ||
            catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ANCOUNT) == 0 ||
            catta_dns_packet_get_field(p, CATTA_DNS_FIELD_NSCOUNT) != 0) {

            catta_log_warn("Invalid response packet from host %s.", catta_address_snprint(t, sizeof(t), src_address));
            return;
        }

        handle_response_packet(s, p, i, src_address, from_local_iface);
    }
}

static void dispatch_legacy_unicast_packet(CattaServer *s, CattaDnsPacket *p) {
    CattaInterface *j;
    CattaLegacyUnicastReflectSlot *slot;

    assert(s);
    assert(p);

    if (catta_dns_packet_check_valid(p) < 0 || catta_dns_packet_is_query(p)) {
        catta_log_warn("Received invalid packet.");
        return;
    }

    if (!(slot = find_slot(s, catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ID)))) {
        catta_log_warn("Received legacy unicast response with unknown id");
        return;
    }

    if (!(j = catta_interface_monitor_get_interface(s->monitor, slot->iface, slot->address.proto)) ||
        !j->announcing)
        return;

    /* Patch the original ID into this response */
    catta_dns_packet_set_field(p, CATTA_DNS_FIELD_ID, slot->original_id);

    /* Forward the response to the correct client */
    catta_interface_send_packet_unicast(j, p, &slot->address, slot->port);

    /* Undo changes to packet */
    catta_dns_packet_set_field(p, CATTA_DNS_FIELD_ID, slot->id);
}

static void mcast_socket_event(CattaWatch *w, int fd, CattaWatchEvent events, void *userdata) {
    CattaServer *s = userdata;
    CattaAddress dest, src;
    CattaDnsPacket *p = NULL;
    CattaIfIndex iface;
    uint16_t port;
    uint8_t ttl;

    assert(w);
    assert(fd >= 0);
    assert(events & CATTA_WATCH_IN);

    if (fd == s->fd_ipv4) {
        dest.proto = src.proto = CATTA_PROTO_INET;
        p = catta_recv_dns_packet_ipv4(s->fd_ipv4, &src.data.ipv4, &port, &dest.data.ipv4, &iface, &ttl);
    } else {
        assert(fd == s->fd_ipv6);
        dest.proto = src.proto = CATTA_PROTO_INET6;
        p = catta_recv_dns_packet_ipv6(s->fd_ipv6, &src.data.ipv6, &port, &dest.data.ipv6, &iface, &ttl);
    }

    if (p) {
        if (iface == CATTA_IF_UNSPEC)
            iface = catta_find_interface_for_address(s->monitor, &dest);

        if (iface != CATTA_IF_UNSPEC)
            dispatch_packet(s, p, &src, port, &dest, iface, ttl);
        else
            catta_log_error("Incoming packet received on address that isn't local.");

        catta_dns_packet_free(p);

        catta_cleanup_dead_entries(s);
    }
}

static void legacy_unicast_socket_event(CattaWatch *w, int fd, CattaWatchEvent events, void *userdata) {
    CattaServer *s = userdata;
    CattaDnsPacket *p = NULL;

    assert(w);
    assert(fd >= 0);
    assert(events & CATTA_WATCH_IN);

    if (fd == s->fd_legacy_unicast_ipv4)
        p = catta_recv_dns_packet_ipv4(s->fd_legacy_unicast_ipv4, NULL, NULL, NULL, NULL, NULL);
    else {
        assert(fd == s->fd_legacy_unicast_ipv6);
        p = catta_recv_dns_packet_ipv6(s->fd_legacy_unicast_ipv6, NULL, NULL, NULL, NULL, NULL);
    }

    if (p) {
        dispatch_legacy_unicast_packet(s, p);
        catta_dns_packet_free(p);

        catta_cleanup_dead_entries(s);
    }
}

static void server_set_state(CattaServer *s, CattaServerState state) {
    assert(s);

    if (s->state == state)
        return;

    s->state = state;

    catta_interface_monitor_update_rrs(s->monitor, 0);

    if (s->callback)
        s->callback(s, state, s->userdata);
}

static void withdraw_host_rrs(CattaServer *s) {
    assert(s);

    if (s->hinfo_entry_group)
        catta_s_entry_group_reset(s->hinfo_entry_group);

    if (s->browse_domain_entry_group)
        catta_s_entry_group_reset(s->browse_domain_entry_group);

    catta_interface_monitor_update_rrs(s->monitor, 1);
    s->n_host_rr_pending = 0;
}

void catta_server_decrease_host_rr_pending(CattaServer *s) {
    assert(s);

    assert(s->n_host_rr_pending > 0);

    if (--s->n_host_rr_pending == 0)
        server_set_state(s, CATTA_SERVER_RUNNING);
}

void catta_host_rr_entry_group_callback(CattaServer *s, CattaSEntryGroup *g, CattaEntryGroupState state, CATTA_GCC_UNUSED void *userdata) {
    assert(s);
    assert(g);

    if (state == CATTA_ENTRY_GROUP_REGISTERING &&
        s->state == CATTA_SERVER_REGISTERING)
        s->n_host_rr_pending ++;

    else if (state == CATTA_ENTRY_GROUP_COLLISION &&
        (s->state == CATTA_SERVER_REGISTERING || s->state == CATTA_SERVER_RUNNING)) {
        withdraw_host_rrs(s);
        server_set_state(s, CATTA_SERVER_COLLISION);

    } else if (state == CATTA_ENTRY_GROUP_ESTABLISHED &&
               s->state == CATTA_SERVER_REGISTERING)
        catta_server_decrease_host_rr_pending(s);
}

static void register_hinfo(CattaServer *s) {
    struct utsname utsname;
    CattaRecord *r;

    assert(s);

    if (!s->config.publish_hinfo)
        return;

    if (s->hinfo_entry_group)
        assert(catta_s_entry_group_is_empty(s->hinfo_entry_group));
    else
        s->hinfo_entry_group = catta_s_entry_group_new(s, catta_host_rr_entry_group_callback, NULL);

    if (!s->hinfo_entry_group) {
        catta_log_warn("Failed to create HINFO entry group: %s", catta_strerror(s->error));
        return;
    }

    /* Fill in HINFO rr */
    if ((r = catta_record_new_full(s->host_name_fqdn, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_HINFO, CATTA_DEFAULT_TTL_HOST_NAME))) {

        if (uname(&utsname) < 0)
            catta_log_warn("uname() failed: %s\n", catta_strerror(errno));
        else {

            r->data.hinfo.cpu = catta_strdup(catta_strup(utsname.machine));
            r->data.hinfo.os = catta_strdup(catta_strup(utsname.sysname));

            catta_log_info("Registering HINFO record with values '%s'/'%s'.", r->data.hinfo.cpu, r->data.hinfo.os);

            if (catta_server_add(s, s->hinfo_entry_group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, CATTA_PUBLISH_UNIQUE, r) < 0) {
                catta_log_warn("Failed to add HINFO RR: %s", catta_strerror(s->error));
                return;
            }
        }

        catta_record_unref(r);
    }

    if (catta_s_entry_group_commit(s->hinfo_entry_group) < 0)
        catta_log_warn("Failed to commit HINFO entry group: %s", catta_strerror(s->error));

}

static void register_localhost(CattaServer *s) {
    CattaAddress a;
    assert(s);

    /* Add localhost entries */
    catta_address_parse("127.0.0.1", CATTA_PROTO_INET, &a);
    catta_server_add_address(s, NULL, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, CATTA_PUBLISH_NO_PROBE|CATTA_PUBLISH_NO_ANNOUNCE, "localhost", &a);

    catta_address_parse("::1", CATTA_PROTO_INET6, &a);
    catta_server_add_address(s, NULL, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, CATTA_PUBLISH_NO_PROBE|CATTA_PUBLISH_NO_ANNOUNCE, "ip6-localhost", &a);
}

static void register_browse_domain(CattaServer *s) {
    assert(s);

    if (!s->config.publish_domain)
        return;

    if (catta_domain_equal(s->domain_name, "local"))
        return;

    if (s->browse_domain_entry_group)
        assert(catta_s_entry_group_is_empty(s->browse_domain_entry_group));
    else
        s->browse_domain_entry_group = catta_s_entry_group_new(s, NULL, NULL);

    if (!s->browse_domain_entry_group) {
        catta_log_warn("Failed to create browse domain entry group: %s", catta_strerror(s->error));
        return;
    }

    if (catta_server_add_ptr(s, s->browse_domain_entry_group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, 0, CATTA_DEFAULT_TTL, "b._dns-sd._udp.local", s->domain_name) < 0) {
        catta_log_warn("Failed to add browse domain RR: %s", catta_strerror(s->error));
        return;
    }

    if (catta_s_entry_group_commit(s->browse_domain_entry_group) < 0)
        catta_log_warn("Failed to commit browse domain entry group: %s", catta_strerror(s->error));
}

static void register_stuff(CattaServer *s) {
    assert(s);

    server_set_state(s, CATTA_SERVER_REGISTERING);
    s->n_host_rr_pending ++; /** Make sure that the state isn't changed tp CATTA_SERVER_RUNNING too early */

    register_hinfo(s);
    register_browse_domain(s);
    catta_interface_monitor_update_rrs(s->monitor, 0);

    assert(s->n_host_rr_pending > 0);
    s->n_host_rr_pending --;

    if (s->n_host_rr_pending == 0)
        server_set_state(s, CATTA_SERVER_RUNNING);
}

static void update_fqdn(CattaServer *s) {
    char *n;

    assert(s);
    assert(s->host_name);
    assert(s->domain_name);

    if (!(n = catta_strdup_printf("%s.%s", s->host_name, s->domain_name)))
        return; /* OOM */

    catta_free(s->host_name_fqdn);
    s->host_name_fqdn = n;
}

int catta_server_set_host_name(CattaServer *s, const char *host_name) {
    char *hn = NULL;
    assert(s);

    CATTA_CHECK_VALIDITY(s, !host_name || catta_is_valid_host_name(host_name), CATTA_ERR_INVALID_HOST_NAME);

    if (!host_name)
        hn = catta_get_host_name_strdup();
    else
        hn = catta_normalize_name_strdup(host_name);

    hn[strcspn(hn, ".")] = 0;

    if (catta_domain_equal(s->host_name, hn) && s->state != CATTA_SERVER_COLLISION) {
        catta_free(hn);
        return catta_server_set_errno(s, CATTA_ERR_NO_CHANGE);
    }

    withdraw_host_rrs(s);

    catta_free(s->host_name);
    s->host_name = hn;

    update_fqdn(s);

    register_stuff(s);
    return CATTA_OK;
}

int catta_server_set_domain_name(CattaServer *s, const char *domain_name) {
    char *dn = NULL;
    assert(s);

    CATTA_CHECK_VALIDITY(s, !domain_name || catta_is_valid_domain_name(domain_name), CATTA_ERR_INVALID_DOMAIN_NAME);

    if (!domain_name)
        dn = catta_strdup("local");
    else
        dn = catta_normalize_name_strdup(domain_name);

    if (catta_domain_equal(s->domain_name, domain_name)) {
        catta_free(dn);
        return catta_server_set_errno(s, CATTA_ERR_NO_CHANGE);
    }

    withdraw_host_rrs(s);

    catta_free(s->domain_name);
    s->domain_name = dn;
    update_fqdn(s);

    register_stuff(s);

    catta_free(dn);
    return CATTA_OK;
}

static int valid_server_config(const CattaServerConfig *sc) {
    CattaStringList *l;

    assert(sc);

    if (sc->n_wide_area_servers > CATTA_WIDE_AREA_SERVERS_MAX)
        return CATTA_ERR_INVALID_CONFIG;

    if (sc->host_name && !catta_is_valid_host_name(sc->host_name))
        return CATTA_ERR_INVALID_HOST_NAME;

    if (sc->domain_name && !catta_is_valid_domain_name(sc->domain_name))
        return CATTA_ERR_INVALID_DOMAIN_NAME;

    for (l = sc->browse_domains; l; l = l->next)
        if (!catta_is_valid_domain_name((char*) l->text))
            return CATTA_ERR_INVALID_DOMAIN_NAME;

    return CATTA_OK;
}

static int setup_sockets(CattaServer *s) {
    assert(s);

    s->fd_ipv4 = s->config.use_ipv4 ? catta_open_socket_ipv4(s->config.disallow_other_stacks) : -1;
    s->fd_ipv6 = s->config.use_ipv6 ? catta_open_socket_ipv6(s->config.disallow_other_stacks) : -1;

    if (s->fd_ipv6 < 0 && s->fd_ipv4 < 0)
        return CATTA_ERR_NO_NETWORK;

    if (s->fd_ipv4 < 0 && s->config.use_ipv4)
        catta_log_notice("Failed to create IPv4 socket, proceeding in IPv6 only mode");
    else if (s->fd_ipv6 < 0 && s->config.use_ipv6)
        catta_log_notice("Failed to create IPv6 socket, proceeding in IPv4 only mode");

    s->fd_legacy_unicast_ipv4 = s->fd_ipv4 >= 0 && s->config.enable_reflector ? catta_open_unicast_socket_ipv4() : -1;
    s->fd_legacy_unicast_ipv6 = s->fd_ipv6 >= 0 && s->config.enable_reflector ? catta_open_unicast_socket_ipv6() : -1;

    s->watch_ipv4 =
        s->watch_ipv6 =
        s->watch_legacy_unicast_ipv4 =
        s->watch_legacy_unicast_ipv6 = NULL;

    if (s->fd_ipv4 >= 0)
        s->watch_ipv4 = s->poll_api->watch_new(s->poll_api, s->fd_ipv4, CATTA_WATCH_IN, mcast_socket_event, s);
    if (s->fd_ipv6 >= 0)
        s->watch_ipv6 = s->poll_api->watch_new(s->poll_api, s->fd_ipv6, CATTA_WATCH_IN, mcast_socket_event, s);

    if (s->fd_legacy_unicast_ipv4 >= 0)
        s->watch_legacy_unicast_ipv4 = s->poll_api->watch_new(s->poll_api, s->fd_legacy_unicast_ipv4, CATTA_WATCH_IN, legacy_unicast_socket_event, s);
    if (s->fd_legacy_unicast_ipv6 >= 0)
        s->watch_legacy_unicast_ipv6 = s->poll_api->watch_new(s->poll_api, s->fd_legacy_unicast_ipv6, CATTA_WATCH_IN, legacy_unicast_socket_event, s);

    return 0;
}

CattaServer *catta_server_new(const CattaPoll *poll_api, const CattaServerConfig *sc, CattaServerCallback callback, void* userdata, int *error) {
    CattaServer *s;
    int e;

    if (sc && (e = valid_server_config(sc)) < 0) {
        if (error)
            *error = e;
        return NULL;
    }

    if (!(s = catta_new(CattaServer, 1))) {
        if (error)
            *error = CATTA_ERR_NO_MEMORY;

        return NULL;
    }

    s->poll_api = poll_api;

    if (sc)
        catta_server_config_copy(&s->config, sc);
    else
        catta_server_config_init(&s->config);

    winsock_init();  // on Windows, call WSAStartup; no-op on other platforms
    if ((e = setup_sockets(s)) < 0) {
        if (error)
            *error = e;

        catta_server_config_free(&s->config);
        catta_free(s);
        winsock_exit();

        return NULL;
    }

    s->n_host_rr_pending = 0;
    s->need_entry_cleanup = 0;
    s->need_group_cleanup = 0;
    s->need_browser_cleanup = 0;
    s->cleanup_time_event = NULL;
    s->hinfo_entry_group = NULL;
    s->browse_domain_entry_group = NULL;
    s->error = CATTA_OK;
    s->state = CATTA_SERVER_INVALID;

    s->callback = callback;
    s->userdata = userdata;

    s->time_event_queue = catta_time_event_queue_new(poll_api);

    s->entries_by_key = catta_hashmap_new((CattaHashFunc) catta_key_hash, (CattaEqualFunc) catta_key_equal, NULL, NULL);
    CATTA_LLIST_HEAD_INIT(CattaEntry, s->entries);
    CATTA_LLIST_HEAD_INIT(CattaGroup, s->groups);

    s->record_browser_hashmap = catta_hashmap_new((CattaHashFunc) catta_key_hash, (CattaEqualFunc) catta_key_equal, NULL, NULL);
    CATTA_LLIST_HEAD_INIT(CattaSRecordBrowser, s->record_browsers);
    CATTA_LLIST_HEAD_INIT(CattaSHostNameResolver, s->host_name_resolvers);
    CATTA_LLIST_HEAD_INIT(CattaSAddressResolver, s->address_resolvers);
    CATTA_LLIST_HEAD_INIT(CattaSDomainBrowser, s->domain_browsers);
    CATTA_LLIST_HEAD_INIT(CattaSServiceTypeBrowser, s->service_type_browsers);
    CATTA_LLIST_HEAD_INIT(CattaSServiceBrowser, s->service_browsers);
    CATTA_LLIST_HEAD_INIT(CattaSServiceResolver, s->service_resolvers);
    CATTA_LLIST_HEAD_INIT(CattaSDNSServerBrowser, s->dns_server_browsers);

    s->legacy_unicast_reflect_slots = NULL;
    s->legacy_unicast_reflect_id = 0;

    s->record_list = catta_record_list_new();

    /* Get host name */
    s->host_name = s->config.host_name ? catta_normalize_name_strdup(s->config.host_name) : catta_get_host_name_strdup();
    s->host_name[strcspn(s->host_name, ".")] = 0;
    s->domain_name = s->config.domain_name ? catta_normalize_name_strdup(s->config.domain_name) : catta_strdup("local");
    s->host_name_fqdn = NULL;
    update_fqdn(s);

    do {
        s->local_service_cookie = (uint32_t) rand() * (uint32_t) rand();
    } while (s->local_service_cookie == CATTA_SERVICE_COOKIE_INVALID);

    if (s->config.enable_wide_area) {
        s->wide_area_lookup_engine = catta_wide_area_engine_new(s);
        catta_wide_area_set_servers(s->wide_area_lookup_engine, s->config.wide_area_servers, s->config.n_wide_area_servers);
    } else
        s->wide_area_lookup_engine = NULL;

    s->multicast_lookup_engine = catta_multicast_lookup_engine_new(s);

    s->monitor = catta_interface_monitor_new(s);
    catta_interface_monitor_sync(s->monitor);

    register_localhost(s);
    register_stuff(s);

    return s;
}

void catta_server_free(CattaServer* s) {
    assert(s);

    /* Remove all browsers */

    while (s->dns_server_browsers)
        catta_s_dns_server_browser_free(s->dns_server_browsers);
    while (s->host_name_resolvers)
        catta_s_host_name_resolver_free(s->host_name_resolvers);
    while (s->address_resolvers)
        catta_s_address_resolver_free(s->address_resolvers);
    while (s->domain_browsers)
        catta_s_domain_browser_free(s->domain_browsers);
    while (s->service_type_browsers)
        catta_s_service_type_browser_free(s->service_type_browsers);
    while (s->service_browsers)
        catta_s_service_browser_free(s->service_browsers);
    while (s->service_resolvers)
        catta_s_service_resolver_free(s->service_resolvers);
    while (s->record_browsers)
        catta_s_record_browser_destroy(s->record_browsers);

    /* Remove all locally rgeistered stuff */

    while(s->entries)
        catta_entry_free(s, s->entries);

    catta_interface_monitor_free(s->monitor);

    while (s->groups)
        catta_entry_group_free(s, s->groups);

    free_slots(s);

    catta_hashmap_free(s->entries_by_key);
    catta_record_list_free(s->record_list);
    catta_hashmap_free(s->record_browser_hashmap);

    if (s->wide_area_lookup_engine)
        catta_wide_area_engine_free(s->wide_area_lookup_engine);
    catta_multicast_lookup_engine_free(s->multicast_lookup_engine);

    if (s->cleanup_time_event)
        catta_time_event_free(s->cleanup_time_event);

    catta_time_event_queue_free(s->time_event_queue);

    /* Free watches */

    if (s->watch_ipv4)
        s->poll_api->watch_free(s->watch_ipv4);
    if (s->watch_ipv6)
        s->poll_api->watch_free(s->watch_ipv6);

    if (s->watch_legacy_unicast_ipv4)
        s->poll_api->watch_free(s->watch_legacy_unicast_ipv4);
    if (s->watch_legacy_unicast_ipv6)
        s->poll_api->watch_free(s->watch_legacy_unicast_ipv6);

    /* Free sockets */

    if (s->fd_ipv4 >= 0)
        closesocket(s->fd_ipv4);
    if (s->fd_ipv6 >= 0)
        closesocket(s->fd_ipv6);

    if (s->fd_legacy_unicast_ipv4 >= 0)
        closesocket(s->fd_legacy_unicast_ipv4);
    if (s->fd_legacy_unicast_ipv6 >= 0)
        closesocket(s->fd_legacy_unicast_ipv6);

    /* Free other stuff */

    catta_free(s->host_name);
    catta_free(s->domain_name);
    catta_free(s->host_name_fqdn);

    catta_server_config_free(&s->config);

    catta_free(s);
    winsock_exit();  // on Windows, call WSACleanup(); no-op on other platforms
}

const char* catta_server_get_domain_name(CattaServer *s) {
    assert(s);

    return s->domain_name;
}

const char* catta_server_get_host_name(CattaServer *s) {
    assert(s);

    return s->host_name;
}

const char* catta_server_get_host_name_fqdn(CattaServer *s) {
    assert(s);

    return s->host_name_fqdn;
}

void* catta_server_get_data(CattaServer *s) {
    assert(s);

    return s->userdata;
}

void catta_server_set_data(CattaServer *s, void* userdata) {
    assert(s);

    s->userdata = userdata;
}

CattaServerState catta_server_get_state(CattaServer *s) {
    assert(s);

    return s->state;
}

CattaServerConfig* catta_server_config_init(CattaServerConfig *c) {
    assert(c);

    memset(c, 0, sizeof(CattaServerConfig));
    c->use_ipv6 = 1;
    c->use_ipv4 = 1;
    c->allow_interfaces = NULL;
    c->deny_interfaces = NULL;
    c->host_name = NULL;
    c->domain_name = NULL;
    c->check_response_ttl = 0;
    c->publish_hinfo = 0;
    c->publish_addresses = 1;
    c->publish_no_reverse = 0;
    c->publish_workstation = 0;
    c->publish_domain = 1;
    c->use_iff_running = 0;
    c->enable_reflector = 0;
    c->reflect_ipv = 0;
    c->add_service_cookie = 0;
    c->enable_wide_area = 0;
    c->n_wide_area_servers = 0;
    c->disallow_other_stacks = 0;
    c->browse_domains = NULL;
    c->disable_publishing = 0;
    c->allow_point_to_point = 0;
    c->publish_aaaa_on_ipv4 = 1;
    c->publish_a_on_ipv6 = 0;
    c->n_cache_entries_max = CATTA_DEFAULT_CACHE_ENTRIES_MAX;
    c->ratelimit_interval = 0;
    c->ratelimit_burst = 0;

    return c;
}

void catta_server_config_free(CattaServerConfig *c) {
    assert(c);

    catta_free(c->host_name);
    catta_free(c->domain_name);
    catta_string_list_free(c->browse_domains);
    catta_string_list_free(c->allow_interfaces);
    catta_string_list_free(c->deny_interfaces);
}

CattaServerConfig* catta_server_config_copy(CattaServerConfig *ret, const CattaServerConfig *c) {
    char *d = NULL, *h = NULL;
    CattaStringList *browse = NULL, *allow = NULL, *deny = NULL;
    assert(ret);
    assert(c);

    if (c->host_name)
        if (!(h = catta_strdup(c->host_name)))
            return NULL;

    if (c->domain_name)
        if (!(d = catta_strdup(c->domain_name))) {
            catta_free(h);
            return NULL;
        }

    if (!(browse = catta_string_list_copy(c->browse_domains)) && c->browse_domains) {
        catta_free(h);
        catta_free(d);
        return NULL;
    }

    if (!(allow = catta_string_list_copy(c->allow_interfaces)) && c->allow_interfaces) {
        catta_string_list_free(browse);
        catta_free(h);
        catta_free(d);
        return NULL;
    }

    if (!(deny = catta_string_list_copy(c->deny_interfaces)) && c->deny_interfaces) {
        catta_string_list_free(allow);
        catta_string_list_free(browse);
        catta_free(h);
        catta_free(d);
        return NULL;
    }

    *ret = *c;
    ret->host_name = h;
    ret->domain_name = d;
    ret->browse_domains = browse;
    ret->allow_interfaces = allow;
    ret->deny_interfaces = deny;

    return ret;
}

int catta_server_errno(CattaServer *s) {
    assert(s);

    return s->error;
}

/* Just for internal use */
int catta_server_set_errno(CattaServer *s, int error) {
    assert(s);

    return s->error = error;
}

uint32_t catta_server_get_local_service_cookie(CattaServer *s) {
    assert(s);

    return s->local_service_cookie;
}

static CattaEntry *find_entry(CattaServer *s, CattaIfIndex iface, CattaProtocol protocol, CattaKey *key) {
    CattaEntry *e;

    assert(s);
    assert(key);

    for (e = catta_hashmap_lookup(s->entries_by_key, key); e; e = e->by_key_next)

        if ((e->iface == iface || e->iface <= 0 || iface <= 0) &&
            (e->protocol == protocol || e->protocol == CATTA_PROTO_UNSPEC || protocol == CATTA_PROTO_UNSPEC) &&
            (!e->group || e->group->state == CATTA_ENTRY_GROUP_ESTABLISHED || e->group->state == CATTA_ENTRY_GROUP_REGISTERING))

            return e;

    return NULL;
}

int catta_server_get_group_of_service(CattaServer *s, CattaIfIndex iface, CattaProtocol protocol, const char *name, const char *type, const char *domain, CattaSEntryGroup** ret_group) {
    CattaKey *key = NULL;
    CattaEntry *e;
    int ret;
    char n[CATTA_DOMAIN_NAME_MAX];

    assert(s);
    assert(name);
    assert(type);
    assert(ret_group);

    CATTA_CHECK_VALIDITY(s, CATTA_IF_VALID(iface), CATTA_ERR_INVALID_INTERFACE);
    CATTA_CHECK_VALIDITY(s, CATTA_PROTO_VALID(protocol), CATTA_ERR_INVALID_PROTOCOL);
    CATTA_CHECK_VALIDITY(s, catta_is_valid_service_name(name), CATTA_ERR_INVALID_SERVICE_NAME);
    CATTA_CHECK_VALIDITY(s, catta_is_valid_service_type_strict(type), CATTA_ERR_INVALID_SERVICE_TYPE);
    CATTA_CHECK_VALIDITY(s, !domain || catta_is_valid_domain_name(domain), CATTA_ERR_INVALID_DOMAIN_NAME);

    if ((ret = catta_service_name_join(n, sizeof(n), name, type, domain) < 0))
        return catta_server_set_errno(s, ret);

    if (!(key = catta_key_new(n, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_SRV)))
        return catta_server_set_errno(s, CATTA_ERR_NO_MEMORY);

    e = find_entry(s, iface, protocol, key);
    catta_key_unref(key);

    if (e) {
        *ret_group = e->group;
        return CATTA_OK;
    }

    return catta_server_set_errno(s, CATTA_ERR_NOT_FOUND);
}

int catta_server_is_service_local(CattaServer *s, CattaIfIndex iface, CattaProtocol protocol, const char *name) {
    CattaKey *key = NULL;
    CattaEntry *e;

    assert(s);
    assert(name);

    if (!s->host_name_fqdn)
        return 0;

    if (!(key = catta_key_new(name, CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_SRV)))
        return 0;

    e = find_entry(s, iface, protocol, key);
    catta_key_unref(key);

    if (!e)
        return 0;

    return catta_domain_equal(s->host_name_fqdn, e->record->data.srv.name);
}

int catta_server_is_record_local(CattaServer *s, CattaIfIndex iface, CattaProtocol protocol, CattaRecord *record) {
    CattaEntry *e;

    assert(s);
    assert(record);

    for (e = catta_hashmap_lookup(s->entries_by_key, record->key); e; e = e->by_key_next)

        if ((e->iface == iface || e->iface <= 0 || iface <= 0) &&
            (e->protocol == protocol || e->protocol == CATTA_PROTO_UNSPEC || protocol == CATTA_PROTO_UNSPEC) &&
            (!e->group || e->group->state == CATTA_ENTRY_GROUP_ESTABLISHED || e->group->state == CATTA_ENTRY_GROUP_REGISTERING) &&
            catta_record_equal_no_ttl(record, e->record))
            return 1;

    return 0;
}

/** Set the wide area DNS servers */
int catta_server_set_wide_area_servers(CattaServer *s, const CattaAddress *a, unsigned n) {
    assert(s);

    if (!s->wide_area_lookup_engine)
        return catta_server_set_errno(s, CATTA_ERR_INVALID_CONFIG);

    catta_wide_area_set_servers(s->wide_area_lookup_engine, a, n);
    return CATTA_OK;
}

const CattaServerConfig* catta_server_get_config(CattaServer *s) {
    assert(s);

    return &s->config;
}

/** Set the browsing domains */
int catta_server_set_browse_domains(CattaServer *s, CattaStringList *domains) {
    CattaStringList *l;

    assert(s);

    for (l = s->config.browse_domains; l; l = l->next)
        if (!catta_is_valid_domain_name((char*) l->text))
            return catta_server_set_errno(s, CATTA_ERR_INVALID_DOMAIN_NAME);

    catta_string_list_free(s->config.browse_domains);
    s->config.browse_domains = catta_string_list_copy(domains);

    return CATTA_OK;
}
