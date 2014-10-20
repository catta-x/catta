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

#include "announce.h"
#include <catta/log.h>
#include "rr-util.h"

#define CATTA_ANNOUNCEMENT_JITTER_MSEC 250
#define CATTA_PROBE_JITTER_MSEC 250
#define CATTA_PROBE_INTERVAL_MSEC 250

static void remove_announcer(CattaServer *s, CattaAnnouncer *a) {
    assert(s);
    assert(a);

    if (a->time_event)
        catta_time_event_free(a->time_event);

    CATTA_LLIST_REMOVE(CattaAnnouncer, by_interface, a->iface->announcers, a);
    CATTA_LLIST_REMOVE(CattaAnnouncer, by_entry, a->entry->announcers, a);

    catta_free(a);
}

static void elapse_announce(CattaTimeEvent *e, void *userdata);

static void set_timeout(CattaAnnouncer *a, const struct timeval *tv) {
    assert(a);

    if (!tv) {
        if (a->time_event) {
            catta_time_event_free(a->time_event);
            a->time_event = NULL;
        }
    } else {

        if (a->time_event)
            catta_time_event_update(a->time_event, tv);
        else
            a->time_event = catta_time_event_new(a->server->time_event_queue, tv, elapse_announce, a);
    }
}

static void next_state(CattaAnnouncer *a);

void catta_s_entry_group_check_probed(CattaSEntryGroup *g, int immediately) {
    CattaEntry *e;
    assert(g);
    assert(!g->dead);

    /* Check whether all group members have been probed */

    if (g->state != CATTA_ENTRY_GROUP_REGISTERING || g->n_probing > 0)
        return;

    catta_s_entry_group_change_state(g, CATTA_ENTRY_GROUP_ESTABLISHED);

    if (g->dead)
        return;

    for (e = g->entries; e; e = e->by_group_next) {
        CattaAnnouncer *a;

        for (a = e->announcers; a; a = a->by_entry_next) {

            if (a->state != CATTA_WAITING)
                continue;

            a->state = CATTA_ANNOUNCING;

            if (immediately) {
                /* Shortcut */

                a->n_iteration = 1;
                next_state(a);
            } else {
                struct timeval tv;
                a->n_iteration = 0;
                catta_elapse_time(&tv, 0, CATTA_ANNOUNCEMENT_JITTER_MSEC);
                set_timeout(a, &tv);
            }
        }
    }
}

static void next_state(CattaAnnouncer *a) {
    assert(a);

    if (a->state == CATTA_WAITING) {

        assert(a->entry->group);

        catta_s_entry_group_check_probed(a->entry->group, 1);

    } else if (a->state == CATTA_PROBING) {

        if (a->n_iteration >= 4) {
            /* Probing done */

            if (a->entry->group) {
                assert(a->entry->group->n_probing);
                a->entry->group->n_probing--;
            }

            if (a->entry->group && a->entry->group->state == CATTA_ENTRY_GROUP_REGISTERING)
                a->state = CATTA_WAITING;
            else {
                a->state = CATTA_ANNOUNCING;
                a->n_iteration = 1;
            }

            set_timeout(a, NULL);
            next_state(a);
        } else {
            struct timeval tv;

            catta_interface_post_probe(a->iface, a->entry->record, 0);

            catta_elapse_time(&tv, CATTA_PROBE_INTERVAL_MSEC, 0);
            set_timeout(a, &tv);

            a->n_iteration++;
        }

    } else if (a->state == CATTA_ANNOUNCING) {

        if (a->entry->flags & CATTA_PUBLISH_UNIQUE)
            /* Send the whole rrset at once */
            catta_server_prepare_matching_responses(a->server, a->iface, a->entry->record->key, 0);
        else
            catta_server_prepare_response(a->server, a->iface, a->entry, 0, 0);

        catta_server_generate_response(a->server, a->iface, NULL, NULL, 0, 0, 0);

        if (++a->n_iteration >= 4) {
            /* Announcing done */

            a->state = CATTA_ESTABLISHED;

            set_timeout(a, NULL);
        } else {
            struct timeval tv;
            catta_elapse_time(&tv, a->sec_delay*1000, CATTA_ANNOUNCEMENT_JITTER_MSEC);

            if (a->n_iteration < 10)
                a->sec_delay *= 2;

            set_timeout(a, &tv);
        }
    }
}

static void elapse_announce(CattaTimeEvent *e, void *userdata) {
    assert(e);

    next_state(userdata);
}

static CattaAnnouncer *get_announcer(CattaServer *s, CattaEntry *e, CattaInterface *i) {
    CattaAnnouncer *a;

    assert(s);
    assert(e);
    assert(i);

    for (a = e->announcers; a; a = a->by_entry_next)
        if (a->iface == i)
            return a;

    return NULL;
}

static void go_to_initial_state(CattaAnnouncer *a) {
    CattaEntry *e;
    struct timeval tv;

    assert(a);
    e = a->entry;

    if ((e->flags & CATTA_PUBLISH_UNIQUE) && !(e->flags & CATTA_PUBLISH_NO_PROBE))
        a->state = CATTA_PROBING;
    else if (!(e->flags & CATTA_PUBLISH_NO_ANNOUNCE)) {

        if (!e->group || e->group->state == CATTA_ENTRY_GROUP_ESTABLISHED)
            a->state = CATTA_ANNOUNCING;
        else
            a->state = CATTA_WAITING;

    } else
        a->state = CATTA_ESTABLISHED;

    a->n_iteration = 1;
    a->sec_delay = 1;

    if (a->state == CATTA_PROBING && e->group)
        e->group->n_probing++;

    if (a->state == CATTA_PROBING)
        set_timeout(a, catta_elapse_time(&tv, 0, CATTA_PROBE_JITTER_MSEC));
    else if (a->state == CATTA_ANNOUNCING)
        set_timeout(a, catta_elapse_time(&tv, 0, CATTA_ANNOUNCEMENT_JITTER_MSEC));
    else
        set_timeout(a, NULL);
}

static void new_announcer(CattaServer *s, CattaInterface *i, CattaEntry *e) {
    CattaAnnouncer *a;

    assert(s);
    assert(i);
    assert(e);
    assert(!e->dead);

    if (!catta_interface_match(i, e->iface, e->protocol) || !i->announcing || !catta_entry_is_commited(e))
        return;

    /* We don't want duplicate announcers */
    if (get_announcer(s, e, i))
        return;

    if ((!(a = catta_new(CattaAnnouncer, 1)))) {
        catta_log_error(__FILE__": Out of memory.");
        return;
    }

    a->server = s;
    a->iface = i;
    a->entry = e;
    a->time_event = NULL;

    CATTA_LLIST_PREPEND(CattaAnnouncer, by_interface, i->announcers, a);
    CATTA_LLIST_PREPEND(CattaAnnouncer, by_entry, e->announcers, a);

    go_to_initial_state(a);
}

void catta_announce_interface(CattaServer *s, CattaInterface *i) {
    CattaEntry *e;

    assert(s);
    assert(i);

    if (!i->announcing)
        return;

    for (e = s->entries; e; e = e->entries_next)
        if (!e->dead)
            new_announcer(s, i, e);
}

static void announce_walk_callback(CattaInterfaceMonitor *m, CattaInterface *i, void* userdata) {
    CattaEntry *e = userdata;

    assert(m);
    assert(i);
    assert(e);
    assert(!e->dead);

    new_announcer(m->server, i, e);
}

void catta_announce_entry(CattaServer *s, CattaEntry *e) {
    assert(s);
    assert(e);
    assert(!e->dead);

    catta_interface_monitor_walk(s->monitor, e->iface, e->protocol, announce_walk_callback, e);
}

void catta_announce_group(CattaServer *s, CattaSEntryGroup *g) {
    CattaEntry *e;

    assert(s);
    assert(g);

    for (e = g->entries; e; e = e->by_group_next)
        if (!e->dead)
            catta_announce_entry(s, e);
}

int catta_entry_is_registered(CattaServer *s, CattaEntry *e, CattaInterface *i) {
    CattaAnnouncer *a;

    assert(s);
    assert(e);
    assert(i);
    assert(!e->dead);

    if (!(a = get_announcer(s, e, i)))
        return 0;

    return
        a->state == CATTA_ANNOUNCING ||
        a->state == CATTA_ESTABLISHED ||
        (a->state == CATTA_WAITING && !(e->flags & CATTA_PUBLISH_UNIQUE));
}

int catta_entry_is_probing(CattaServer *s, CattaEntry *e, CattaInterface *i) {
    CattaAnnouncer *a;

    assert(s);
    assert(e);
    assert(i);
    assert(!e->dead);

    if (!(a = get_announcer(s, e, i)))
        return 0;

    return
        a->state == CATTA_PROBING ||
        (a->state == CATTA_WAITING && (e->flags & CATTA_PUBLISH_UNIQUE));
}

void catta_entry_return_to_initial_state(CattaServer *s, CattaEntry *e, CattaInterface *i) {
    CattaAnnouncer *a;

    assert(s);
    assert(e);
    assert(i);

    if (!(a = get_announcer(s, e, i)))
        return;

    if (a->state == CATTA_PROBING && a->entry->group)
        a->entry->group->n_probing--;

    go_to_initial_state(a);
}

static CattaRecord *make_goodbye_record(CattaRecord *r) {
    CattaRecord *g;

    assert(r);

    if (!(g = catta_record_copy(r)))
        return NULL; /* OOM */

    assert(g->ref == 1);
    g->ttl = 0;

    return g;
}

static int is_duplicate_entry(CattaServer *s, CattaEntry *e) {
    CattaEntry *i;

    assert(s);
    assert(e);

    for (i = catta_hashmap_lookup(s->entries_by_key, e->record->key); i; i = i->by_key_next) {

        if ((i == e) || (i->dead))
            continue;

        if (!catta_record_equal_no_ttl(i->record, e->record))
            continue;

        return 1;
    }

    return 0;
}

static void send_goodbye_callback(CattaInterfaceMonitor *m, CattaInterface *i, void* userdata) {
    CattaEntry *e = userdata;
    CattaRecord *g;

    assert(m);
    assert(i);
    assert(e);
    assert(!e->dead);

    if (!catta_interface_match(i, e->iface, e->protocol))
        return;

    if (e->flags & CATTA_PUBLISH_NO_ANNOUNCE)
        return;

    if (!catta_entry_is_registered(m->server, e, i))
        return;

    if (is_duplicate_entry(m->server, e))
        return;

    if (!(g = make_goodbye_record(e->record)))
        return; /* OOM */

    catta_interface_post_response(i, g, e->flags & CATTA_PUBLISH_UNIQUE, NULL, 1);
    catta_record_unref(g);
}

static void reannounce(CattaAnnouncer *a) {
    CattaEntry *e;
    struct timeval tv;

    assert(a);
    e = a->entry;

    /* If the group this entry belongs to is not even commited, there's nothing to reannounce */
    if (e->group && (e->group->state == CATTA_ENTRY_GROUP_UNCOMMITED || e->group->state == CATTA_ENTRY_GROUP_COLLISION))
        return;

    /* Because we might change state we decrease the probing counter first */
    if (a->state == CATTA_PROBING && a->entry->group)
        a->entry->group->n_probing--;

    if (a->state == CATTA_PROBING ||
        (a->state == CATTA_WAITING && (e->flags & CATTA_PUBLISH_UNIQUE) && !(e->flags & CATTA_PUBLISH_NO_PROBE)))

        /* We were probing or waiting after probe, so we restart probing from the beginning here */

        a->state = CATTA_PROBING;
    else if (a->state == CATTA_WAITING)

        /* We were waiting, but were not probing before, so we continue waiting  */
        a->state = CATTA_WAITING;

    else if (e->flags & CATTA_PUBLISH_NO_ANNOUNCE)

        /* No announcer needed */
        a->state = CATTA_ESTABLISHED;

    else {

        /* Ok, let's restart announcing */
        a->state = CATTA_ANNOUNCING;
    }

    /* Now let's increase the probing counter again */
    if (a->state == CATTA_PROBING && e->group)
        e->group->n_probing++;

    a->n_iteration = 1;
    a->sec_delay = 1;

    if (a->state == CATTA_PROBING)
        set_timeout(a, catta_elapse_time(&tv, 0, CATTA_PROBE_JITTER_MSEC));
    else if (a->state == CATTA_ANNOUNCING)
        set_timeout(a, catta_elapse_time(&tv, 0, CATTA_ANNOUNCEMENT_JITTER_MSEC));
    else
        set_timeout(a, NULL);
}


static void reannounce_walk_callback(CattaInterfaceMonitor *m, CattaInterface *i, void* userdata) {
    CattaEntry *e = userdata;
    CattaAnnouncer *a;

    assert(m);
    assert(i);
    assert(e);
    assert(!e->dead);

    if (!(a = get_announcer(m->server, e, i)))
        return;

    reannounce(a);
}

void catta_reannounce_entry(CattaServer *s, CattaEntry *e) {

    assert(s);
    assert(e);
    assert(!e->dead);

    catta_interface_monitor_walk(s->monitor, e->iface, e->protocol, reannounce_walk_callback, e);
}

void catta_goodbye_interface(CattaServer *s, CattaInterface *i, int send_goodbye, int remove) {
    assert(s);
    assert(i);

    if (send_goodbye)
        if (i->announcing) {
            CattaEntry *e;

            for (e = s->entries; e; e = e->entries_next)
                if (!e->dead)
                    send_goodbye_callback(s->monitor, i, e);
        }

    if (remove)
        while (i->announcers)
            remove_announcer(s, i->announcers);
}

void catta_goodbye_entry(CattaServer *s, CattaEntry *e, int send_goodbye, int remove) {
    assert(s);
    assert(e);

    if (send_goodbye)
        if (!e->dead)
            catta_interface_monitor_walk(s->monitor, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, send_goodbye_callback, e);

    if (remove)
        while (e->announcers)
            remove_announcer(s, e->announcers);
}

