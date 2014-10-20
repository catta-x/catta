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
#include <catta/error.h>
#include <catta/domain.h>

#include "querier.h"
#include <catta/log.h>

struct CattaQuerier {
    CattaInterface *iface;

    CattaKey *key;
    int n_used;

    unsigned sec_delay;

    CattaTimeEvent *time_event;

    struct timeval creation_time;

    unsigned post_id;
    int post_id_valid;

    CATTA_LLIST_FIELDS(CattaQuerier, queriers);
};

void catta_querier_free(CattaQuerier *q) {
    assert(q);

    CATTA_LLIST_REMOVE(CattaQuerier, queriers, q->iface->queriers, q);
    catta_hashmap_remove(q->iface->queriers_by_key, q->key);

    catta_key_unref(q->key);
    catta_time_event_free(q->time_event);

    catta_free(q);
}

static void querier_elapse_callback(CATTA_GCC_UNUSED CattaTimeEvent *e, void *userdata) {
    CattaQuerier *q = userdata;
    struct timeval tv;

    assert(q);

    if (q->n_used <= 0) {

        /* We are not referenced by anyone anymore, so let's free
         * ourselves. We should not send out any further queries from
         * this querier object anymore. */

        catta_querier_free(q);
        return;
    }

    if (catta_interface_post_query(q->iface, q->key, 0, &q->post_id)) {

        /* The queue accepted our query. We store the query id here,
         * that allows us to drop the query at a later point if the
         * query is very short-lived. */

        q->post_id_valid = 1;
    }

    q->sec_delay *= 2;

    if (q->sec_delay >= 60*60)  /* 1h */
        q->sec_delay = 60*60;

    catta_elapse_time(&tv, q->sec_delay*1000, 0);
    catta_time_event_update(q->time_event, &tv);
}

void catta_querier_add(CattaInterface *i, CattaKey *key, struct timeval *ret_ctime) {
    CattaQuerier *q;
    struct timeval tv;

    assert(i);
    assert(key);

    if ((q = catta_hashmap_lookup(i->queriers_by_key, key))) {

        /* Someone is already browsing for records of this RR key */
        q->n_used++;

        /* Return the creation time. This is used for generating the
         * ALL_FOR_NOW event one second after the querier was
         * initially created. */
        if (ret_ctime)
            *ret_ctime = q->creation_time;
        return;
    }

    /* No one is browsing for this RR key, so we add a new querier */
    if (!(q = catta_new(CattaQuerier, 1)))
        return; /* OOM */

    q->key = catta_key_ref(key);
    q->iface = i;
    q->n_used = 1;
    q->sec_delay = 1;
    q->post_id_valid = 0;
    gettimeofday(&q->creation_time, NULL);

    /* Do the initial query */
    if (catta_interface_post_query(i, key, 0, &q->post_id))
        q->post_id_valid = 1;

    /* Schedule next queries */
    q->time_event = catta_time_event_new(i->monitor->server->time_event_queue, catta_elapse_time(&tv, q->sec_delay*1000, 0), querier_elapse_callback, q);

    CATTA_LLIST_PREPEND(CattaQuerier, queriers, i->queriers, q);
    catta_hashmap_insert(i->queriers_by_key, q->key, q);

    /* Return the creation time. This is used for generating the
     * ALL_FOR_NOW event one second after the querier was initially
     * created. */
    if (ret_ctime)
        *ret_ctime = q->creation_time;
}

void catta_querier_remove(CattaInterface *i, CattaKey *key) {
    CattaQuerier *q;

    /* There was no querier for this RR key, or it wasn't referenced
     * by anyone. */
    if (!(q = catta_hashmap_lookup(i->queriers_by_key, key)) || q->n_used <= 0)
        return;

    if ((--q->n_used) <= 0) {

        /* Nobody references us anymore. */

        if (q->post_id_valid && catta_interface_withraw_query(i, q->post_id)) {

            /* We succeeded in withdrawing our query from the queue,
             * so let's drop dead. */

            catta_querier_free(q);
        }

        /* If we failed to withdraw our query from the queue, we stay
         * alive, in case someone else might recycle our querier at a
         * later point. We are freed at our next expiry, in case
         * nobody recycled us. */
    }
}

static void remove_querier_callback(CattaInterfaceMonitor *m, CattaInterface *i, void* userdata) {
    assert(m);
    assert(i);
    assert(userdata);

    if (i->announcing)
        catta_querier_remove(i, (CattaKey*) userdata);
}

void catta_querier_remove_for_all(CattaServer *s, CattaIfIndex idx, CattaProtocol protocol, CattaKey *key) {
    assert(s);
    assert(key);

    catta_interface_monitor_walk(s->monitor, idx, protocol, remove_querier_callback, key);
}

struct cbdata {
    CattaKey *key;
    struct timeval *ret_ctime;
};

static void add_querier_callback(CattaInterfaceMonitor *m, CattaInterface *i, void* userdata) {
    struct cbdata *cbdata = userdata;

    assert(m);
    assert(i);
    assert(cbdata);

    if (i->announcing) {
        struct timeval tv;
        catta_querier_add(i, cbdata->key, &tv);

        if (cbdata->ret_ctime && catta_timeval_compare(&tv, cbdata->ret_ctime) > 0)
            *cbdata->ret_ctime = tv;
    }
}

void catta_querier_add_for_all(CattaServer *s, CattaIfIndex idx, CattaProtocol protocol, CattaKey *key, struct timeval *ret_ctime) {
    struct cbdata cbdata;

    assert(s);
    assert(key);

    cbdata.key = key;
    cbdata.ret_ctime = ret_ctime;

    if (ret_ctime)
        ret_ctime->tv_sec = ret_ctime->tv_usec = 0;

    catta_interface_monitor_walk(s->monitor, idx, protocol, add_querier_callback, &cbdata);
}

int catta_querier_shall_refresh_cache(CattaInterface *i, CattaKey *key) {
    CattaQuerier *q;

    assert(i);
    assert(key);

    /* Called by the cache maintainer */

    if (!(q = catta_hashmap_lookup(i->queriers_by_key, key)))
        /* This key is currently not subscribed at all, so no cache
         * refresh is needed */
        return 0;

    if (q->n_used <= 0) {

        /* If this is an entry nobody references right now, don't
         * consider it "existing". */

        /* Remove this querier since it is referenced by nobody
         * and the cached data will soon be out of date */
        catta_querier_free(q);

        /* Tell the cache that no refresh is needed */
        return 0;

    } else {
        struct timeval tv;

        /* We can defer our query a little, since the cache will now
         * issue a refresh query anyway. */
        catta_elapse_time(&tv, q->sec_delay*1000, 0);
        catta_time_event_update(q->time_event, &tv);

        /* Tell the cache that a refresh should be issued */
        return 1;
    }
}

void catta_querier_free_all(CattaInterface *i) {
    assert(i);

    while (i->queriers)
        catta_querier_free(i->queriers);
}
