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

#include <assert.h>
#include <stdlib.h>

#include <catta/timeval.h>
#include <catta/malloc.h>
#include <catta/log.h>

#include "timeeventq.h"

struct CattaTimeEvent {
    CattaTimeEventQueue *queue;
    CattaPrioQueueNode *node;
    struct timeval expiry;
    struct timeval last_run;
    CattaTimeEventCallback callback;
    void* userdata;
};

struct CattaTimeEventQueue {
    const CattaPoll *poll_api;
    CattaPrioQueue *prioq;
    CattaTimeout *timeout;
};

static int compare(const void* _a, const void* _b) {
    const CattaTimeEvent *a = _a,  *b = _b;
    int ret;

    if ((ret = catta_timeval_compare(&a->expiry, &b->expiry)) != 0)
        return ret;

    /* If both exevents are scheduled for the same time, put the entry
     * that has been run earlier the last time first. */
    return catta_timeval_compare(&a->last_run, &b->last_run);
}

static CattaTimeEvent* time_event_queue_root(CattaTimeEventQueue *q) {
    assert(q);

    return q->prioq->root ? q->prioq->root->data : NULL;
}

static void update_timeout(CattaTimeEventQueue *q) {
    CattaTimeEvent *e;
    assert(q);

    if ((e = time_event_queue_root(q)))
        q->poll_api->timeout_update(q->timeout, &e->expiry);
    else
        q->poll_api->timeout_update(q->timeout, NULL);
}

static void expiration_event(CATTA_GCC_UNUSED CattaTimeout *timeout, void *userdata) {
    CattaTimeEventQueue *q = userdata;
    CattaTimeEvent *e;

    if ((e = time_event_queue_root(q))) {
        struct timeval now;

        gettimeofday(&now, NULL);

        /* Check if expired */
        if (catta_timeval_compare(&now, &e->expiry) >= 0) {

            /* Make sure to move the entry away from the front */
            e->last_run = now;
            catta_prio_queue_shuffle(q->prioq, e->node);

            /* Run it */
            assert(e->callback);
            e->callback(e, e->userdata);

            update_timeout(q);
            return;
        }
    }

    catta_log_debug(__FILE__": Strange, expiration_event() called, but nothing really happened.");
    update_timeout(q);
}

static void fix_expiry_time(CattaTimeEvent *e) {
    struct timeval now;
    assert(e);

    return; /*** DO WE REALLY NEED THIS? ***/

    gettimeofday(&now, NULL);

    if (catta_timeval_compare(&now, &e->expiry) > 0)
        e->expiry = now;
}

CattaTimeEventQueue* catta_time_event_queue_new(const CattaPoll *poll_api) {
    CattaTimeEventQueue *q;

    if (!(q = catta_new(CattaTimeEventQueue, 1))) {
        catta_log_error(__FILE__": Out of memory");
        goto oom;
    }

    q->poll_api = poll_api;

    if (!(q->prioq = catta_prio_queue_new(compare)))
        goto oom;

    if (!(q->timeout = poll_api->timeout_new(poll_api, NULL, expiration_event, q)))
        goto oom;

    return q;

oom:

    if (q) {
        catta_free(q);

        if (q->prioq)
            catta_prio_queue_free(q->prioq);
    }

    return NULL;
}

void catta_time_event_queue_free(CattaTimeEventQueue *q) {
    CattaTimeEvent *e;

    assert(q);

    while ((e = time_event_queue_root(q)))
        catta_time_event_free(e);
    catta_prio_queue_free(q->prioq);

    q->poll_api->timeout_free(q->timeout);

    catta_free(q);
}

CattaTimeEvent* catta_time_event_new(
    CattaTimeEventQueue *q,
    const struct timeval *timeval,
    CattaTimeEventCallback callback,
    void* userdata) {

    CattaTimeEvent *e;

    assert(q);
    assert(callback);
    assert(userdata);

    if (!(e = catta_new(CattaTimeEvent, 1))) {
        catta_log_error(__FILE__": Out of memory");
        return NULL; /* OOM */
    }

    e->queue = q;
    e->callback = callback;
    e->userdata = userdata;

    if (timeval)
        e->expiry = *timeval;
    else {
        e->expiry.tv_sec = 0;
        e->expiry.tv_usec = 0;
    }

    fix_expiry_time(e);

    e->last_run.tv_sec = 0;
    e->last_run.tv_usec = 0;

    if (!(e->node = catta_prio_queue_put(q->prioq, e))) {
        catta_free(e);
        return NULL;
    }

    update_timeout(q);
    return e;
}

void catta_time_event_free(CattaTimeEvent *e) {
    CattaTimeEventQueue *q;
    assert(e);

    q = e->queue;

    catta_prio_queue_remove(q->prioq, e->node);
    catta_free(e);

    update_timeout(q);
}

void catta_time_event_update(CattaTimeEvent *e, const struct timeval *timeval) {
    assert(e);
    assert(timeval);

    e->expiry = *timeval;
    fix_expiry_time(e);
    catta_prio_queue_shuffle(e->queue->prioq, e->node);

    update_timeout(e->queue);
}

