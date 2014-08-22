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

#include "query-sched.h"
#include <catta/log.h>

#define CATTA_QUERY_HISTORY_MSEC 100
#define CATTA_QUERY_DEFER_MSEC 100

typedef struct CattaQueryJob CattaQueryJob;
typedef struct CattaKnownAnswer CattaKnownAnswer;

struct CattaQueryJob {
    unsigned id;
    int n_posted;

    CattaQueryScheduler *scheduler;
    CattaTimeEvent *time_event;

    int done;
    struct timeval delivery;

    CattaKey *key;

    /* Jobs are stored in a simple linked list. It might turn out in
     * the future that this list grows too long and we must switch to
     * some other kind of data structure. This needs further
     * investigation. I expect the list to be very short (< 20
     * entries) most of the time, but this might be a wrong
     * assumption, especially on setups where traffic reflection is
     * involved. */

    CATTA_LLIST_FIELDS(CattaQueryJob, jobs);
};

struct CattaKnownAnswer {
    CattaQueryScheduler *scheduler;
    CattaRecord *record;

    CATTA_LLIST_FIELDS(CattaKnownAnswer, known_answer);
};

struct CattaQueryScheduler {
    CattaInterface *interface;
    CattaTimeEventQueue *time_event_queue;

    unsigned next_id;

    CATTA_LLIST_HEAD(CattaQueryJob, jobs);
    CATTA_LLIST_HEAD(CattaQueryJob, history);
    CATTA_LLIST_HEAD(CattaKnownAnswer, known_answers);
};

static CattaQueryJob* job_new(CattaQueryScheduler *s, CattaKey *key, int done) {
    CattaQueryJob *qj;

    assert(s);
    assert(key);

    if (!(qj = catta_new(CattaQueryJob, 1))) {
        catta_log_error(__FILE__": Out of memory");
        return NULL;
    }

    qj->scheduler = s;
    qj->key = catta_key_ref(key);
    qj->time_event = NULL;
    qj->n_posted = 1;
    qj->id = s->next_id++;

    if ((qj->done = done))
        CATTA_LLIST_PREPEND(CattaQueryJob, jobs, s->history, qj);
    else
        CATTA_LLIST_PREPEND(CattaQueryJob, jobs, s->jobs, qj);

    return qj;
}

static void job_free(CattaQueryScheduler *s, CattaQueryJob *qj) {
    assert(s);
    assert(qj);

    if (qj->time_event)
        catta_time_event_free(qj->time_event);

    if (qj->done)
        CATTA_LLIST_REMOVE(CattaQueryJob, jobs, s->history, qj);
    else
        CATTA_LLIST_REMOVE(CattaQueryJob, jobs, s->jobs, qj);

    catta_key_unref(qj->key);
    catta_free(qj);
}

static void elapse_callback(CattaTimeEvent *e, void* data);

static void job_set_elapse_time(CattaQueryScheduler *s, CattaQueryJob *qj, unsigned msec, unsigned jitter) {
    struct timeval tv;

    assert(s);
    assert(qj);

    catta_elapse_time(&tv, msec, jitter);

    if (qj->time_event)
        catta_time_event_update(qj->time_event, &tv);
    else
        qj->time_event = catta_time_event_new(s->time_event_queue, &tv, elapse_callback, qj);
}

static void job_mark_done(CattaQueryScheduler *s, CattaQueryJob *qj) {
    assert(s);
    assert(qj);

    assert(!qj->done);

    CATTA_LLIST_REMOVE(CattaQueryJob, jobs, s->jobs, qj);
    CATTA_LLIST_PREPEND(CattaQueryJob, jobs, s->history, qj);

    qj->done = 1;

    job_set_elapse_time(s, qj, CATTA_QUERY_HISTORY_MSEC, 0);
    gettimeofday(&qj->delivery, NULL);
}

CattaQueryScheduler *catta_query_scheduler_new(CattaInterface *i) {
    CattaQueryScheduler *s;
    assert(i);

    if (!(s = catta_new(CattaQueryScheduler, 1))) {
        catta_log_error(__FILE__": Out of memory");
        return NULL; /* OOM */
    }

    s->interface = i;
    s->time_event_queue = i->monitor->server->time_event_queue;
    s->next_id = 0;

    CATTA_LLIST_HEAD_INIT(CattaQueryJob, s->jobs);
    CATTA_LLIST_HEAD_INIT(CattaQueryJob, s->history);
    CATTA_LLIST_HEAD_INIT(CattaKnownAnswer, s->known_answers);

    return s;
}

void catta_query_scheduler_free(CattaQueryScheduler *s) {
    assert(s);

    assert(!s->known_answers);
    catta_query_scheduler_clear(s);
    catta_free(s);
}

void catta_query_scheduler_clear(CattaQueryScheduler *s) {
    assert(s);

    while (s->jobs)
        job_free(s, s->jobs);
    while (s->history)
        job_free(s, s->history);
}

static void* known_answer_walk_callback(CattaCache *c, CattaKey *pattern, CattaCacheEntry *e, void* userdata) {
    CattaQueryScheduler *s = userdata;
    CattaKnownAnswer *ka;

    assert(c);
    assert(pattern);
    assert(e);
    assert(s);

    if (catta_cache_entry_half_ttl(c, e))
        return NULL;

    if (!(ka = catta_new0(CattaKnownAnswer, 1))) {
        catta_log_error(__FILE__": Out of memory");
        return NULL;
    }

    ka->scheduler = s;
    ka->record = catta_record_ref(e->record);

    CATTA_LLIST_PREPEND(CattaKnownAnswer, known_answer, s->known_answers, ka);
    return NULL;
}

static int packet_add_query_job(CattaQueryScheduler *s, CattaDnsPacket *p, CattaQueryJob *qj) {
    assert(s);
    assert(p);
    assert(qj);

    if (!catta_dns_packet_append_key(p, qj->key, 0))
        return 0;

    /* Add all matching known answers to the list */
    catta_cache_walk(s->interface->cache, qj->key, known_answer_walk_callback, s);

    job_mark_done(s, qj);

    return 1;
}

static void append_known_answers_and_send(CattaQueryScheduler *s, CattaDnsPacket *p) {
    CattaKnownAnswer *ka;
    unsigned n;
    assert(s);
    assert(p);

    n = 0;

    while ((ka = s->known_answers)) {
        int too_large = 0;

        while (!catta_dns_packet_append_record(p, ka->record, 0, 0)) {

            if (catta_dns_packet_is_empty(p)) {
                /* The record is too large to fit into one packet, so
                   there's no point in sending it. Better is letting
                   the owner of the record send it as a response. This
                   has the advantage of a cache refresh. */

                too_large = 1;
                break;
            }

            catta_dns_packet_set_field(p, CATTA_DNS_FIELD_FLAGS, catta_dns_packet_get_field(p, CATTA_DNS_FIELD_FLAGS) | CATTA_DNS_FLAG_TC);
            catta_dns_packet_set_field(p, CATTA_DNS_FIELD_ANCOUNT, n);
            catta_interface_send_packet(s->interface, p);
            catta_dns_packet_free(p);

            p = catta_dns_packet_new_query(s->interface->hardware->mtu);
            n = 0;
        }

        CATTA_LLIST_REMOVE(CattaKnownAnswer, known_answer, s->known_answers, ka);
        catta_record_unref(ka->record);
        catta_free(ka);

        if (!too_large)
            n++;
    }

    catta_dns_packet_set_field(p, CATTA_DNS_FIELD_ANCOUNT, n);
    catta_interface_send_packet(s->interface, p);
    catta_dns_packet_free(p);
}

static void elapse_callback(CATTA_GCC_UNUSED CattaTimeEvent *e, void* data) {
    CattaQueryJob *qj = data;
    CattaQueryScheduler *s;
    CattaDnsPacket *p;
    unsigned n;
    int b;

    assert(qj);
    s = qj->scheduler;

    if (qj->done) {
        /* Lets remove it  from the history */
        job_free(s, qj);
        return;
    }

    assert(!s->known_answers);

    if (!(p = catta_dns_packet_new_query(s->interface->hardware->mtu)))
        return; /* OOM */

    b = packet_add_query_job(s, p, qj);
    assert(b); /* An query must always fit in */
    n = 1;

    /* Try to fill up packet with more queries, if available */
    while (s->jobs) {

        if (!packet_add_query_job(s, p, s->jobs))
            break;

        n++;
    }

    catta_dns_packet_set_field(p, CATTA_DNS_FIELD_QDCOUNT, n);

    /* Now add known answers */
    append_known_answers_and_send(s, p);
}

static CattaQueryJob* find_scheduled_job(CattaQueryScheduler *s, CattaKey *key) {
    CattaQueryJob *qj;

    assert(s);
    assert(key);

    for (qj = s->jobs; qj; qj = qj->jobs_next) {
        assert(!qj->done);

        if (catta_key_equal(qj->key, key))
            return qj;
    }

    return NULL;
}

static CattaQueryJob* find_history_job(CattaQueryScheduler *s, CattaKey *key) {
    CattaQueryJob *qj;

    assert(s);
    assert(key);

    for (qj = s->history; qj; qj = qj->jobs_next) {
        assert(qj->done);

        if (catta_key_equal(qj->key, key)) {
            /* Check whether this entry is outdated */

            if (catta_age(&qj->delivery) > CATTA_QUERY_HISTORY_MSEC*1000) {
                /* it is outdated, so let's remove it */
                job_free(s, qj);
                return NULL;
            }

            return qj;
        }
    }

    return NULL;
}

int catta_query_scheduler_post(CattaQueryScheduler *s, CattaKey *key, int immediately, unsigned *ret_id) {
    struct timeval tv;
    CattaQueryJob *qj;

    assert(s);
    assert(key);

    if ((qj = find_history_job(s, key)))
        return 0;

    catta_elapse_time(&tv, immediately ? 0 : CATTA_QUERY_DEFER_MSEC, 0);

    if ((qj = find_scheduled_job(s, key))) {
        /* Duplicate questions suppression */

        if (catta_timeval_compare(&tv, &qj->delivery) < 0) {
            /* If the new entry should be scheduled earlier,
             * update the old entry */
            qj->delivery = tv;
            catta_time_event_update(qj->time_event, &qj->delivery);
        }

        qj->n_posted++;

    } else {

        if (!(qj = job_new(s, key, 0)))
            return 0; /* OOM */

        qj->delivery = tv;
        qj->time_event = catta_time_event_new(s->time_event_queue, &qj->delivery, elapse_callback, qj);
    }

    if (ret_id)
        *ret_id = qj->id;

    return 1;
}

void catta_query_scheduler_incoming(CattaQueryScheduler *s, CattaKey *key) {
    CattaQueryJob *qj;

    assert(s);
    assert(key);

    /* This function is called whenever an incoming query was
     * received. We drop scheduled queries that match. The keyword is
     * "DUPLICATE QUESTION SUPPRESION". */

    if ((qj = find_scheduled_job(s, key))) {
        job_mark_done(s, qj);
        return;
    }

    /* Look if there's a history job for this key. If there is, just
     * update the elapse time */
    if (!(qj = find_history_job(s, key)))
        if (!(qj = job_new(s, key, 1)))
            return; /* OOM */

    gettimeofday(&qj->delivery, NULL);
    job_set_elapse_time(s, qj, CATTA_QUERY_HISTORY_MSEC, 0);
}

int catta_query_scheduler_withdraw_by_id(CattaQueryScheduler *s, unsigned id) {
    CattaQueryJob *qj;

    assert(s);

    /* Very short lived queries can withdraw an already scheduled item
     * from the queue using this function, simply by passing the id
     * returned by catta_query_scheduler_post(). */

    for (qj = s->jobs; qj; qj = qj->jobs_next) {
        assert(!qj->done);

        if (qj->id == id) {
            /* Entry found */

            assert(qj->n_posted >= 1);

            if (--qj->n_posted <= 0) {

                /* We withdraw this job only if the calling object was
                 * the only remaining poster. (Usually this is the
                 * case since there should exist only one querier per
                 * key, but there are exceptions, notably reflected
                 * traffic.) */

                job_free(s, qj);
                return 1;
            }
        }
    }

    return 0;
}
