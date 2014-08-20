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

#include "response-sched.h"
#include <catta/log.h>
#include "rr-util.h"

/* Local packets are supressed this long after sending them */
#define CATTA_RESPONSE_HISTORY_MSEC 500

/* Local packets are deferred this long before sending them */
#define CATTA_RESPONSE_DEFER_MSEC 20

/* Additional jitter for deferred packets */
#define CATTA_RESPONSE_JITTER_MSEC 100

/* Remote packets can suppress local traffic as long as this value */
#define CATTA_RESPONSE_SUPPRESS_MSEC 700

typedef struct CattaResponseJob CattaResponseJob;

typedef enum {
    CATTA_SCHEDULED,
    CATTA_DONE,
    CATTA_SUPPRESSED
} CattaResponseJobState;

struct CattaResponseJob {
    CattaResponseScheduler *scheduler;
    CattaTimeEvent *time_event;

    CattaResponseJobState state;
    struct timeval delivery;

    CattaRecord *record;
    int flush_cache;
    CattaAddress querier;
    int querier_valid;

    CATTA_LLIST_FIELDS(CattaResponseJob, jobs);
};

struct CattaResponseScheduler {
    CattaInterface *interface;
    CattaTimeEventQueue *time_event_queue;

    CATTA_LLIST_HEAD(CattaResponseJob, jobs);
    CATTA_LLIST_HEAD(CattaResponseJob, history);
    CATTA_LLIST_HEAD(CattaResponseJob, suppressed);
};

static CattaResponseJob* job_new(CattaResponseScheduler *s, CattaRecord *record, CattaResponseJobState state) {
    CattaResponseJob *rj;

    assert(s);
    assert(record);

    if (!(rj = catta_new(CattaResponseJob, 1))) {
        catta_log_error(__FILE__": Out of memory");
        return NULL;
    }

    rj->scheduler = s;
    rj->record = catta_record_ref(record);
    rj->time_event = NULL;
    rj->flush_cache = 0;
    rj->querier_valid = 0;

    if ((rj->state = state) == CATTA_SCHEDULED)
        CATTA_LLIST_PREPEND(CattaResponseJob, jobs, s->jobs, rj);
    else if (rj->state == CATTA_DONE)
        CATTA_LLIST_PREPEND(CattaResponseJob, jobs, s->history, rj);
    else  /* rj->state == CATTA_SUPPRESSED */
        CATTA_LLIST_PREPEND(CattaResponseJob, jobs, s->suppressed, rj);

    return rj;
}

static void job_free(CattaResponseScheduler *s, CattaResponseJob *rj) {
    assert(s);
    assert(rj);

    if (rj->time_event)
        catta_time_event_free(rj->time_event);

    if (rj->state == CATTA_SCHEDULED)
        CATTA_LLIST_REMOVE(CattaResponseJob, jobs, s->jobs, rj);
    else if (rj->state == CATTA_DONE)
        CATTA_LLIST_REMOVE(CattaResponseJob, jobs, s->history, rj);
    else /* rj->state == CATTA_SUPPRESSED */
        CATTA_LLIST_REMOVE(CattaResponseJob, jobs, s->suppressed, rj);

    catta_record_unref(rj->record);
    catta_free(rj);
}

static void elapse_callback(CattaTimeEvent *e, void* data);

static void job_set_elapse_time(CattaResponseScheduler *s, CattaResponseJob *rj, unsigned msec, unsigned jitter) {
    struct timeval tv;

    assert(s);
    assert(rj);

    catta_elapse_time(&tv, msec, jitter);

    if (rj->time_event)
        catta_time_event_update(rj->time_event, &tv);
    else
        rj->time_event = catta_time_event_new(s->time_event_queue, &tv, elapse_callback, rj);
}

static void job_mark_done(CattaResponseScheduler *s, CattaResponseJob *rj) {
    assert(s);
    assert(rj);

    assert(rj->state == CATTA_SCHEDULED);

    CATTA_LLIST_REMOVE(CattaResponseJob, jobs, s->jobs, rj);
    CATTA_LLIST_PREPEND(CattaResponseJob, jobs, s->history, rj);

    rj->state = CATTA_DONE;

    job_set_elapse_time(s, rj, CATTA_RESPONSE_HISTORY_MSEC, 0);

    gettimeofday(&rj->delivery, NULL);
}

CattaResponseScheduler *catta_response_scheduler_new(CattaInterface *i) {
    CattaResponseScheduler *s;
    assert(i);

    if (!(s = catta_new(CattaResponseScheduler, 1))) {
        catta_log_error(__FILE__": Out of memory");
        return NULL;
    }

    s->interface = i;
    s->time_event_queue = i->monitor->server->time_event_queue;

    CATTA_LLIST_HEAD_INIT(CattaResponseJob, s->jobs);
    CATTA_LLIST_HEAD_INIT(CattaResponseJob, s->history);
    CATTA_LLIST_HEAD_INIT(CattaResponseJob, s->suppressed);

    return s;
}

void catta_response_scheduler_free(CattaResponseScheduler *s) {
    assert(s);

    catta_response_scheduler_clear(s);
    catta_free(s);
}

void catta_response_scheduler_clear(CattaResponseScheduler *s) {
    assert(s);

    while (s->jobs)
        job_free(s, s->jobs);
    while (s->history)
        job_free(s, s->history);
    while (s->suppressed)
        job_free(s, s->suppressed);
}

static void enumerate_aux_records_callback(CATTA_GCC_UNUSED CattaServer *s, CattaRecord *r, int flush_cache, void* userdata) {
    CattaResponseJob *rj = userdata;

    assert(r);
    assert(rj);

    catta_response_scheduler_post(rj->scheduler, r, flush_cache, rj->querier_valid ? &rj->querier : NULL, 0);
}

static int packet_add_response_job(CattaResponseScheduler *s, CattaDnsPacket *p, CattaResponseJob *rj) {
    assert(s);
    assert(p);
    assert(rj);

    /* Try to add this record to the packet */
    if (!catta_dns_packet_append_record(p, rj->record, rj->flush_cache, 0))
        return 0;

    /* Ok, this record will definitely be sent, so schedule the
     * auxilliary packets, too */
    catta_server_enumerate_aux_records(s->interface->monitor->server, s->interface, rj->record, enumerate_aux_records_callback, rj);
    job_mark_done(s, rj);

    return 1;
}

static void send_response_packet(CattaResponseScheduler *s, CattaResponseJob *rj) {
    CattaDnsPacket *p;
    unsigned n;

    assert(s);
    assert(rj);

    if (!(p = catta_dns_packet_new_response(s->interface->hardware->mtu, 1)))
        return; /* OOM */
    n = 1;

    /* Put it in the packet. */
    if (packet_add_response_job(s, p, rj)) {

        /* Try to fill up packet with more responses, if available */
        while (s->jobs) {

            if (!packet_add_response_job(s, p, s->jobs))
                break;

            n++;
        }

    } else {
        size_t size;

        catta_dns_packet_free(p);

        /* OK, the packet was too small, so create one that fits */
        size = catta_record_get_estimate_size(rj->record) + CATTA_DNS_PACKET_HEADER_SIZE;

        if (!(p = catta_dns_packet_new_response(size + CATTA_DNS_PACKET_EXTRA_SIZE, 1)))
            return; /* OOM */

        if (!packet_add_response_job(s, p, rj)) {
            catta_dns_packet_free(p);

            catta_log_warn("Record too large, cannot send");
            job_mark_done(s, rj);
            return;
        }
    }

    catta_dns_packet_set_field(p, CATTA_DNS_FIELD_ANCOUNT, n);
    catta_interface_send_packet(s->interface, p);
    catta_dns_packet_free(p);
}

static void elapse_callback(CATTA_GCC_UNUSED CattaTimeEvent *e, void* data) {
    CattaResponseJob *rj = data;

    assert(rj);

    if (rj->state == CATTA_DONE || rj->state == CATTA_SUPPRESSED)
        job_free(rj->scheduler, rj);         /* Lets drop this entry */
    else
        send_response_packet(rj->scheduler, rj);
}

static CattaResponseJob* find_scheduled_job(CattaResponseScheduler *s, CattaRecord *record) {
    CattaResponseJob *rj;

    assert(s);
    assert(record);

    for (rj = s->jobs; rj; rj = rj->jobs_next) {
        assert(rj->state == CATTA_SCHEDULED);

        if (catta_record_equal_no_ttl(rj->record, record))
            return rj;
    }

    return NULL;
}

static CattaResponseJob* find_history_job(CattaResponseScheduler *s, CattaRecord *record) {
    CattaResponseJob *rj;

    assert(s);
    assert(record);

    for (rj = s->history; rj; rj = rj->jobs_next) {
        assert(rj->state == CATTA_DONE);

        if (catta_record_equal_no_ttl(rj->record, record)) {
            /* Check whether this entry is outdated */

/*             catta_log_debug("history age: %u", (unsigned) (catta_age(&rj->delivery)/1000)); */

            if (catta_age(&rj->delivery)/1000 > CATTA_RESPONSE_HISTORY_MSEC) {
                /* it is outdated, so let's remove it */
                job_free(s, rj);
                return NULL;
            }

            return rj;
        }
    }

    return NULL;
}

static CattaResponseJob* find_suppressed_job(CattaResponseScheduler *s, CattaRecord *record, const CattaAddress *querier) {
    CattaResponseJob *rj;

    assert(s);
    assert(record);
    assert(querier);

    for (rj = s->suppressed; rj; rj = rj->jobs_next) {
        assert(rj->state == CATTA_SUPPRESSED);
        assert(rj->querier_valid);

        if (catta_record_equal_no_ttl(rj->record, record) &&
            catta_address_cmp(&rj->querier, querier) == 0) {
            /* Check whether this entry is outdated */

            if (catta_age(&rj->delivery) > CATTA_RESPONSE_SUPPRESS_MSEC*1000) {
                /* it is outdated, so let's remove it */
                job_free(s, rj);
                return NULL;
            }

            return rj;
        }
    }

    return NULL;
}

int catta_response_scheduler_post(CattaResponseScheduler *s, CattaRecord *record, int flush_cache, const CattaAddress *querier, int immediately) {
    CattaResponseJob *rj;
    struct timeval tv;
/*     char *t; */

    assert(s);
    assert(record);

    assert(!catta_key_is_pattern(record->key));

/*     t = catta_record_to_string(record); */
/*     catta_log_debug("post %i %s", immediately, t); */
/*     catta_free(t); */

    /* Check whether this response is suppressed */
    if (querier &&
        (rj = find_suppressed_job(s, record, querier)) &&
        catta_record_is_goodbye(record) == catta_record_is_goodbye(rj->record) &&
        rj->record->ttl >= record->ttl/2) {

/*         catta_log_debug("Response suppressed by known answer suppression.");  */
        return 0;
    }

    /* Check if we already sent this response recently */
    if ((rj = find_history_job(s, record))) {

        if (catta_record_is_goodbye(record) == catta_record_is_goodbye(rj->record) &&
            rj->record->ttl >= record->ttl/2 &&
            (rj->flush_cache || !flush_cache)) {
/*             catta_log_debug("Response suppressed by local duplicate suppression (history)");  */
            return 0;
        }

        /* Outdated ... */
        job_free(s, rj);
    }

    catta_elapse_time(&tv, immediately ? 0 : CATTA_RESPONSE_DEFER_MSEC, immediately ? 0 : CATTA_RESPONSE_JITTER_MSEC);

    if ((rj = find_scheduled_job(s, record))) {
/*          catta_log_debug("Response suppressed by local duplicate suppression (scheduled)"); */

        /* Update a little ... */

        /* Update the time if the new is prior to the old */
        if (catta_timeval_compare(&tv, &rj->delivery) < 0) {
            rj->delivery = tv;
            catta_time_event_update(rj->time_event, &rj->delivery);
        }

        /* Update the flush cache bit */
        if (flush_cache)
            rj->flush_cache = 1;

        /* Update the querier field */
        if (!querier || (rj->querier_valid && catta_address_cmp(querier, &rj->querier) != 0))
            rj->querier_valid = 0;

        /* Update record data (just for the TTL) */
        catta_record_unref(rj->record);
        rj->record = catta_record_ref(record);

        return 1;
    } else {
/*         catta_log_debug("Accepted new response job.");  */

        /* Create a new job and schedule it */
        if (!(rj = job_new(s, record, CATTA_SCHEDULED)))
            return 0; /* OOM */

        rj->delivery = tv;
        rj->time_event = catta_time_event_new(s->time_event_queue, &rj->delivery, elapse_callback, rj);
        rj->flush_cache = flush_cache;

        if ((rj->querier_valid = !!querier))
            rj->querier = *querier;

        return 1;
    }
}

void catta_response_scheduler_incoming(CattaResponseScheduler *s, CattaRecord *record, int flush_cache) {
    CattaResponseJob *rj;
    assert(s);

    /* This function is called whenever an incoming response was
     * receieved. We drop scheduled responses which match here. The
     * keyword is "DUPLICATE ANSWER SUPPRESION". */

    if ((rj = find_scheduled_job(s, record))) {

        if ((!rj->flush_cache || flush_cache) &&    /* flush cache bit was set correctly */
            catta_record_is_goodbye(record) == catta_record_is_goodbye(rj->record) &&   /* both goodbye packets, or both not */
            record->ttl >= rj->record->ttl/2) {     /* sensible TTL */

            /* A matching entry was found, so let's mark it done */
/*             catta_log_debug("Response suppressed by distributed duplicate suppression"); */
            job_mark_done(s, rj);
        }

        return;
    }

    if ((rj = find_history_job(s, record))) {
        /* Found a history job, let's update it */
        catta_record_unref(rj->record);
        rj->record = catta_record_ref(record);
    } else
        /* Found no existing history job, so let's create a new one */
        if (!(rj = job_new(s, record, CATTA_DONE)))
            return; /* OOM */

    rj->flush_cache = flush_cache;
    rj->querier_valid = 0;

    gettimeofday(&rj->delivery, NULL);
    job_set_elapse_time(s, rj, CATTA_RESPONSE_HISTORY_MSEC, 0);
}

void catta_response_scheduler_suppress(CattaResponseScheduler *s, CattaRecord *record, const CattaAddress *querier) {
    CattaResponseJob *rj;

    assert(s);
    assert(record);
    assert(querier);

    if ((rj = find_scheduled_job(s, record))) {

        if (rj->querier_valid && catta_address_cmp(querier, &rj->querier) == 0 && /* same originator */
            catta_record_is_goodbye(record) == catta_record_is_goodbye(rj->record) && /* both goodbye packets, or both not */
            record->ttl >= rj->record->ttl/2) {                                  /* sensible TTL */

            /* A matching entry was found, so let's drop it */
/*             catta_log_debug("Known answer suppression active!"); */
            job_free(s, rj);
        }
    }

    if ((rj = find_suppressed_job(s, record, querier))) {

        /* Let's update the old entry */
        catta_record_unref(rj->record);
        rj->record = catta_record_ref(record);

    } else {

        /* Create a new entry */
        if (!(rj = job_new(s, record, CATTA_SUPPRESSED)))
            return; /* OOM */
        rj->querier_valid = 1;
        rj->querier = *querier;
    }

    gettimeofday(&rj->delivery, NULL);
    job_set_elapse_time(s, rj, CATTA_RESPONSE_SUPPRESS_MSEC, 0);
}

void catta_response_scheduler_force(CattaResponseScheduler *s) {
    assert(s);

    /* Send all scheduled responses immediately */
    while (s->jobs)
        send_response_packet(s, s->jobs);
}
