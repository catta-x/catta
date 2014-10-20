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

#include <catta/domain.h>
#include <catta/timeval.h>
#include <catta/malloc.h>

#include "probe-sched.h"
#include <catta/log.h>
#include "rr-util.h"

#define CATTA_PROBE_HISTORY_MSEC 150
#define CATTA_PROBE_DEFER_MSEC 50

typedef struct CattaProbeJob CattaProbeJob;

struct CattaProbeJob {
    CattaProbeScheduler *scheduler;
    CattaTimeEvent *time_event;

    int chosen; /* Use for packet assembling */
    int done;
    struct timeval delivery;

    CattaRecord *record;

    CATTA_LLIST_FIELDS(CattaProbeJob, jobs);
};

struct CattaProbeScheduler {
    CattaInterface *iface;
    CattaTimeEventQueue *time_event_queue;

    CATTA_LLIST_HEAD(CattaProbeJob, jobs);
    CATTA_LLIST_HEAD(CattaProbeJob, history);
};

static CattaProbeJob* job_new(CattaProbeScheduler *s, CattaRecord *record, int done) {
    CattaProbeJob *pj;

    assert(s);
    assert(record);

    if (!(pj = catta_new(CattaProbeJob, 1))) {
        catta_log_error(__FILE__": Out of memory");
        return NULL; /* OOM */
    }

    pj->scheduler = s;
    pj->record = catta_record_ref(record);
    pj->time_event = NULL;
    pj->chosen = 0;

    if ((pj->done = done))
        CATTA_LLIST_PREPEND(CattaProbeJob, jobs, s->history, pj);
    else
        CATTA_LLIST_PREPEND(CattaProbeJob, jobs, s->jobs, pj);

    return pj;
}

static void job_free(CattaProbeScheduler *s, CattaProbeJob *pj) {
    assert(pj);

    if (pj->time_event)
        catta_time_event_free(pj->time_event);

    if (pj->done)
        CATTA_LLIST_REMOVE(CattaProbeJob, jobs, s->history, pj);
    else
        CATTA_LLIST_REMOVE(CattaProbeJob, jobs, s->jobs, pj);

    catta_record_unref(pj->record);
    catta_free(pj);
}

static void elapse_callback(CattaTimeEvent *e, void* data);

static void job_set_elapse_time(CattaProbeScheduler *s, CattaProbeJob *pj, unsigned msec, unsigned jitter) {
    struct timeval tv;

    assert(s);
    assert(pj);

    catta_elapse_time(&tv, msec, jitter);

    if (pj->time_event)
        catta_time_event_update(pj->time_event, &tv);
    else
        pj->time_event = catta_time_event_new(s->time_event_queue, &tv, elapse_callback, pj);
}

static void job_mark_done(CattaProbeScheduler *s, CattaProbeJob *pj) {
    assert(s);
    assert(pj);

    assert(!pj->done);

    CATTA_LLIST_REMOVE(CattaProbeJob, jobs, s->jobs, pj);
    CATTA_LLIST_PREPEND(CattaProbeJob, jobs, s->history, pj);

    pj->done = 1;

    job_set_elapse_time(s, pj, CATTA_PROBE_HISTORY_MSEC, 0);
    gettimeofday(&pj->delivery, NULL);
}

CattaProbeScheduler *catta_probe_scheduler_new(CattaInterface *i) {
    CattaProbeScheduler *s;

    assert(i);

    if (!(s = catta_new(CattaProbeScheduler, 1))) {
        catta_log_error(__FILE__": Out of memory");
        return NULL;
    }

    s->iface = i;
    s->time_event_queue = i->monitor->server->time_event_queue;

    CATTA_LLIST_HEAD_INIT(CattaProbeJob, s->jobs);
    CATTA_LLIST_HEAD_INIT(CattaProbeJob, s->history);

    return s;
}

void catta_probe_scheduler_free(CattaProbeScheduler *s) {
    assert(s);

    catta_probe_scheduler_clear(s);
    catta_free(s);
}

void catta_probe_scheduler_clear(CattaProbeScheduler *s) {
    assert(s);

    while (s->jobs)
        job_free(s, s->jobs);
    while (s->history)
        job_free(s, s->history);
}

static int packet_add_probe_query(CattaProbeScheduler *s, CattaDnsPacket *p, CattaProbeJob *pj) {
    size_t size;
    CattaKey *k;
    int b;

    assert(s);
    assert(p);
    assert(pj);

    assert(!pj->chosen);

    /* Estimate the size for this record */
    size =
        catta_key_get_estimate_size(pj->record->key) +
        catta_record_get_estimate_size(pj->record);

    /* Too large */
    if (size > catta_dns_packet_space(p))
        return 0;

    /* Create the probe query */
    if (!(k = catta_key_new(pj->record->key->name, pj->record->key->clazz, CATTA_DNS_TYPE_ANY)))
        return 0; /* OOM */

    b = !!catta_dns_packet_append_key(p, k, 0);
    assert(b);

    /* Mark this job for addition to the packet */
    pj->chosen = 1;

    /* Scan for more jobs whith matching key pattern */
    for (pj = s->jobs; pj; pj = pj->jobs_next) {
        if (pj->chosen)
            continue;

        /* Does the record match the probe? */
        if (k->clazz != pj->record->key->clazz || !catta_domain_equal(k->name, pj->record->key->name))
            continue;

        /* This job wouldn't fit in */
        if (catta_record_get_estimate_size(pj->record) > catta_dns_packet_space(p))
            break;

        /* Mark this job for addition to the packet */
        pj->chosen = 1;
    }

    catta_key_unref(k);

    return 1;
}

static void elapse_callback(CATTA_GCC_UNUSED CattaTimeEvent *e, void* data) {
    CattaProbeJob *pj = data, *next;
    CattaProbeScheduler *s;
    CattaDnsPacket *p;
    unsigned n;

    assert(pj);
    s = pj->scheduler;

    if (pj->done) {
        /* Lets remove it  from the history */
        job_free(s, pj);
        return;
    }

    if (!(p = catta_dns_packet_new_query(s->iface->hardware->mtu)))
        return; /* OOM */
    n = 1;

    /* Add the import probe */
    if (!packet_add_probe_query(s, p, pj)) {
        size_t size;
        CattaKey *k;
        int b;

        catta_dns_packet_free(p);

        /* The probe didn't fit in the package, so let's allocate a larger one */

        size =
            catta_key_get_estimate_size(pj->record->key) +
            catta_record_get_estimate_size(pj->record) +
            CATTA_DNS_PACKET_HEADER_SIZE;

        if (!(p = catta_dns_packet_new_query(size + CATTA_DNS_PACKET_EXTRA_SIZE)))
            return; /* OOM */

        if (!(k = catta_key_new(pj->record->key->name, pj->record->key->clazz, CATTA_DNS_TYPE_ANY))) {
            catta_dns_packet_free(p);
            return;  /* OOM */
        }

        b = catta_dns_packet_append_key(p, k, 0) && catta_dns_packet_append_record(p, pj->record, 0, 0);
        catta_key_unref(k);

        if (b) {
            catta_dns_packet_set_field(p, CATTA_DNS_FIELD_NSCOUNT, 1);
            catta_dns_packet_set_field(p, CATTA_DNS_FIELD_QDCOUNT, 1);
            catta_interface_send_packet(s->iface, p);
        } else
            catta_log_warn("Probe record too large, cannot send");

        catta_dns_packet_free(p);
        job_mark_done(s, pj);

        return;
    }

    /* Try to fill up packet with more probes, if available */
    for (pj = s->jobs; pj; pj = pj->jobs_next) {

        if (pj->chosen)
            continue;

        if (!packet_add_probe_query(s, p, pj))
            break;

        n++;
    }

    catta_dns_packet_set_field(p, CATTA_DNS_FIELD_QDCOUNT, n);

    n = 0;

    /* Now add the chosen records to the authorative section */
    for (pj = s->jobs; pj; pj = next) {

        next = pj->jobs_next;

        if (!pj->chosen)
            continue;

        if (!catta_dns_packet_append_record(p, pj->record, 0, 0)) {
/*             catta_log_warn("Bad probe size estimate!"); */

            /* Unmark all following jobs */
            for (; pj; pj = pj->jobs_next)
                pj->chosen = 0;

            break;
        }

        job_mark_done(s, pj);

        n ++;
    }

    catta_dns_packet_set_field(p, CATTA_DNS_FIELD_NSCOUNT, n);

    /* Send it now */
    catta_interface_send_packet(s->iface, p);
    catta_dns_packet_free(p);
}

static CattaProbeJob* find_scheduled_job(CattaProbeScheduler *s, CattaRecord *record) {
    CattaProbeJob *pj;

    assert(s);
    assert(record);

    for (pj = s->jobs; pj; pj = pj->jobs_next) {
        assert(!pj->done);

        if (catta_record_equal_no_ttl(pj->record, record))
            return pj;
    }

    return NULL;
}

static CattaProbeJob* find_history_job(CattaProbeScheduler *s, CattaRecord *record) {
    CattaProbeJob *pj;

    assert(s);
    assert(record);

    for (pj = s->history; pj; pj = pj->jobs_next) {
        assert(pj->done);

        if (catta_record_equal_no_ttl(pj->record, record)) {
            /* Check whether this entry is outdated */

            if (catta_age(&pj->delivery) > CATTA_PROBE_HISTORY_MSEC*1000) {
                /* it is outdated, so let's remove it */
                job_free(s, pj);
                return NULL;
            }

            return pj;
        }
    }

    return NULL;
}

int catta_probe_scheduler_post(CattaProbeScheduler *s, CattaRecord *record, int immediately) {
    CattaProbeJob *pj;
    struct timeval tv;

    assert(s);
    assert(record);
    assert(!catta_key_is_pattern(record->key));

    if ((pj = find_history_job(s, record)))
        return 0;

    catta_elapse_time(&tv, immediately ? 0 : CATTA_PROBE_DEFER_MSEC, 0);

    if ((pj = find_scheduled_job(s, record))) {

        if (catta_timeval_compare(&tv, &pj->delivery) < 0) {
            /* If the new entry should be scheduled earlier, update the old entry */
            pj->delivery = tv;
            catta_time_event_update(pj->time_event, &pj->delivery);
        }

        return 1;
    } else {
        /* Create a new job and schedule it */
        if (!(pj = job_new(s, record, 0)))
            return 0; /* OOM */

        pj->delivery = tv;
        pj->time_event = catta_time_event_new(s->time_event_queue, &pj->delivery, elapse_callback, pj);


/*     catta_log_debug("Accepted new probe job."); */

        return 1;
    }
}
