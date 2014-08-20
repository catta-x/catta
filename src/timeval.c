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

#include <pthread.h>
#include <stdlib.h>
#include <assert.h>

#include <catta/timeval.h>

int catta_timeval_compare(const struct timeval *a, const struct timeval *b) {
    assert(a);
    assert(b);

    if (a->tv_sec < b->tv_sec)
        return -1;

    if (a->tv_sec > b->tv_sec)
        return 1;

    if (a->tv_usec < b->tv_usec)
        return -1;

    if (a->tv_usec > b->tv_usec)
        return 1;

    return 0;
}

CattaUsec catta_timeval_diff(const struct timeval *a, const struct timeval *b) {
    assert(a);
    assert(b);

    if (catta_timeval_compare(a, b) < 0)
        return - catta_timeval_diff(b, a);

    return ((CattaUsec) a->tv_sec - b->tv_sec)*1000000 + a->tv_usec - b->tv_usec;
}

struct timeval* catta_timeval_add(struct timeval *a, CattaUsec usec) {
    CattaUsec u;
    assert(a);

    u = usec + a->tv_usec;

    if (u < 0) {
        a->tv_usec = (long) (1000000 + (u % 1000000));
        a->tv_sec += (long) (-1 + (u / 1000000));
    } else {
        a->tv_usec = (long) (u % 1000000);
        a->tv_sec += (long) (u / 1000000);
    }

    return a;
}

CattaUsec catta_age(const struct timeval *a) {
    struct timeval now;

    assert(a);

    gettimeofday(&now, NULL);

    return catta_timeval_diff(&now, a);
}

struct timeval *catta_elapse_time(struct timeval *tv, unsigned msec, unsigned jitter) {
    assert(tv);

    gettimeofday(tv, NULL);

    if (msec)
        catta_timeval_add(tv, (CattaUsec) msec*1000);

    if (jitter) {
        static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
        static int last_rand;
        static time_t timestamp = 0;

        time_t now;
        int r;

        now = time(NULL);

        pthread_mutex_lock(&mutex);
        if (now >= timestamp + 10) {
            timestamp = now;
            last_rand = rand();
        }

        r = last_rand;

        pthread_mutex_unlock(&mutex);

        /* We use the same jitter for 10 seconds. That way our
         * time events elapse in bursts which has the advantage that
         * packet data can be aggregated better */

        catta_timeval_add(tv, (CattaUsec) (jitter*1000.0*r/(RAND_MAX+1.0)));
    }

    return tv;
}

