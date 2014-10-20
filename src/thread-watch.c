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

#include <sys/poll.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>

#include <catta/llist.h>
#include <catta/malloc.h>
#include <catta/timeval.h>
#include <catta/simple-watch.h>
#include <catta/thread-watch.h>

struct CattaThreadedPoll {
    CattaSimplePoll *simple_poll;
    pthread_t thread_id;
    pthread_mutex_t mutex;
    int thread_running;
    int retval;
};

static int poll_func(struct pollfd *ufds, unsigned int nfds, int timeout, void *userdata) {
    pthread_mutex_t *mutex = userdata;
    int r;

    /* Before entering poll() we unlock the mutex, so that
     * catta_simple_poll_quit() can succeed from another thread. */

    pthread_mutex_unlock(mutex);
    r = poll(ufds, nfds, timeout);
    pthread_mutex_lock(mutex);

    return r;
}

static void* thread(void *userdata){
    CattaThreadedPoll *p = userdata;

#ifndef _WIN32
    sigset_t mask;

    /* Make sure that signals are delivered to the main thread */
    sigfillset(&mask);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);
#endif

    pthread_mutex_lock(&p->mutex);
    p->retval = catta_simple_poll_loop(p->simple_poll);
    pthread_mutex_unlock(&p->mutex);

    return NULL;
}

CattaThreadedPoll *catta_threaded_poll_new(void) {
    CattaThreadedPoll *p;

    if (!(p = catta_new(CattaThreadedPoll, 1)))
        goto fail; /* OOM */

    if (!(p->simple_poll = catta_simple_poll_new()))
        goto fail;

    pthread_mutex_init(&p->mutex, NULL);

    catta_simple_poll_set_func(p->simple_poll, poll_func, &p->mutex);

    p->thread_running = 0;

    return p;

fail:
    if (p) {
        if (p->simple_poll) {
            catta_simple_poll_free(p->simple_poll);
            pthread_mutex_destroy(&p->mutex);
        }

        catta_free(p);
    }

    return NULL;
}

void catta_threaded_poll_free(CattaThreadedPoll *p) {
    assert(p);

    /* Make sure that this function is not called from the helper thread */
    assert(!p->thread_running || !pthread_equal(pthread_self(), p->thread_id));

    if (p->thread_running)
        catta_threaded_poll_stop(p);

    if (p->simple_poll)
        catta_simple_poll_free(p->simple_poll);

    pthread_mutex_destroy(&p->mutex);
    catta_free(p);
}

const CattaPoll* catta_threaded_poll_get(CattaThreadedPoll *p) {
    assert(p);

    return catta_simple_poll_get(p->simple_poll);
}

int catta_threaded_poll_start(CattaThreadedPoll *p) {
    assert(p);

    assert(!p->thread_running);

    if (pthread_create(&p->thread_id, NULL, thread, p) < 0)
        return -1;

    p->thread_running = 1;

    return 0;
}

int catta_threaded_poll_stop(CattaThreadedPoll *p) {
    assert(p);

    if (!p->thread_running)
        return -1;

    /* Make sure that this function is not called from the helper thread */
    assert(!pthread_equal(pthread_self(), p->thread_id));

    pthread_mutex_lock(&p->mutex);
    catta_simple_poll_quit(p->simple_poll);
    pthread_mutex_unlock(&p->mutex);

    pthread_join(p->thread_id, NULL);
    p->thread_running = 0;

    return p->retval;
}

void catta_threaded_poll_quit(CattaThreadedPoll *p) {
    assert(p);

    /* Make sure that this function is called from the helper thread */
    assert(pthread_equal(pthread_self(), p->thread_id));

    catta_simple_poll_quit(p->simple_poll);
}

void catta_threaded_poll_lock(CattaThreadedPoll *p) {
    assert(p);

    /* Make sure that this function is not called from the helper thread */
    assert(!p->thread_running || !pthread_equal(pthread_self(), p->thread_id));

    pthread_mutex_lock(&p->mutex);
}

void catta_threaded_poll_unlock(CattaThreadedPoll *p) {
    assert(p);

    /* Make sure that this function is not called from the helper thread */
    assert(!p->thread_running || !pthread_equal(pthread_self(), p->thread_id));

    pthread_mutex_unlock(&p->mutex);
}
