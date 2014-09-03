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

#include <catta/llist.h>
#include <catta/malloc.h>
#include <catta/timeval.h>
#include <catta/simple-watch.h>
#include "fdutil.h"                 // catta_set_nonblock
#include "internal.h"               // closesocket

struct CattaWatch {
    CattaSimplePoll *simple_poll;
    int dead;

    int idx;
    struct pollfd pollfd;

    CattaWatchCallback callback;
    void *userdata;

    CATTA_LLIST_FIELDS(CattaWatch, watches);
};

struct CattaTimeout {
    CattaSimplePoll *simple_poll;
    int dead;

    int enabled;
    struct timeval expiry;

    CattaTimeoutCallback callback;
    void  *userdata;

    CATTA_LLIST_FIELDS(CattaTimeout, timeouts);
};

struct CattaSimplePoll {
    CattaPoll api;
    CattaPollFunc poll_func;
    void *poll_func_userdata;

    struct pollfd* pollfds;
    int n_pollfds, max_pollfds, rebuild_pollfds;

    int watch_req_cleanup, timeout_req_cleanup;
    int quit;
    int events_valid;

    int n_watches;
    CATTA_LLIST_HEAD(CattaWatch, watches);
    CATTA_LLIST_HEAD(CattaTimeout, timeouts);

    int wakeup_pipe[2];
    int wakeup_issued;

    int prepared_timeout;

    enum {
        STATE_INIT,
        STATE_PREPARING,
        STATE_PREPARED,
        STATE_RUNNING,
        STATE_RAN,
        STATE_DISPATCHING,
        STATE_DISPATCHED,
        STATE_QUIT,
        STATE_FAILURE
    } state;
};

void catta_simple_poll_wakeup(CattaSimplePoll *s) {
    char c = 'W';
    assert(s);

    write(s->wakeup_pipe[1], &c, sizeof(c));
    s->wakeup_issued = 1;
}

static void clear_wakeup(CattaSimplePoll *s) {
    char c[10]; /* Read ten at a time */

    if (!s->wakeup_issued)
        return;

    s->wakeup_issued = 0;

    for(;;)
        if (read(s->wakeup_pipe[0], &c, sizeof(c)) != sizeof(c))
            break;
}

static CattaWatch* watch_new(const CattaPoll *api, int fd, CattaWatchEvent event, CattaWatchCallback callback, void *userdata) {
    CattaWatch *w;
    CattaSimplePoll *s;

    assert(api);
    assert(fd >= 0);
    assert(callback);

    s = api->userdata;
    assert(s);

    if (!(w = catta_new(CattaWatch, 1)))
        return NULL;

    /* If there is a background thread running the poll() for us, tell it to exit the poll() */
    catta_simple_poll_wakeup(s);

    w->simple_poll = s;
    w->dead = 0;

    w->pollfd.fd = fd;
    w->pollfd.events = event;
    w->pollfd.revents = 0;

    w->callback = callback;
    w->userdata = userdata;

    w->idx = -1;
    s->rebuild_pollfds = 1;

    CATTA_LLIST_PREPEND(CattaWatch, watches, s->watches, w);
    s->n_watches++;

    return w;
}

static void watch_update(CattaWatch *w, CattaWatchEvent events) {
    assert(w);
    assert(!w->dead);

    /* If there is a background thread running the poll() for us, tell it to exit the poll() */
    catta_simple_poll_wakeup(w->simple_poll);

    w->pollfd.events = events;

    if (w->idx != -1) {
        assert(w->simple_poll);
        w->simple_poll->pollfds[w->idx] = w->pollfd;
    } else
        w->simple_poll->rebuild_pollfds = 1;
}

static CattaWatchEvent watch_get_events(CattaWatch *w) {
    assert(w);
    assert(!w->dead);

    if (w->idx != -1 && w->simple_poll->events_valid)
        return w->simple_poll->pollfds[w->idx].revents;

    return 0;
}

static void remove_pollfd(CattaWatch *w) {
    assert(w);

    if (w->idx == -1)
        return;

    w->simple_poll->rebuild_pollfds = 1;
}

static void watch_free(CattaWatch *w) {
    assert(w);

    assert(!w->dead);

    /* If there is a background thread running the poll() for us, tell it to exit the poll() */
    catta_simple_poll_wakeup(w->simple_poll);

    remove_pollfd(w);

    w->dead = 1;
    w->simple_poll->n_watches --;
    w->simple_poll->watch_req_cleanup = 1;
}

static void destroy_watch(CattaWatch *w) {
    assert(w);

    remove_pollfd(w);
    CATTA_LLIST_REMOVE(CattaWatch, watches, w->simple_poll->watches, w);

    if (!w->dead)
        w->simple_poll->n_watches --;

    catta_free(w);
}

static void cleanup_watches(CattaSimplePoll *s, int all) {
    CattaWatch *w, *next;
    assert(s);

    for (w = s->watches; w; w = next) {
        next = w->watches_next;

        if (all || w->dead)
            destroy_watch(w);
    }

    s->timeout_req_cleanup = 0;
}

static CattaTimeout* timeout_new(const CattaPoll *api, const struct timeval *tv, CattaTimeoutCallback callback, void *userdata) {
    CattaTimeout *t;
    CattaSimplePoll *s;

    assert(api);
    assert(callback);

    s = api->userdata;
    assert(s);

    if (!(t = catta_new(CattaTimeout, 1)))
        return NULL;

    /* If there is a background thread running the poll() for us, tell it to exit the poll() */
    catta_simple_poll_wakeup(s);

    t->simple_poll = s;
    t->dead = 0;

    if ((t->enabled = !!tv))
        t->expiry = *tv;

    t->callback = callback;
    t->userdata = userdata;

    CATTA_LLIST_PREPEND(CattaTimeout, timeouts, s->timeouts, t);
    return t;
}

static void timeout_update(CattaTimeout *t, const struct timeval *tv) {
    assert(t);
    assert(!t->dead);

    /* If there is a background thread running the poll() for us, tell it to exit the poll() */
    catta_simple_poll_wakeup(t->simple_poll);

    if ((t->enabled = !!tv))
        t->expiry = *tv;
}

static void timeout_free(CattaTimeout *t) {
    assert(t);
    assert(!t->dead);

    /* If there is a background thread running the poll() for us, tell it to exit the poll() */
    catta_simple_poll_wakeup(t->simple_poll);

    t->dead = 1;
    t->simple_poll->timeout_req_cleanup = 1;
}


static void destroy_timeout(CattaTimeout *t) {
    assert(t);

    CATTA_LLIST_REMOVE(CattaTimeout, timeouts, t->simple_poll->timeouts, t);

    catta_free(t);
}

static void cleanup_timeouts(CattaSimplePoll *s, int all) {
    CattaTimeout *t, *next;
    assert(s);

    for (t = s->timeouts; t; t = next) {
        next = t->timeouts_next;

        if (all || t->dead)
            destroy_timeout(t);
    }

    s->timeout_req_cleanup = 0;
}

CattaSimplePoll *catta_simple_poll_new(void) {
    CattaSimplePoll *s;

    if (!(s = catta_new(CattaSimplePoll, 1)))
        return NULL;

    winsock_init();  // on Windows, pipe uses sockets; no-op on other platforms
    if (pipe(s->wakeup_pipe) < 0) {
        catta_free(s);
        winsock_exit();
        return NULL;
    }

    catta_set_nonblock(s->wakeup_pipe[0]);
    catta_set_nonblock(s->wakeup_pipe[1]);

    s->api.userdata = s;

    s->api.watch_new = watch_new;
    s->api.watch_free = watch_free;
    s->api.watch_update = watch_update;
    s->api.watch_get_events = watch_get_events;

    s->api.timeout_new = timeout_new;
    s->api.timeout_free = timeout_free;
    s->api.timeout_update = timeout_update;

    s->pollfds = NULL;
    s->max_pollfds = s->n_pollfds = 0;
    s->rebuild_pollfds = 1;
    s->quit = 0;
    s->n_watches = 0;
    s->events_valid = 0;

    s->watch_req_cleanup = 0;
    s->timeout_req_cleanup = 0;

    s->prepared_timeout = 0;

    s->state = STATE_INIT;

    s->wakeup_issued = 0;

    catta_simple_poll_set_func(s, NULL, NULL);

    CATTA_LLIST_HEAD_INIT(CattaWatch, s->watches);
    CATTA_LLIST_HEAD_INIT(CattaTimeout, s->timeouts);

    return s;
}

void catta_simple_poll_free(CattaSimplePoll *s) {
    assert(s);

    cleanup_timeouts(s, 1);
    cleanup_watches(s, 1);
    assert(s->n_watches == 0);

    catta_free(s->pollfds);

    if (s->wakeup_pipe[0] >= 0)
        closesocket(s->wakeup_pipe[0]);

    if (s->wakeup_pipe[1] >= 0)
        closesocket(s->wakeup_pipe[1]);

    catta_free(s);
    winsock_exit();  // match the winsock_init in catta_simple_poll_new
}

static int rebuild(CattaSimplePoll *s) {
    CattaWatch *w;
    int idx;

    assert(s);

    if (s->n_watches+1 > s->max_pollfds) {
        struct pollfd *n;

        s->max_pollfds = s->n_watches + 10;

        if (!(n = catta_realloc(s->pollfds, sizeof(struct pollfd) * s->max_pollfds)))
            return -1;

        s->pollfds = n;
    }


    s->pollfds[0].fd = s->wakeup_pipe[0];
    s->pollfds[0].events = POLLIN;
    s->pollfds[0].revents = 0;

    idx = 1;

    for (w = s->watches; w; w = w->watches_next) {

        if(w->dead)
            continue;

        assert(w->idx < s->max_pollfds);
        s->pollfds[w->idx = idx++] = w->pollfd;
    }

    s->n_pollfds = idx;
    s->events_valid = 0;
    s->rebuild_pollfds = 0;

    return 0;
}

static CattaTimeout* find_next_timeout(CattaSimplePoll *s) {
    CattaTimeout *t, *n = NULL;
    assert(s);

    for (t = s->timeouts; t; t = t->timeouts_next) {

        if (t->dead || !t->enabled)
            continue;

        if (!n || catta_timeval_compare(&t->expiry, &n->expiry) < 0)
            n = t;
    }

    return n;
}

static void timeout_callback(CattaTimeout *t) {
    assert(t);
    assert(!t->dead);
    assert(t->enabled);

    t->enabled = 0;
    t->callback(t, t->userdata);
}

int catta_simple_poll_prepare(CattaSimplePoll *s, int timeout) {
    CattaTimeout *next_timeout;

    assert(s);
    assert(s->state == STATE_INIT || s->state == STATE_DISPATCHED || s->state == STATE_FAILURE);
    s->state = STATE_PREPARING;

    /* Clear pending wakeup requests */
    clear_wakeup(s);

    /* Cleanup things first */
    if (s->watch_req_cleanup)
        cleanup_watches(s, 0);

    if (s->timeout_req_cleanup)
        cleanup_timeouts(s, 0);

    /* Check whether a quit was requested */
    if (s->quit) {
        s->state = STATE_QUIT;
        return 1;
    }

    /* Do we need to rebuild our array of pollfds? */
    if (s->rebuild_pollfds)
        if (rebuild(s) < 0) {
            s->state = STATE_FAILURE;
            return -1;
        }

    /* Calculate the wakeup time */
    if ((next_timeout = find_next_timeout(s))) {
        struct timeval now;
        int t;
        CattaUsec usec;

        if (next_timeout->expiry.tv_sec == 0 &&
            next_timeout->expiry.tv_usec == 0) {

            /* Just a shortcut so that we don't need to call gettimeofday() */
            timeout = 0;
            goto finish;
        }

        gettimeofday(&now, NULL);
        usec = catta_timeval_diff(&next_timeout->expiry, &now);

        if (usec <= 0) {
            /* Timeout elapsed */

            timeout = 0;
            goto finish;
        }

        /* Calculate sleep time. We add 1ms because otherwise we'd
         * wake up too early most of the time */
        t = (int) (usec / 1000) + 1;

        if (timeout < 0 || timeout > t)
            timeout = t;
    }

finish:
    s->prepared_timeout = timeout;
    s->state = STATE_PREPARED;
    return 0;
}

int catta_simple_poll_run(CattaSimplePoll *s) {
    assert(s);
    assert(s->state == STATE_PREPARED || s->state == STATE_FAILURE);

    s->state = STATE_RUNNING;

    for (;;) {
        errno = 0;

        if (s->poll_func(s->pollfds, s->n_pollfds, s->prepared_timeout, s->poll_func_userdata) < 0) {

            if (errno == EINTR)
                continue;

            s->state = STATE_FAILURE;
            return -1;
        }

        break;
    }

    /* The poll events are now valid again */
    s->events_valid = 1;

    /* Update state */
    s->state = STATE_RAN;
    return 0;
}

int catta_simple_poll_dispatch(CattaSimplePoll *s) {
    CattaTimeout *next_timeout;
    CattaWatch *w;

    assert(s);
    assert(s->state == STATE_RAN);
    s->state = STATE_DISPATCHING;

    /* We execute only on callback in every iteration */

    /* Check whether the wakeup time has been reached now */
    if ((next_timeout = find_next_timeout(s))) {

        if (next_timeout->expiry.tv_sec == 0 && next_timeout->expiry.tv_usec == 0) {

            /* Just a shortcut so that we don't need to call gettimeofday() */
            timeout_callback(next_timeout);
            goto finish;
        }

        if (catta_age(&next_timeout->expiry) >= 0) {

            /* Timeout elapsed */
            timeout_callback(next_timeout);
            goto finish;
        }
    }

    /* Look for some kind of I/O event */
    for (w = s->watches; w; w = w->watches_next) {

        if (w->dead)
            continue;

        assert(w->idx >= 0);
        assert(w->idx < s->n_pollfds);

        if (s->pollfds[w->idx].revents != 0) {
            w->callback(w, w->pollfd.fd, s->pollfds[w->idx].revents, w->userdata);
            goto finish;
        }
    }

finish:

    s->state = STATE_DISPATCHED;
    return 0;
}

int catta_simple_poll_iterate(CattaSimplePoll *s, int timeout) {
    int r;

    if ((r = catta_simple_poll_prepare(s, timeout)) != 0)
        return r;

    if ((r = catta_simple_poll_run(s)) != 0)
        return r;

    if ((r = catta_simple_poll_dispatch(s)) != 0)
        return r;

    return 0;
}

void catta_simple_poll_quit(CattaSimplePoll *s) {
    assert(s);

    s->quit = 1;

    /* If there is a background thread running the poll() for us, tell it to exit the poll() */
    catta_simple_poll_wakeup(s);
}

const CattaPoll* catta_simple_poll_get(CattaSimplePoll *s) {
    assert(s);

    return &s->api;
}

static int system_poll(struct pollfd *ufds, unsigned int nfds, int timeout, CATTA_GCC_UNUSED void *userdata) {
    return poll(ufds, nfds, timeout);
}

void catta_simple_poll_set_func(CattaSimplePoll *s, CattaPollFunc func, void *userdata) {
    assert(s);

    s->poll_func = func ? func : system_poll;
    s->poll_func_userdata = func ? userdata : NULL;

    /* If there is a background thread running the poll() for us, tell it to exit the poll() */
    catta_simple_poll_wakeup(s);
}

int catta_simple_poll_loop(CattaSimplePoll *s) {
    int r;

    assert(s);

    for (;;)
        if ((r = catta_simple_poll_iterate(s, -1)) != 0)
            if (r >= 0 || errno != EINTR)
                return r;
}
