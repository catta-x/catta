#ifndef foowatchhfoo
#define foowatchhfoo

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

/** \file watch.h Simplistic main loop abstraction */

#ifdef _WIN32
    #include <winsock2.h> // POLLIN
#else
    #include <sys/poll.h>
    #include <sys/time.h>
#endif

#include <catta/cdecl.h>

CATTA_C_DECL_BEGIN

/** An I/O watch object */
typedef struct CattaWatch CattaWatch;

/** A timeout watch object */
typedef struct CattaTimeout CattaTimeout;

/** An event polling abstraction object */
typedef struct CattaPoll CattaPoll;

/** Type of watch events */
typedef enum {
    CATTA_WATCH_IN = POLLIN,      /**< Input event */
    CATTA_WATCH_OUT = POLLOUT,    /**< Output event */
    CATTA_WATCH_ERR = POLLERR,    /**< Error event */
    CATTA_WATCH_HUP = POLLHUP     /**< Hangup event */
} CattaWatchEvent;

/** Called whenever an I/O event happens  on an I/O watch */
typedef void (*CattaWatchCallback)(CattaWatch *w, int fd, CattaWatchEvent event, void *userdata);

/** Called when the timeout is reached */
typedef void (*CattaTimeoutCallback)(CattaTimeout *t, void *userdata);

/** Defines an abstracted event polling API. This may be used to
 connect Catta to other main loops. This is loosely based on Unix
 poll(2). A consumer will call watch_new() for all file descriptors it
 wants to listen for events on. In addition he can call timeout_new()
 to define time based events .*/
struct CattaPoll {

    /** Some abstract user data usable by the provider of the API */
    void* userdata;

    /** Create a new watch for the specified file descriptor and for
     * the specified events. The API will call the callback function
     * whenever any of the events happens. */
    CattaWatch* (*watch_new)(const CattaPoll *api, int fd, CattaWatchEvent event, CattaWatchCallback callback, void *userdata);

    /** Update the events to wait for. It is safe to call this function from an CattaWatchCallback */
    void (*watch_update)(CattaWatch *w, CattaWatchEvent event);

    /** Return the events that happened. It is safe to call this function from an CattaWatchCallback  */
    CattaWatchEvent (*watch_get_events)(CattaWatch *w);

    /** Free a watch. It is safe to call this function from an CattaWatchCallback */
    void (*watch_free)(CattaWatch *w);

    /** Set a wakeup time for the polling loop. The API will call the
    callback function when the absolute time *tv is reached. If tv is
    NULL, the timeout is disabled. After the timeout expired the
    callback function will be called and the timeout is disabled. You
    can reenable it by calling timeout_update()  */
    CattaTimeout* (*timeout_new)(const CattaPoll *api, const struct timeval *tv, CattaTimeoutCallback callback, void *userdata);

    /** Update the absolute expiration time for a timeout, If tv is
     * NULL, the timeout is disabled. It is safe to call this function from an CattaTimeoutCallback */
    void (*timeout_update)(CattaTimeout *, const struct timeval *tv);

    /** Free a timeout. It is safe to call this function from an CattaTimeoutCallback */
    void (*timeout_free)(CattaTimeout *t);
};

CATTA_C_DECL_END

#endif

