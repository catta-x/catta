#ifndef foothreadedwatchhfoo
#define foothreadedwatchhfoo

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

/** \file thread-watch.h Threaded poll() based main loop implementation */

#include <catta/cdecl.h>
#include <catta/watch.h>

CATTA_C_DECL_BEGIN

/** A main loop object that runs an CattaSimplePoll in its own thread. \since 0.6.4 */
typedef struct CattaThreadedPoll CattaThreadedPoll;

/** Create a new event loop object. This will allocate the internal
 * CattaSimplePoll, but will not start the helper thread. \since 0.6.4 */
CattaThreadedPoll *catta_threaded_poll_new(void);

/** Free an event loop object. This will stop the associated event loop
 * thread (if it is running). \since 0.6.4 */
void catta_threaded_poll_free(CattaThreadedPoll *p);

/** Return the abstracted poll API object for this event loop
 * object. The will return the same pointer each time it is
 * called. \since 0.6.4 */
const CattaPoll* catta_threaded_poll_get(CattaThreadedPoll *p);

/** Start the event loop helper thread. After the thread has started
 * you must make sure to access the event loop object
 * (CattaThreadedPoll, CattaPoll and all its associated objects)
 * synchronized, i.e. with proper locking. You may want to use
 * catta_threaded_poll_lock()/catta_threaded_poll_unlock() for this,
 * which will lock the the entire event loop. Please note that event
 * loop callback functions are called from the event loop helper thread
 * with that lock held, i.e. catta_threaded_poll_lock() calls are not
 * required from event callbacks. \since 0.6.4 */
int catta_threaded_poll_start(CattaThreadedPoll *p);

/** Request that the event loop quits and the associated thread
 stops. Call this from outside the helper thread if you want to shut
 it down. \since 0.6.4 */
int catta_threaded_poll_stop(CattaThreadedPoll *p);

/** Request that the event loop quits and the associated thread
 stops. Call this from inside the helper thread if you want to shut it
 down. \since 0.6.4  */
void catta_threaded_poll_quit(CattaThreadedPoll *p);

/** Lock the main loop object. Use this if you want to access the event
 * loop objects (such as creating a new event source) from anything
 * else but the event loop helper thread, i.e. from anything else but event
 * loop callbacks \since 0.6.4  */
void catta_threaded_poll_lock(CattaThreadedPoll *p);

/** Unlock the event loop object, use this as counterpart to
 * catta_threaded_poll_lock() \since 0.6.4 */
void catta_threaded_poll_unlock(CattaThreadedPoll *p);

CATTA_C_DECL_END

#endif
