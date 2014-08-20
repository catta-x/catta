#ifndef footimeeventqhfoo
#define footimeeventqhfoo

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

#include <sys/types.h>

typedef struct CattaTimeEventQueue CattaTimeEventQueue;
typedef struct CattaTimeEvent CattaTimeEvent;

#include <catta/watch.h>

#include "prioq.h"

typedef void (*CattaTimeEventCallback)(CattaTimeEvent *e, void* userdata);

CattaTimeEventQueue* catta_time_event_queue_new(const CattaPoll *poll_api);
void catta_time_event_queue_free(CattaTimeEventQueue *q);

CattaTimeEvent* catta_time_event_new(
    CattaTimeEventQueue *q,
    const struct timeval *timeval,
    CattaTimeEventCallback callback,
    void* userdata);

void catta_time_event_free(CattaTimeEvent *e);
void catta_time_event_update(CattaTimeEvent *e, const struct timeval *timeval);

#endif
