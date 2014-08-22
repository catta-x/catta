#ifndef foobrowsehfoo
#define foobrowsehfoo

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

#include <catta/llist.h>
#include <catta/core.h>
#include <catta/lookup.h>

#include "timeeventq.h"
#include "internal.h"
#include "dns.h"

typedef struct CattaSRBLookup CattaSRBLookup;

struct CattaSRecordBrowser {
    CATTA_LLIST_FIELDS(CattaSRecordBrowser, browser);
    int dead;
    CattaServer *server;

    CattaKey *key;
    CattaIfIndex interface;
    CattaProtocol protocol;
    CattaLookupFlags flags;

    CattaTimeEvent *defer_time_event;

    CattaSRecordBrowserCallback callback;
    void* userdata;

    /* Lookup data */
    CATTA_LLIST_HEAD(CattaSRBLookup, lookups);
    unsigned n_lookups;

    CattaSRBLookup *root_lookup;
};

void catta_browser_cleanup(CattaServer *server);

void catta_s_record_browser_destroy(CattaSRecordBrowser *b);
void catta_s_record_browser_restart(CattaSRecordBrowser *b);

#endif
