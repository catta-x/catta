#ifndef fooannouncehfoo
#define fooannouncehfoo

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

typedef struct CattaAnnouncer CattaAnnouncer;

#include <catta/llist.h>
#include <catta/publish.h>
#include "iface.h"
#include "internal.h"
#include "timeeventq.h"

typedef enum {
    CATTA_PROBING,         /* probing phase */
    CATTA_WAITING,         /* wait for other records in group */
    CATTA_ANNOUNCING,      /* announcing phase */
    CATTA_ESTABLISHED      /* we'e established */
} CattaAnnouncerState;

struct CattaAnnouncer {
    CattaServer *server;
    CattaInterface *interface;
    CattaEntry *entry;

    CattaTimeEvent *time_event;

    CattaAnnouncerState state;
    unsigned n_iteration;
    unsigned sec_delay;

    CATTA_LLIST_FIELDS(CattaAnnouncer, by_interface);
    CATTA_LLIST_FIELDS(CattaAnnouncer, by_entry);
};

void catta_announce_interface(CattaServer *s, CattaInterface *i);
void catta_announce_entry(CattaServer *s, CattaEntry *e);
void catta_announce_group(CattaServer *s, CattaSEntryGroup *g);

void catta_entry_return_to_initial_state(CattaServer *s, CattaEntry *e, CattaInterface *i);

void catta_s_entry_group_check_probed(CattaSEntryGroup *g, int immediately);

int catta_entry_is_registered(CattaServer *s, CattaEntry *e, CattaInterface *i);
int catta_entry_is_probing(CattaServer *s, CattaEntry *e, CattaInterface *i);

void catta_goodbye_interface(CattaServer *s, CattaInterface *i, int send_goodbye, int rem);
void catta_goodbye_entry(CattaServer *s, CattaEntry *e, int send_goodbye, int rem);

void catta_reannounce_entry(CattaServer *s, CattaEntry *e);

#endif
