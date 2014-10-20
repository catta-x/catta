#ifndef foocachehfoo
#define foocachehfoo

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

typedef struct CattaCache CattaCache;

#include <catta/llist.h>
#include "prioq.h"
#include "internal.h"
#include "timeeventq.h"
#include "hashmap.h"

typedef enum {
    CATTA_CACHE_VALID,
    CATTA_CACHE_EXPIRY1,
    CATTA_CACHE_EXPIRY2,
    CATTA_CACHE_EXPIRY3,
    CATTA_CACHE_EXPIRY_FINAL,
    CATTA_CACHE_POOF,       /* Passive observation of failure */
    CATTA_CACHE_POOF_FINAL,
    CATTA_CACHE_GOODBYE_FINAL,
    CATTA_CACHE_REPLACE_FINAL
} CattaCacheEntryState;

typedef struct CattaCacheEntry CattaCacheEntry;

struct CattaCacheEntry {
    CattaCache *cache;
    CattaRecord *record;
    struct timeval timestamp;
    struct timeval poof_timestamp;
    struct timeval expiry;
    int cache_flush;
    int poof_num;

    CattaAddress origin;

    CattaCacheEntryState state;
    CattaTimeEvent *time_event;

    CattaAddress poof_address;

    CATTA_LLIST_FIELDS(CattaCacheEntry, by_key);
    CATTA_LLIST_FIELDS(CattaCacheEntry, entry);
};

struct CattaCache {
    CattaServer *server;

    CattaInterface *iface;

    CattaHashmap *hashmap;

    CATTA_LLIST_HEAD(CattaCacheEntry, entries);

    unsigned n_entries;

    int last_rand;
    time_t last_rand_timestamp;
};

CattaCache *catta_cache_new(CattaServer *server, CattaInterface *iface);
void catta_cache_free(CattaCache *c);

void catta_cache_update(CattaCache *c, CattaRecord *r, int cache_flush, const CattaAddress *a);

int catta_cache_dump(CattaCache *c, CattaDumpCallback callback, void* userdata);

typedef void* CattaCacheWalkCallback(CattaCache *c, CattaKey *pattern, CattaCacheEntry *e, void* userdata);
void* catta_cache_walk(CattaCache *c, CattaKey *pattern, CattaCacheWalkCallback cb, void* userdata);

int catta_cache_entry_half_ttl(CattaCache *c, CattaCacheEntry *e);

/** Start the "Passive observation of Failure" algorithm for all
 * records of the specified key. The specified address is  */
void catta_cache_start_poof(CattaCache *c, CattaKey *key, const CattaAddress *a);

/* Stop a previously started POOF algorithm for a record. (Used for response suppresions records */
void catta_cache_stop_poof(CattaCache *c, CattaRecord *record, const CattaAddress *a);

void catta_cache_flush(CattaCache *c);

#endif
