#ifndef foowideareahfoo
#define foowideareahfoo

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

#include <catta/lookup.h>
#include "browse.h"

typedef struct CattaWideAreaLookupEngine CattaWideAreaLookupEngine;
typedef struct CattaWideAreaLookup CattaWideAreaLookup;

typedef void (*CattaWideAreaLookupCallback)(
    CattaWideAreaLookupEngine *e,
    CattaBrowserEvent event,
    CattaLookupResultFlags flags,
    CattaRecord *r,
    void *userdata);

CattaWideAreaLookupEngine *catta_wide_area_engine_new(CattaServer *s);
void catta_wide_area_engine_free(CattaWideAreaLookupEngine *e);

unsigned catta_wide_area_scan_cache(CattaWideAreaLookupEngine *e, CattaKey *key, CattaWideAreaLookupCallback callback, void *userdata);
void catta_wide_area_cache_dump(CattaWideAreaLookupEngine *e, CattaDumpCallback callback, void* userdata);
void catta_wide_area_set_servers(CattaWideAreaLookupEngine *e, const CattaAddress *a, unsigned n);
void catta_wide_area_clear_cache(CattaWideAreaLookupEngine *e);
void catta_wide_area_cleanup(CattaWideAreaLookupEngine *e);
int catta_wide_area_has_servers(CattaWideAreaLookupEngine *e);

CattaWideAreaLookup *catta_wide_area_lookup_new(CattaWideAreaLookupEngine *e, CattaKey *key, CattaWideAreaLookupCallback callback, void *userdata);
void catta_wide_area_lookup_free(CattaWideAreaLookup *q);



#endif

