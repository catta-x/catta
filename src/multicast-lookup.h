#ifndef foomulticastlookuphfoo
#define foomulticastlookuphfoo

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

typedef struct CattaMulticastLookupEngine CattaMulticastLookupEngine;
typedef struct CattaMulticastLookup CattaMulticastLookup;

typedef void (*CattaMulticastLookupCallback)(
    CattaMulticastLookupEngine *e,
    CattaIfIndex idx,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    CattaLookupResultFlags flags,
    CattaRecord *r,
    void *userdata);

CattaMulticastLookupEngine *catta_multicast_lookup_engine_new(CattaServer *s);
void catta_multicast_lookup_engine_free(CattaMulticastLookupEngine *e);

unsigned catta_multicast_lookup_engine_scan_cache(CattaMulticastLookupEngine *e, CattaIfIndex idx, CattaProtocol protocol, CattaKey *key, CattaMulticastLookupCallback callback, void *userdata);
void catta_multicast_lookup_engine_new_interface(CattaMulticastLookupEngine *e, CattaInterface *i);
void catta_multicast_lookup_engine_cleanup(CattaMulticastLookupEngine *e);
void catta_multicast_lookup_engine_notify(CattaMulticastLookupEngine *e, CattaInterface *i, CattaRecord *record, CattaBrowserEvent event);

CattaMulticastLookup *catta_multicast_lookup_new(CattaMulticastLookupEngine *e, CattaIfIndex idx, CattaProtocol protocol, CattaKey *key, CattaMulticastLookupCallback callback, void *userdata);
void catta_multicast_lookup_free(CattaMulticastLookup *q);


#endif

