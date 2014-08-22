#ifndef fooresponseschedhfoo
#define fooresponseschedhfoo

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

typedef struct CattaResponseScheduler CattaResponseScheduler;

#include <catta/address.h>
#include "iface.h"

CattaResponseScheduler *catta_response_scheduler_new(CattaInterface *i);
void catta_response_scheduler_free(CattaResponseScheduler *s);
void catta_response_scheduler_clear(CattaResponseScheduler *s);
void catta_response_scheduler_force(CattaResponseScheduler *s);

int catta_response_scheduler_post(CattaResponseScheduler *s, CattaRecord *record, int flush_cache, const CattaAddress *querier, int immediately);
void catta_response_scheduler_incoming(CattaResponseScheduler *s, CattaRecord *record, int flush_cache);
void catta_response_scheduler_suppress(CattaResponseScheduler *s, CattaRecord *record, const CattaAddress *querier);

#endif
