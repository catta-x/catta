#ifndef foorrlisthfoo
#define foorrlisthfoo

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


#include <catta/rr.h>

typedef struct CattaRecordList CattaRecordList;

CattaRecordList *catta_record_list_new(void);
void catta_record_list_free(CattaRecordList *l);
void catta_record_list_flush(CattaRecordList *l);

CattaRecord* catta_record_list_next(CattaRecordList *l, int *ret_flush_cache, int *ret_unicast_response, int *ret_auxiliary);
void catta_record_list_push(CattaRecordList *l, CattaRecord *r, int flush_cache, int unicast_response, int auxiliary);
void catta_record_list_drop(CattaRecordList *l, CattaRecord *r);

int catta_record_list_all_flush_cache(CattaRecordList *l);

int catta_record_list_is_empty(CattaRecordList *l);

#endif
