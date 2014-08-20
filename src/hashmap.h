#ifndef foohashmaphfoo
#define foohashmaphfoo

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

#include <catta/cdecl.h>

CATTA_C_DECL_BEGIN

typedef struct CattaHashmap CattaHashmap;

typedef unsigned (*CattaHashFunc)(const void *data);
typedef int (*CattaEqualFunc)(const void *a, const void *b);
typedef void (*CattaFreeFunc)(void *p);

CattaHashmap* catta_hashmap_new(CattaHashFunc hash_func, CattaEqualFunc equal_func, CattaFreeFunc key_free_func, CattaFreeFunc value_free_func);

void catta_hashmap_free(CattaHashmap *m);
void* catta_hashmap_lookup(CattaHashmap *m, const void *key);
int catta_hashmap_insert(CattaHashmap *m, void *key, void *value);
int catta_hashmap_replace(CattaHashmap *m, void *key, void *value);
void catta_hashmap_remove(CattaHashmap *m, const void *key);

typedef void (*CattaHashmapForeachCallback)(void *key, void *value, void *userdata);

void catta_hashmap_foreach(CattaHashmap *m, CattaHashmapForeachCallback callback, void *userdata);

unsigned catta_string_hash(const void *data);
int catta_string_equal(const void *a, const void *b);

unsigned catta_int_hash(const void *data);
int catta_int_equal(const void *a, const void *b);

CATTA_C_DECL_END

#endif
