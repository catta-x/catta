#ifndef foomallochfoo
#define foomallochfoo

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

/** \file malloc.h Memory allocation */

#include <sys/types.h>
#include <stdarg.h>
#include <limits.h>
#include <assert.h>

#include <catta/cdecl.h>
#include <catta/gccmacro.h>

CATTA_C_DECL_BEGIN

/** Allocate some memory, just like the libc malloc() */
void *catta_malloc(size_t size) CATTA_GCC_ALLOC_SIZE(1);

/** Similar to catta_malloc() but set the memory to zero */
void *catta_malloc0(size_t size) CATTA_GCC_ALLOC_SIZE(1);

/** Free some memory */
void catta_free(void *p);

/** Similar to libc's realloc() */
void *catta_realloc(void *p, size_t size) CATTA_GCC_ALLOC_SIZE(2);

/** Internal helper for catta_new() */
static inline void* CATTA_GCC_ALLOC_SIZE2(1,2) catta_new_internal(unsigned n, size_t k) {
    assert(n < INT_MAX/k);
    return catta_malloc(n*k);
}

/** Allocate n new structures of the specified type. */
#define catta_new(type, n) ((type*) catta_new_internal((n), sizeof(type)))

/** Internal helper for catta_new0() */
static inline void* CATTA_GCC_ALLOC_SIZE2(1,2) catta_new0_internal(unsigned n, size_t k) {
    assert(n < INT_MAX/k);
    return catta_malloc0(n*k);
}

/** Same as catta_new() but set the memory to zero */
#define catta_new0(type, n) ((type*) catta_new0_internal((n), sizeof(type)))

/** Just like libc's strdup() */
char *catta_strdup(const char *s);

/** Just like libc's strndup() */
char *catta_strndup(const char *s, size_t l);

/** Duplicate the given memory block into a new one allocated with catta_malloc() */
void *catta_memdup(const void *s, size_t l) CATTA_GCC_ALLOC_SIZE(2);

/** Wraps allocator functions */
typedef struct CattaAllocator {
    void* (*malloc)(size_t size) CATTA_GCC_ALLOC_SIZE(1);
    void (*free)(void *p);
    void* (*realloc)(void *p, size_t size) CATTA_GCC_ALLOC_SIZE(2);
    void* (*calloc)(size_t nmemb, size_t size) CATTA_GCC_ALLOC_SIZE2(1,2);   /**< May be NULL */
} CattaAllocator;

/** Change the allocator. May be NULL to return to default (libc)
 * allocators. The structure is not copied! */
void catta_set_allocator(const CattaAllocator *a);

/** Like sprintf() but store the result in a freshly allocated buffer. Free this with catta_free() */
char *catta_strdup_printf(const char *fmt, ... ) CATTA_GCC_PRINTF_ATTR12;

/** \cond fulldocs */
/** Same as catta_strdup_printf() but take a va_list instead of varargs */
char *catta_strdup_vprintf(const char *fmt, va_list ap);
/** \endcond */

CATTA_C_DECL_END

#endif
