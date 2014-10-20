#ifndef foogccmacrohfoo
#define foogccmacrohfoo

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

/** \file gccmacro.h Defines some macros for GCC extensions */

#include <catta/cdecl.h>

CATTA_C_DECL_BEGIN

#if defined(__GNUC__) && (__GNUC__ >= 4) && (__GNUC_MINOR__ >= 3)
#define CATTA_GCC_ALLOC_SIZE(x) __attribute__ ((__alloc_size__(x)))
#define CATTA_GCC_ALLOC_SIZE2(x,y) __attribute__ ((__alloc_size__(x,y)))
#else
/** Macro for usage of GCC's alloc_size attribute */
#define CATTA_GCC_ALLOC_SIZE(x)
#define CATTA_GCC_ALLOC_SIZE2(x,y)
#endif

#if defined(__GNUC__) && (__GNUC__ >= 4)
#define CATTA_GCC_SENTINEL __attribute__ ((sentinel))
#else
/** Macro for usage of GCC's sentinel compilation warnings */
#define CATTA_GCC_SENTINEL
#endif

#ifdef __GNUC__
#define CATTA_GCC_PRINTF_ATTR(a,b) __attribute__ ((format (printf, a, b)))
#else
/** Macro for usage of GCC's printf compilation warnings */
#define CATTA_GCC_PRINTF_ATTR(a,b)
#endif

/** Same as CATTA_GCC_PRINTF_ATTR but hard coded to arguments 1 and 2 */
#define CATTA_GCC_PRINTF_ATTR12 CATTA_GCC_PRINTF_ATTR(1,2)

/** Same as CATTA_GCC_PRINTF_ATTR but hard coded to arguments 2 and 3 */
#define CATTA_GCC_PRINTF_ATTR23 CATTA_GCC_PRINTF_ATTR(2,3)

#ifdef __GNUC__
#define CATTA_GCC_NORETURN __attribute__((noreturn))
#else
/** Macro for no-return functions */
#define CATTA_GCC_NORETURN
#endif

#ifdef __GNUC__
#define CATTA_GCC_UNUSED __attribute__ ((unused))
#else
/** Macro for not used parameter */
#define CATTA_GCC_UNUSED
#endif

CATTA_C_DECL_END

#endif
