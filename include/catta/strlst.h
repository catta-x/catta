#ifndef footxtlisthfoo
#define footxtlisthfoo

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

/** \file strlst.h Implementation of a data type to store lists of strings */

#include <sys/types.h>
#include <inttypes.h>
#include <stdarg.h>

#include <catta/cdecl.h>
#include <catta/gccmacro.h>

CATTA_C_DECL_BEGIN

/** Linked list of strings that can contain any number of binary
 * characters, including NUL bytes. An empty list is created by
 * assigning a NULL to a pointer to CattaStringList. The string list
 * is stored in reverse order, so that appending to the string list is
 * effectively a prepending to the linked list.  This object is used
 * primarily for storing DNS TXT record data. */
typedef struct CattaStringList {
    struct CattaStringList *next; /**< Pointer to the next linked list element */
    size_t size;  /**< Size of text[] */
    uint8_t text[1]; /**< Character data */
} CattaStringList;

/** @{ \name Construction and destruction */

/** Create a new string list by taking a variable list of NUL
 * terminated strings. The strings are copied using g_strdup(). The
 * argument list must be terminated by a NULL pointer. */
CattaStringList *catta_string_list_new(const char *txt, ...) CATTA_GCC_SENTINEL;

/** \cond fulldocs */
/** Same as catta_string_list_new() but pass a va_list structure */
CattaStringList *catta_string_list_new_va(va_list va);
/** \endcond */

/** Create a new string list from a string array. The strings are
 * copied using g_strdup(). length should contain the length of the
 * array, or -1 if the array is NULL terminated*/
CattaStringList *catta_string_list_new_from_array(const char **array, int length);

/** Free a string list */
void catta_string_list_free(CattaStringList *l);

/** @} */

/** @{ \name Adding strings */

/** Append a NUL terminated string to the specified string list. The
 * passed string is copied using g_strdup(). Returns the new list
 * start. */
CattaStringList *catta_string_list_add(CattaStringList *l, const char *text);

/** Append a new NUL terminated formatted string to the specified string list */
CattaStringList *catta_string_list_add_printf(CattaStringList *l, const char *format, ...) CATTA_GCC_PRINTF_ATTR23;

/** \cond fulldocs */
/** Append a new NUL terminated formatted string to the specified string list */
CattaStringList *catta_string_list_add_vprintf(CattaStringList *l, const char *format, va_list va);
/** \endcond */

/** Append an arbitrary length byte string to the list. Returns the
 * new list start. */
CattaStringList *catta_string_list_add_arbitrary(CattaStringList *l, const uint8_t *text, size_t size);

/** Append a new entry to the string list. The string is not filled
with data. The caller should fill in string data afterwards by writing
it to l->text, where l is the pointer returned by this function. This
function exists solely to optimize a few operations where otherwise
superfluous string copying would be necessary. */
CattaStringList*catta_string_list_add_anonymous(CattaStringList *l, size_t size);

/** Same as catta_string_list_add(), but takes a variable number of
 * NUL terminated strings. The argument list must be terminated by a
 * NULL pointer. Returns the new list start. */
CattaStringList *catta_string_list_add_many(CattaStringList *r, ...) CATTA_GCC_SENTINEL;

/** \cond fulldocs */
/** Same as catta_string_list_add_many(), but use a va_list
 * structure. Returns the new list start. */
CattaStringList *catta_string_list_add_many_va(CattaStringList *r, va_list va);
/** \endcond */

/** @} */

/** @{ \name String list operations */

/** Convert the string list object to a single character string,
 * seperated by spaces and enclosed in "". catta_free() the result! This
 * function doesn't work well with strings that contain NUL bytes. */
char* catta_string_list_to_string(CattaStringList *l);

/** \cond fulldocs */
/** Serialize the string list object in a way that is compatible with
 * the storing of DNS TXT records. Strings longer than 255 bytes are truncated. */
size_t catta_string_list_serialize(CattaStringList *l, void * data, size_t size);

/** Inverse of catta_string_list_serialize() */
int catta_string_list_parse(const void *data, size_t size, CattaStringList **ret);
/** \endcond */

/** Compare to string lists */
int catta_string_list_equal(const CattaStringList *a, const CattaStringList *b);

/** Copy a string list */
CattaStringList *catta_string_list_copy(const CattaStringList *l);

/** Reverse the string list. */
CattaStringList* catta_string_list_reverse(CattaStringList *l);

/** Return the number of elements in the string list */
unsigned catta_string_list_length(const CattaStringList *l);

/** @} */

/** @{ \name Accessing items */

/** Returns the next item in the string list */
CattaStringList *catta_string_list_get_next(CattaStringList *l);

/** Returns the text for the current item */
uint8_t *catta_string_list_get_text(CattaStringList *l);

/** Returns the size of the current text */
size_t catta_string_list_get_size(CattaStringList *l);

/** @} */

/** @{ \name DNS-SD TXT pair handling */

/** Find the string list entry for the given DNS-SD TXT key */
CattaStringList *catta_string_list_find(CattaStringList *l, const char *key);

/** Return the DNS-SD TXT key and value for the specified string list
 * item. If size is not NULL it will be filled with the length of
 * value. (for strings containing NUL bytes). If the entry doesn't
 * contain a value *value will be set to NULL. You need to
 * catta_free() the strings returned in *key and *value. */
int catta_string_list_get_pair(CattaStringList *l, char **key, char **value, size_t *size);

/** Add a new DNS-SD TXT key value pair to the string list. value may
 * be NULL in case you want to specify a key without a value */
CattaStringList *catta_string_list_add_pair(CattaStringList *l, const char *key, const char *value);

/** Same as catta_string_list_add_pair() but allow strings containing NUL bytes in *value. */
CattaStringList *catta_string_list_add_pair_arbitrary(CattaStringList *l, const char *key, const uint8_t *value, size_t size);

/** @} */

/** \cond fulldocs */
/** Try to find a magic service cookie in the specified DNS-SD string
 * list. Or return CATTA_SERVICE_COOKIE_INVALID if none is found. */
uint32_t catta_string_list_get_service_cookie(CattaStringList *l);
/** \endcond */

CATTA_C_DECL_END

#endif

