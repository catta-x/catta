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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <catta/strlst.h>
#include <catta/malloc.h>
#include <catta/defs.h>

CattaStringList*catta_string_list_add_anonymous(CattaStringList *l, size_t size) {
    CattaStringList *n;

    if (!(n = catta_malloc(sizeof(CattaStringList) + size)))
        return NULL;

    n->next = l;
    n->size = size;

    /* NUL terminate strings, just to make sure */
    n->text[size] = 0;

    return n;
}

CattaStringList *catta_string_list_add_arbitrary(CattaStringList *l, const uint8_t*text, size_t size) {
    CattaStringList *n;

    assert(size == 0 || text);

    if (!(n = catta_string_list_add_anonymous(l, size)))
        return NULL;

    if (size > 0)
        memcpy(n->text, text, size);

    return n;
}

CattaStringList *catta_string_list_add(CattaStringList *l, const char *text) {
    assert(text);

    return catta_string_list_add_arbitrary(l, (const uint8_t*) text, strlen(text));
}

int catta_string_list_parse(const void* data, size_t size, CattaStringList **ret) {
    const uint8_t *c;
    CattaStringList *r = NULL;

    assert(data);
    assert(ret);

    c = data;
    while (size > 0) {
        size_t k;

        k = *(c++);
        size--;

        if (k > size)
            goto fail; /* Overflow */

        if (k > 0) { /* Ignore empty strings */
            CattaStringList *n;

            if (!(n = catta_string_list_add_arbitrary(r, c, k)))
                goto fail; /* OOM */

            r = n;
        }

        c += k;
        size -= k;
    }

    *ret = r;

    return 0;

fail:
    catta_string_list_free(r);
    return -1;
}

void catta_string_list_free(CattaStringList *l) {
    CattaStringList *n;

    while (l) {
        n = l->next;
        catta_free(l);
        l = n;
    }
}

CattaStringList* catta_string_list_reverse(CattaStringList *l) {
    CattaStringList *r = NULL, *n;

    while (l) {
        n = l->next;
        l->next = r;
        r = l;
        l = n;
    }

    return r;
}

char* catta_string_list_to_string(CattaStringList *l) {
    CattaStringList *n;
    size_t s = 0;
    char *t, *e;

    for (n = l; n; n = n->next) {
        if (n != l)
            s ++;

        s += n->size+2;
    }

    if (!(t = e = catta_new(char, s+1)))
        return NULL;

    l = catta_string_list_reverse(l);

    for (n = l; n; n = n->next) {
        if (n != l)
            *(e++) = ' ';

        *(e++) = '"';
        strncpy(e, (char*) n->text, n->size);
        e[n->size] = 0;
        e = strchr(e, 0);
        *(e++) = '"';

        assert(e);
    }

    l = catta_string_list_reverse(l);

    *e = 0;

    return t;
}

size_t catta_string_list_serialize(CattaStringList *l, void *data, size_t size) {
    size_t used = 0;

    if (data) {
        CattaStringList *n;
        uint8_t *c;

        l = catta_string_list_reverse(l);
        c = data;

        for (n = l; size > 1 && n; n = n->next) {
            size_t k;

            if ((k = n->size) == 0)
                /* Skip empty strings */
                continue;

            if (k > 255)
                /* Truncate strings at 255 characters */
                k = 255;

            if (k > size-1)
                /* Make sure this string fits in */
                k = size-1;

            *(c++) = (uint8_t) k;
            memcpy(c, n->text, k);
            c += k;

            used += 1 + k;
            size -= 1 + k;
        }

        l = catta_string_list_reverse(l);

        if (used == 0 && size > 0) {

            /* Empty lists are treated specially. To comply with
             * section 6.1 of the DNS-SD spec, we return a single
             * empty string (i.e. a NUL byte)*/

            *(uint8_t*) data = 0;
            used = 1;
        }

    } else {
        CattaStringList *n;

        for (n = l; n; n = n->next) {
            size_t k;

            if ((k = n->size) == 0)
                continue;

            if (k > 255)
                k = 255;

            used += 1+k;
        }

        if (used == 0)
            used = 1;
    }

    return used;
}

int catta_string_list_equal(const CattaStringList *a, const CattaStringList *b) {

    for (;;) {
        if (!a && !b)
            return 1;

        if (!a || !b)
            return 0;

        if (a->size != b->size)
            return 0;

        if (a->size != 0 && memcmp(a->text, b->text, a->size) != 0)
            return 0;

        a = a->next;
        b = b->next;
    }
}

CattaStringList *catta_string_list_add_many(CattaStringList *r, ...) {
    va_list va;

    va_start(va, r);
    r = catta_string_list_add_many_va(r, va);
    va_end(va);

    return r;
}

CattaStringList *catta_string_list_add_many_va(CattaStringList *r, va_list va) {
    const char *txt;

    while ((txt = va_arg(va, const char*)))
        r = catta_string_list_add(r, txt);

    return r;
}

CattaStringList *catta_string_list_new(const char *txt, ...) {
    va_list va;
    CattaStringList *r = NULL;

    if (txt) {
        r = catta_string_list_add(r, txt);

        va_start(va, txt);
        r = catta_string_list_add_many_va(r, va);
        va_end(va);
    }

    return r;
}

CattaStringList *catta_string_list_new_va(va_list va) {
    return catta_string_list_add_many_va(NULL, va);
}

CattaStringList *catta_string_list_copy(const CattaStringList *l) {
    CattaStringList *r = NULL;

    for (; l; l = l->next)
        if (!(r = catta_string_list_add_arbitrary(r, l->text, l->size))) {
            catta_string_list_free(r);
            return NULL;
        }

    return catta_string_list_reverse(r);
}

CattaStringList *catta_string_list_new_from_array(const char *array[], int length) {
    CattaStringList *r = NULL;
    int i;

    assert(array);

    for (i = 0; length >= 0 ? i < length : !!array[i]; i++)
        r = catta_string_list_add(r, array[i]);

    return r;
}

unsigned catta_string_list_length(const CattaStringList *l) {
    unsigned n = 0;

    for (; l; l = l->next)
        n++;

    return n;
}

CattaStringList *catta_string_list_add_vprintf(CattaStringList *l, const char *format, va_list va) {
    size_t len = 80;
    CattaStringList *r;

    assert(format);

    if (!(r = catta_malloc(sizeof(CattaStringList) + len)))
        return NULL;

    for (;;) {
        int n;
        CattaStringList *nr;
        va_list va2;

        va_copy(va2, va);
        n = vsnprintf((char*) r->text, len, format, va2);
        va_end(va2);

        if (n >= 0 && n < (int) len)
            break;

        if (n >= 0)
            len = n+1;
        else
            len *= 2;

        if (!(nr = catta_realloc(r, sizeof(CattaStringList) + len))) {
            catta_free(r);
            return NULL;
        }

        r = nr;
    }

    r->next = l;
    r->size = strlen((char*) r->text);

    return r;
}

CattaStringList *catta_string_list_add_printf(CattaStringList *l, const char *format, ...) {
    va_list va;

    assert(format);

    va_start(va, format);
    l  = catta_string_list_add_vprintf(l, format, va);
    va_end(va);

    return l;
}

CattaStringList *catta_string_list_find(CattaStringList *l, const char *key) {
    size_t n;

    assert(key);
    n = strlen(key);

    for (; l; l = l->next) {
        if (strcasecmp((char*) l->text, key) == 0)
            return l;

        if (strncasecmp((char*) l->text, key, n) == 0 && l->text[n] == '=')
            return l;
    }

    return NULL;
}

CattaStringList *catta_string_list_add_pair(CattaStringList *l, const char *key, const char *value) {
    assert(key);

    if (value)
        return catta_string_list_add_printf(l, "%s=%s", key, value);
    else
        return catta_string_list_add(l, key);
}

CattaStringList *catta_string_list_add_pair_arbitrary(CattaStringList *l, const char *key, const uint8_t *value, size_t size) {
    size_t n;
    assert(key);

    if (!value)
        return catta_string_list_add(l, key);

    n = strlen(key);

    if (!(l = catta_string_list_add_anonymous(l, n + 1 + size)))
        return NULL;

    memcpy(l->text, key, n);
    l->text[n] = '=';
    memcpy(l->text + n + 1, value, size);

    return l;
}

int catta_string_list_get_pair(CattaStringList *l, char **key, char **value, size_t *size) {
    char *e;

    assert(l);

    if (!(e = memchr(l->text, '=', l->size))) {

        if (key)
            if (!(*key = catta_strdup((char*) l->text)))
                return -1;

        if (value)
            *value = NULL;

        if (size)
            *size = 0;

    } else {
        size_t n;

        if (key)
            if (!(*key = catta_strndup((char*) l->text, e - (char *) l->text)))
                return -1;

        e++; /* Advance after '=' */

        n = l->size - (e - (char*) l->text);

        if (value) {

            if (!(*value = catta_memdup(e, n+1))) {
                if (key)
                    catta_free(*key);
                return -1;
            }

            (*value)[n] = 0;
        }

        if (size)
            *size = n;
    }

    return 0;
}

CattaStringList *catta_string_list_get_next(CattaStringList *l) {
    assert(l);
    return l->next;
}

uint8_t *catta_string_list_get_text(CattaStringList *l) {
    assert(l);
    return l->text;
}

size_t catta_string_list_get_size(CattaStringList *l) {
    assert(l);
    return l->size;
}

uint32_t catta_string_list_get_service_cookie(CattaStringList *l) {
    CattaStringList *f;
    char *value = NULL, *end = NULL;
    uint32_t ret;

    if (!(f = catta_string_list_find(l, CATTA_SERVICE_COOKIE)))
        return CATTA_SERVICE_COOKIE_INVALID;

    if (catta_string_list_get_pair(f, NULL, &value, NULL) < 0 || !value)
        return CATTA_SERVICE_COOKIE_INVALID;

    ret = (uint32_t) strtoll(value, &end, 0);

    if (*value && end && *end != 0) {
        catta_free(value);
        return CATTA_SERVICE_COOKIE_INVALID;
    }

    catta_free(value);

    return ret;
}
