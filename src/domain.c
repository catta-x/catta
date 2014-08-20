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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>

#include <catta/domain.h>
#include <catta/malloc.h>
#include <catta/error.h>
#include <catta/address.h>
#include "utf8.h"

/* Read the first label from string *name, unescape "\" and write it to dest */
char *catta_unescape_label(const char **name, char *dest, size_t size) {
    unsigned i = 0;
    char *d;

    assert(dest);
    assert(size > 0);
    assert(name);

    d = dest;

    for (;;) {
        if (i >= size)
            return NULL;

        if (**name == '.') {
            (*name)++;
            break;
        }

        if (**name == 0)
            break;

        if (**name == '\\') {
            /* Escaped character */

            (*name) ++;

            if (**name == 0)
                /* Ending NUL */
                return NULL;

            else if (**name == '\\' || **name == '.') {
                /* Escaped backslash or dot */
                *(d++) = *((*name) ++);
                i++;
            } else if (isdigit(**name)) {
                int n;

                /* Escaped literal ASCII character */

                if (!isdigit(*(*name+1)) || !isdigit(*(*name+2)))
                    return NULL;

                n = ((uint8_t) (**name - '0') * 100) + ((uint8_t) (*(*name+1) - '0') * 10) + ((uint8_t) (*(*name +2) - '0'));

                if (n > 255 || n == 0)
                    return NULL;

                *(d++) = (char) n;
                i++;

                (*name) += 3;
            } else
                return NULL;

        } else {

            /* Normal character */

            *(d++) = *((*name) ++);
            i++;
        }
    }

    assert(i < size);

    *d = 0;

    if (!catta_utf8_valid(dest))
        return NULL;

    return dest;
}

/* Escape "\" and ".", append \0 */
char *catta_escape_label(const char* src, size_t src_length, char **ret_name, size_t *ret_size) {
    char *r;

    assert(src);
    assert(ret_name);
    assert(*ret_name);
    assert(ret_size);
    assert(*ret_size > 0);

    r = *ret_name;

    while (src_length > 0) {
        if (*src == '.' || *src == '\\') {

            /* Dot or backslash */

            if (*ret_size < 3)
                return NULL;

            *((*ret_name) ++) = '\\';
            *((*ret_name) ++) = *src;
            (*ret_size) -= 2;

        } else if (
            *src == '_' ||
            *src == '-' ||
            (*src >= '0' && *src <= '9') ||
            (*src >= 'a' && *src <= 'z') ||
            (*src >= 'A' && *src <= 'Z')) {

            /* Proper character */

            if (*ret_size < 2)
                return NULL;

            *((*ret_name)++) = *src;
            (*ret_size) --;

        } else {

            /* Everything else */

            if (*ret_size < 5)
                return NULL;

            *((*ret_name) ++) = '\\';
            *((*ret_name) ++) = '0' + (char)  ((uint8_t) *src / 100);
            *((*ret_name) ++) = '0' + (char) (((uint8_t) *src / 10) % 10);
            *((*ret_name) ++) = '0' + (char)  ((uint8_t) *src % 10);

            (*ret_size) -= 4;
        }

        src_length --;
        src++;
    }

    **ret_name = 0;

    return r;
}

char *catta_normalize_name(const char *s, char *ret_s, size_t size) {
    int empty = 1;
    char *r;

    assert(s);
    assert(ret_s);
    assert(size > 0);

    r = ret_s;
    *ret_s = 0;

    while (*s) {
        char label[CATTA_LABEL_MAX];

        if (!(catta_unescape_label(&s, label, sizeof(label))))
            return NULL;

        if (label[0] == 0) {

            if (*s == 0 && empty)
                return ret_s;

            return NULL;
        }

        if (!empty) {
            if (size < 1)
                return NULL;

            *(r++) = '.';
            size--;

        } else
            empty = 0;

        catta_escape_label(label, strlen(label), &r, &size);
    }

    return ret_s;
}

char *catta_normalize_name_strdup(const char *s) {
    char t[CATTA_DOMAIN_NAME_MAX];
    assert(s);

    if (!(catta_normalize_name(s, t, sizeof(t))))
        return NULL;

    return catta_strdup(t);
}

int catta_domain_equal(const char *a, const char *b) {
    assert(a);
    assert(b);

    if (a == b)
        return 1;

    for (;;) {
        char ca[CATTA_LABEL_MAX], cb[CATTA_LABEL_MAX], *r;

        r = catta_unescape_label(&a, ca, sizeof(ca));
        assert(r);
        r = catta_unescape_label(&b, cb, sizeof(cb));
        assert(r);

        if (strcasecmp(ca, cb))
            return 0;

        if (!*a && !*b)
            return 1;
    }

    return 1;
}

int catta_is_valid_service_type_generic(const char *t) {
    assert(t);

    if (strlen(t) >= CATTA_DOMAIN_NAME_MAX || !*t)
        return 0;

    do {
        char label[CATTA_LABEL_MAX];

        if (!(catta_unescape_label(&t, label, sizeof(label))))
            return 0;

        if (strlen(label) <= 2 || label[0] != '_')
            return 0;

    } while (*t);

    return 1;
}

int catta_is_valid_service_type_strict(const char *t) {
    char label[CATTA_LABEL_MAX];
    assert(t);

    if (strlen(t) >= CATTA_DOMAIN_NAME_MAX || !*t)
        return 0;

    /* Application name */

    if (!(catta_unescape_label(&t, label, sizeof(label))))
        return 0;

    if (strlen(label) <= 2 || label[0] != '_')
        return 0;

    if (!*t)
        return 0;

    /* _tcp or _udp boilerplate */

    if (!(catta_unescape_label(&t, label, sizeof(label))))
        return 0;

    if (strcasecmp(label, "_tcp") && strcasecmp(label, "_udp"))
        return 0;

    if (*t)
        return 0;

    return 1;
}

const char *catta_get_type_from_subtype(const char *t) {
    char label[CATTA_LABEL_MAX];
    const char *ret;
    assert(t);

    if (strlen(t) >= CATTA_DOMAIN_NAME_MAX || !*t)
        return NULL;

    /* Subtype name */

    if (!(catta_unescape_label(&t, label, sizeof(label))))
        return NULL;

    if (strlen(label) <= 2 || label[0] != '_')
        return NULL;

    if (!*t)
        return NULL;

    /* String "_sub" */

    if (!(catta_unescape_label(&t, label, sizeof(label))))
        return NULL;

    if (strcasecmp(label, "_sub"))
        return NULL;

    if (!*t)
        return NULL;

    ret = t;

    /* Application name */

    if (!(catta_unescape_label(&t, label, sizeof(label))))
        return NULL;

    if (strlen(label) <= 2 || label[0] != '_')
        return NULL;

    if (!*t)
        return NULL;

    /* _tcp or _udp boilerplate */

    if (!(catta_unescape_label(&t, label, sizeof(label))))
        return NULL;

    if (strcasecmp(label, "_tcp") && strcasecmp(label, "_udp"))
        return NULL;

    if (*t)
        return NULL;

    return ret;
}

int catta_is_valid_service_subtype(const char *t) {
    assert(t);

    return !!catta_get_type_from_subtype(t);
}

int catta_is_valid_domain_name(const char *t) {
    int is_first = 1;
    assert(t);

    if (strlen(t) >= CATTA_DOMAIN_NAME_MAX)
        return 0;

    do {
        char label[CATTA_LABEL_MAX];

        if (!(catta_unescape_label(&t, label, sizeof(label))))
            return 0;

        /* Explicitly allow the root domain name */
        if (is_first && label[0] == 0 && *t == 0)
            return 1;

        is_first = 0;

        if (label[0] == 0)
            return 0;

    } while (*t);

    return 1;
}

int catta_is_valid_service_name(const char *t) {
    assert(t);

    if (strlen(t) >= CATTA_LABEL_MAX || !*t)
        return 0;

    return 1;
}

int catta_is_valid_host_name(const char *t) {
    char label[CATTA_LABEL_MAX];
    assert(t);

    if (strlen(t) >= CATTA_DOMAIN_NAME_MAX || !*t)
        return 0;

    if (!(catta_unescape_label(&t, label, sizeof(label))))
        return 0;

    if (strlen(label) < 1)
        return 0;

    if (*t)
        return 0;

    return 1;
}

unsigned catta_domain_hash(const char *s) {
    unsigned hash = 0;

    while (*s) {
        char c[CATTA_LABEL_MAX], *p, *r;

        r = catta_unescape_label(&s, c, sizeof(c));
        assert(r);

        for (p = c; *p; p++)
            hash = 31 * hash + tolower(*p);
    }

    return hash;
}

int catta_service_name_join(char *p, size_t size, const char *name, const char *type, const char *domain) {
    char escaped_name[CATTA_LABEL_MAX*4];
    char normalized_type[CATTA_DOMAIN_NAME_MAX];
    char normalized_domain[CATTA_DOMAIN_NAME_MAX];

    assert(p);

    /* Validity checks */

    if ((name && !catta_is_valid_service_name(name)))
        return CATTA_ERR_INVALID_SERVICE_NAME;

    if (!catta_is_valid_service_type_generic(type))
        return CATTA_ERR_INVALID_SERVICE_TYPE;

    if (!catta_is_valid_domain_name(domain))
        return CATTA_ERR_INVALID_DOMAIN_NAME;

    /* Preparation */

    if (name) {
        size_t l = sizeof(escaped_name);
        char *e = escaped_name, *r;
        r = catta_escape_label(name, strlen(name), &e, &l);
        assert(r);
    }

    if (!(catta_normalize_name(type, normalized_type, sizeof(normalized_type))))
        return CATTA_ERR_INVALID_SERVICE_TYPE;

    if (!(catta_normalize_name(domain, normalized_domain, sizeof(normalized_domain))))
        return CATTA_ERR_INVALID_DOMAIN_NAME;

    /* Concatenation */

    snprintf(p, size, "%s%s%s.%s", name ? escaped_name : "", name ? "." : "", normalized_type, normalized_domain);

    return CATTA_OK;
}

#ifndef HAVE_STRLCPY

static size_t strlcpy(char *dest, const char *src, size_t n) {
    assert(dest);
    assert(src);

    if (n > 0) {
        strncpy(dest, src, n-1);
        dest[n-1] = 0;
    }

    return strlen(src);
}

#endif

int catta_service_name_split(const char *p, char *name, size_t name_size, char *type, size_t type_size, char *domain, size_t domain_size) {
    enum {
        NAME,
        TYPE,
        DOMAIN
    } state;
    int type_empty = 1, domain_empty = 1;

    assert(p);
    assert(type);
    assert(type_size > 0);
    assert(domain);
    assert(domain_size > 0);

    if (name) {
        assert(name_size > 0);
        *name = 0;
        state = NAME;
    } else
        state = TYPE;

    *type = *domain = 0;

    while (*p) {
        char buf[64];

        if (!(catta_unescape_label(&p, buf, sizeof(buf))))
            return -1;

        switch (state) {
            case NAME:
                strlcpy(name, buf, name_size);
                state = TYPE;
                break;

            case TYPE:

                if (buf[0] == '_') {

                    if (!type_empty) {
                        if (!type_size)
                            return CATTA_ERR_NO_MEMORY;

                        *(type++) = '.';
                        type_size --;

                    } else
                        type_empty = 0;

                    if (!(catta_escape_label(buf, strlen(buf), &type, &type_size)))
                        return CATTA_ERR_NO_MEMORY;

                    break;
                }

                state = DOMAIN;
                /* fall through */

            case DOMAIN:

                if (!domain_empty) {
                    if (!domain_size)
                        return CATTA_ERR_NO_MEMORY;

                    *(domain++) = '.';
                    domain_size --;
                } else
                    domain_empty = 0;

                if (!(catta_escape_label(buf, strlen(buf), &domain, &domain_size)))
                    return CATTA_ERR_NO_MEMORY;

                break;
        }
    }

    return 0;
}

int catta_is_valid_fqdn(const char *t) {
    char label[CATTA_LABEL_MAX];
    char normalized[CATTA_DOMAIN_NAME_MAX];
    const char *k = t;
    CattaAddress a;
    assert(t);

    if (strlen(t) >= CATTA_DOMAIN_NAME_MAX)
        return 0;

    if (!catta_is_valid_domain_name(t))
        return 0;

    /* Check if there are at least two labels*/
    if (!(catta_unescape_label(&k, label, sizeof(label))))
        return 0;

    if (label[0] == 0 || !k)
        return 0;

    if (!(catta_unescape_label(&k, label, sizeof(label))))
        return 0;

    if (label[0] == 0 || !k)
        return 0;

    /* Make sure that the name is not an IP address */
    if (!(catta_normalize_name(t, normalized, sizeof(normalized))))
        return 0;

    if (catta_address_parse(normalized, CATTA_PROTO_UNSPEC, &a))
        return 0;

    return 1;
}
