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
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#include <catta/alternative.h>
#include <catta/malloc.h>
#include <catta/domain.h>
#include "utf8.h"

static void drop_incomplete_utf8(char *c) {
    char *e;

    e = strchr(c, 0) - 1;

    while (e >= c) {

        if (catta_utf8_valid(c))
            break;

        assert(*e & 128);
        *e = 0;

        e--;
    }
}

char *catta_alternative_host_name(const char *s) {
    const char *e;
    char *r;

    assert(s);

    if (!catta_is_valid_host_name(s))
        return NULL;

    if ((e = strrchr(s, '-'))) {
        const char *p;

        e++;

        for (p = e; *p; p++)
            if (!isdigit(*p)) {
                e = NULL;
                break;
            }

        if (e && (*e == '0' || *e == 0))
            e = NULL;
    }

    if (e) {
        char *c, *m;
        size_t l;
        int n;

        n = atoi(e)+1;
        if (!(m = catta_strdup_printf("%i", n)))
            return NULL;

        l = e-s-1;

        if (l >= CATTA_LABEL_MAX-1-strlen(m)-1)
            l = CATTA_LABEL_MAX-1-strlen(m)-1;

        if (!(c = catta_strndup(s, l))) {
            catta_free(m);
            return NULL;
        }

        drop_incomplete_utf8(c);

        r = catta_strdup_printf("%s-%s", c, m);
        catta_free(c);
        catta_free(m);

    } else {
        char *c;

        if (!(c = catta_strndup(s, CATTA_LABEL_MAX-1-2)))
            return NULL;

        drop_incomplete_utf8(c);

        r = catta_strdup_printf("%s-2", c);
        catta_free(c);
    }

    assert(catta_is_valid_host_name(r));

    return r;
}

char *catta_alternative_service_name(const char *s) {
    const char *e;
    char *r;

    assert(s);

    if (!catta_is_valid_service_name(s))
        return NULL;

    if ((e = strstr(s, " #"))) {
        const char *n, *p;
        e += 2;

        while ((n = strstr(e, " #")))
            e = n + 2;

        for (p = e; *p; p++)
            if (!isdigit(*p)) {
                e = NULL;
                break;
            }

        if (e && (*e == '0' || *e == 0))
            e = NULL;
    }

    if (e) {
        char *c, *m;
        size_t l;
        int n;

        n = atoi(e)+1;
        if (!(m = catta_strdup_printf("%i", n)))
            return NULL;

        l = e-s-2;

        if (l >= CATTA_LABEL_MAX-1-strlen(m)-2)
            l = CATTA_LABEL_MAX-1-strlen(m)-2;

        if (!(c = catta_strndup(s, l))) {
            catta_free(m);
            return NULL;
        }

        drop_incomplete_utf8(c);

        r = catta_strdup_printf("%s #%s", c, m);
        catta_free(c);
        catta_free(m);
    } else {
        char *c;

        if (!(c = catta_strndup(s, CATTA_LABEL_MAX-1-3)))
            return NULL;

        drop_incomplete_utf8(c);

        r = catta_strdup_printf("%s #2", c);
        catta_free(c);
    }

    assert(catta_is_valid_service_name(r));

    return r;
}
