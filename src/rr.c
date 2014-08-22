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
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>

#include <catta/domain.h>
#include <catta/malloc.h>
#include <catta/defs.h>

#include <catta/rr.h>
#include <catta/log.h>
#include "util.h"
#include "hashmap.h"
#include "domain-util.h"
#include "rr-util.h"
#include "addr-util.h"

CattaKey *catta_key_new(const char *name, uint16_t class, uint16_t type) {
    CattaKey *k;
    assert(name);

    if (!(k = catta_new(CattaKey, 1))) {
        catta_log_error("catta_new() failed.");
        return NULL;
    }

    if (!(k->name = catta_normalize_name_strdup(name))) {
        catta_log_error("catta_normalize_name() failed.");
        catta_free(k);
        return NULL;
    }

    k->ref = 1;
    k->clazz = class;
    k->type = type;

    return k;
}

CattaKey *catta_key_new_cname(CattaKey *key) {
    assert(key);

    if (key->clazz != CATTA_DNS_CLASS_IN)
        return NULL;

    if (key->type == CATTA_DNS_TYPE_CNAME)
        return NULL;

    return catta_key_new(key->name, key->clazz, CATTA_DNS_TYPE_CNAME);
}

CattaKey *catta_key_ref(CattaKey *k) {
    assert(k);
    assert(k->ref >= 1);

    k->ref++;

    return k;
}

void catta_key_unref(CattaKey *k) {
    assert(k);
    assert(k->ref >= 1);

    if ((--k->ref) <= 0) {
        catta_free(k->name);
        catta_free(k);
    }
}

CattaRecord *catta_record_new(CattaKey *k, uint32_t ttl) {
    CattaRecord *r;

    assert(k);

    if (!(r = catta_new(CattaRecord, 1))) {
        catta_log_error("catta_new() failed.");
        return NULL;
    }

    r->ref = 1;
    r->key = catta_key_ref(k);

    memset(&r->data, 0, sizeof(r->data));

    r->ttl = ttl != (uint32_t) -1 ? ttl : CATTA_DEFAULT_TTL;

    return r;
}

CattaRecord *catta_record_new_full(const char *name, uint16_t class, uint16_t type, uint32_t ttl) {
    CattaRecord *r;
    CattaKey *k;

    assert(name);

    if (!(k = catta_key_new(name, class, type))) {
        catta_log_error("catta_key_new() failed.");
        return NULL;
    }

    r = catta_record_new(k, ttl);
    catta_key_unref(k);

    if (!r) {
        catta_log_error("catta_record_new() failed.");
        return NULL;
    }

    return r;
}

CattaRecord *catta_record_ref(CattaRecord *r) {
    assert(r);
    assert(r->ref >= 1);

    r->ref++;
    return r;
}

void catta_record_unref(CattaRecord *r) {
    assert(r);
    assert(r->ref >= 1);

    if ((--r->ref) <= 0) {
        switch (r->key->type) {

            case CATTA_DNS_TYPE_SRV:
                catta_free(r->data.srv.name);
                break;

            case CATTA_DNS_TYPE_PTR:
            case CATTA_DNS_TYPE_CNAME:
            case CATTA_DNS_TYPE_NS:
                catta_free(r->data.ptr.name);
                break;

            case CATTA_DNS_TYPE_HINFO:
                catta_free(r->data.hinfo.cpu);
                catta_free(r->data.hinfo.os);
                break;

            case CATTA_DNS_TYPE_TXT:
                catta_string_list_free(r->data.txt.string_list);
                break;

            case CATTA_DNS_TYPE_A:
            case CATTA_DNS_TYPE_AAAA:
                break;

            default:
                catta_free(r->data.generic.data);
        }

        catta_key_unref(r->key);
        catta_free(r);
    }
}

const char *catta_dns_class_to_string(uint16_t class) {
    if (class & CATTA_DNS_CACHE_FLUSH)
        return "FLUSH";

    switch (class) {
        case CATTA_DNS_CLASS_IN:
            return "IN";
        case CATTA_DNS_CLASS_ANY:
            return "ANY";
        default:
            return NULL;
    }
}

const char *catta_dns_type_to_string(uint16_t type) {
    switch (type) {
        case CATTA_DNS_TYPE_CNAME:
            return "CNAME";
        case CATTA_DNS_TYPE_A:
            return "A";
        case CATTA_DNS_TYPE_AAAA:
            return "AAAA";
        case CATTA_DNS_TYPE_PTR:
            return "PTR";
        case CATTA_DNS_TYPE_HINFO:
            return "HINFO";
        case CATTA_DNS_TYPE_TXT:
            return "TXT";
        case CATTA_DNS_TYPE_SRV:
            return "SRV";
        case CATTA_DNS_TYPE_ANY:
            return "ANY";
        case CATTA_DNS_TYPE_SOA:
            return "SOA";
        case CATTA_DNS_TYPE_NS:
            return "NS";
        default:
            return NULL;
    }
}

char *catta_key_to_string(const CattaKey *k) {
    char class[16], type[16];
    const char *c, *t;

    assert(k);
    assert(k->ref >= 1);

    /* According to RFC3597 */

    if (!(c = catta_dns_class_to_string(k->clazz))) {
        snprintf(class, sizeof(class), "CLASS%u", k->clazz);
        c = class;
    }

    if (!(t = catta_dns_type_to_string(k->type))) {
        snprintf(type, sizeof(type), "TYPE%u", k->type);
        t = type;
    }

    return catta_strdup_printf("%s\t%s\t%s", k->name, c, t);
}

char *catta_record_to_string(const CattaRecord *r) {
    char *p, *s;
    char buf[1024], *t = NULL, *d = NULL;

    assert(r);
    assert(r->ref >= 1);

    switch (r->key->type) {
        case CATTA_DNS_TYPE_A:
            inet_ntop(AF_INET, &r->data.a.address.address, t = buf, sizeof(buf));
            break;

        case CATTA_DNS_TYPE_AAAA:
            inet_ntop(AF_INET6, &r->data.aaaa.address.address, t = buf, sizeof(buf));
            break;

        case CATTA_DNS_TYPE_PTR:
        case CATTA_DNS_TYPE_CNAME:
        case CATTA_DNS_TYPE_NS:

            t = r->data.ptr.name;
            break;

        case CATTA_DNS_TYPE_TXT:
            t = d = catta_string_list_to_string(r->data.txt.string_list);
            break;

        case CATTA_DNS_TYPE_HINFO:

            snprintf(t = buf, sizeof(buf), "\"%s\" \"%s\"", r->data.hinfo.cpu, r->data.hinfo.os);
            break;

        case CATTA_DNS_TYPE_SRV:

            snprintf(t = buf, sizeof(buf), "%u %u %u %s",
                     r->data.srv.priority,
                     r->data.srv.weight,
                     r->data.srv.port,
                     r->data.srv.name);

            break;

        default: {

            uint8_t *c;
            uint16_t n;
            int i;
            char *e;

            /* According to RFC3597 */

            snprintf(t = buf, sizeof(buf), "\\# %u", r->data.generic.size);

            e = strchr(t, 0);

            for (c = r->data.generic.data, n = r->data.generic.size, i = 0;
                 n > 0 && i < 20;
                 c ++, n --, i++) {

                sprintf(e, " %02X", *c);
                e = strchr(e, 0);
            }

            break;
        }
    }

    p = catta_key_to_string(r->key);
    s = catta_strdup_printf("%s %s ; ttl=%u", p, t, r->ttl);
    catta_free(p);
    catta_free(d);

    return s;
}

int catta_key_equal(const CattaKey *a, const CattaKey *b) {
    assert(a);
    assert(b);

    if (a == b)
        return 1;

    return catta_domain_equal(a->name, b->name) &&
        a->type == b->type &&
        a->clazz == b->clazz;
}

int catta_key_pattern_match(const CattaKey *pattern, const CattaKey *k) {
    assert(pattern);
    assert(k);

    assert(!catta_key_is_pattern(k));

    if (pattern == k)
        return 1;

    return catta_domain_equal(pattern->name, k->name) &&
        (pattern->type == k->type || pattern->type == CATTA_DNS_TYPE_ANY) &&
        (pattern->clazz == k->clazz || pattern->clazz == CATTA_DNS_CLASS_ANY);
}

int catta_key_is_pattern(const CattaKey *k) {
    assert(k);

    return
        k->type == CATTA_DNS_TYPE_ANY ||
        k->clazz == CATTA_DNS_CLASS_ANY;
}

unsigned catta_key_hash(const CattaKey *k) {
    assert(k);

    return
        catta_domain_hash(k->name) +
        k->type +
        k->clazz;
}

static int rdata_equal(const CattaRecord *a, const CattaRecord *b) {
    assert(a);
    assert(b);
    assert(a->key->type == b->key->type);

    switch (a->key->type) {
        case CATTA_DNS_TYPE_SRV:
            return
                a->data.srv.priority == b->data.srv.priority &&
                a->data.srv.weight == b->data.srv.weight &&
                a->data.srv.port == b->data.srv.port &&
                catta_domain_equal(a->data.srv.name, b->data.srv.name);

        case CATTA_DNS_TYPE_PTR:
        case CATTA_DNS_TYPE_CNAME:
        case CATTA_DNS_TYPE_NS:
            return catta_domain_equal(a->data.ptr.name, b->data.ptr.name);

        case CATTA_DNS_TYPE_HINFO:
            return
                !strcmp(a->data.hinfo.cpu, b->data.hinfo.cpu) &&
                !strcmp(a->data.hinfo.os, b->data.hinfo.os);

        case CATTA_DNS_TYPE_TXT:
            return catta_string_list_equal(a->data.txt.string_list, b->data.txt.string_list);

        case CATTA_DNS_TYPE_A:
            return memcmp(&a->data.a.address, &b->data.a.address, sizeof(CattaIPv4Address)) == 0;

        case CATTA_DNS_TYPE_AAAA:
            return memcmp(&a->data.aaaa.address, &b->data.aaaa.address, sizeof(CattaIPv6Address)) == 0;

        default:
            return a->data.generic.size == b->data.generic.size &&
                (a->data.generic.size == 0 || memcmp(a->data.generic.data, b->data.generic.data, a->data.generic.size) == 0);
    }

}

int catta_record_equal_no_ttl(const CattaRecord *a, const CattaRecord *b) {
    assert(a);
    assert(b);

    if (a == b)
        return 1;

    return
        catta_key_equal(a->key, b->key) &&
        rdata_equal(a, b);
}


CattaRecord *catta_record_copy(CattaRecord *r) {
    CattaRecord *copy;

    if (!(copy = catta_new(CattaRecord, 1))) {
        catta_log_error("catta_new() failed.");
        return NULL;
    }

    copy->ref = 1;
    copy->key = catta_key_ref(r->key);
    copy->ttl = r->ttl;

    switch (r->key->type) {
        case CATTA_DNS_TYPE_PTR:
        case CATTA_DNS_TYPE_CNAME:
        case CATTA_DNS_TYPE_NS:
            if (!(copy->data.ptr.name = catta_strdup(r->data.ptr.name)))
                goto fail;
            break;

        case CATTA_DNS_TYPE_SRV:
            copy->data.srv.priority = r->data.srv.priority;
            copy->data.srv.weight = r->data.srv.weight;
            copy->data.srv.port = r->data.srv.port;
            if (!(copy->data.srv.name = catta_strdup(r->data.srv.name)))
                goto fail;
            break;

        case CATTA_DNS_TYPE_HINFO:
            if (!(copy->data.hinfo.os = catta_strdup(r->data.hinfo.os)))
                goto fail;

            if (!(copy->data.hinfo.cpu = catta_strdup(r->data.hinfo.cpu))) {
                catta_free(r->data.hinfo.os);
                goto fail;
            }
            break;

        case CATTA_DNS_TYPE_TXT:
            copy->data.txt.string_list = catta_string_list_copy(r->data.txt.string_list);
            break;

        case CATTA_DNS_TYPE_A:
            copy->data.a.address = r->data.a.address;
            break;

        case CATTA_DNS_TYPE_AAAA:
            copy->data.aaaa.address = r->data.aaaa.address;
            break;

        default:
            if (!(copy->data.generic.data = catta_memdup(r->data.generic.data, r->data.generic.size)))
                goto fail;
            copy->data.generic.size = r->data.generic.size;
            break;

    }

    return copy;

fail:
    catta_log_error("Failed to allocate memory");

    catta_key_unref(copy->key);
    catta_free(copy);

    return NULL;
}


size_t catta_key_get_estimate_size(CattaKey *k) {
    assert(k);

    return strlen(k->name)+1+4;
}

size_t catta_record_get_estimate_size(CattaRecord *r) {
    size_t n;
    assert(r);

    n = catta_key_get_estimate_size(r->key) + 4 + 2;

    switch (r->key->type) {
        case CATTA_DNS_TYPE_PTR:
        case CATTA_DNS_TYPE_CNAME:
        case CATTA_DNS_TYPE_NS:
            n += strlen(r->data.ptr.name) + 1;
            break;

        case CATTA_DNS_TYPE_SRV:
            n += 6 + strlen(r->data.srv.name) + 1;
            break;

        case CATTA_DNS_TYPE_HINFO:
            n += strlen(r->data.hinfo.os) + 1 + strlen(r->data.hinfo.cpu) + 1;
            break;

        case CATTA_DNS_TYPE_TXT:
            n += catta_string_list_serialize(r->data.txt.string_list, NULL, 0);
            break;

        case CATTA_DNS_TYPE_A:
            n += sizeof(CattaIPv4Address);
            break;

        case CATTA_DNS_TYPE_AAAA:
            n += sizeof(CattaIPv6Address);
            break;

        default:
            n += r->data.generic.size;
    }

    return n;
}

static int lexicographical_memcmp(const void* a, size_t al, const void* b, size_t bl) {
    size_t c;
    int ret;

    assert(a);
    assert(b);

    c = al < bl ? al : bl;
    if ((ret = memcmp(a, b, c)))
        return ret;

    if (al == bl)
        return 0;
    else
        return al == c ? 1 : -1;
}

static int uint16_cmp(uint16_t a, uint16_t b) {
    return a == b ? 0 : (a < b ? -1 : 1);
}

int catta_record_lexicographical_compare(CattaRecord *a, CattaRecord *b) {
    int r;
/*      char *t1, *t2; */

    assert(a);
    assert(b);

/*     t1 = catta_record_to_string(a); */
/*     t2 = catta_record_to_string(b); */
/*     g_message("lexicocmp: %s %s", t1, t2); */
/*     catta_free(t1); */
/*     catta_free(t2); */

    if (a == b)
        return 0;

    if ((r = uint16_cmp(a->key->clazz, b->key->clazz)) ||
        (r = uint16_cmp(a->key->type, b->key->type)))
        return r;

    switch (a->key->type) {

        case CATTA_DNS_TYPE_PTR:
        case CATTA_DNS_TYPE_CNAME:
        case CATTA_DNS_TYPE_NS:
            return catta_binary_domain_cmp(a->data.ptr.name, b->data.ptr.name);

        case CATTA_DNS_TYPE_SRV: {
            if ((r = uint16_cmp(a->data.srv.priority, b->data.srv.priority)) == 0 &&
                (r = uint16_cmp(a->data.srv.weight, b->data.srv.weight)) == 0 &&
                (r = uint16_cmp(a->data.srv.port, b->data.srv.port)) == 0)
                r = catta_binary_domain_cmp(a->data.srv.name, b->data.srv.name);

            return r;
        }

        case CATTA_DNS_TYPE_HINFO: {

            if ((r = strcmp(a->data.hinfo.cpu, b->data.hinfo.cpu)) ||
                (r = strcmp(a->data.hinfo.os, b->data.hinfo.os)))
                return r;

            return 0;

        }

        case CATTA_DNS_TYPE_TXT: {

            uint8_t *ma = NULL, *mb = NULL;
            size_t asize, bsize;

            asize = catta_string_list_serialize(a->data.txt.string_list, NULL, 0);
            bsize = catta_string_list_serialize(b->data.txt.string_list, NULL, 0);

            if (asize > 0 && !(ma = catta_new(uint8_t, asize)))
                goto fail;

            if (bsize > 0 && !(mb = catta_new(uint8_t, bsize))) {
                catta_free(ma);
                goto fail;
            }

            catta_string_list_serialize(a->data.txt.string_list, ma, asize);
            catta_string_list_serialize(b->data.txt.string_list, mb, bsize);

            if (asize && bsize)
                r = lexicographical_memcmp(ma, asize, mb, bsize);
            else if (asize && !bsize)
                r = 1;
            else if (!asize && bsize)
                r = -1;
            else
                r = 0;

            catta_free(ma);
            catta_free(mb);

            return r;
        }

        case CATTA_DNS_TYPE_A:
            return memcmp(&a->data.a.address, &b->data.a.address, sizeof(CattaIPv4Address));

        case CATTA_DNS_TYPE_AAAA:
            return memcmp(&a->data.aaaa.address, &b->data.aaaa.address, sizeof(CattaIPv6Address));

        default:
            return lexicographical_memcmp(a->data.generic.data, a->data.generic.size,
                                          b->data.generic.data, b->data.generic.size);
    }


fail:
    catta_log_error(__FILE__": Out of memory");
    return -1; /* or whatever ... */
}

int catta_record_is_goodbye(CattaRecord *r) {
    assert(r);

    return r->ttl == 0;
}

int catta_key_is_valid(CattaKey *k) {
    assert(k);

    if (!catta_is_valid_domain_name(k->name))
        return 0;

    return 1;
}

int catta_record_is_valid(CattaRecord *r) {
    assert(r);

    if (!catta_key_is_valid(r->key))
        return 0;

    switch (r->key->type) {

        case CATTA_DNS_TYPE_PTR:
        case CATTA_DNS_TYPE_CNAME:
        case CATTA_DNS_TYPE_NS:
            return catta_is_valid_domain_name(r->data.ptr.name);

        case CATTA_DNS_TYPE_SRV:
            return catta_is_valid_domain_name(r->data.srv.name);

        case CATTA_DNS_TYPE_HINFO:
            return
                strlen(r->data.hinfo.os) <= 255 &&
                strlen(r->data.hinfo.cpu) <= 255;

        case CATTA_DNS_TYPE_TXT: {

            CattaStringList *strlst;

            for (strlst = r->data.txt.string_list; strlst; strlst = strlst->next)
                if (strlst->size > 255 || strlst->size <= 0)
                    return 0;

            return 1;
        }
    }

    return 1;
}

static CattaAddress *get_address(const CattaRecord *r, CattaAddress *a) {
    assert(r);

    switch (r->key->type) {
        case CATTA_DNS_TYPE_A:
            a->proto = CATTA_PROTO_INET;
            a->data.ipv4 = r->data.a.address;
            break;

        case CATTA_DNS_TYPE_AAAA:
            a->proto = CATTA_PROTO_INET6;
            a->data.ipv6 = r->data.aaaa.address;
            break;

        default:
            return NULL;
    }

    return a;
}

int catta_record_is_link_local_address(const CattaRecord *r) {
    CattaAddress a;

    assert(r);

    if (!get_address(r, &a))
        return 0;

    return catta_address_is_link_local(&a);
}
