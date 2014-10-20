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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <netinet/in.h>

#include <catta/defs.h>
#include <catta/domain.h>
#include <catta/malloc.h>

#include "dns.h"
#include <catta/log.h>

CattaDnsPacket* catta_dns_packet_new(unsigned mtu) {
    CattaDnsPacket *p;
    size_t max_size;

    if (mtu <= 0)
        max_size = CATTA_DNS_PACKET_SIZE_MAX;
    else if (mtu >= CATTA_DNS_PACKET_EXTRA_SIZE)
        max_size = mtu - CATTA_DNS_PACKET_EXTRA_SIZE;
    else
        max_size = 0;

    if (max_size < CATTA_DNS_PACKET_HEADER_SIZE)
        max_size = CATTA_DNS_PACKET_HEADER_SIZE;

    if (!(p = catta_malloc(sizeof(CattaDnsPacket) + max_size)))
        return p;

    p->size = p->rindex = CATTA_DNS_PACKET_HEADER_SIZE;
    p->max_size = max_size;
    p->name_table = NULL;
    p->data = NULL;

    memset(CATTA_DNS_PACKET_DATA(p), 0, p->size);
    return p;
}

CattaDnsPacket* catta_dns_packet_new_query(unsigned mtu) {
    CattaDnsPacket *p;

    if (!(p = catta_dns_packet_new(mtu)))
        return NULL;

    catta_dns_packet_set_field(p, CATTA_DNS_FIELD_FLAGS, CATTA_DNS_FLAGS(0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
    return p;
}

CattaDnsPacket* catta_dns_packet_new_response(unsigned mtu, int aa) {
    CattaDnsPacket *p;

    if (!(p = catta_dns_packet_new(mtu)))
        return NULL;

    catta_dns_packet_set_field(p, CATTA_DNS_FIELD_FLAGS, CATTA_DNS_FLAGS(1, 0, aa, 0, 0, 0, 0, 0, 0, 0));
    return p;
}

CattaDnsPacket* catta_dns_packet_new_reply(CattaDnsPacket* p, unsigned mtu, int copy_queries, int aa) {
    CattaDnsPacket *r;
    assert(p);

    if (!(r = catta_dns_packet_new_response(mtu, aa)))
        return NULL;

    if (copy_queries) {
        unsigned saved_rindex;
        uint32_t n;

        saved_rindex = p->rindex;
        p->rindex = CATTA_DNS_PACKET_HEADER_SIZE;

        for (n = catta_dns_packet_get_field(p, CATTA_DNS_FIELD_QDCOUNT); n > 0; n--) {
            CattaKey *k;
            int unicast_response;

            if ((k = catta_dns_packet_consume_key(p, &unicast_response))) {
                catta_dns_packet_append_key(r, k, unicast_response);
                catta_key_unref(k);
            }
        }

        p->rindex = saved_rindex;

        catta_dns_packet_set_field(r, CATTA_DNS_FIELD_QDCOUNT, catta_dns_packet_get_field(p, CATTA_DNS_FIELD_QDCOUNT));
    }

    catta_dns_packet_set_field(r, CATTA_DNS_FIELD_ID, catta_dns_packet_get_field(p, CATTA_DNS_FIELD_ID));

    catta_dns_packet_set_field(r, CATTA_DNS_FIELD_FLAGS,
                               (catta_dns_packet_get_field(r, CATTA_DNS_FIELD_FLAGS) & ~CATTA_DNS_FLAG_OPCODE) |
                               (catta_dns_packet_get_field(p, CATTA_DNS_FIELD_FLAGS) & CATTA_DNS_FLAG_OPCODE));

    return r;
}


void catta_dns_packet_free(CattaDnsPacket *p) {
    assert(p);

    if (p->name_table)
        catta_hashmap_free(p->name_table);

    catta_free(p);
}

void catta_dns_packet_set_field(CattaDnsPacket *p, unsigned idx, uint16_t v) {
    assert(p);
    assert(idx < CATTA_DNS_PACKET_HEADER_SIZE);

    ((uint16_t*) CATTA_DNS_PACKET_DATA(p))[idx] = htons(v);
}

uint16_t catta_dns_packet_get_field(CattaDnsPacket *p, unsigned idx) {
    assert(p);
    assert(idx < CATTA_DNS_PACKET_HEADER_SIZE);

    return ntohs(((uint16_t*) CATTA_DNS_PACKET_DATA(p))[idx]);
}

void catta_dns_packet_inc_field(CattaDnsPacket *p, unsigned idx) {
    assert(p);
    assert(idx < CATTA_DNS_PACKET_HEADER_SIZE);

    catta_dns_packet_set_field(p, idx, catta_dns_packet_get_field(p, idx) + 1);
}


static void name_table_cleanup(void *key, void *value, void *user_data) {
    CattaDnsPacket *p = user_data;

    if ((uint8_t*) value >= CATTA_DNS_PACKET_DATA(p) + p->size)
        catta_hashmap_remove(p->name_table, key);
}

void catta_dns_packet_cleanup_name_table(CattaDnsPacket *p) {
    if (p->name_table)
        catta_hashmap_foreach(p->name_table, name_table_cleanup, p);
}

uint8_t* catta_dns_packet_append_name(CattaDnsPacket *p, const char *name) {
    uint8_t *d, *saved_ptr = NULL;
    size_t saved_size;

    assert(p);
    assert(name);

    saved_size = p->size;
    saved_ptr = catta_dns_packet_extend(p, 0);

    while (*name) {
        uint8_t* prev;
        const char *pname;
        char label[64], *u;

        /* Check whether we can compress this name. */

        if (p->name_table && (prev = catta_hashmap_lookup(p->name_table, name))) {
            unsigned idx;

            assert(prev >= CATTA_DNS_PACKET_DATA(p));
            idx = (unsigned) (prev - CATTA_DNS_PACKET_DATA(p));

            assert(idx < p->size);

            if (idx < 0x4000) {
                uint8_t *t;
                if (!(t = (uint8_t*) catta_dns_packet_extend(p, sizeof(uint16_t))))
                    return NULL;

		t[0] = (uint8_t) ((0xC000 | idx) >> 8);
		t[1] = (uint8_t) idx;
                return saved_ptr;
            }
        }

        pname = name;

        if (!(catta_unescape_label(&name, label, sizeof(label))))
            goto fail;

        if (!(d = catta_dns_packet_append_string(p, label)))
            goto fail;

        if (!p->name_table)
            /* This works only for normalized domain names */
            p->name_table = catta_hashmap_new(catta_string_hash, catta_string_equal, catta_free, NULL);

        if (!(u = catta_strdup(pname)))
            catta_log_error("catta_strdup() failed.");
        else
            catta_hashmap_insert(p->name_table, u, d);
    }

    if (!(d = catta_dns_packet_extend(p, 1)))
        goto fail;

    *d = 0;

    return saved_ptr;

fail:
    p->size = saved_size;
    catta_dns_packet_cleanup_name_table(p);

    return NULL;
}

uint8_t* catta_dns_packet_append_uint16(CattaDnsPacket *p, uint16_t v) {
    uint8_t *d;
    assert(p);

    if (!(d = catta_dns_packet_extend(p, sizeof(uint16_t))))
        return NULL;

    d[0] = (uint8_t) (v >> 8);
    d[1] = (uint8_t) v;
    return d;
}

uint8_t *catta_dns_packet_append_uint32(CattaDnsPacket *p, uint32_t v) {
    uint8_t *d;
    assert(p);

    if (!(d = catta_dns_packet_extend(p, sizeof(uint32_t))))
        return NULL;

    d[0] = (uint8_t) (v >> 24);
    d[1] = (uint8_t) (v >> 16);
    d[2] = (uint8_t) (v >> 8);
    d[3] = (uint8_t) v;

    return d;
}

uint8_t *catta_dns_packet_append_bytes(CattaDnsPacket  *p, const void *b, size_t l) {
    uint8_t* d;

    assert(p);
    assert(b);
    assert(l);

    if (!(d = catta_dns_packet_extend(p, l)))
        return NULL;

    memcpy(d, b, l);
    return d;
}

uint8_t* catta_dns_packet_append_string(CattaDnsPacket *p, const char *s) {
    uint8_t* d;
    size_t k;

    assert(p);
    assert(s);

    if ((k = strlen(s)) >= 255)
        k = 255;

    if (!(d = catta_dns_packet_extend(p, k+1)))
        return NULL;

    *d = (uint8_t) k;
    memcpy(d+1, s, k);

    return d;
}

uint8_t *catta_dns_packet_extend(CattaDnsPacket *p, size_t l) {
    uint8_t *d;

    assert(p);

    if (p->size+l > p->max_size)
        return NULL;

    d = CATTA_DNS_PACKET_DATA(p) + p->size;
    p->size += l;

    return d;
}

int catta_dns_packet_check_valid(CattaDnsPacket *p) {
    uint16_t flags;
    assert(p);

    if (p->size < CATTA_DNS_PACKET_HEADER_SIZE)
        return -1;

    flags = catta_dns_packet_get_field(p, CATTA_DNS_FIELD_FLAGS);

    if (flags & CATTA_DNS_FLAG_OPCODE)
        return -1;

    return 0;
}

int catta_dns_packet_check_valid_multicast(CattaDnsPacket *p) {
    uint16_t flags;
    assert(p);

    if (catta_dns_packet_check_valid(p) < 0)
        return -1;

    flags = catta_dns_packet_get_field(p, CATTA_DNS_FIELD_FLAGS);

    if (flags & CATTA_DNS_FLAG_RCODE)
        return -1;

    return 0;
}

int catta_dns_packet_is_query(CattaDnsPacket *p) {
    assert(p);

    return !(catta_dns_packet_get_field(p, CATTA_DNS_FIELD_FLAGS) & CATTA_DNS_FLAG_QR);
}

static int consume_labels(CattaDnsPacket *p, unsigned idx, char *ret_name, size_t l) {
    int ret = 0;
    int compressed = 0;
    int first_label = 1;
    unsigned label_ptr;
    int i;
    assert(p && ret_name && l);

    for (i = 0; i < CATTA_DNS_LABELS_MAX; i++) {
        uint8_t n;

        if (idx+1 > p->size)
            return -1;

        n = CATTA_DNS_PACKET_DATA(p)[idx];

        if (!n) {
            idx++;
            if (!compressed)
                ret++;

            if (l < 1)
                return -1;
            *ret_name = 0;

            return ret;

        } else if (n <= 63) {
            /* Uncompressed label */
            idx++;
            if (!compressed)
                ret++;

            if (idx + n > p->size)
                return -1;

            if ((size_t) n + 1 > l)
                return -1;

            if (!first_label) {
                *(ret_name++) = '.';
                l--;
            } else
                first_label = 0;

            if (!(catta_escape_label((char*) CATTA_DNS_PACKET_DATA(p) + idx, n, &ret_name, &l)))
                return -1;

            idx += n;

            if (!compressed)
                ret += n;
        } else if ((n & 0xC0) == 0xC0) {
            /* Compressed label */

            if (idx+2 > p->size)
                return -1;

            label_ptr = ((unsigned) (CATTA_DNS_PACKET_DATA(p)[idx] & ~0xC0)) << 8 | CATTA_DNS_PACKET_DATA(p)[idx+1];

            if ((label_ptr < CATTA_DNS_PACKET_HEADER_SIZE) || (label_ptr >= idx))
                return -1;

            idx = label_ptr;

            if (!compressed)
                ret += 2;

            compressed = 1;
        } else
            return -1;
    }

    return -1;
}

int catta_dns_packet_consume_name(CattaDnsPacket *p, char *ret_name, size_t l) {
    int r;

    if ((r = consume_labels(p, p->rindex, ret_name, l)) < 0)
        return -1;

    p->rindex += r;
    return 0;
}

int catta_dns_packet_consume_uint16(CattaDnsPacket *p, uint16_t *ret_v) {
    uint8_t *d;

    assert(p);
    assert(ret_v);

    if (p->rindex + sizeof(uint16_t) > p->size)
        return -1;

    d = (uint8_t*) (CATTA_DNS_PACKET_DATA(p) + p->rindex);
    *ret_v = (d[0] << 8) | d[1];
    p->rindex += sizeof(uint16_t);

    return 0;
}

int catta_dns_packet_consume_uint32(CattaDnsPacket *p, uint32_t *ret_v) {
    uint8_t* d;

    assert(p);
    assert(ret_v);

    if (p->rindex + sizeof(uint32_t) > p->size)
        return -1;

    d = (uint8_t*) (CATTA_DNS_PACKET_DATA(p) + p->rindex);
    *ret_v = (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3];
    p->rindex += sizeof(uint32_t);

    return 0;
}

int catta_dns_packet_consume_bytes(CattaDnsPacket *p, void * ret_data, size_t l) {
    assert(p);
    assert(ret_data);
    assert(l > 0);

    if (p->rindex + l > p->size)
        return -1;

    memcpy(ret_data, CATTA_DNS_PACKET_DATA(p) + p->rindex, l);
    p->rindex += l;

    return 0;
}

int catta_dns_packet_consume_string(CattaDnsPacket *p, char *ret_string, size_t l) {
    size_t k;

    assert(p);
    assert(ret_string);
    assert(l > 0);

    if (p->rindex >= p->size)
        return -1;

    k = CATTA_DNS_PACKET_DATA(p)[p->rindex];

    if (p->rindex+1+k > p->size)
        return -1;

    if (l > k+1)
        l = k+1;

    memcpy(ret_string, CATTA_DNS_PACKET_DATA(p)+p->rindex+1, l-1);
    ret_string[l-1] = 0;

    p->rindex += 1+k;

    return 0;
}

const void* catta_dns_packet_get_rptr(CattaDnsPacket *p) {
    assert(p);

    if (p->rindex > p->size)
        return NULL;

    return CATTA_DNS_PACKET_DATA(p) + p->rindex;
}

int catta_dns_packet_skip(CattaDnsPacket *p, size_t length) {
    assert(p);

    if (p->rindex + length > p->size)
        return -1;

    p->rindex += length;
    return 0;
}

static int parse_rdata(CattaDnsPacket *p, CattaRecord *r, uint16_t rdlength) {
    char buf[CATTA_DOMAIN_NAME_MAX];
    const void* start;

    assert(p);
    assert(r);

    start = catta_dns_packet_get_rptr(p);

    switch (r->key->type) {
        case CATTA_DNS_TYPE_PTR:
        case CATTA_DNS_TYPE_CNAME:
        case CATTA_DNS_TYPE_NS:

            if (catta_dns_packet_consume_name(p, buf, sizeof(buf)) < 0)
                return -1;

            r->data.ptr.name = catta_strdup(buf);
            break;


        case CATTA_DNS_TYPE_SRV:

            if (catta_dns_packet_consume_uint16(p, &r->data.srv.priority) < 0 ||
                catta_dns_packet_consume_uint16(p, &r->data.srv.weight) < 0 ||
                catta_dns_packet_consume_uint16(p, &r->data.srv.port) < 0 ||
                catta_dns_packet_consume_name(p, buf, sizeof(buf)) < 0)
                return -1;

            r->data.srv.name = catta_strdup(buf);
            break;

        case CATTA_DNS_TYPE_HINFO:

            if (catta_dns_packet_consume_string(p, buf, sizeof(buf)) < 0)
                return -1;

            r->data.hinfo.cpu = catta_strdup(buf);

            if (catta_dns_packet_consume_string(p, buf, sizeof(buf)) < 0)
                return -1;

            r->data.hinfo.os = catta_strdup(buf);
            break;

        case CATTA_DNS_TYPE_TXT:

            if (rdlength > 0) {
                if (catta_string_list_parse(catta_dns_packet_get_rptr(p), rdlength, &r->data.txt.string_list) < 0)
                    return -1;

                if (catta_dns_packet_skip(p, rdlength) < 0)
                    return -1;
            } else
                r->data.txt.string_list = NULL;

            break;

        case CATTA_DNS_TYPE_A:

/*             catta_log_debug("A"); */

            if (catta_dns_packet_consume_bytes(p, &r->data.a.address, sizeof(CattaIPv4Address)) < 0)
                return -1;

            break;

        case CATTA_DNS_TYPE_AAAA:

/*             catta_log_debug("aaaa"); */

            if (catta_dns_packet_consume_bytes(p, &r->data.aaaa.address, sizeof(CattaIPv6Address)) < 0)
                return -1;

            break;

        default:

/*             catta_log_debug("generic"); */

            if (rdlength > 0) {

                r->data.generic.data = catta_memdup(catta_dns_packet_get_rptr(p), rdlength);
                r->data.generic.size = rdlength;

                if (catta_dns_packet_skip(p, rdlength) < 0)
                    return -1;
            }

            break;
    }

    /* Check if we read enough data */
    if ((const uint8_t*) catta_dns_packet_get_rptr(p) - (const uint8_t*) start != rdlength)
        return -1;

    return 0;
}

CattaRecord* catta_dns_packet_consume_record(CattaDnsPacket *p, int *ret_cache_flush) {
    char name[CATTA_DOMAIN_NAME_MAX];
    uint16_t type, class;
    uint32_t ttl;
    uint16_t rdlength;
    CattaRecord *r = NULL;

    assert(p);

    if (catta_dns_packet_consume_name(p, name, sizeof(name)) < 0 ||
        catta_dns_packet_consume_uint16(p, &type) < 0 ||
        catta_dns_packet_consume_uint16(p, &class) < 0 ||
        catta_dns_packet_consume_uint32(p, &ttl) < 0 ||
        catta_dns_packet_consume_uint16(p, &rdlength) < 0 ||
        p->rindex + rdlength > p->size)
        goto fail;

    if (ret_cache_flush)
        *ret_cache_flush = !!(class & CATTA_DNS_CACHE_FLUSH);
    class &= ~CATTA_DNS_CACHE_FLUSH;

    if (!(r = catta_record_new_full(name, class, type, ttl)))
        goto fail;

    if (parse_rdata(p, r, rdlength) < 0)
        goto fail;

    if (!catta_record_is_valid(r))
        goto fail;

    return r;

fail:
    if (r)
        catta_record_unref(r);

    return NULL;
}

CattaKey* catta_dns_packet_consume_key(CattaDnsPacket *p, int *ret_unicast_response) {
    char name[256];
    uint16_t type, class;
    CattaKey *k;

    assert(p);

    if (catta_dns_packet_consume_name(p, name, sizeof(name)) < 0 ||
        catta_dns_packet_consume_uint16(p, &type) < 0 ||
        catta_dns_packet_consume_uint16(p, &class) < 0)
        return NULL;

    if (ret_unicast_response)
        *ret_unicast_response = !!(class & CATTA_DNS_UNICAST_RESPONSE);

    class &= ~CATTA_DNS_UNICAST_RESPONSE;

    if (!(k = catta_key_new(name, class, type)))
        return NULL;

    if (!catta_key_is_valid(k)) {
        catta_key_unref(k);
        return NULL;
    }

    return k;
}

uint8_t* catta_dns_packet_append_key(CattaDnsPacket *p, CattaKey *k, int unicast_response) {
    uint8_t *t;
    size_t size;

    assert(p);
    assert(k);

    size = p->size;

    if (!(t = catta_dns_packet_append_name(p, k->name)) ||
        !catta_dns_packet_append_uint16(p, k->type) ||
        !catta_dns_packet_append_uint16(p, k->clazz | (unicast_response ? CATTA_DNS_UNICAST_RESPONSE : 0))) {
        p->size = size;
        catta_dns_packet_cleanup_name_table(p);

        return NULL;
    }

    return t;
}

static int append_rdata(CattaDnsPacket *p, CattaRecord *r) {
    assert(p);
    assert(r);

    switch (r->key->type) {

        case CATTA_DNS_TYPE_PTR:
        case CATTA_DNS_TYPE_CNAME:
        case CATTA_DNS_TYPE_NS:

            if (!(catta_dns_packet_append_name(p, r->data.ptr.name)))
                return -1;

            break;

        case CATTA_DNS_TYPE_SRV:

            if (!catta_dns_packet_append_uint16(p, r->data.srv.priority) ||
                !catta_dns_packet_append_uint16(p, r->data.srv.weight) ||
                !catta_dns_packet_append_uint16(p, r->data.srv.port) ||
                !catta_dns_packet_append_name(p, r->data.srv.name))
                return -1;

            break;

        case CATTA_DNS_TYPE_HINFO:
            if (!catta_dns_packet_append_string(p, r->data.hinfo.cpu) ||
                !catta_dns_packet_append_string(p, r->data.hinfo.os))
                return -1;

            break;

        case CATTA_DNS_TYPE_TXT: {

            uint8_t *data;
            size_t n;

            n = catta_string_list_serialize(r->data.txt.string_list, NULL, 0);

            if (!(data = catta_dns_packet_extend(p, n)))
                return -1;

            catta_string_list_serialize(r->data.txt.string_list, data, n);
            break;
        }


        case CATTA_DNS_TYPE_A:

            if (!catta_dns_packet_append_bytes(p, &r->data.a.address, sizeof(r->data.a.address)))
                return -1;

            break;

        case CATTA_DNS_TYPE_AAAA:

            if (!catta_dns_packet_append_bytes(p, &r->data.aaaa.address, sizeof(r->data.aaaa.address)))
                return -1;

            break;

        default:

            if (r->data.generic.size)
                if (!catta_dns_packet_append_bytes(p, r->data.generic.data, r->data.generic.size))
                    return -1;

            break;
    }

    return 0;
}


uint8_t* catta_dns_packet_append_record(CattaDnsPacket *p, CattaRecord *r, int cache_flush, unsigned max_ttl) {
    uint8_t *t, *l, *start;
    size_t size;

    assert(p);
    assert(r);

    size = p->size;

    if (!(t = catta_dns_packet_append_name(p, r->key->name)) ||
        !catta_dns_packet_append_uint16(p, r->key->type) ||
        !catta_dns_packet_append_uint16(p, cache_flush ? (r->key->clazz | CATTA_DNS_CACHE_FLUSH) : (r->key->clazz &~ CATTA_DNS_CACHE_FLUSH)) ||
        !catta_dns_packet_append_uint32(p, (max_ttl && r->ttl > max_ttl) ? max_ttl : r->ttl) ||
        !(l = catta_dns_packet_append_uint16(p, 0)))
        goto fail;

    start = catta_dns_packet_extend(p, 0);

    if (append_rdata(p, r) < 0)
        goto fail;

    size = catta_dns_packet_extend(p, 0) - start;
    assert(size <= CATTA_DNS_RDATA_MAX);

/*     catta_log_debug("appended %u", size); */

    l[0] = (uint8_t) ((uint16_t) size >> 8);
    l[1] = (uint8_t) ((uint16_t) size);

    return t;


fail:
    p->size = size;
    catta_dns_packet_cleanup_name_table(p);

    return NULL;
}

int catta_dns_packet_is_empty(CattaDnsPacket *p) {
    assert(p);

    return p->size <= CATTA_DNS_PACKET_HEADER_SIZE;
}

size_t catta_dns_packet_space(CattaDnsPacket *p) {
    assert(p);

    assert(p->size <= p->max_size);

    return p->max_size - p->size;
}

int catta_rdata_parse(CattaRecord *record, const void* rdata, size_t size) {
    int ret;
    CattaDnsPacket p;

    assert(record);
    assert(rdata);

    p.data = (void*) rdata;
    p.max_size = p.size = size;
    p.rindex = 0;
    p.name_table = NULL;

    ret = parse_rdata(&p, record, size);

    assert(!p.name_table);

    return ret;
}

size_t catta_rdata_serialize(CattaRecord *record, void *rdata, size_t max_size) {
    int ret;
    CattaDnsPacket p;

    assert(record);
    assert(rdata);
    assert(max_size > 0);

    p.data = (void*) rdata;
    p.max_size = max_size;
    p.size = p.rindex = 0;
    p.name_table = NULL;

    ret = append_rdata(&p, record);

    if (p.name_table)
         catta_hashmap_free(p.name_table);

    if (ret < 0)
        return (size_t) -1;

    return p.size;
}
