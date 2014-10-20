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

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include <catta/address.h>
#include <catta/malloc.h>

static size_t address_get_size(const CattaAddress *a) {
    assert(a);

    if (a->proto == CATTA_PROTO_INET)
        return 4;
    else if (a->proto == CATTA_PROTO_INET6)
        return 16;

    return 0;
}

int catta_address_cmp(const CattaAddress *a, const CattaAddress *b) {
    assert(a);
    assert(b);

    if (a->proto != b->proto)
        return -1;

    return memcmp(a->data.data, b->data.data, address_get_size(a));
}

char *catta_address_snprint(char *s, size_t length, const CattaAddress *a) {
    assert(s);
    assert(length);
    assert(a);

    if (!(inet_ntop(catta_proto_to_af(a->proto), (void *)a->data.data, s, length)))
        return NULL;

    return s;
}

char* catta_reverse_lookup_name(const CattaAddress *a, char *ret_s, size_t length) {
    assert(ret_s);
    assert(length > 0);
    assert(a);

    if (a->proto == CATTA_PROTO_INET) {
        uint32_t n = ntohl(a->data.ipv4.address);
        snprintf(
            ret_s, length,
            "%u.%u.%u.%u.in-addr.arpa",
            n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, n >> 24);
    } else {
        assert(a->proto == CATTA_PROTO_INET6);

        snprintf(
            ret_s, length,
            "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.arpa",
            a->data.ipv6.address[15] & 0xF, a->data.ipv6.address[15] >> 4,
            a->data.ipv6.address[14] & 0xF, a->data.ipv6.address[14] >> 4,
            a->data.ipv6.address[13] & 0xF, a->data.ipv6.address[13] >> 4,
            a->data.ipv6.address[12] & 0xF, a->data.ipv6.address[12] >> 4,
            a->data.ipv6.address[11] & 0xF, a->data.ipv6.address[11] >> 4,
            a->data.ipv6.address[10] & 0xF, a->data.ipv6.address[10] >> 4,
            a->data.ipv6.address[ 9] & 0xF, a->data.ipv6.address[ 9] >> 4,
            a->data.ipv6.address[ 8] & 0xF, a->data.ipv6.address[ 8] >> 4,
            a->data.ipv6.address[ 7] & 0xF, a->data.ipv6.address[ 7] >> 4,
            a->data.ipv6.address[ 6] & 0xF, a->data.ipv6.address[ 6] >> 4,
            a->data.ipv6.address[ 5] & 0xF, a->data.ipv6.address[ 5] >> 4,
            a->data.ipv6.address[ 4] & 0xF, a->data.ipv6.address[ 4] >> 4,
            a->data.ipv6.address[ 3] & 0xF, a->data.ipv6.address[ 3] >> 4,
            a->data.ipv6.address[ 2] & 0xF, a->data.ipv6.address[ 2] >> 4,
            a->data.ipv6.address[ 1] & 0xF, a->data.ipv6.address[ 1] >> 4,
            a->data.ipv6.address[ 0] & 0xF, a->data.ipv6.address[ 0] >> 4);
    }

    return ret_s;
}

CattaAddress *catta_address_parse(const char *s, CattaProtocol proto, CattaAddress *ret_addr) {
    assert(ret_addr);
    assert(s);

    if (proto == CATTA_PROTO_UNSPEC) {
        if (inet_pton(AF_INET, s, ret_addr->data.data) <= 0) {
            if (inet_pton(AF_INET6, s, ret_addr->data.data) <= 0)
                return NULL;
            else
                ret_addr->proto = CATTA_PROTO_INET6;
        } else
            ret_addr->proto = CATTA_PROTO_INET;
    } else {
        if (inet_pton(catta_proto_to_af(proto), s, ret_addr->data.data) <= 0)
            return NULL;

        ret_addr->proto = proto;
    }

    return ret_addr;
}

int catta_proto_to_af(CattaProtocol proto) {
    if (proto == CATTA_PROTO_INET)
        return AF_INET;
    if (proto == CATTA_PROTO_INET6)
        return AF_INET6;

    assert(proto == CATTA_PROTO_UNSPEC);
    return AF_UNSPEC;
}

CattaProtocol catta_af_to_proto(int af) {
    if (af == AF_INET)
        return CATTA_PROTO_INET;
    if (af == AF_INET6)
        return CATTA_PROTO_INET6;

    assert(af == AF_UNSPEC);
    return CATTA_PROTO_UNSPEC;
}

const char* catta_proto_to_string(CattaProtocol proto) {
    if (proto == CATTA_PROTO_INET)
        return "IPv4";
    if (proto == CATTA_PROTO_INET6)
        return "IPv6";

    assert(proto == CATTA_PROTO_UNSPEC);
    return "UNSPEC";
}
