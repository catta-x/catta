#ifndef foodnshfoo
#define foodnshfoo

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

#include <catta/rr.h>
#include "hashmap.h"

#define CATTA_DNS_PACKET_HEADER_SIZE 12
#define CATTA_DNS_PACKET_EXTRA_SIZE 48
#define CATTA_DNS_LABELS_MAX 127
#define CATTA_DNS_RDATA_MAX 0xFFFF
#define CATTA_DNS_PACKET_SIZE_MAX (CATTA_DNS_PACKET_HEADER_SIZE + 256 + 2 + 2 + 4 + 2 + CATTA_DNS_RDATA_MAX)

typedef struct CattaDnsPacket {
    size_t size, rindex, max_size;
    CattaHashmap *name_table; /* for name compression */
    uint8_t *data;
} CattaDnsPacket;

#define CATTA_DNS_PACKET_DATA(p) ((p)->data ? (p)->data : ((uint8_t*) p) + sizeof(CattaDnsPacket))

CattaDnsPacket* catta_dns_packet_new(unsigned mtu);
CattaDnsPacket* catta_dns_packet_new_query(unsigned mtu);
CattaDnsPacket* catta_dns_packet_new_response(unsigned mtu, int aa);

CattaDnsPacket* catta_dns_packet_new_reply(CattaDnsPacket* p, unsigned mtu, int copy_queries, int aa);

void catta_dns_packet_free(CattaDnsPacket *p);
void catta_dns_packet_set_field(CattaDnsPacket *p, unsigned idx, uint16_t v);
uint16_t catta_dns_packet_get_field(CattaDnsPacket *p, unsigned idx);
void catta_dns_packet_inc_field(CattaDnsPacket *p, unsigned idx);

uint8_t *catta_dns_packet_extend(CattaDnsPacket *p, size_t l);

void catta_dns_packet_cleanup_name_table(CattaDnsPacket *p);

uint8_t *catta_dns_packet_append_uint16(CattaDnsPacket *p, uint16_t v);
uint8_t *catta_dns_packet_append_uint32(CattaDnsPacket *p, uint32_t v);
uint8_t *catta_dns_packet_append_name(CattaDnsPacket *p, const char *name);
uint8_t *catta_dns_packet_append_bytes(CattaDnsPacket  *p, const void *d, size_t l);
uint8_t* catta_dns_packet_append_key(CattaDnsPacket *p, CattaKey *k, int unicast_response);
uint8_t* catta_dns_packet_append_record(CattaDnsPacket *p, CattaRecord *r, int cache_flush, unsigned max_ttl);
uint8_t* catta_dns_packet_append_string(CattaDnsPacket *p, const char *s);

int catta_dns_packet_is_query(CattaDnsPacket *p);
int catta_dns_packet_check_valid(CattaDnsPacket *p);
int catta_dns_packet_check_valid_multicast(CattaDnsPacket *p);

int catta_dns_packet_consume_uint16(CattaDnsPacket *p, uint16_t *ret_v);
int catta_dns_packet_consume_uint32(CattaDnsPacket *p, uint32_t *ret_v);
int catta_dns_packet_consume_name(CattaDnsPacket *p, char *ret_name, size_t l);
int catta_dns_packet_consume_bytes(CattaDnsPacket *p, void* ret_data, size_t l);
CattaKey* catta_dns_packet_consume_key(CattaDnsPacket *p, int *ret_unicast_response);
CattaRecord* catta_dns_packet_consume_record(CattaDnsPacket *p, int *ret_cache_flush);
int catta_dns_packet_consume_string(CattaDnsPacket *p, char *ret_string, size_t l);

const void* catta_dns_packet_get_rptr(CattaDnsPacket *p);

int catta_dns_packet_skip(CattaDnsPacket *p, size_t length);

int catta_dns_packet_is_empty(CattaDnsPacket *p);
size_t catta_dns_packet_space(CattaDnsPacket *p);

#define CATTA_DNS_FIELD_ID 0
#define CATTA_DNS_FIELD_FLAGS 1
#define CATTA_DNS_FIELD_QDCOUNT 2
#define CATTA_DNS_FIELD_ANCOUNT 3
#define CATTA_DNS_FIELD_NSCOUNT 4
#define CATTA_DNS_FIELD_ARCOUNT 5

#define CATTA_DNS_FLAG_QR (1 << 15)
#define CATTA_DNS_FLAG_OPCODE (15 << 11)
#define CATTA_DNS_FLAG_RCODE (15)
#define CATTA_DNS_FLAG_TC (1 << 9)
#define CATTA_DNS_FLAG_AA (1 << 10)

#define CATTA_DNS_FLAGS(qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode) \
        (((uint16_t) !!qr << 15) |  \
         ((uint16_t) (opcode & 15) << 11) | \
         ((uint16_t) !!aa << 10) | \
         ((uint16_t) !!tc << 9) | \
         ((uint16_t) !!rd << 8) | \
         ((uint16_t) !!ra << 7) | \
         ((uint16_t) !!ad << 5) | \
         ((uint16_t) !!cd << 4) | \
         ((uint16_t) (rcode & 15)))

#define CATTA_MDNS_SUFFIX_LOCAL "local"
#define CATTA_MDNS_SUFFIX_ADDR_IPV4 "254.169.in-addr.arpa"
#define CATTA_MDNS_SUFFIX_ADDR_IPV6 "0.8.e.f.ip6.arpa"

#endif

