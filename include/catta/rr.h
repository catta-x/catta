#ifndef foorrhfoo
#define foorrhfoo

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

/** \file rr.h Functions and definitions for manipulating DNS resource record (RR) data. */

#include <inttypes.h>
#include <sys/types.h>

#include <catta/strlst.h>
#include <catta/address.h>
#include <catta/cdecl.h>

CATTA_C_DECL_BEGIN

/** DNS record types, see RFC 1035, in addition to those defined in defs.h */
enum {
    CATTA_DNS_TYPE_ANY = 0xFF,   /**< Special query type for requesting all records */
    CATTA_DNS_TYPE_OPT = 41,     /**< EDNS0 option */
    CATTA_DNS_TYPE_TKEY = 249,
    CATTA_DNS_TYPE_TSIG = 250,
    CATTA_DNS_TYPE_IXFR = 251,
    CATTA_DNS_TYPE_AXFR = 252
};

/** DNS record classes, see RFC 1035, in addition to those defined in defs.h */
enum {
    CATTA_DNS_CLASS_ANY = 0xFF,         /**< Special query type for requesting all records */
    CATTA_DNS_CACHE_FLUSH = 0x8000,     /**< Not really a class but a bit which may be set in response packets, see mDNS spec for more information */
    CATTA_DNS_UNICAST_RESPONSE = 0x8000 /**< Not really a class but a bit which may be set in query packets, see mDNS spec for more information */
};

/** Encapsulates a DNS query key consisting of class, type and
    name. Use catta_key_ref()/catta_key_unref() for manipulating the
    reference counter. The structure is intended to be treated as "immutable", no
    changes should be imposed after creation */
typedef struct CattaKey {
    int ref;           /**< Reference counter */
    char *name;        /**< Record name */
    uint16_t clazz;    /**< Record class, one of the CATTA_DNS_CLASS_xxx constants */
    uint16_t type;     /**< Record type, one of the CATTA_DNS_TYPE_xxx constants */
} CattaKey;

/** Encapsulates a DNS resource record. The structure is intended to
 * be treated as "immutable", no changes should be imposed after
 * creation. */
typedef struct CattaRecord {
    int ref;         /**< Reference counter */
    CattaKey *key;   /**< Reference to the query key of this record */

    uint32_t ttl;     /**< DNS TTL of this record */

    union {

        struct {
            void* data;
            uint16_t size;
        } generic; /**< Generic record data for unknown types */

        struct {
            uint16_t priority;
            uint16_t weight;
            uint16_t port;
            char *name;
        } srv; /**< Data for SRV records */

        struct {
            char *name;
        } ptr, ns, cname; /**< Data for PTR, NS and CNAME records */

        struct {
            char *cpu;
            char *os;
        } hinfo; /**< Data for HINFO records */

        struct {
            CattaStringList *string_list;
        } txt; /**< Data for TXT records */

        struct {
            CattaIPv4Address address;
        } a; /**< Data for A records */

        struct {
            CattaIPv6Address address;
        } aaaa; /**< Data for AAAA records */

    } data; /**< Record data */

} CattaRecord;

/** Create a new CattaKey object. The reference counter will be set to 1. */
CattaKey *catta_key_new(const char *name, uint16_t clazz, uint16_t type);

/** Increase the reference counter of an CattaKey object by one */
CattaKey *catta_key_ref(CattaKey *k);

/** Decrease the reference counter of an CattaKey object by one */
void catta_key_unref(CattaKey *k);

/** Check whether two CattaKey object contain the same
 * data. CATTA_DNS_CLASS_ANY/CATTA_DNS_TYPE_ANY are treated like any
 * other class/type. */
int catta_key_equal(const CattaKey *a, const CattaKey *b);

/** Return a numeric hash value for a key for usage in hash tables. */
unsigned catta_key_hash(const CattaKey *k);

/** Create a new record object. Record data should be filled in right after creation. The reference counter is set to 1. */
CattaRecord *catta_record_new(CattaKey *k, uint32_t ttl);

/** Create a new record object. Record data should be filled in right after creation. The reference counter is set to 1. */
CattaRecord *catta_record_new_full(const char *name, uint16_t clazz, uint16_t type, uint32_t ttl);

/** Increase the reference counter of an CattaRecord by one. */
CattaRecord *catta_record_ref(CattaRecord *r);

/** Decrease the reference counter of an CattaRecord by one. */
void catta_record_unref(CattaRecord *r);

/** Return a textual representation of the specified DNS class. The
 * returned pointer points to a read only internal string. */
const char *catta_dns_class_to_string(uint16_t clazz);

/** Return a textual representation of the specified DNS class. The
 * returned pointer points to a read only internal string. */
const char *catta_dns_type_to_string(uint16_t type);

/** Create a textual representation of the specified key. catta_free() the
 * result! */
char *catta_key_to_string(const CattaKey *k);

/** Create a textual representation of the specified record, similar
 * in style to BIND zone file data. catta_free() the result! */
char *catta_record_to_string(const CattaRecord *r);

/** Check whether two records are equal (regardless of the TTL */
int catta_record_equal_no_ttl(const CattaRecord *a, const CattaRecord *b);

/** Check whether the specified key is valid */
int catta_key_is_valid(CattaKey *k);

/** Check whether the specified record is valid */
int catta_record_is_valid(CattaRecord *r);

/** Parse a binary rdata object and fill it into *record. This function is actually implemented in dns.c */
int catta_rdata_parse(CattaRecord *record, const void* rdata, size_t size);

/** Serialize an CattaRecord object into binary rdata. This function is actually implemented in dns.c */
size_t catta_rdata_serialize(CattaRecord *record, void *rdata, size_t max_size);

/** Return TRUE if the CattaRecord object is a link-local A or AAAA address */
int catta_record_is_link_local_address(const CattaRecord *r);

CATTA_C_DECL_END

#endif
