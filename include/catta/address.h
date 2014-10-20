#ifndef fooaddresshfoo
#define fooaddresshfoo

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

/** \file address.h Definitions and functions to manipulate IP addresses. */

#include <inttypes.h>
#include <sys/types.h>

#include <catta/cdecl.h>

CATTA_C_DECL_BEGIN

/** Protocol family specification, takes the values CATTA_PROTO_INET, CATTA_PROTO_INET6, CATTA_PROTO_UNSPEC */
typedef int CattaProtocol;

/** Numeric network interface index. Takes OS dependent values and the special constant CATTA_IF_UNSPEC  */
typedef int CattaIfIndex;

/** Values for CattaProtocol */
enum {
    CATTA_PROTO_INET = 0,     /**< IPv4 */
    CATTA_PROTO_INET6 = 1,   /**< IPv6 */
    CATTA_PROTO_UNSPEC = -1  /**< Unspecified/all protocol(s) */
};

/** Special values for CattaIfIndex */
enum {
    CATTA_IF_UNSPEC = -1       /**< Unspecified/all interface(s) */
};

/** Maximum size of an address in string form */
#define CATTA_ADDRESS_STR_MAX 40 /* IPv6 Max = 4*8 + 7 + 1 for NUL */

/** Return TRUE if the specified interface index is valid */
#define CATTA_IF_VALID(iface) (((iface) >= 0) || ((iface) == CATTA_IF_UNSPEC))

/** Return TRUE if the specified protocol is valid */
#define CATTA_PROTO_VALID(protocol) (((protocol) == CATTA_PROTO_INET) || ((protocol) == CATTA_PROTO_INET6) || ((protocol) == CATTA_PROTO_UNSPEC))

/** An IPv4 address */
typedef struct CattaIPv4Address {
    uint32_t address; /**< Address data in network byte order. */
} CattaIPv4Address;

/** An IPv6 address */
typedef struct CattaIPv6Address {
    uint8_t address[16]; /**< Address data */
} CattaIPv6Address;

/** Protocol (address family) independent address structure */
typedef struct CattaAddress {
    CattaProtocol proto; /**< Address family */

    union {
        CattaIPv6Address ipv6;  /**< Address when IPv6 */
        CattaIPv4Address ipv4;  /**< Address when IPv4 */
        uint8_t data[1];        /**< Type-independent data field */
    } data;
} CattaAddress;

/** @{ \name Comparison */

/** Compare two addresses. Returns 0 when equal, a negative value when a < b, a positive value when a > b. */
int catta_address_cmp(const CattaAddress *a, const CattaAddress *b);

/** @} */

/** @{ \name String conversion */

/** Convert the specified address *a to a human readable character string, use CATTA_ADDRESS_STR_MAX to allocate an array of the right size */
char *catta_address_snprint(char *ret_s, size_t length, const CattaAddress *a);

/** Convert the specified human readable character string to an
 * address structure. Set af to CATTA_UNSPEC for automatic address
 * family detection. */
CattaAddress *catta_address_parse(const char *s, CattaProtocol af, CattaAddress *ret_addr);

/** @} */

/** \cond fulldocs */
/** Generate the DNS reverse lookup name for an IPv4 or IPv6 address. */
char* catta_reverse_lookup_name(const CattaAddress *a, char *ret_s, size_t length);
/** \endcond */

/** @{ \name Protocol/address family handling */

/** Map CATTA_PROTO_xxx constants to Unix AF_xxx constants */
int catta_proto_to_af(CattaProtocol proto);

/** Map Unix AF_xxx constants to CATTA_PROTO_xxx constants */
CattaProtocol catta_af_to_proto(int af);

/** Return a textual representation of the specified protocol number. i.e. "IPv4", "IPv6" or "UNSPEC" */
const char* catta_proto_to_string(CattaProtocol proto);

/** @} */

CATTA_C_DECL_END

#endif
