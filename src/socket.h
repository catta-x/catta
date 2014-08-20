#ifndef foosockethfoo
#define foosockethfoo

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

#include <inttypes.h>

#include "dns.h"

#define CATTA_MDNS_PORT 5353
#define CATTA_DNS_PORT 53
#define CATTA_IPV4_MCAST_GROUP "224.0.0.251"
#define CATTA_IPV6_MCAST_GROUP "ff02::fb"

int catta_open_socket_ipv4(int no_reuse);
int catta_open_socket_ipv6(int no_reuse);

int catta_open_unicast_socket_ipv4(void);
int catta_open_unicast_socket_ipv6(void);

int catta_send_dns_packet_ipv4(int fd, CattaIfIndex iface, CattaDnsPacket *p, const CattaIPv4Address *src_address, const CattaIPv4Address *dst_address, uint16_t dst_port);
int catta_send_dns_packet_ipv6(int fd, CattaIfIndex iface, CattaDnsPacket *p, const CattaIPv6Address *src_address, const CattaIPv6Address *dst_address, uint16_t dst_port);

CattaDnsPacket *catta_recv_dns_packet_ipv4(int fd, CattaIPv4Address *ret_src_address, uint16_t *ret_src_port, CattaIPv4Address *ret_dst_address, CattaIfIndex *ret_iface, uint8_t *ret_ttl);
CattaDnsPacket *catta_recv_dns_packet_ipv6(int fd, CattaIPv6Address *ret_src_address, uint16_t *ret_src_port, CattaIPv6Address *ret_dst_address, CattaIfIndex *ret_iface, uint8_t *ret_ttl);

int catta_mdns_mcast_join_ipv4(int fd, const CattaIPv4Address *local_address, int iface, int join);
int catta_mdns_mcast_join_ipv6(int fd, const CattaIPv6Address *local_address, int iface, int join);

#endif
