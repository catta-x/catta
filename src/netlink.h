#ifndef foonetlinkhfoo
#define foonetlinkhfoo

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

#include <sys/socket.h>
#include <asm/types.h>
#include <inttypes.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <catta/watch.h>

typedef struct CattaNetlink CattaNetlink;

typedef void (*CattaNetlinkCallback)(CattaNetlink *n, struct nlmsghdr *m, void* userdata);

CattaNetlink *catta_netlink_new(const CattaPoll *poll_api, uint32_t groups, CattaNetlinkCallback callback, void* userdata);
void catta_netlink_free(CattaNetlink *n);
int catta_netlink_send(CattaNetlink *n, struct nlmsghdr *m, unsigned *ret_seq);
int catta_netlink_work(CattaNetlink *n, int block);

#endif
