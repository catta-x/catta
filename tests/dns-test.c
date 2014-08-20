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

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <catta/domain.h>
#include <catta/defs.h>
#include <catta/malloc.h>
#include <catta/log.h>

#include "../src/dns.h"
#include "../src/util.h"

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char *argv[]) {
    char t[CATTA_DOMAIN_NAME_MAX], *m;
    const char *a, *b, *c, *d;
    CattaDnsPacket *p;
    CattaRecord *r, *r2;
    uint8_t rdata[CATTA_DNS_RDATA_MAX];
    size_t l;

    p = catta_dns_packet_new(0);

    assert(catta_dns_packet_append_name(p, a = "Ahello.hello.hello.de."));
    assert(catta_dns_packet_append_name(p, b = "Bthis is a test.hello.de."));
    assert(catta_dns_packet_append_name(p, c = "Cthis\\.is\\.a\\.test\\.with\\.dots.hello.de."));
    assert(catta_dns_packet_append_name(p, d = "Dthis\\\\is another test.hello.de."));

    catta_hexdump(CATTA_DNS_PACKET_DATA(p), p->size);

    assert(catta_dns_packet_consume_name(p, t, sizeof(t)) == 0);
    catta_log_debug(">%s<", t);
    assert(catta_domain_equal(a, t));

    assert(catta_dns_packet_consume_name(p, t, sizeof(t)) == 0);
    catta_log_debug(">%s<", t);
    assert(catta_domain_equal(b, t));

    assert(catta_dns_packet_consume_name(p, t, sizeof(t)) == 0);
    catta_log_debug(">%s<", t);
    assert(catta_domain_equal(c, t));

    assert(catta_dns_packet_consume_name(p, t, sizeof(t)) == 0);
    catta_log_debug(">%s<", t);
    assert(catta_domain_equal(d, t));

    catta_dns_packet_free(p);

    /* RDATA PARSING AND SERIALIZATION */

    /* Create an CattaRecord with some usful data */
    r = catta_record_new_full("foobar.local", CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_HINFO, CATTA_DEFAULT_TTL);
    assert(r);
    r->data.hinfo.cpu = catta_strdup("FOO");
    r->data.hinfo.os = catta_strdup("BAR");

    /* Serialize it into a blob */
    assert((l = catta_rdata_serialize(r, rdata, sizeof(rdata))) != (size_t) -1);

    /* Print it */
    catta_hexdump(rdata, l);

    /* Create a new record and fill in the data from the blob */
    r2 = catta_record_new(r->key, CATTA_DEFAULT_TTL);
    assert(r2);
    assert(catta_rdata_parse(r2, rdata, l) >= 0);

    /* Compare both versions */
    assert(catta_record_equal_no_ttl(r, r2));

    /* Free the records */
    catta_record_unref(r);
    catta_record_unref(r2);

    r = catta_record_new_full("foobar", 77, 77, CATTA_DEFAULT_TTL);
    assert(r);

    assert(r->data.generic.data = catta_memdup("HALLO", r->data.generic.size = 5));

    m = catta_record_to_string(r);
    assert(m);

    catta_log_debug(">%s<", m);

    catta_free(m);
    catta_record_unref(r);

    return 0;
}
