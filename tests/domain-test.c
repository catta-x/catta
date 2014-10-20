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

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <catta/domain.h>
#include <catta/malloc.h>

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char *argv[]) {
    char *s;
    char t[256], r[256];
    const char *p;
    size_t size;
    char name[64], type[CATTA_DOMAIN_NAME_MAX], domain[CATTA_DOMAIN_NAME_MAX];

    printf("%s\n", s = catta_normalize_name_strdup("foo.foo\\046."));
    catta_free(s);

    printf("%s\n", s = catta_normalize_name_strdup("foo.foo\\.foo."));
    catta_free(s);


    printf("%s\n", s = catta_normalize_name_strdup("fo\\\\o\\..f oo."));
    catta_free(s);

    printf("%i\n", catta_domain_equal("\\065aa bbb\\.\\046cc.cc\\\\.dee.fff.", "Aaa BBB\\.\\.cc.cc\\\\.dee.fff"));
    printf("%i\n", catta_domain_equal("A", "a"));

    printf("%i\n", catta_domain_equal("a", "aaa"));

    printf("%u = %u\n", catta_domain_hash("ccc\\065aa.aa\\.b\\\\."), catta_domain_hash("cccAaa.aa\\.b\\\\"));


    catta_service_name_join(t, sizeof(t), "foo.foo.foo \\.", "_http._tcp", "test.local");
    printf("<%s>\n", t);

    catta_service_name_split(t, name, sizeof(name), type, sizeof(type), domain, sizeof(domain));
    printf("name: <%s>; type: <%s>; domain <%s>\n", name, type, domain);

    catta_service_name_join(t, sizeof(t), NULL, "_http._tcp", "one.two\\. .local");
    printf("<%s>\n", t);

    catta_service_name_split(t, NULL, 0, type, sizeof(type), domain, sizeof(domain));
    printf("name: <>; type: <%s>; domain <%s>\n", type, domain);


    p = "--:---\\\\\\123\\065_äöü\\064\\.\\\\sjöödfhh.sdfjhskjdf";
    printf("unescaped: <%s>, rest: %s\n", catta_unescape_label(&p, t, sizeof(t)), p);

    size = sizeof(r);
    s = r;

    printf("escaped: <%s>\n", catta_escape_label(t, strlen(t), &s, &size));

    p = r;
    printf("unescaped: <%s>\n", catta_unescape_label(&p, t, sizeof(t)));

    assert(catta_is_valid_service_type_generic("_foo._bar._waldo"));
    assert(!catta_is_valid_service_type_strict("_foo._bar._waldo"));
    assert(!catta_is_valid_service_subtype("_foo._bar._waldo"));

    assert(catta_is_valid_service_type_generic("_foo._tcp"));
    assert(catta_is_valid_service_type_strict("_foo._tcp"));
    assert(!catta_is_valid_service_subtype("_foo._tcp"));

    assert(!catta_is_valid_service_type_generic("_foo._bar.waldo"));
    assert(!catta_is_valid_service_type_strict("_foo._bar.waldo"));
    assert(!catta_is_valid_service_subtype("_foo._bar.waldo"));

    assert(!catta_is_valid_service_type_generic(""));
    assert(!catta_is_valid_service_type_strict(""));
    assert(!catta_is_valid_service_subtype(""));

    assert(catta_is_valid_service_type_generic("_foo._sub._bar._tcp"));
    assert(!catta_is_valid_service_type_strict("_foo._sub._bar._tcp"));
    assert(catta_is_valid_service_subtype("_foo._sub._bar._tcp"));

    printf("%s\n", catta_get_type_from_subtype("_foo._sub._bar._tcp"));

    assert(!catta_is_valid_host_name("sf.ooo."));
    assert(catta_is_valid_host_name("sfooo."));
    assert(catta_is_valid_host_name("sfooo"));

    assert(catta_is_valid_domain_name("."));
    assert(catta_is_valid_domain_name(""));

    assert(catta_normalize_name(".", t, sizeof(t)));
    assert(catta_normalize_name("", t, sizeof(t)));

    assert(!catta_is_valid_fqdn("."));
    assert(!catta_is_valid_fqdn(""));
    assert(!catta_is_valid_fqdn("foo"));
    assert(catta_is_valid_fqdn("foo.bar"));
    assert(catta_is_valid_fqdn("foo.bar."));
    assert(catta_is_valid_fqdn("gnurz.foo.bar."));
    assert(!catta_is_valid_fqdn("192.168.50.1"));
    assert(!catta_is_valid_fqdn("::1"));
    assert(!catta_is_valid_fqdn(".192.168.50.1."));

    return 0;
}
