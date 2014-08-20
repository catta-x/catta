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

#include <catta/alternative.h>
#include <catta/malloc.h>
#include <catta/domain.h>

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char *argv[]) {
    const char* const test_strings[] = {
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXüüüüüüü",
        "gurke",
        "-",
        " #",
        "1",
        "#0",
        " #0",
        " #1",
        "#-1",
        " #-1",
        "-0",
        "--0",
        "-1",
        "--1",
        "-2",
        "gurke1",
        "gurke0",
        "gurke-2",
        "gurke #0",
        "gurke #1",
        "gurke #",
        "gurke#1",
        "gurke-",
        "gurke---",
        "gurke #",
        "gurke ###",
        NULL
    };

    char *r = NULL;
    int i, j, k;

    for (k = 0; test_strings[k]; k++) {

        printf(">>>>>%s<<<<\n", test_strings[k]);

        for (j = 0; j < 2; j++) {

            for (i = 0; i <= 100; i++) {
                char *n;

                n = i == 0 ? catta_strdup(test_strings[k]) : (j ? catta_alternative_service_name(r) : catta_alternative_host_name(r));
                catta_free(r);
                r = n;

                if (j)
                    assert(catta_is_valid_service_name(n));
                else
                    assert(catta_is_valid_host_name(n));

                printf("%s\n", r);
            }
        }
    }

    catta_free(r);
    return 0;
}
