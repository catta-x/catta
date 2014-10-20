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

#include <catta/gccmacro.h>
#include <catta/timeval.h>

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char *argv[]) {

    struct timeval a = { 5, 5 }, b;

    b = a;

    printf("%li.%li\n", a.tv_sec, a.tv_usec);
    catta_timeval_add(&a, -50);

    printf("%li.%li\n", a.tv_sec, a.tv_usec);

    printf("%li\n", (long) catta_timeval_diff(&a, &b));

    return 0;
}
