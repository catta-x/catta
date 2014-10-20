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

#include <sys/select.h>
#include <unistd.h>
#include <assert.h>

#ifdef HAVE_FCNTL
#include <fcntl.h>
#else
#include <sys/ioctl.h>
#endif

#include "fdutil.h"

int catta_set_cloexec(int fd) {
    int n;

    assert(fd >= 0);

#if defined(HAVE_FCNTL)
    if ((n = fcntl(fd, F_GETFD)) < 0)
        return -1;

    if (n & FD_CLOEXEC)
        return 0;

    return fcntl(fd, F_SETFD, n|FD_CLOEXEC);
#elif defined(_WIN32)
    (void)n;
    if(!SetHandleInformation((HANDLE)fd, HANDLE_FLAG_INHERIT, 0))
        return -1;
    return 0;
#else
    (void)n;
    return -1;
#endif
}

int catta_set_nonblock(int fd) {
    int n;

    assert(fd >= 0);

#ifdef HAVE_FCNTL
    if ((n = fcntl(fd, F_GETFL)) < 0)
        return -1;

    if (n & O_NONBLOCK)
        return 0;

    return fcntl(fd, F_SETFL, n|O_NONBLOCK);
#else
    n = 1;
    return ioctl(fd, FIONBIO, &n);
#endif
}

int catta_wait_for_write(int fd) {
    fd_set fds;
    int r;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    if ((r = select(fd+1, NULL, &fds, NULL, NULL)) < 0)
        return -1;

    assert(r > 0);

    return 0;
}
