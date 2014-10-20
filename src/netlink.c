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

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <assert.h>

#include <catta/malloc.h>
#include "netlink.h"
#include <catta/log.h>

struct CattaNetlink {
    int fd;
    unsigned seq;
    CattaNetlinkCallback callback;
    void* userdata;
    uint8_t* buffer;
    size_t buffer_length;

    const CattaPoll *poll_api;
    CattaWatch *watch;
};

int catta_netlink_work(CattaNetlink *nl, int block) {
    ssize_t bytes;
    struct msghdr smsg;
    struct cmsghdr *cmsg;
    struct ucred *cred;
    struct iovec iov;
    struct nlmsghdr *p;
    char cred_msg[CMSG_SPACE(sizeof(struct ucred))];

    assert(nl);

    iov.iov_base = nl->buffer;
    iov.iov_len = nl->buffer_length;

    smsg.msg_name = NULL;
    smsg.msg_namelen = 0;
    smsg.msg_iov = &iov;
    smsg.msg_iovlen = 1;
    smsg.msg_control = cred_msg;
    smsg.msg_controllen = sizeof(cred_msg);
    smsg.msg_flags = (block ? 0 : MSG_DONTWAIT);

    if ((bytes = recvmsg(nl->fd, &smsg, 0)) < 0) {
        if (errno == EAGAIN || errno == EINTR)
            return 0;

        catta_log_error(__FILE__": recvmsg() failed: %s", strerror(errno));
        return -1;
    }

    cmsg = CMSG_FIRSTHDR(&smsg);

    if (!cmsg || cmsg->cmsg_type != SCM_CREDENTIALS) {
        catta_log_warn("No sender credentials received, ignoring data.");
        return -1;
    }

    cred = (struct ucred*) CMSG_DATA(cmsg);

    if (cred->uid != 0)
        return -1;

    p = (struct nlmsghdr *) nl->buffer;

    assert(nl->callback);

    for (; bytes > 0; p = NLMSG_NEXT(p, bytes)) {
        if (!NLMSG_OK(p, (size_t) bytes)) {
            catta_log_warn(__FILE__": packet truncated");
            return -1;
        }

        nl->callback(nl, p, nl->userdata);
    }

    return 0;
}

static void socket_event(CattaWatch *w, int fd, CATTA_GCC_UNUSED CattaWatchEvent event, void *userdata) {
    CattaNetlink *nl = userdata;

    assert(w);
    assert(nl);
    assert(fd == nl->fd);

    catta_netlink_work(nl, 0);
}

CattaNetlink *catta_netlink_new(const CattaPoll *poll_api, uint32_t groups, void (*cb) (CattaNetlink *nl, struct nlmsghdr *n, void* userdata), void* userdata) {
    int fd = -1;
    const int on = 1;
    struct sockaddr_nl addr;
    CattaNetlink *nl = NULL;

    assert(poll_api);
    assert(cb);

    if ((fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
        catta_log_error(__FILE__": socket(PF_NETLINK): %s", strerror(errno));
        return NULL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = groups;
    addr.nl_pid = 0; // use 0 instead of getpid() to allow multiple instances of catta in one process

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        catta_log_error(__FILE__": bind(): %s", strerror(errno));
        goto fail;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0) {
        catta_log_error(__FILE__": SO_PASSCRED: %s", strerror(errno));
        goto fail;
    }

    if (!(nl = catta_new(CattaNetlink, 1))) {
        catta_log_error(__FILE__": catta_new() failed.");
        goto fail;
    }

    nl->poll_api = poll_api;
    nl->fd = fd;
    nl->seq = 0;
    nl->callback = cb;
    nl->userdata = userdata;

    if (!(nl->buffer = catta_new(uint8_t, nl->buffer_length = 64*1024))) {
        catta_log_error(__FILE__": catta_new() failed.");
        goto fail;
    }

    if (!(nl->watch = poll_api->watch_new(poll_api, fd, CATTA_WATCH_IN, socket_event, nl))) {
        catta_log_error(__FILE__": Failed to create watch.");
        goto fail;
    }

    return nl;

fail:

    if (fd >= 0)
        close(fd);

    if (nl) {
        catta_free(nl->buffer);
        catta_free(nl);
    }

    return NULL;
}

void catta_netlink_free(CattaNetlink *nl) {
    assert(nl);

    if (nl->watch)
        nl->poll_api->watch_free(nl->watch);

    if (nl->fd >= 0)
        close(nl->fd);

    catta_free(nl->buffer);
    catta_free(nl);
}

int catta_netlink_send(CattaNetlink *nl, struct nlmsghdr *m, unsigned *ret_seq) {
    assert(nl);
    assert(m);

    m->nlmsg_seq = nl->seq++;
    m->nlmsg_flags |= NLM_F_ACK;

    if (send(nl->fd, m, m->nlmsg_len, 0) < 0) {
        catta_log_error(__FILE__": send(): %s", strerror(errno));
        return -1;
    }

    if (ret_seq)
        *ret_seq = m->nlmsg_seq;

    return 0;
}
