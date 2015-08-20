#include "catta/compat/wincompat.h"
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>

#include <catta/log.h>

// helper: convert WSAGetLastError() to an errno constant
static int wsa_errno(void)
{
    switch(WSAGetLastError()) {
        case WSAEACCES:         return EACCES;
        case WSAECONNRESET:     return ECONNRESET;
        case WSAEFAULT:         return EFAULT;
        case WSAEINPROGRESS:    return EINPROGRESS;
        case WSAEINTR:          return EINTR;
        case WSAEINVAL:         return EINVAL;
        case WSAEMSGSIZE:       return EMSGSIZE;
        case WSAENETDOWN:       return ENETDOWN;
        case WSAENETRESET:      return ENETRESET;
        case WSAENOBUFS:        return ENOBUFS;
        case WSAENOTCONN:       return ENOTCONN;
        case WSAENOTSOCK:       return ENOTSOCK;
        case WSAEOPNOTSUPP:     return EOPNOTSUPP;
        case WSAESHUTDOWN:      return ESHUTDOWN;
        case WSAETIMEDOUT:      return ETIMEDOUT;
        case WSAEWOULDBLOCK:    return EWOULDBLOCK;
        default:
            return EINVAL;
    }
}

void winsock_init(void)
{
    WSADATA wsa;
    int error;

    if((error = WSAStartup(MAKEWORD(2,2), &wsa)) != 0)
        catta_log_error("WSAStartup() failed: %d", error);
}

void winsock_exit(void)
{
    if(WSACleanup() == SOCKET_ERROR)
        catta_log_warn("WSACleanup() failed: %d", WSAGetLastError());
}

char *errnostrsocket(void)
{
    static char buf[256];

    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, WSAGetLastError(), 0, buf, sizeof(buf), NULL);

    return buf;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    LPFN_WSARECVMSG WSARecvMsg = NULL;
    GUID wsaid = WSAID_WSARECVMSG;
    DWORD b;

    DWORD bytesrcvd;
    WSAMSG wsamsg;
    size_t i;
    int r;

    // size_t is larger than DWORD on 64bit
    if(msg->msg_iovlen > UINT32_MAX) {
        errno = EINVAL;
        return -1;
    }

    // obtain the function pointer to WSARecvMsg
    r = WSAIoctl(sockfd, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &wsaid, sizeof(wsaid), &WSARecvMsg, sizeof(WSARecvMsg),
                 &b, NULL, NULL);
    if(r == SOCKET_ERROR) {
        errno = wsa_errno();
        return -1;
    }
    assert(b == sizeof(WSARecvMsg));
    assert(WSARecvMsg != NULL);

    // convert msghdr to WSAMSG structure
    wsamsg.name = msg->msg_name;
    wsamsg.namelen = msg->msg_namelen;
    wsamsg.lpBuffers = malloc(msg->msg_iovlen * sizeof(WSABUF));
    wsamsg.dwBufferCount = msg->msg_iovlen;
    wsamsg.Control.len = msg->msg_controllen;
    wsamsg.Control.buf = msg->msg_control;
    wsamsg.dwFlags = (DWORD)flags;

    // all flags that fit into dwFlags also fit through the flags argument
    assert(sizeof(DWORD) <= sizeof(flags));

    if(wsamsg.lpBuffers == NULL) {
        // malloc will have set errno
        return -1;
    }

    // re-wrap iovecs as WSABUFs
    for(i=0; i<msg->msg_iovlen; i++) {
        // size_t vs. u_long
        if(msg->msg_iov[i].iov_len > ULONG_MAX) {
            free(wsamsg.lpBuffers);
            errno = EINVAL;
            return -1;
        }

        wsamsg.lpBuffers[i].len = msg->msg_iov[i].iov_len;
        wsamsg.lpBuffers[i].buf = msg->msg_iov[i].iov_base;
    }

    r = WSARecvMsg(sockfd, &wsamsg, &bytesrcvd, NULL, NULL);

    // the allocated WSABUF wrappers are no longer needed
    free(wsamsg.lpBuffers);

    if(r == SOCKET_ERROR) {
        // XXX do we need special handling for ENETRESET, EMSGSIZE, ETIMEDOUT?
        errno = wsa_errno();
        return -1;
    }

    // DWORD has one bit more than ssize_t on 32bit
    // XXX check for this condition before the WSARecvMsg call
    if(bytesrcvd > SSIZE_MAX) {
        errno = EINVAL;
        return -1;
    }

    // transfer results from wsamsg to msg
    // NB: the data and control buffers are shared
    msg->msg_controllen = wsamsg.Control.len;
    msg->msg_flags = (int)wsamsg.dwFlags;
        // all flags that fit into dwFlags also fit into msg_flags (see above)

    return bytesrcvd;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    LPFN_WSASENDMSG WSASendMsg = NULL;
    GUID wsaid = WSAID_WSASENDMSG;
    DWORD b;

    DWORD bytessent;
    WSAMSG wsamsg;
    size_t i;
    int r;

    // size_t is larger than DWORD on 64bit
    if(msg->msg_iovlen > UINT32_MAX) {
        errno = EINVAL;
        return -1;
    }

    // obtain the function pointer to WSASendMsg
    r = WSAIoctl(sockfd, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &wsaid, sizeof(wsaid), &WSASendMsg, sizeof(WSASendMsg),
                 &b, NULL, NULL);
    if(r == SOCKET_ERROR) {
        errno = wsa_errno();
        return -1;
    }
    assert(b == sizeof(WSASendMsg));
    assert(WSASendMsg != NULL);

    // convert msghdr to WSAMSG structure
    wsamsg.name = msg->msg_name;
    wsamsg.namelen = msg->msg_namelen;
    wsamsg.lpBuffers = malloc(msg->msg_iovlen * sizeof(WSABUF));
    wsamsg.dwBufferCount = msg->msg_iovlen;
    wsamsg.Control.len = msg->msg_controllen;
    wsamsg.Control.buf = msg->msg_control;
    wsamsg.dwFlags = 0; // ignored

    if(wsamsg.lpBuffers == NULL) {
        // malloc will have set errno
        return -1;
    }

    // re-wrap iovecs as WSABUFs
    for(i=0; i<msg->msg_iovlen; i++) {
        // size_t vs. u_long
        if(msg->msg_iov[i].iov_len > ULONG_MAX) {
            free(wsamsg.lpBuffers);
            errno = EINVAL;
            return -1;
        }

        wsamsg.lpBuffers[i].len = msg->msg_iov[i].iov_len;
        wsamsg.lpBuffers[i].buf = msg->msg_iov[i].iov_base;
    }

    r = WSASendMsg(sockfd, &wsamsg, flags, &bytessent, NULL, NULL);

    // the allocated WSABUF wrappers are no longer needed
    free(wsamsg.lpBuffers);

    if(r == SOCKET_ERROR) {
        // XXX do we need special handling for ENETRESET, ETIMEDOUT?
        errno = wsa_errno();
        return -1;
    }

    // DWORD has one bit more than ssize_t on 32bit
    // XXX check for this condition before sending anything
    if(bytessent > SSIZE_MAX) {
        errno = EINVAL;
        return -1;
    }

    return bytessent;
}

int ioctl(int d, unsigned long request, int *p)
{
    u_long arg = *p;

    if(ioctlsocket(d, request, &arg) == SOCKET_ERROR) {
        errno = wsa_errno();
        return -1;
    }

    if(arg > INT_MAX) {
        errno = EINVAL;
        return -1;
    }

    *p = arg;
    return 0;
}

int pipe(int pipefd[2])
{
    int lsock = (int)INVALID_SOCKET;
    struct sockaddr_in laddr;
    socklen_t laddrlen = sizeof(laddr);

    pipefd[0] = pipefd[1] = (int)INVALID_SOCKET;

    // bind a listening socket to a TCP port on localhost
    laddr.sin_family = AF_INET;
    laddr.sin_port = 0;
    laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if((lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == SOCKET_ERROR)
        goto fail;
    if(bind(lsock, (struct sockaddr *)&laddr, sizeof(laddr)) == SOCKET_ERROR)
        goto fail;
    if(listen(lsock, 1) == SOCKET_ERROR)
        goto fail;

    // determine which address (i.e. port) we got bound to
    if(getsockname(lsock, (struct sockaddr *)&laddr, &laddrlen) == SOCKET_ERROR)
        goto fail;
    assert(laddrlen == sizeof(laddr));
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    // connect and accept
    if((pipefd[0] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == SOCKET_ERROR)
        goto fail;
    if(connect(pipefd[0], (const struct sockaddr *)&laddr, sizeof(laddr)) == SOCKET_ERROR)
        goto fail;
    if((pipefd[1] = accept(lsock, NULL, NULL)) == SOCKET_ERROR)
        goto fail;

    // close the listener
    closesocket(lsock);

    return 0;

fail:
    errno = wsa_errno();
    closesocket(pipefd[0]);
    closesocket(lsock);
    return -1;
}

int uname(struct utsname *buf)
{
    SYSTEM_INFO si;
    const char *arch = "unknown";

    memset(buf, 0, sizeof(struct utsname));

    // operating system
    strncpy(buf->sysname, "Windows", sizeof(buf->sysname)-1);
    strncpy(buf->release, "unknown", sizeof(buf->sysname)-1);   // we don't need it
    strncpy(buf->version, "unknown", sizeof(buf->sysname)-1);   // we don't need it

    // computer (node) name
    DWORD nodename_size = sizeof(buf->nodename)-1;
    if(GetComputerName(buf->nodename, &nodename_size) == 0) {
        errno = EFAULT;
        return -1;
    }

    // hardware type
    GetSystemInfo(&si);
    switch(si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: arch = "amd64"; break;
        case PROCESSOR_ARCHITECTURE_ARM:   arch = "arm";   break;
        case PROCESSOR_ARCHITECTURE_IA64:  arch = "ia64";  break;
        case PROCESSOR_ARCHITECTURE_INTEL: arch = "x86";   break;
        default: arch = "unknown";
    }
    strncpy(buf->machine, arch, sizeof(buf->machine)-1);

    return 0;
}
