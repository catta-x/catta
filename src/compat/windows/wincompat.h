#ifndef foowincompatfoo
#define foowincompatfoo

// This file and its companion wincompat.c provide some Posix interfaces to
// Windows APIs so the rest of the code can keep using them.


// require at least Windows Vista
#undef WINVER
#undef _WIN32_WINNT
#define WINVER 0x0600
#define _WIN32_WINNT WINVER

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>


// wrappers around WSAStartup/WSACleanup to avoid clutter
void winsock_init(void);
void winsock_exit(void);


// the equivalent of strerror(errno) for Windows sockets
char *errnostrsocket(void);


// Winsock doesn't have recvmsg/sendmsg but offers the same functionality
// with WSARecvMsg/WSASendMsg, so we implement the former in terms of the
// latter.

struct iovec {                   /* Scatter/gather array items */
   void  *iov_base;              /* Starting address */
   size_t iov_len;               /* Number of bytes to transfer */
};

struct msghdr {
   void         *msg_name;       /* optional address */
   socklen_t     msg_namelen;    /* size of address */
   struct iovec *msg_iov;        /* scatter/gather array */
   size_t        msg_iovlen;     /* # elements in msg_iov */
   void         *msg_control;    /* ancillary data, see below */
   size_t        msg_controllen; /* ancillary data buffer len */
   int           msg_flags;      /* flags on received message */
};

// MSDN says this struct is called wsacmsghdr but MingW uses _WSACMSGHDR.
// TODO: Verify what it is on actual Windows.
// cf. http://msdn.microsoft.com/en-us/library/ms741645(v=vs.85).aspx
#ifdef __MINGW32__
#define cmsghdr _WSACMSGHDR     // as in 'struct cmsghdr'
#else
#define cmsghdr wsacmsghdr      // as in 'struct cmsghdr'
#endif

static inline struct cmsghdr *CMSG_FIRSTHDR(struct msghdr *m) {
    WSAMSG wm;
    wm.Control.len = m->msg_controllen;
    wm.Control.buf = m->msg_control;
    return WSA_CMSG_FIRSTHDR(&wm);
}

static inline struct cmsghdr *CMSG_NXTHDR(struct msghdr *m, struct cmsghdr *c) {
    WSAMSG wm;
    wm.Control.len = m->msg_controllen;
    wm.Control.buf = m->msg_control;
    return WSA_CMSG_NXTHDR(&wm, c);
}

#define CMSG_SPACE(len) WSA_CMSG_SPACE(len)
#define CMSG_LEN(len) WSA_CMSG_LEN(len)

// we're going to be naughty and redefine CMSG_DATA as an alias even though it
// is also a constant defined in wincrypt.h which we don't care about.
#undef CMSG_DATA
#define CMSG_DATA(c) WSA_CMSG_DATA(c)

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

// ESHUTDOWN does not seem to exist on Windows, even though WSAESHUTDOWN does.
// MingW doesn't define it and MSDN doesn't list it, so we alias it to EBADF.
// cf. http://msdn.microsoft.com/en-us/library/5814770t.aspx
#ifndef ESHUTDOWN
#define ESHUTDOWN EBADF
#endif


// Windows doesn't have ioctl but offers ioctlsocket for some socket-related
// functions. Unfortunately, argument types differ, so we implement a
// (restricted) wrapper.
int ioctl(int d, unsigned long request, int *p);


// Windows lacks poll, but WSAPoll is good enough for us.
#define poll(fds, nfds, timeout) WSAPoll(fds, nfds, timeout)

// Windows lacks pipe. It has an equivalent CreatePipe but we really need
// something to give to WSAPoll, so we fake it with a local TCP socket. (ugh)
int pipe(int pipefd[2]);

// pipe(socket)-specific read/write/close equivalents
#define closepipe closesocket
#define writepipe(s,buf,len) send(s, buf, len, 0)
#define readpipe(s,buf,len) recv(s, buf, len, 0)


// Windows logically doesn't have uname, so we supply a replacement.

struct utsname {
   char sysname[9];    /* Operating system name (e.g., "Linux") */
   char nodename[MAX_COMPUTERNAME_LENGTH+1];
                       /* Name within "some implementation-defined network" */
   char release[9];    /* Operating system release (e.g., "2.6.28") */
   char version[9];    /* Operating system version */
   char machine[9];    /* Hardware identifier */
};

int uname(struct utsname *buf);


#endif
