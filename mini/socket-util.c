/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#if defined(__linux__)
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#endif
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/if.h>
#endif

#include "alloc-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "io-util.h"
#include "log.h"
#include "memory-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
//#include "sysctl-util.h"
#include "user-util.h"
#include "utf8.h"

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <stdio.h>

typedef unsigned int gid_t;
#define ERR(e) \
        { \
        fprintf(stderr, "%s:%s failed: %d [%s@%ld]\n",__FUNCTION__,e,WSAGetLastError(),__FILE__,__LINE__); \
        }
#define	EXFULL		54	/* Exchange full */
#endif

int getpeercred(int fd, struct ucred* ucred) {
#if defined(__linux__)
    socklen_t n = sizeof(struct ucred);
    struct ucred u;
    int r;

    assert(fd >= 0);
    assert(ucred);

    r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &u, &n);
    if (r < 0)
        return -errno;

    if (n != sizeof(struct ucred))
        return -EIO;

    /* Check if the data is actually useful and not suppressed due to namespacing issues */
    if (!pid_is_valid(u.pid))
        return -ENODATA;

    /* Note that we don't check UID/GID here, as namespace translation works differently there: instead of
     * receiving in "invalid" user/group we get the overflow UID/GID. */

    *ucred = u;
#endif
    return 0;
}

int getpeersec(int fd, char** ret) {
#if defined(__linux__)
    _cleanup_free_ char* s = NULL;
    socklen_t n = 64;

    assert(fd >= 0);
    assert(ret);

    for (;;) {
        s = new0(char, n + 1);
        if (!s)
            return -ENOMEM;

        if (getsockopt(fd, SOL_SOCKET, SO_PEERSEC, s, &n) >= 0)
            break;

        if (errno != ERANGE)
            return -errno;

        //s = mfree(s);
        free(s);
        s = NULL;
    }

    if (isempty(s))
        return -EOPNOTSUPP;

    //*ret = TAKE_PTR(s);
    *ret = s;
    s = NULL;
#endif
    return 0;
}

int getpeergroups(int fd, gid_t** ret) {
    socklen_t n = sizeof(gid_t) * 64;
    _cleanup_free_ gid_t* d = NULL;

    assert(fd >= 0);
    assert(ret);

    for (;;) {
        d = malloc(n);
        if (!d)
            return -ENOMEM;

        if (getsockopt(fd, SOL_SOCKET, SO_PEERGROUPS, d, &n) >= 0)
            break;

        if (errno != ERANGE)
            return -errno;

        //d = mfree(d);
        free(d);
        d = NULL;
    }

    assert_se(n % sizeof(gid_t) == 0);
    n /= sizeof(gid_t);

    if ((socklen_t)(int)n != n)
        return -E2BIG;

    //*ret = TAKE_PTR(d);
    *ret = d;
    d = NULL;

    return (int)n;
}

int sockaddr_pretty(
    const struct sockaddr* _sa,
    socklen_t salen,
    bool translate_ipv6,
    bool include_port,
    char** ret) {

    union sockaddr_union* sa = (union sockaddr_union*)_sa;
    char* p = NULL;
    int r;

    assert(sa);
    assert(salen >= sizeof(sa->sa.sa_family));

    switch (sa->sa.sa_family) {

    case AF_INET: {
        uint32_t a;

        a = be32toh(sa->in.sin_addr.s_addr);

        if (include_port)
            r = asprintf(&p,
                "%u.%u.%u.%u:%u",
                a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF,
                be16toh(sa->in.sin_port));
        else
            r = asprintf(&p,
                "%u.%u.%u.%u",
                a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF);
        if (r < 0)
            return -ENOMEM;
        break;
    }

    case AF_INET6: {
        static const unsigned char ipv4_prefix[] = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
        };

        if (translate_ipv6 &&
            memcmp(&sa->in6.sin6_addr, ipv4_prefix, sizeof(ipv4_prefix)) == 0) {
            const uint8_t* a = sa->in6.sin6_addr.s6_addr + 12;
            if (include_port)
                r = asprintf(&p,
                    "%u.%u.%u.%u:%u",
                    a[0], a[1], a[2], a[3],
                    be16toh(sa->in6.sin6_port));
            else
                r = asprintf(&p,
                    "%u.%u.%u.%u",
                    a[0], a[1], a[2], a[3]);
            if (r < 0)
                return -ENOMEM;
        }
        else {
            char a[INET6_ADDRSTRLEN];

            inet_ntop(AF_INET6, &sa->in6.sin6_addr, a, sizeof(a));

            if (include_port) {
                if (asprintf(&p,
                    "[%s]:%u%s%s",
                    a,
                    be16toh(sa->in6.sin6_port),
                    sa->in6.sin6_scope_id != 0 ? "%" : "",
                    ""//FORMAT_IFNAME_FULL(sa->in6.sin6_scope_id, FORMAT_IFNAME_IFINDEX)
                ) < 0)
                    return -ENOMEM;
            }
            else {
                if (sa->in6.sin6_scope_id != 0)
                    ;// p = strjoin(a, "%", FORMAT_IFNAME_FULL(sa->in6.sin6_scope_id, FORMAT_IFNAME_IFINDEX));
                else
                    p = strdup(a);
                if (!p)
                    return -ENOMEM;
            }
        }

        break;
    }

    case AF_UNIX:
        if (salen <= offsetof(struct sockaddr_un, sun_path) ||
            (sa->un.sun_path[0] == 0 && salen == offsetof(struct sockaddr_un, sun_path) + 1))
            /* The name must have at least one character (and the leading NUL does not count) */
            p = strdup("<unnamed>");
        else {
            /* Note that we calculate the path pointer here through the .un_buffer[] field, in order to
             * outtrick bounds checking tools such as ubsan, which are too smart for their own good: on
             * Linux the kernel may return sun_path[] data one byte longer than the declared size of the
             * field. */
            char* path = (char*)sa->un_buffer + offsetof(struct sockaddr_un, sun_path);
            size_t path_len = salen - offsetof(struct sockaddr_un, sun_path);

            if (path[0] == 0) {
                /* Abstract socket. When parsing address information from, we
                 * explicitly reject overly long paths and paths with embedded NULs.
                 * But we might get such a socket from the outside. Let's return
                 * something meaningful and printable in this case. */

                _cleanup_free_ char* e = NULL;

                e = cescape_length(path + 1, path_len - 1);
                if (!e)
                    return -ENOMEM;

                p = strjoin("@", e);
            }
            else {
                if (path[path_len - 1] == '\0')
                    /* We expect a terminating NUL and don't print it */
                    path_len--;

                p = cescape_length(path, path_len);
            }
        }
        if (!p)
            return -ENOMEM;

        break;

    case AF_VSOCK:
        if (include_port) {
            if (sa->vm.svm_cid == VMADDR_CID_ANY)
                r = asprintf(&p, "vsock::%u", sa->vm.svm_port);
            else
                r = asprintf(&p, "vsock:%u:%u", sa->vm.svm_cid, sa->vm.svm_port);
        }
        else
            r = asprintf(&p, "vsock:%u", sa->vm.svm_cid);
        if (r < 0)
            return -ENOMEM;
        break;

    default:
        return -EOPNOTSUPP;
    }

    *ret = p;
    return 0;
}

void cmsg_close_all(struct msghdr* mh) {
#if defined(__linux__)
    struct cmsghdr* cmsg;

    assert(mh);

    CMSG_FOREACH(cmsg, mh)
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
            close_many((int*)CMSG_DATA(cmsg), (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
#endif

}

ssize_t recvmsg_safe(int sockfd, struct msghdr* msg, int flags) {
    ssize_t n;

    /* A wrapper around recvmsg() that checks for MSG_CTRUNC, and turns it into an error, in a reasonably
     * safe way, closing any SCM_RIGHTS fds in the error path.
     *
     * Note that unlike our usual coding style this might modify *msg on failure. */
#ifdef WIN32

    LPWSAMSG wmsg = (LPWSAMSG)msg;

    /*
    LPFN_WSARECVMSG     lpfnWSARecvMsg = NULL;
    GUID                guidWSARecvMsg = WSAID_WSARECVMSG;
    DWORD               dwBytes = 0;
    if (SOCKET_ERROR == WSAIoctl(sockfd,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &guidWSARecvMsg,
            sizeof(guidWSARecvMsg),
            &lpfnWSARecvMsg,
            sizeof(lpfnWSARecvMsg),
            &dwBytes,
            NULL,
            NULL
    ))
    {
        ERR("WSAIoctl SIO_GET_EXTENSION_FUNCTION_POINTER");
        return -errno;
    }
    
    if (SOCKET_ERROR == lpfnWSARecvMsg(sockfd,
            wmsg,
            &dwBytes,
            NULL,
            NULL
    ))
    {
        int e = WSAGetLastError();
        if (WSA_IO_PENDING != e)
        {
            ERR("WSARecvMsg");
        }
        n = -e;
    }
    else {
        n = dwBytes;
    }
    
    // try WSARecv
    if (SOCKET_ERROR == WSARecv(sockfd, wmsg->lpBuffers, wmsg->dwBufferCount, &dwBytes, NULL, NULL, NULL))
    {
        ERR("WSARecv");
        printf("WSARecv Bytes: %d\n", dwBytes);
        for (int i = 0; i < dwBytes; i++) {
            printf("%02x ", wmsg->lpBuffers->buf[i]);
        }
        printf("\n");
    }
    */

    int iResult = recv(sockfd, wmsg->lpBuffers->buf, wmsg->lpBuffers->len, /*flags*/0);
    if (iResult > 0) {
        fprintf(stderr, "Bytes received: %d\n", iResult);
        int i;
        for (i = 0; i < iResult; i++) {
            fprintf(stderr, "%02x ", wmsg->lpBuffers->buf[i]);
        }
        fprintf(stderr, "\n");
    }
    else if (iResult == 0) {
        fprintf(stderr, "Connection closed\n");
        iResult = -ECONNRESET;
    }
    else {
        int e = WSAGetLastError();
        fprintf(stderr, "recv failed: %d, buf len: %lu\n", e, wmsg->lpBuffers->len);
        if (e == WSAEWOULDBLOCK) {
            /*This error is returned from operations on nonblocking sockets 
            that cannot be completed immediately, for example recv when no data is queued to be read from the socket. 
            It is a nonfatal error, and the operation should be retried later.*/
            iResult = -EAGAIN;
        }
        else
        {
            iResult = -e;
        }
    }

    n = iResult;

    if (n < 0)
        return n;
#else
    n = recvmsg(sockfd, msg, flags);
    printf(">> recvmsg: %ld\n", n);
    if (n < 0)
        return -errno;
#endif
    

    if (FLAGS_SET(msg->msg_flags, MSG_CTRUNC)) {
        cmsg_close_all(msg);
        return -EXFULL; /* a recognizable error code */
    }

    return n;
}


// from sd_daemon.c
//int sd_is_socket(int fd, int family, int type, int listening) {
//    return 1;
//}

// sync-util.c
int fsync_full(int fd) {
    return 0;
}

// fd-util.c
int fd_move_above_stdio(int fd) {
    int flags, copy;
    PROTECT_ERRNO;

    /* Moves the specified file descriptor if possible out of the range [0…2], i.e. the range of
     * stdin/stdout/stderr. If it can't be moved outside of this range the original file descriptor is
     * returned. This call is supposed to be used for long-lasting file descriptors we allocate in our code that
     * might get loaded into foreign code, and where we want ensure our fds are unlikely used accidentally as
     * stdin/stdout/stderr of unrelated code.
     *
     * Note that this doesn't fix any real bugs, it just makes it less likely that our code will be affected by
     * buggy code from others that mindlessly invokes 'fprintf(stderr, …' or similar in places where stderr has
     * been closed before.
     *
     * This function is written in a "best-effort" and "least-impact" style. This means whenever we encounter an
     * error we simply return the original file descriptor, and we do not touch errno. */

    if (fd < 0 || fd > 2)
        return fd;
#if defined(__linux__)
    flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0)
        return fd;

    if (flags & FD_CLOEXEC)
        copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    else
        copy = fcntl(fd, F_DUPFD, 3);
    if (copy < 0)
        return fd;

    assert(copy > 2);

    (void)close(fd);
    return copy;
#else
    return fd;

#endif
}

int fd_set_sndbuf(int fd, size_t n, bool increase) {
    int r, value;
    socklen_t l = sizeof(value);

    if (n > INT_MAX)
        return -ERANGE;

    r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &l);
    if (r >= 0 && l == sizeof(value) && increase ? (size_t)value >= n * 2 : (size_t)value == n * 2)
        return 0;

    /* First, try to set the buffer size with SO_SNDBUF. */
    r = setsockopt_int(fd, SOL_SOCKET, SO_SNDBUF, n);
    if (r < 0)
        return r;

    /* SO_SNDBUF above may set to the kernel limit, instead of the requested size.
     * So, we need to check the actual buffer size here. */
    l = sizeof(value);
    r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &l);
    if (r >= 0 && l == sizeof(value) && increase ? (size_t)value >= n * 2 : (size_t)value == n * 2)
        return 1;

#if defined(__linux__)
    /* If we have the privileges we will ignore the kernel limit. */
    r = setsockopt_int(fd, SOL_SOCKET, SO_SNDBUFFORCE, n);
    if (r < 0)
        return r;
#endif
    return 1;
}

int fd_set_rcvbuf(int fd, size_t n, bool increase) {
    int r, value;
    socklen_t l = sizeof(value);

    if (n > INT_MAX)
        return -ERANGE;

    r = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &l);
    if (r >= 0 && l == sizeof(value) && increase ? (size_t)value >= n * 2 : (size_t)value == n * 2)
        return 0;

    /* First, try to set the buffer size with SO_RCVBUF. */
    r = setsockopt_int(fd, SOL_SOCKET, SO_RCVBUF, n);
    if (r < 0)
        return r;

    /* SO_RCVBUF above may set to the kernel limit, instead of the requested size.
     * So, we need to check the actual buffer size here. */
    l = sizeof(value);
    r = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &l);
    if (r >= 0 && l == sizeof(value) && increase ? (size_t)value >= n * 2 : (size_t)value == n * 2)
        return 1;

#if defined(__linux__)
    /* If we have the privileges we will ignore the kernel limit. */
    r = setsockopt_int(fd, SOL_SOCKET, SO_RCVBUFFORCE, n);
    if (r < 0)
        return r;
#endif

    return 1;
}

int sockaddr_port(const struct sockaddr* _sa, unsigned* ret_port) {
    const union sockaddr_union* sa = (const union sockaddr_union*)_sa;

    /* Note, this returns the port as 'unsigned' rather than 'uint16_t', as AF_VSOCK knows larger ports */

    assert(sa);

    switch (sa->sa.sa_family) {

    case AF_INET:
        *ret_port = be16toh(sa->in.sin_port);
        return 0;

    case AF_INET6:
        *ret_port = be16toh(sa->in6.sin6_port);
        return 0;

    case AF_VSOCK:
        *ret_port = sa->vm.svm_port;
        return 0;

    default:
        return -EAFNOSUPPORT;
    }
}

int sockaddr_un_set_path(struct sockaddr_un* ret, const char* path) {
    size_t l;

    assert(ret);
    assert(path);

    /* Initialize ret->sun_path from the specified argument. This will interpret paths starting with '@' as
     * abstract namespace sockets, and those starting with '/' as regular filesystem sockets. It won't accept
     * anything else (i.e. no relative paths), to avoid ambiguities. Note that this function cannot be used to
     * reference paths in the abstract namespace that include NUL bytes in the name. */

    l = strlen(path);
    if (l < 2)
        return -EINVAL;
    if (!IN_SET(path[0], '/', '@'))
        return -EINVAL;

    /* Don't allow paths larger than the space in sockaddr_un. Note that we are a tiny bit more restrictive than
     * the kernel is: we insist on NUL termination (both for abstract namespace and regular file system socket
     * addresses!), which the kernel doesn't. We do this to reduce chance of incompatibility with other apps that
     * do not expect non-NUL terminated file system path. */
    if (l + 1 > sizeof(ret->sun_path))
        return -EINVAL;

    *ret = (struct sockaddr_un){
            .sun_family = AF_UNIX,
    };

    if (path[0] == '@') {
        /* Abstract namespace socket */
        memcpy(ret->sun_path + 1, path + 1, l); /* copy *with* trailing NUL byte */
        return (int)(offsetof(struct sockaddr_un, sun_path) + l); /* 🔥 *don't* 🔥 include trailing NUL in size */

    }
    else {
        assert(path[0] == '/');

        /* File system socket */
        memcpy(ret->sun_path, path, l + 1); /* copy *with* trailing NUL byte */
        return (int)(offsetof(struct sockaddr_un, sun_path) + l + 1); /* include trailing NUL in size */
    }
}