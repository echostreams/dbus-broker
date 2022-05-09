#if defined WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <WinSock2.h>
#include <stdlib.h>
#include <stdio.h>

#include <poll.h>

#ifndef MAX
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif


typedef unsigned int dbus_bool_t;
typedef struct { SOCKET sock; } DBusSocket;
/** Mostly-opaque type representing an error that occurred */
typedef struct DBusError DBusError;
typedef DBusSocket DBusPollable;

typedef struct
{
    DBusPollable fd;   /**< File descriptor */
    short events;      /**< Events to poll for */
    short revents;     /**< Events that occurred */
} DBusPollFD;

/** There is data to read */
#define _DBUS_POLLIN      0x0001
/** There is urgent data to read */
#define _DBUS_POLLPRI     0x0002
/** Writing now will not block */
#define _DBUS_POLLOUT     0x0004
/** Error condition */
#define _DBUS_POLLERR     0x0008
/** Hung up */
#define _DBUS_POLLHUP     0x0010
/** Invalid request: fd not open */
#define _DBUS_POLLNVAL    0x0020


/**
 * Object representing an exception.
 */
struct DBusError
{
    const char* name;    /**< public error name field */
    const char* message; /**< public error message field */

    unsigned int dummy1 : 1; /**< placeholder */
    unsigned int dummy2 : 1; /**< placeholder */
    unsigned int dummy3 : 1; /**< placeholder */
    unsigned int dummy4 : 1; /**< placeholder */
    unsigned int dummy5 : 1; /**< placeholder */

    void* padding1; /**< placeholder */
};


#define DBUS_SOCKET_API_RETURNS_ERROR(n) ((n) == SOCKET_ERROR)
#define DBUS_SOCKET_SET_ERRNO() (_dbus_win_set_errno (WSAGetLastError()))
#define _DBUS_ZERO(object) (memset (&(object), '\0', sizeof ((object))))
#define _dbus_verbose(fmt,...) _dbus_verbose_real( __FILE__,__LINE__,__FUNCTION__,fmt, ## __VA_ARGS__)
#define _DBUS_GNUC_NORETURN
void _dbus_real_assert_not_reached(const char* explanation,
    const char* file,
    int         line) _DBUS_GNUC_NORETURN;
#define _dbus_assert_not_reached(explanation)                                   \
  _dbus_real_assert_not_reached (explanation, __FILE__, __LINE__)

/**
 * Aborts the program with SIGABRT (dumping core).
 */
void
_dbus_abort(void)
{
    //const char* s;

    //_dbus_print_backtrace();

    //s = _dbus_getenv("DBUS_BLOCK_ON_ABORT");
    //if (s && *s)
    //{
    //    /* don't use _dbus_warn here since it can _dbus_abort() */
    //    fprintf(stderr, "  Process %lu sleeping for gdb attach\n", _dbus_pid_for_log());
    //    _dbus_sleep_milliseconds(1000 * 180);
    //}

    abort();
    //_dbus_exit(1); /* in case someone manages to ignore SIGABRT ? */
    _exit(1);
}


/**
 * Internals of _dbus_assert_not_reached(); it's a function
 * rather than a macro with the inline code so
 * that the assertion failure blocks don't show up
 * in test suite coverage, and to shrink code size.
 *
 * @param explanation what was reached that shouldn't have been
 * @param file file the assertion is in
 * @param line line the assertion is in
 */
void
_dbus_real_assert_not_reached(const char* explanation,
    const char* file,
    int         line)
{
    //_dbus_warn(
    fprintf(stderr, 
        "File \"%s\" line %d should not have been reached: %s",
        file, line, explanation);
    _dbus_abort();
}

/**
 * Prints a warning message to stderr
 * if the user has enabled verbose mode.
 * This is the real function implementation,
 * use _dbus_verbose() macro in code.
 *
 * @param format printf-style format string.
 */
#define DBUS_CPP_SUPPORTS_VARIABLE_MACRO_ARGUMENTS
//#define DBUS_USE_OUTPUT_DEBUG_STRING
void
_dbus_verbose_real(
#ifdef DBUS_CPP_SUPPORTS_VARIABLE_MACRO_ARGUMENTS
    const char* file,
    const int line,
    const char* function,
#endif
    const char* format,
    ...)
{
    va_list args;
    static dbus_bool_t need_pid = TRUE;
    size_t len;
    //long sec, usec;

    /* things are written a bit oddly here so that
     * in the non-verbose case we just have the one
     * conditional and return immediately.
     */
    //if (!_dbus_is_verbose_real())
    //    return;

#ifndef DBUS_USE_OUTPUT_DEBUG_STRING
    /* Print out pid before the line */
    if (need_pid)
    {
        //_dbus_print_thread();
    }
    //_dbus_get_real_time(&sec, &usec);
    //fprintf(stderr, "%ld.%06ld ", sec, usec);
#endif

    /* Only print pid again if the next line is a new line */
    len = strlen(format);
    if (format[len - 1] == '\n')
        need_pid = TRUE;
    else
        need_pid = FALSE;

    va_start(args, format);
#ifdef DBUS_USE_OUTPUT_DEBUG_STRING
    {
        char buf[1024];
        strcpy(buf, module_name);
#ifdef DBUS_CPP_SUPPORTS_VARIABLE_MACRO_ARGUMENTS
        sprintf(buf + strlen(buf), "[%s(%d):%s] ", _dbus_file_path_extract_elements_from_tail(file, 2), line, function);
#endif
        vsprintf(buf + strlen(buf), format, args);
        va_end(args);
        OutputDebugStringA(buf);
    }
#else
#ifdef DBUS_CPP_SUPPORTS_VARIABLE_MACRO_ARGUMENTS
    fprintf(stderr, "[%s(%d):%s] ", /*_dbus_file_path_extract_elements_from_tail(file, 2)*/file, line, function);
#endif

    vfprintf(stderr, format, args);
    va_end(args);

    fflush(stderr);
#endif
}

void
_dbus_win_set_errno(int err)
{
#ifdef DBUS_WINCE
    SetLastError(err);
#else
    errno = err;
#endif
}

/**
 * @returns #FALSE if no memory
 */
dbus_bool_t
_dbus_win_startup_winsock(void)
{
    /* Straight from MSDN, deuglified */

    /* Protected by _DBUS_LOCK_sysdeps */
    static dbus_bool_t beenhere = FALSE;

    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    //if (!_DBUS_LOCK(sysdeps))
    //    return FALSE;

    if (beenhere)
        goto out;

    wVersionRequested = MAKEWORD(2, 0);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        _dbus_assert_not_reached("Could not initialize WinSock");
        _dbus_abort();
    }

    /* Confirm that the WinSock DLL supports 2.0.  Note that if the DLL
     * supports versions greater than 2.0 in addition to 2.0, it will
     * still return 2.0 in wVersion since that is the version we
     * requested.
     */
    if (LOBYTE(wsaData.wVersion) != 2 ||
        HIBYTE(wsaData.wVersion) != 0)
    {
        _dbus_assert_not_reached("No usable WinSock found");
        _dbus_abort();
    }

    beenhere = TRUE;

out:
    //_DBUS_UNLOCK(sysdeps);
    return TRUE;
}

/************************************************************************

 pipes

 ************************************************************************/

 /**
  * Creates pair of connect sockets (as in socketpair()).
  * Sets both ends of the pair nonblocking.
  *
  * Marks both file descriptors as close-on-exec
  *
  * @param fd1 return location for one end
  * @param fd2 return location for the other end
  * @param blocking #TRUE if pair should be blocking
  * @param error error return
  * @returns #FALSE on failure (if error is set)
  */
dbus_bool_t
_dbus_socketpair(DBusSocket* fd1,
    DBusSocket* fd2,
    dbus_bool_t blocking,
    DBusError* error)
{
    SOCKET temp, socket1 = -1, socket2 = -1;
    struct sockaddr_in saddr;
    int len;
    u_long arg;

    if (!_dbus_win_startup_winsock())
    {
        //_DBUS_SET_OOM(error);
        return FALSE;
    }

    temp = socket(AF_INET, SOCK_STREAM, 0);
    if (temp == INVALID_SOCKET)
    {
        DBUS_SOCKET_SET_ERRNO();
        goto out0;
    }

    _DBUS_ZERO(saddr);
    saddr.sin_family = AF_INET;
    saddr.sin_port = 0;
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(temp, (struct sockaddr*)&saddr, sizeof(saddr)) == SOCKET_ERROR)
    {
        DBUS_SOCKET_SET_ERRNO();
        goto out0;
    }

    if (listen(temp, 1) == SOCKET_ERROR)
    {
        DBUS_SOCKET_SET_ERRNO();
        goto out0;
    }

    len = sizeof(saddr);
    if (getsockname(temp, (struct sockaddr*)&saddr, &len) == SOCKET_ERROR)
    {
        DBUS_SOCKET_SET_ERRNO();
        goto out0;
    }

    socket1 = socket(AF_INET, SOCK_STREAM, 0);
    if (socket1 == INVALID_SOCKET)
    {
        DBUS_SOCKET_SET_ERRNO();
        goto out0;
    }

    if (connect(socket1, (struct sockaddr*)&saddr, len) == SOCKET_ERROR)
    {
        DBUS_SOCKET_SET_ERRNO();
        goto out1;
    }

    socket2 = accept(temp, (struct sockaddr*)&saddr, &len);
    if (socket2 == INVALID_SOCKET)
    {
        DBUS_SOCKET_SET_ERRNO();
        goto out1;
    }

    if (!blocking)
    {
        arg = 1;
        if (ioctlsocket(socket1, FIONBIO, &arg) == SOCKET_ERROR)
        {
            DBUS_SOCKET_SET_ERRNO();
            goto out2;
        }

        arg = 1;
        if (ioctlsocket(socket2, FIONBIO, &arg) == SOCKET_ERROR)
        {
            DBUS_SOCKET_SET_ERRNO();
            goto out2;
        }
    }

    fd1->sock = socket1;
    fd2->sock = socket2;

    _dbus_verbose("full-duplex pipe %Iu:%Iu <-> %Iu:%Iu\n",
        fd1->sock, socket1, fd2->sock, socket2);

    closesocket(temp);

    return TRUE;

out2:
    closesocket(socket2);
out1:
    closesocket(socket1);
out0:
    closesocket(temp);

    //dbus_set_error(error, _dbus_error_from_errno(errno),
    //    "Could not setup socket pair: %s",
    //    _dbus_strerror_from_errno());

    return FALSE;
}

#define DBUS_ENABLE_VERBOSE_MODE

/**
 * Wrapper for poll().
 *
 * @param fds the file descriptors to poll
 * @param n_fds number of descriptors in the array
 * @param timeout_milliseconds timeout or -1 for infinite
 * @returns numbers of fds with revents, or <0 on error
 */
int
_dbus_poll(DBusPollFD* fds,
    int         n_fds,
    int         timeout_milliseconds)
{
#define USE_CHRIS_IMPL 0

#if USE_CHRIS_IMPL

#define DBUS_POLL_CHAR_BUFFER_SIZE 2000
    char msg[DBUS_POLL_CHAR_BUFFER_SIZE];
    char* msgp;

    int ret = 0;
    int i;
    struct timeval tv;
    int ready;

#define DBUS_STACK_WSAEVENTS 256
    WSAEVENT eventsOnStack[DBUS_STACK_WSAEVENTS];
    WSAEVENT* pEvents = NULL;
    if (n_fds > DBUS_STACK_WSAEVENTS)
        pEvents = calloc(sizeof(WSAEVENT), n_fds);
    else
        pEvents = eventsOnStack;


#ifdef DBUS_ENABLE_VERBOSE_MODE
    msgp = msg;
    msgp += sprintf(msgp, "WSAEventSelect: to=%d\n\t", timeout_milliseconds);
    for (i = 0; i < n_fds; i++)
    {
        DBusPollFD* fdp = &fds[i];


        if (fdp->events & _DBUS_POLLIN)
            msgp += sprintf(msgp, "R:%Iu ", fdp->fd.sock);

        if (fdp->events & _DBUS_POLLOUT)
            msgp += sprintf(msgp, "W:%Iu ", fdp->fd.sock);

        msgp += sprintf(msgp, "E:%Iu\n\t", fdp->fd.sock);

        // FIXME: more robust code for long  msg
        //        create on heap when msg[] becomes too small
        if (msgp >= msg + DBUS_POLL_CHAR_BUFFER_SIZE)
        {
            _dbus_assert_not_reached("buffer overflow in _dbus_poll");
        }
    }

    msgp += sprintf(msgp, "\n");
    _dbus_verbose("%s", msg);
#endif
    for (i = 0; i < n_fds; i++)
    {
        DBusPollFD* fdp = &fds[i];
        WSAEVENT ev;
        long lNetworkEvents = FD_OOB;

        ev = WSACreateEvent();

        if (fdp->events & _DBUS_POLLIN)
            lNetworkEvents |= FD_READ | FD_ACCEPT | FD_CLOSE;

        if (fdp->events & _DBUS_POLLOUT)
            lNetworkEvents |= FD_WRITE | FD_CONNECT;

        WSAEventSelect(fdp->fd.sock, ev, lNetworkEvents);

        pEvents[i] = ev;
    }


    ready = WSAWaitForMultipleEvents(n_fds, pEvents, FALSE, timeout_milliseconds, FALSE);

    if (DBUS_SOCKET_API_RETURNS_ERROR(ready))
    {
        DBUS_SOCKET_SET_ERRNO();
        if (errno != WSAEWOULDBLOCK)
            _dbus_verbose("WSAWaitForMultipleEvents: failed: %s\n", _dbus_strerror_from_errno());
        ret = -1;
    }
    else if (ready == WSA_WAIT_TIMEOUT)
    {
        _dbus_verbose("WSAWaitForMultipleEvents: WSA_WAIT_TIMEOUT\n");
        ret = 0;
    }
    else if (ready >= WSA_WAIT_EVENT_0 && ready < (int)(WSA_WAIT_EVENT_0 + n_fds))
    {
        msgp = msg;
        msgp += sprintf(msgp, "WSAWaitForMultipleEvents: =%d\n\t", ready);

        for (i = 0; i < n_fds; i++)
        {
            DBusPollFD* fdp = &fds[i];
            WSANETWORKEVENTS ne;

            fdp->revents = 0;

            WSAEnumNetworkEvents(fdp->fd.sock, pEvents[i], &ne);

            if (ne.lNetworkEvents & (FD_READ | FD_ACCEPT | FD_CLOSE))
                fdp->revents |= _DBUS_POLLIN;

            if (ne.lNetworkEvents & (FD_WRITE | FD_CONNECT))
                fdp->revents |= _DBUS_POLLOUT;

            if (ne.lNetworkEvents & (FD_OOB))
                fdp->revents |= _DBUS_POLLERR;

            if (ne.lNetworkEvents & (FD_READ | FD_ACCEPT | FD_CLOSE))
                msgp += sprintf(msgp, "R:%Iu ", fdp->fd.sock);

            if (ne.lNetworkEvents & (FD_WRITE | FD_CONNECT))
                msgp += sprintf(msgp, "W:%Iu ", fdp->fd.sock);

            if (ne.lNetworkEvents & (FD_OOB))
                msgp += sprintf(msgp, "E:%Iu ", fdp->fd.sock);

            msgp += sprintf(msgp, "lNetworkEvents:%d ", ne.lNetworkEvents);

            if (ne.lNetworkEvents)
                ret++;

            WSAEventSelect(fdp->fd.sock, pEvents[i], 0);
        }

        msgp += sprintf(msgp, "\n");
        _dbus_verbose("%s", msg);
    }
    else
    {
        _dbus_verbose("WSAWaitForMultipleEvents: failed for unknown reason!");
        ret = -1;
    }

    for (i = 0; i < n_fds; i++)
    {
        WSACloseEvent(pEvents[i]);
    }

    if (n_fds > DBUS_STACK_WSAEVENTS)
        free(pEvents);

    return ret;

#else   /* USE_CHRIS_IMPL */

#ifdef DBUS_ENABLE_VERBOSE_MODE
#define DBUS_POLL_CHAR_BUFFER_SIZE 2000
    char msg[DBUS_POLL_CHAR_BUFFER_SIZE];
    char* msgp;
#endif

    fd_set read_set, write_set, err_set;
    SOCKET max_fd = 0;
    int i;
    struct timeval tv;
    int ready;

    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_ZERO(&err_set);


#ifdef DBUS_ENABLE_VERBOSE_MODE
    msgp = msg;
    msgp += sprintf(msgp, "select: to=%d\n\t", timeout_milliseconds);
    for (i = 0; i < n_fds; i++)
    {
        DBusPollFD* fdp = &fds[i];


        //if (fdp->events & _DBUS_POLLIN)
        if (fdp->events & POLLIN)
            msgp += sprintf(msgp, "R:%Iu ", fdp->fd.sock);

        //if (fdp->events & _DBUS_POLLOUT)
        if (fdp->events & POLLOUT)
            msgp += sprintf(msgp, "W:%Iu ", fdp->fd.sock);

        msgp += sprintf(msgp, "E:%Iu\n\t", fdp->fd.sock);

        // FIXME: more robust code for long  msg
        //        create on heap when msg[] becomes too small
        if (msgp >= msg + DBUS_POLL_CHAR_BUFFER_SIZE)
        {
            _dbus_assert_not_reached("buffer overflow in _dbus_poll");
        }
    }

    msgp += sprintf(msgp, "\n");
    _dbus_verbose("%s", msg);
#endif
    for (i = 0; i < n_fds; i++)
    {
        DBusPollFD* fdp = &fds[i];

        //if (fdp->events & _DBUS_POLLIN)
        if (fdp->events & POLLIN)
            FD_SET(fdp->fd.sock, &read_set);

        //if (fdp->events & _DBUS_POLLOUT)
        if (fdp->events & POLLOUT)
            FD_SET(fdp->fd.sock, &write_set);

        FD_SET(fdp->fd.sock, &err_set);

        max_fd = MAX(max_fd, fdp->fd.sock);
    }

    // Avoid random lockups with send(), for lack of a better solution so far
    tv.tv_sec = timeout_milliseconds < 0 ? 1 : timeout_milliseconds / 1000;
    tv.tv_usec = timeout_milliseconds < 0 ? 0 : (timeout_milliseconds % 1000) * 1000;

    ready = select((int)max_fd + 1, &read_set, &write_set, &err_set, &tv);

    if (DBUS_SOCKET_API_RETURNS_ERROR(ready))
    {
        DBUS_SOCKET_SET_ERRNO();
        if (errno != WSAEWOULDBLOCK)
            _dbus_verbose("select: failed: %s\n", /*_dbus_strerror_from_errno()*/strerror(errno));
    }
    else if (ready == 0)
        _dbus_verbose("select: = 0\n");
    else
        if (ready > 0)
        {
#ifdef DBUS_ENABLE_VERBOSE_MODE
            msgp = msg;
            msgp += sprintf(msgp, "select: = %d:\n\t", ready);

            for (i = 0; i < n_fds; i++)
            {
                DBusPollFD* fdp = &fds[i];

                if (FD_ISSET(fdp->fd.sock, &read_set))
                    msgp += sprintf(msgp, "R:%Iu ", fdp->fd.sock);

                if (FD_ISSET(fdp->fd.sock, &write_set))
                    msgp += sprintf(msgp, "W:%Iu ", fdp->fd.sock);

                if (FD_ISSET(fdp->fd.sock, &err_set))
                    msgp += sprintf(msgp, "E:%Iu\n\t", fdp->fd.sock);
            }
            msgp += sprintf(msgp, "\n");
            _dbus_verbose("%s", msg);
#endif

            for (i = 0; i < n_fds; i++)
            {
                DBusPollFD* fdp = &fds[i];

                fdp->revents = 0;

                if (FD_ISSET(fdp->fd.sock, &read_set))
                    //fdp->revents |= _DBUS_POLLIN;
                    fdp->revents |= POLLIN;

                if (FD_ISSET(fdp->fd.sock, &write_set))
                    //fdp->revents |= _DBUS_POLLOUT;
                    fdp->revents |= POLLOUT;

                if (FD_ISSET(fdp->fd.sock, &err_set))
                    //fdp->revents |= _DBUS_POLLERR;
                    fdp->revents |= POLLERR;
            }
        }
    return ready;
#endif  /* USE_CHRIS_IMPL */
}


int socketpair(int domain, int type, int protocol, int sv[2])
{
    DBusSocket s1;
    DBusSocket s2;
    DBusError error;
    int ret = _dbus_socketpair(&s1, &s2, 0, &error);
    sv[0] = s1.sock;
    sv[1] = s2.sock;
    return ret;
}

#include <sys/signalfd.h>
#include <time.h>
typedef unsigned int nfds_t;
extern int fio_poll(struct pollfd fds[], nfds_t nfds, int timeout);

int ppoll(struct pollfd* fds, nfds_t nfds,
    const struct timespec* timeout_ts, const sigset_t* sigmask)
{
    /*
    ready = ppoll(&fds, nfds, timeout_ts, &sigmask);

    is equivalent to atomically executing the following calls :
    
    sigset_t origmask;
    int timeout;

    timeout = (timeout_ts == NULL) ? -1 :
        (timeout_ts.tv_sec * 1000 + timeout_ts.tv_nsec / 1000000);
    sigprocmask(SIG_SETMASK, &sigmask, &origmask);
    ready = poll(&fds, nfds, timeout);
    sigprocmask(SIG_SETMASK, &origmask, NULL);
    */

    int timeout;
    int ret;
    timeout = (timeout_ts == NULL) ? -1 :
        (timeout_ts->tv_sec * 1000 + timeout_ts->tv_nsec / 1000000);

    //ret = _dbus_poll(fds, nfds, timeout);

    //printf("=== start of WSAPoll, timeout: %d\n", timeout);
    //ret = WSAPoll(fds, nfds, timeout);
    //printf("=== end of WSAPoll, return: %d\n", ret);

    //ret = poll(fds, nfds, timeout);
    ret = fio_poll(fds, nfds, timeout);

    /*
    if (ret == 0) {
        for (int i = 0; i < nfds; i++) {
            printf("fds %d, %02x %x %x\n", i, fds[i].fd, fds[i].events, fds[i].revents);
        }
    }
    */
    return ret;
}

#endif // WIN32