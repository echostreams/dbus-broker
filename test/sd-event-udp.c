#if defined(__linux__)
#include <alloca.h>
#else
#include <wepoll/wepoll.h>
#endif
#include <endian.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>



static int io_handler(sd_event_source* es, int fd, uint32_t revents, void* userdata) {
    void* buffer;
    ssize_t n;
    

    /* UDP enforces a somewhat reasonable maximum datagram size of 64K, we can just allocate the buffer on the stack */
#ifdef WIN32
    u_long sz;
    if (ioctlsocket(fd, FIONREAD, &sz) < 0)
        return -errno;
    buffer = _alloca(sz);
#else
    int sz;
    if (ioctl(fd, FIONREAD, &sz) < 0)
        return -errno;
    buffer = alloca(sz);
#endif        

    n = recv(fd, buffer, sz, 0);
    if (n < 0) {
        if (errno == EAGAIN)
            return 0;

        return -errno;
    }

    if (n == 5 && memcmp(buffer, "EXIT\n", 5) == 0) {
        /* Request a clean exit */
        sd_event_exit(sd_event_source_get_event(es), 0);
        return 0;
    }

    fwrite(buffer, 1, n, stdout);
    fflush(stdout);
    return 0;
}

int main(int argc, char* argv[]) {
    union {
        struct sockaddr_in in;
        struct sockaddr sa;
    } sa;
    sd_event_source* event_source = NULL;
    sd_event* event = NULL;
    int fd = -1, r;
    

    r = sd_event_default(&event);
    if (r < 0)
        goto finish;

#if defined(__linux__)
    sigset_t ss;
    if (sigemptyset(&ss) < 0 ||
        sigaddset(&ss, SIGTERM) < 0 ||
        sigaddset(&ss, SIGINT) < 0) {
        r = -errno;
        goto finish;
    }

    /* Block SIGTERM first, so that the event loop can handle it */
    if (sigprocmask(SIG_BLOCK, &ss, NULL) < 0) {
        r = -errno;
        goto finish;
    }
#endif
    /* Let's make use of the default handler and "floating" reference features of sd_event_add_signal() */
    r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
    if (r < 0)
        goto finish;
    r = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
    if (r < 0)
        goto finish;

    /* Enable automatic service watchdog support */
#if defined(__linux__)
    //r = sd_event_set_watchdog(event, true);
    //if (r < 0)
    //    goto finish;
#endif

#ifdef WIN32
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    
#else
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#endif
    if (fd < 0) {
        r = -errno;
        goto finish;
    }

    sa.in = (struct sockaddr_in){
            .sin_family = AF_INET,
            .sin_port = htobe16(7777),
    };
    if (bind(fd, &sa.sa, sizeof(sa)) < 0) {
        r = -errno;
        goto finish;
    }

    r = sd_event_add_io(event, &event_source, fd, EPOLLIN, io_handler, NULL);
    if (r < 0)
        goto finish;

    (void)sd_notifyf(false,
        "READY=1\n"
        "STATUS=Daemon startup completed, processing events.");

    r = sd_event_loop(event);

finish:
    event_source = sd_event_source_unref(event_source);
    event = sd_event_unref(event);

    if (fd >= 0) {
#ifdef WIN32
        closesocket(fd);
#else
        (void)close(fd);
#endif
    }
    if (r < 0)
        fprintf(stderr, "Failure: %s\n", strerror(-r));

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}