
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <process.h>    /* _beginthread, _endthread */

//#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>


#ifndef PIPE_BUF
#define PIPE_BUF 4096
#endif

typedef struct Broker Broker;

struct Broker {
#ifdef WIN32
    HANDLE thread;
    struct sockaddr address;
#else
    pthread_t thread;
    struct sockaddr_un address;
#endif
    socklen_t n_address;
    int listener_fd;
    int pipe_fds[2];
    pid_t pid;
    pid_t child_pid;
};

Broker* win_broker_free(Broker* broker) {
    if (!broker)
        return NULL;

    c_assert(broker->listener_fd < 0);
    c_assert(broker->pipe_fds[0] < 0);
    c_assert(broker->pipe_fds[1] < 0);

    free(broker);

    return NULL;
}

C_DEFINE_CLEANUP(Broker*, win_broker_free);

#define BROKER_NULL {                                                           \
                .address.sa_family = AF_INET,                                   \
                .n_address = sizeof(struct sockaddr),                           \
                .listener_fd = -1,                                              \
                .pipe_fds[0] = -1,                                              \
                .pipe_fds[1] = -1,                                              \
        }

void win_broker_new(Broker** brokerp) {
    _c_cleanup_(win_broker_freep) Broker* broker = NULL;

    broker = calloc(1, sizeof(*broker));
    c_assert(broker);

    *broker = (Broker)BROKER_NULL;

    *brokerp = broker;
    broker = NULL;
}

void win_broker_thread(void* userdata)
{
    _c_cleanup_(sd_event_unrefp) sd_event* event = NULL;
    _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
    Broker* broker = userdata;
    int r;

    c_assert(broker->pipe_fds[0] >= 0);
    c_assert(broker->pipe_fds[1] >= 0);

#if 0
    util_event_new(&event);

    r = sd_event_add_signal(event, NULL, SIGUSR1, util_event_sigusr1, broker);
    c_assert(r >= 0);

    if (broker->listener_fd >= 0) {
        util_fork_broker(&bus, event, broker->listener_fd, &broker->child_pid);
        /* dbus-broker reports its controller in GetConnectionUnixProcessID */
        broker->pid = getpid();
        broker->listener_fd = c_close(broker->listener_fd);
    }
    else {
        c_assert(broker->listener_fd < 0);
        util_fork_daemon(event, broker->pipe_fds[1], &broker->child_pid);
        /* dbus-daemon reports itself in GetConnectionUnixProcessID */
        broker->pid = broker->child_pid;
    }

    broker->pipe_fds[1] = c_close(broker->pipe_fds[1]);

    r = sd_event_loop(event);
    c_assert(r >= 0);

    broker->pipe_fds[0] = c_close(broker->pipe_fds[0]);
    return (void*)(uintptr_t)r;
#endif
}

void win_broker_spawn(Broker* broker) {
    char buffer[PIPE_BUF + 1] = {};
    //sigset_t signew, sigold;
    ssize_t n;
    char* e;
    int r;

    c_assert(broker->listener_fd < 0);
    c_assert(broker->pipe_fds[0] < 0);
    c_assert(broker->pipe_fds[1] < 0);

#if defined(__linux__)
    /*
     * Lets make sure we exit if our parent does. We are a test-runner, so
     * this should be enforced by our environment, but sadly it isn't. So
     * lets use this hack to enforce it everywhere and cleanup properly.
     */
    r = prctl(PR_SET_PDEATHSIG, SIGTERM);
    c_assert(!r);

    /*
     * SIGCHLD signal delivery is non-deterministic in thread-groups.
     * Hence, we must block SIGCHLD in *all* threads if we want to reliably
     * catch broker-deaths via sd_event_add_child(). Lets just enforce this
     * here.
     */
    sigemptyset(&signew);
    sigaddset(&signew, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &signew, NULL);

    sigemptyset(&signew);
    sigaddset(&signew, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &signew, &sigold);
#endif

    /*
     * Create a pipe object that we inherit into the forked daemon. In case
     * of dbus-daemon(1) it is actually used to retrieve data from it. In
     * case of dbus-broker, we use it to block until our child called
     * exec() (as a synchronization primitive).
     */

#ifdef WIN32
    r = _pipe(broker->pipe_fds, 256, O_BINARY);
#else
#ifdef WSL2
    r = pipe2(broker->pipe_fds, O_CLOEXEC);
#else
    r = pipe2(broker->pipe_fds, O_CLOEXEC | O_DIRECT);
#endif // WSL2  
#endif // WIN32

    c_assert(r >= 0);

    {
        /*
         * Create listener socket, let the kernel pick a random address
         * and remember it in @broker. Spawn a thread, which will then
         * run and babysit the broker.
         */
        broker->listener_fd = socket(AF_INET, SOCK_STREAM, 0);
        c_assert(broker->listener_fd >= 0);

        struct addrinfo hints, * res;
        // Before using hint you have to make sure that the data structure is empty 
        memset(&hints, 0, sizeof(hints));
        // Set the attribute for hint
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM; // TCP Socket SOCK_DGRAM 
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_PASSIVE;

        // Fill the res data structure and make sure that the results make sense. 
        int status = getaddrinfo(NULL, "8888", &hints, &res);
        if (status != 0)
        {
            fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
            WSACleanup();
            return;
        }

        r = bind(broker->listener_fd, res->ai_addr, res->ai_addrlen);
        c_assert(r >= 0);

        char* bindaddr;
        sockaddr_pretty((const struct sockaddr*)res->ai_addr, res->ai_addrlen,
            true, true, &bindaddr);

        printf("I am now accepting connections at %s ...\n", bindaddr);
        free(bindaddr);
        memcpy(&broker->address, res->ai_addr, res->ai_addrlen);
        broker->n_address = res->ai_addrlen;
        free(res);

        r = listen(broker->listener_fd, 256);
        c_assert(r >= 0);

#ifdef WIN32
        broker->thread = _beginthread(win_broker_thread, 0, (void*)broker);
        if (broker->thread == INVALID_HANDLE_VALUE)
        {
            r = errno;
        }
#else
        r = pthread_create(&broker->thread, NULL, win_broker_thread, broker);
#endif
        c_assert(r >= 0);
    }

    /* block until we get EOF, so we know the daemon was exec'ed */
    r = _read(broker->pipe_fds[0], buffer, sizeof(buffer) - 1);
    c_assert(!r);

#if defined(__linux__)
    pthread_sigmask(SIG_SETMASK, &sigold, NULL);
#endif
}

int main(int argc, char** argv)
{
    _c_cleanup_(win_broker_freep) Broker* broker = NULL;
    void* value;
    int r;

    log_set_max_level(7);

    // Initialize Winsock.
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        wprintf(L"WSAStartup failed with error: %ld\n", iResult);
        return 1;
    }

    win_broker_new(&broker);
    win_broker_spawn(broker);

    c_assert(broker->listener_fd >= 0 || broker->pipe_fds[0] >= 0);

    //r = pthread_join(broker->thread, &value);
    c_assert(!r);
    c_assert(!value);

    c_assert(broker->listener_fd < 0);
    c_assert(broker->pipe_fds[0] < 0);

    WSACleanup();

    return 0;
}
