
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

void log_set_max_level(int);

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

#define POLICY_T_BATCH                                                          \
                "bt"                                                            \
                "a(btbs)"                                                       \
                "a(btssssuutt)"                                                 \
                "a(btssssuutt)"

#define POLICY_T                                                                \
                "a(u(" POLICY_T_BATCH "))"                                      \
                "a(buu(" POLICY_T_BATCH "))"                                    \
                "a(ss)"                                                         \
                "b"

static int util_append_policy(sd_bus_message* m) {
    int r;

    r = sd_bus_message_open_container(m, 'v', "(" POLICY_T ")");
    c_assert(r >= 0);

    r = sd_bus_message_open_container(m, 'r', POLICY_T);
    c_assert(r >= 0);

    /* per-uid batches */
    {
        r = sd_bus_message_open_container(m, 'a', "(u(" POLICY_T_BATCH "))");
        c_assert(r >= 0);

        r = sd_bus_message_open_container(m, 'r', "u(" POLICY_T_BATCH ")");
        c_assert(r >= 0);

        /* Fall-back UID */
        r = sd_bus_message_append(m, "u", (uint32_t)-1);
        c_assert(r >= 0);

        r = sd_bus_message_open_container(m, 'r', POLICY_T_BATCH);
        c_assert(r >= 0);

        /*
         * Default test policy:
         *  - allow all connections
         *  - allow everyone to own names
         *  - allow all sends
         *  - allow all recvs
         */
        r = sd_bus_message_append(m,
            "bt" "a(btbs)" "a(btssssuutt)" "a(btssssuutt)",
            true, UINT64_C(1),
            1, true, UINT64_C(1), true, "",
            1, true, UINT64_C(1), "", "", "", "", 0, 0, UINT64_C(0), UINT64_MAX,
            1, true, UINT64_C(1), "", "", "", "", 0, 0, UINT64_C(0), UINT64_MAX);
        c_assert(r >= 0);

        r = sd_bus_message_close_container(m);
        c_assert(r >= 0);

        r = sd_bus_message_close_container(m);
        c_assert(r >= 0);

        r = sd_bus_message_close_container(m);
        c_assert(r >= 0);
    }

    /* per-gid and uid-range batches */
    {
        r = sd_bus_message_open_container(m, 'a', "(buu(" POLICY_T_BATCH "))");
        c_assert(r >= 0);

        r = sd_bus_message_close_container(m);
        c_assert(r >= 0);
    }

    /* empty SELinux policy */
    {
        r = sd_bus_message_open_container(m, 'a', "(ss)");
        c_assert(r >= 0);

        r = sd_bus_message_close_container(m);
        c_assert(r >= 0);
    }

    /* disable AppArmor */
    {
        r = sd_bus_message_append(m, "b", false);
        c_assert(r >= 0);
    }

    r = sd_bus_message_close_container(m);
    c_assert(r >= 0);

    r = sd_bus_message_close_container(m);
    c_assert(r >= 0);

    return 0;
}

static int util_method_reload_config(sd_bus_message* message, void* userdata, sd_bus_error* error) {
    sd_bus* bus;
    _c_cleanup_(sd_bus_message_unrefp) sd_bus_message* message2 = NULL;
    int r;

    bus = sd_bus_message_get_bus(message);

    r = sd_bus_message_new_method_call(bus,
        &message2,
        NULL,
        "/org/bus1/DBus/Listener/0",
        "org.bus1.DBus.Listener",
        "SetPolicy");
    c_assert(r >= 0);

    r = util_append_policy(message2);
    c_assert(r >= 0);

    r = sd_bus_call(bus, message2, -1, NULL, NULL);
    c_assert(r >= 0);

    return sd_bus_reply_method_return(message, NULL);
}

const sd_bus_vtable util_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_METHOD("ReloadConfig", NULL, NULL, util_method_reload_config, 0),

        SD_BUS_VTABLE_END
};

void win_fork_broker(sd_bus** busp, sd_event* event, int listener_fd, pid_t* pidp) {
    _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
    _c_cleanup_(sd_bus_message_unrefp) sd_bus_message* message = NULL;
    _c_cleanup_(c_freep) char* fdstr = NULL;
    int r, pair[2];
    pid_t pid;
#ifdef WIN32
    r = socketpair(AF_INET, SOCK_STREAM, 0, pair);
#else
    r = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair);
#endif
    c_assert(r >= 0);

    //pid = fork();
    // the PID of the child process is returned in the parent, and 
    // 0 is returned in the child
    //c_assert(pid >= 0);
    //c_close(pair[!!pid]);

#if 0
    if (pid == 0) {
        /* clear the FD_CLOEXEC flag */
        r = fcntl(pair[1], F_GETFD);
        c_assert(r >= 0);
        r = fcntl(pair[1], F_SETFD, r & ~FD_CLOEXEC);
        c_assert(r >= 0);

        r = asprintf(&fdstr, "%d", pair[1]);
        c_assert(r >= 0);

        r = execl(
#ifdef MESON_BUILD
            "./src/dbus-broker",
            "./src/dbus-broker",
#else
            "./dbus-broker",
            "./dbus-broker",
#endif
            "--controller", fdstr,
            "--machine-id", "0123456789abcdef0123456789abcdef",
            "--max-matches", "1000000",
            "--max-objects", "1000000",
            "--max-bytes", "1000000000",
            (char*)NULL);
        /* execl(2) only returns on error */
        c_assert(r >= 0);
        abort();
    }
#endif
    r = asprintf(&fdstr, "%d", pair[1]);
    c_assert(r >= 0);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    char cmd[256];
    sprintf(cmd, "dbus-broker "
        "--controller %s "
        "--machine-id " "0123456789abcdef0123456789abcdef "
        "--max-matches " "1000000 "
        "--max-objects " "1000000 "
        "--max-bytes " "1000000000", fdstr);
    // Start the child process. 
    if (!CreateProcess(
        NULL,           // No module name (use command line)
        cmd,            // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        TRUE,           // Set handle inheritance to TRUE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi)            // Pointer to PROCESS_INFORMATION structure
        )
    {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return;
    }

    pid = pi.dwProcessId;

    Sleep(3000);

    /* remember the daemon's pid */
    if (pidp)
        *pidp = pid;

    //r = sd_event_add_child(event, NULL, pid, WEXITED, util_event_sigchld, NULL);
    //c_assert(r >= 0);

    r = sd_bus_new(&bus);
    c_assert(r >= 0);

    /* consumes the fd */
    r = sd_bus_set_fd(bus, pair[0], pair[0]);
    c_assert(r >= 0);

    //r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL);
    //c_assert(r >= 0);

    r = sd_bus_add_object_vtable(bus, NULL, "/org/bus1/DBus/Controller", "org.bus1.DBus.Controller", util_vtable, NULL);
    c_assert(r >= 0);

    r = sd_bus_start(bus);
    c_assert(r >= 0);

/*
    r = sd_bus_message_new_method_call(bus,
        &message,
        NULL,
        "/org/bus1/DBus/Broker",
        "org.bus1.DBus.Broker",
        "AddListener");
    c_assert(r >= 0);

    r = sd_bus_message_append(message,
        "oh",
        "/org/bus1/DBus/Listener/0",
        listener_fd);
    c_assert(r >= 0);

    r = util_append_policy(message);
    c_assert(r >= 0);

    r = sd_bus_call(bus, message, -1, NULL, NULL);
    c_assert(r >= 0);
*/
    *busp = bus;
    bus = NULL;
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
#endif

    if (broker->listener_fd >= 0) {
        win_fork_broker(&bus, event, broker->listener_fd, &broker->child_pid);
        /* dbus-broker reports its controller in GetConnectionUnixProcessID */
        broker->pid = getpid();
        //broker->listener_fd = c_close(broker->listener_fd);
        closesocket(broker->listener_fd);
        broker->listener_fd = INVALID_SOCKET;
    }
#if 0
    else {
        c_assert(broker->listener_fd < 0);
        util_fork_daemon(event, broker->pipe_fds[1], &broker->child_pid);
        /* dbus-daemon reports itself in GetConnectionUnixProcessID */
        broker->pid = broker->child_pid;
    }
#endif
    broker->pipe_fds[1] = c_close(broker->pipe_fds[1]);

    //r = sd_event_loop(event);
    //c_assert(r >= 0);
    
    for (;;) {
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message* m = NULL;
        r = sd_bus_process(bus, &m);
        if (r < 0) {
            fprintf(stderr, "Failed to process requests\n");
            break;
        }

        if (r == 0) {
            r = sd_bus_wait(bus, UINT64_MAX);
            if (r < 0) {
                fprintf(stderr, "Failed to wait\n");
                break;
            }

            continue;
        }

        if (!m)
            continue;

        fprintf(stderr, ">>>> Got message! member=%s", sd_bus_message_get_member(m));
    }


    broker->pipe_fds[0] = c_close(broker->pipe_fds[0]);
    //return (void*)(uintptr_t)r;

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

        struct addrinfo hints, *res;
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
        freeaddrinfo(res);

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
    WaitForSingleObject(broker->thread, INFINITE);

    //c_assert(!r);
    //c_assert(!value);

    //c_assert(broker->listener_fd < 0);
    //c_assert(broker->pipe_fds[0] < 0);

    WSACleanup();

    return 0;
}
