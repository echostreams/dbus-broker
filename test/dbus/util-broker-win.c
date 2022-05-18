#if defined(WIN32) || defined(_WIN64)

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <process.h>    /* _beginthread, _endthread */
#include <AclAPI.h>
#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util-broker.h"

int socketpair(int domain, int type, int protocol, int sv[2]);
int asprintf(char** strp, const char* fmt, ...);
int sockaddr_pretty(const struct sockaddr* _sa, socklen_t salen,
    bool translate_ipv6, bool include_port, char** ret);


#define PTHREAD_CANCELED       ((void *)(size_t) -1)

#ifndef PIPE_BUF
#define PIPE_BUF 4096
#endif

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

void util_broker_consume_signal(sd_bus* bus, const char* interface, const char* member) {
    _c_cleanup_(sd_bus_message_unrefp) sd_bus_message* message = NULL;
    int r;

    for (;;) {
        r = sd_bus_wait(bus, (uint64_t)-1);
        c_assert(r >= 0);

        r = sd_bus_process(bus, &message);
        c_assert(r >= 0);

        if (message)
            break;
    }

    r = sd_bus_message_is_signal(message, interface, member);
    c_assert(r > 0);
}


void util_broker_connect(Broker* broker, sd_bus** busp) {
    _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
    _c_cleanup_(c_closep) int fd = -1;
    int r;
#ifdef WIN32
    fd = socket(AF_INET, SOCK_STREAM, 0);
#else
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#endif
    c_assert(fd >= 0);

    r = connect(fd, (struct sockaddr*)&broker->address, broker->n_address);
    c_assert(r >= 0);

    r = sd_bus_new(&bus);
    c_assert(r >= 0);

    /* consumes @fd */
    r = sd_bus_set_fd(bus, fd, fd);
    fd = -1;
    c_assert(r >= 0);

    r = sd_bus_set_bus_client(bus, true);
    c_assert(r >= 0);

    r = sd_bus_start(bus);
    c_assert(r >= 0);

    util_broker_consume_signal(bus, "org.freedesktop.DBus", "NameAcquired");

    *busp = bus;
    bus = NULL;
}

void win_broker_terminate(Broker* broker) {
    DWORD value;
    BOOL r;

    //c_assert(broker->listener_fd >= 0 || broker->pipe_fds[0] >= 0);

    r = TerminateThread(broker->thread, (DWORD)(intptr_t)PTHREAD_CANCELED);
    c_assert(r == TRUE);

    DWORD waitResult = WaitForSingleObject(broker->thread, INFINITE);
    c_assert(waitResult == WAIT_OBJECT_0);

    r = GetExitCodeThread(broker->thread, &value);
    c_assert(r == TRUE);
    c_assert(value == (DWORD)(intptr_t)PTHREAD_CANCELED);

    r = CloseHandle(broker->thread);
    c_assert(r == TRUE);

    HANDLE hBroker = OpenProcess(PROCESS_TERMINATE, false, broker->child_pid);
    c_assert(hBroker != NULL);

    r = TerminateProcess(hBroker, 1);
    c_assert(r == TRUE);

    r = CloseHandle(hBroker);
    c_assert(r == TRUE);

    c_assert(broker->listener_fd < 0);
    c_assert(broker->pipe_fds[0] < 0);

    fprintf(stderr, "*** broker terminated ***\n");
}

void win_broker_new(Broker** brokerp) {
    _c_cleanup_(win_broker_freep) Broker* broker = NULL;

    broker = calloc(1, sizeof(*broker));
    c_assert(broker);

    *broker = (Broker)BROKER_NULL;

    *brokerp = broker;
    broker = NULL;
}

Broker* win_broker_free(Broker* broker) {
    if (!broker)
        return NULL;

    c_assert(broker->listener_fd < 0);
    c_assert(broker->pipe_fds[0] < 0);
    c_assert(broker->pipe_fds[1] < 0);

    free(broker);

    return NULL;
}


void win_fork_broker(sd_bus** busp, sd_event* event, int listener_fd, pid_t* pidp,
    struct sockaddr* addr, socklen_t addrlen
    ) {
    _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
    //_c_cleanup_(sd_bus_message_unrefp) sd_bus_message* message = NULL;
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

    char bindaddr[64];
    uint32_t a;
    struct sockaddr_in* sa = (struct sockaddr_in*)addr;
    a = __builtin_bswap32(sa->sin_addr.s_addr);

    r = sprintf(bindaddr,
        "tcp:host=%u.%u.%u.%u,port=%u",
        a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF,
        __builtin_bswap16(sa->sin_port));

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    //si.dwFlags |= STARTF_USESTDHANDLES;

    ZeroMemory(&pi, sizeof(pi));
    char cmd[256];
    sprintf(cmd, "dbus-broker "
        "--controller %s "
        "--machine-id " "0123456789abcdef0123456789abcdef "
        "--max-matches " "1000000 "
        "--max-objects " "1000000 "
        "--max-bytes " "1000000000 "
        "--address %s", fdstr, bindaddr);
    // Start the child process. 
    if (!CreateProcess(
        NULL,           // No module name (use command line)
        cmd,            // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        TRUE,           // Set handle inheritance to TRUE
        /*CREATE_NEW_CONSOLE*/0,     // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi)            // Pointer to PROCESS_INFORMATION structure
        )
    {
        fprintf(stderr, "CreateProcess failed (%lu).\n", GetLastError());
        return;
    }

    if (SetSecurityInfo(pi.hProcess, SE_KERNEL_OBJECT, PROCESS_TERMINATE, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        fprintf(stderr, "SetSecurityInfo failed\n");
    }

    pid = pi.dwProcessId;

    Sleep(100);

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
    * busp = bus;
    bus = NULL;
}

unsigned int win_broker_thread(void* userdata)
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

    //if (broker->listener_fd >= 0) {
        win_fork_broker(&bus, event, broker->listener_fd, &broker->child_pid, &broker->address, broker->n_address);
        /* dbus-broker reports its controller in GetConnectionUnixProcessID */
        broker->pid = _getpid();
        //broker->listener_fd = c_close(broker->listener_fd);
        //closesocket(broker->listener_fd);
        //broker->listener_fd = (int)INVALID_SOCKET;
    //}
#if 0
    else {
        c_assert(broker->listener_fd < 0);
        util_fork_daemon(event, broker->pipe_fds[1], &broker->child_pid);
        /* dbus-daemon reports itself in GetConnectionUnixProcessID */
        broker->pid = broker->child_pid;
    }
#endif
    broker->pipe_fds[1] = c_close(broker->pipe_fds[1]);
        
    // Set broker->event to signaled
    if (!SetEvent(broker->event))
    {
        fprintf(stderr, "SetEvent failed (%lu)\n", GetLastError());
    }
    broker->pipe_fds[0] = c_close(broker->pipe_fds[0]);

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
    
    //broker->pipe_fds[0] = c_close(broker->pipe_fds[0]);
    //return (void*)(uintptr_t)r;
    return r;
}

void win_broker_spawn(Broker* broker) {
    //char buffer[PIPE_BUF + 1] = {};
    //sigset_t signew, sigold;
    //ssize_t n;
    //char* e;
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
    // Create a manual-reset event object. The broker thread sets this
    // object to the signaled state when it finishes forking dbus-broker

    broker->event = CreateEvent(
        NULL,               // default security attributes
        TRUE,               // manual-reset event
        FALSE,              // initial state is nonsignaled
        TEXT("WaitEvent")   // object name
    );

    if (broker->event == NULL)
    {
        fprintf(stderr, "CreateEvent failed (%lu)\n", GetLastError());
    }
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
#if 1
        //broker->listener_fd = socket(AF_INET, SOCK_STREAM, 0);
        //c_assert(broker->listener_fd >= 0);

        struct addrinfo hints, * res;
        // Before using hint you have to make sure that the data structure is empty 
        memset(&hints, 0, sizeof(hints));
        // Set the attribute for hint
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM; // TCP Socket SOCK_DGRAM 
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_PASSIVE;

        // Fill the res data structure and make sure that the results make sense. 
        int status = getaddrinfo("127.0.0.1", "8080", &hints, &res);
        if (status != 0)
        {
            fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
            WSACleanup();
            return;
        }

        //u_long iMode = 1;
        //status = ioctlsocket(broker->listener_fd, FIONBIO, &iMode);
        //if (status != NO_ERROR) {
        //    printf("ioctlsocket failed with error: %d\n", status);
        //}

        //r = bind(broker->listener_fd, res->ai_addr, res->ai_addrlen);
        //c_assert(r >= 0);

        char* bindaddr;
        sockaddr_pretty((const struct sockaddr*)res->ai_addr, res->ai_addrlen,
            true, true, &bindaddr);

        fprintf(stderr, "I am now accepting connections at %s ...\n", bindaddr);
        free(bindaddr);
        memcpy(&broker->address, res->ai_addr, res->ai_addrlen);
        broker->n_address = res->ai_addrlen;
        freeaddrinfo(res);

        //r = listen(broker->listener_fd, 256);
        //c_assert(r >= 0);
#endif

#ifdef WIN32
        unsigned int thread_id;
        broker->thread = (HANDLE)_beginthreadex(NULL, 0, win_broker_thread, (void*)broker, 0, &thread_id);
        if (broker->thread == INVALID_HANDLE_VALUE)
        {
            r = errno;
        }
#else
        r = pthread_create(&broker->thread, NULL, util_broker_thread, broker);
#endif
        c_assert(r >= 0);
    }

    /* block until we get EOF, so we know the daemon was exec'ed */
    //r = _read(broker->pipe_fds[0], buffer, sizeof(buffer) - 1);
    //c_assert(!r);
    DWORD dwWaitResult;

    fprintf(stderr, "Waiting for daemon event...\n");
    dwWaitResult = WaitForSingleObject(
        broker->event, // event handle
        INFINITE);     // indefinite wait
    switch (dwWaitResult)
    {
        // Event object was signaled
    case WAIT_OBJECT_0:        
        fprintf(stderr, "Broker spawned...\n");
        break;

        // An error occurred
    default:
        fprintf(stderr, "Wait error (%lu)\n", GetLastError());
        break;
    }


#if defined(__linux__)
    pthread_sigmask(SIG_SETMASK, &sigold, NULL);
#endif
}

#endif