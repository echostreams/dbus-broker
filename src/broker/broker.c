/*
 * Broker
 */

#include <c-list.h>
#include <c-stdaux.h>
#include <signal.h>
#include <stdlib.h>
#if defined(__linux__)
#include <sys/epoll.h>
#else
#include <wepoll/wepoll.h>
struct ucred {
        unsigned int   pid;
        unsigned int   uid;
        unsigned int   gid;
};
#define	LOG_INFO	6	/* informational */
#endif
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "broker/broker.h"
#include "broker/controller.h"
#include "broker/main.h"
#include "bus/bus.h"
#include "catalog/catalog-ids.h"
#include "dbus/connection.h"
#include "dbus/message.h"
#include "util/dispatch.h"
#include "util/error.h"
#include "util/log.h"
#include "util/proc.h"
#include "util/sockopt.h"
#include "util/user.h"

static int broker_dispatch_signals(DispatchFile *file) {
        Broker *broker = c_container_of(file, Broker, signals_file);
        struct signalfd_siginfo si;
        ssize_t l;

        c_assert(dispatch_file_events(file) == EPOLLIN);

        l = read(broker->signals_fd, &si, sizeof(si));
        if (l < 0)
                return error_origin(-errno);

        c_assert(l == sizeof(si));

        return DISPATCH_E_EXIT;
}

int broker_new(Broker **brokerp, const char *machine_id, int log_fd, int controller_fd, uint64_t max_bytes, uint64_t max_fds, uint64_t max_matches, uint64_t max_objects) {
        _c_cleanup_(broker_freep) Broker *broker = NULL;
        struct ucred ucred;
        socklen_t z;
        sigset_t sigmask;
        int r, log_type;

        if (log_fd >= 0) {
                z = sizeof(log_type);
                r = getsockopt(log_fd, SOL_SOCKET, SO_TYPE, &log_type, &z);
                if (r < 0)
                        return error_origin(-errno);
        }

#if defined(__linux__)
        z = sizeof(ucred);
        r = getsockopt(controller_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &z);
        if (r < 0)
                return error_origin(-errno);
#endif

        broker = calloc(1, sizeof(*broker));
        if (!broker)
                return error_origin(-ENOMEM);

        broker->log = (Log)LOG_NULL;
        broker->bus = (Bus)BUS_NULL(broker->bus);
        broker->dispatcher = (DispatchContext)DISPATCH_CONTEXT_NULL(broker->dispatcher);
        broker->signals_fd = -1;
        broker->signals_file = (DispatchFile)DISPATCH_FILE_NULL(broker->signals_file);
        broker->controller = (Controller)CONTROLLER_NULL(broker->controller);

        if (log_fd < 0) {
            //log_init(&broker->log);
#ifdef WIN32
            log_init_stderr(&broker->log, _fileno(stderr));
#else
            log_init_stderr(&broker->log, STDERR_FILENO);
#endif
        }
        else if (log_type == SOCK_STREAM)
                log_init_stderr(&broker->log, log_fd);
        else if (log_type == SOCK_DGRAM)
                log_init_journal(&broker->log, log_fd);
        else
                return error_origin(-ENOTRECOVERABLE);

        /* XXX: make this run-time optional */
        log_set_lossy(&broker->log, true);

        r = bus_init(&broker->bus, &broker->log, machine_id, max_bytes, max_fds, max_matches, max_objects);
        if (r)
                return error_fold(r);

        /*
         * We need the seclabel to run the broker for 2 reasons: First, if
         * 'org.freedesktop.DBus' is queried for the seclabel, we need to
         * return some value. Second, all unlabeled names get this label
         * assigned by default. Due to the latter, this seclabel is actually
         * referenced in selinux rules, to allow peers to own names.
         * We use SO_PEERSEC on the controller socket to get this label.
         * However, note that this used to return the 'unlabeled_t' entry for
         * socketpairs until kernel v4.17. From v4.17 onwards it now returns
         * the correct label. There is no way to detect this at runtime,
         * though. We hard-require 4.17. If you use older kernels, you will get
         * selinux denials.
         */
        r = sockopt_get_peersec(controller_fd, &broker->bus.seclabel, &broker->bus.n_seclabel);
        if (r)
                return error_fold(r);

        r = sockopt_get_peergroups(controller_fd,
                                   &broker->log,
                                   ucred.uid,
                                   ucred.gid,
                                   &broker->bus.gids,
                                   &broker->bus.n_gids);
        if (r)
                return error_fold(r);

        broker->bus.pid = ucred.pid;
        r = user_registry_ref_user(&broker->bus.users, &broker->bus.user, ucred.uid);
        if (r)
                return error_fold(r);

        r = dispatch_context_init(&broker->dispatcher);
        if (r)
                return error_fold(r);

#if defined(__linux__)

        sigemptyset(&sigmask);
        sigaddset(&sigmask, SIGTERM);
        sigaddset(&sigmask, SIGINT);

        broker->signals_fd = signalfd(-1, &sigmask, SFD_CLOEXEC | SFD_NONBLOCK);
        if (broker->signals_fd < 0)
                return error_origin(-errno);


        r = dispatch_file_init(&broker->signals_file,
                               &broker->dispatcher,
                               broker_dispatch_signals,
                               broker->signals_fd,
                               EPOLLIN,
                               0);
        if (r)
                return error_fold(r);

        dispatch_file_select(&broker->signals_file, EPOLLIN);
#endif

        r = controller_init(&broker->controller, broker, controller_fd);
        if (r)
                return error_fold(r);

#ifdef WIN32
        ControllerListener* listener;
        PolicyRegistry* policy = NULL;
        r = policy_registry_new(&policy, broker->bus.seclabel);
        if (r)
            return error_fold(r);
        const char policy_sig[] = 
                "("
                 "a(u(bta(btbs)a(btssssuutt)a(btssssuutt)))"
                 "a(buu(bta(btbs)a(btssssuutt)a(btssssuutt)))"
                 "a(ss)"
                 "b"
                ")";
        CDVarType* type = NULL;
        size_t n_data;
        void* data;

        r = c_dvar_type_new_from_string(&type, policy_sig);
        c_assert(!r);
        _c_cleanup_(c_dvar_freep) CDVar* var = NULL;
        r = c_dvar_new(&var);
        c_assert(!r);

        c_dvar_begin_write(var, (__BYTE_ORDER == __BIG_ENDIAN), c_dvar_type_v, 1);

        c_dvar_write(var, "<([(u(", type, UINT32_C(-1));
        c_dvar_write(var, "bt", UINT32_C(1), UINT64_C(1));
        c_dvar_write(var, "[(btbs)]", UINT32_C(1), UINT64_C(1), true, "");
        c_dvar_write(var, "[(btssssuutt)]", UINT32_C(1), UINT64_C(1), "", "", "", "", 0, 0, UINT64_C(0), UINT64_MAX);
        c_dvar_write(var, "[(btssssuutt)]))]", UINT32_C(1), UINT64_C(1), "", "", "", "", 0, 0, UINT64_C(0), UINT64_MAX);
        c_dvar_write(var, "[]");
        c_dvar_write(var, "[]");
        c_dvar_write(var, "b)>", UINT32_C(0));

        r = c_dvar_end_write(var, &data, &n_data);
        c_assert(!r);

        c_dvar_begin_read(var, c_dvar_is_big_endian(var), c_dvar_type_v, 1, data, n_data);

        policy_registry_import(policy, var);

        /*
         * Create listener socket, let the kernel pick a random address
         * and remember it in @broker. Spawn a thread, which will then
         * run and babysit the broker.
         */
        SOCKET listener_fd = socket(AF_INET, SOCK_STREAM, 0);
        c_assert(listener_fd >= 0);

        struct addrinfo hints, * res;
        // Before using hint you have to make sure that the data structure is empty 
        memset(&hints, 0, sizeof(hints));
        // Set the attribute for hint
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM; // TCP Socket SOCK_DGRAM 
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_PASSIVE;

        // Fill the res data structure and make sure that the results make sense. 
        int status = getaddrinfo(NULL, "8080", &hints, &res);
        if (status != 0)
        {
            fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
            return -1;
        }
        /*************************************************************/
        /* Set socket to be nonblocking. All of the sockets for      */
        /* the incoming connections will also be nonblocking since   */
        /* they will inherit that state from the listening socket.   */
        /*************************************************************/
        u_long iMode = 1;
        status = ioctlsocket(listener_fd, FIONBIO, &iMode);
        if (status != NO_ERROR) {
            printf("ioctlsocket failed with error: %d\n", status);
        }

        if (!SetHandleInformation((HANDLE)listener_fd, HANDLE_FLAG_INHERIT, 0))
        {
            printf("SetHandleInformation failed with error: %d\n", GetLastError());
        }

        r = bind(listener_fd, res->ai_addr, res->ai_addrlen);
        c_assert(r >= 0);

        char bindaddr[64];
        uint32_t a;
        struct sockaddr_in* sa = (struct sockaddr_in*)res->ai_addr;
        a = be32toh(sa->sin_addr.s_addr);

        
        r = sprintf(bindaddr,
                "%u.%u.%u.%u:%u",
                a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF,
                be16toh(sa->sin_port));

        printf("I am now accepting connections at %s ...\n", bindaddr);
        freeaddrinfo(res);

        r = listen(listener_fd, 256);
        c_assert(r >= 0);

        controller_add_listener(&broker->controller,
            &listener,
            "/org/bus1/DBus/Listener/",
            listener_fd,
            policy);

        r = c_dvar_end_read(var);
        c_assert(!r);
        free(data);
        

#endif // WIN32

        *brokerp = broker;
        broker = NULL;
        return 0;
}

Broker *broker_free(Broker *broker) {
        if (!broker)
                return NULL;

        controller_deinit(&broker->controller);
        dispatch_file_deinit(&broker->signals_file);
        c_close(broker->signals_fd);
        dispatch_context_deinit(&broker->dispatcher);
        bus_deinit(&broker->bus);
        log_deinit(&broker->log);
        free(broker);

        return NULL;
}

static int broker_log_metrics(Broker *broker) {
        Metrics *metrics = &broker->bus.metrics;
        double stddev;
        int r;

        stddev = metrics_read_standard_deviation(metrics);
        log_appendf(broker->bus.log,
                    "DBUS_BROKER_METRICS_DISPATCH_COUNT=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_MIN=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_MAX=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_AVG=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_STDDEV=%.0f\n",
                    metrics->count,
                    metrics->minimum,
                    metrics->maximum,
                    metrics->average,
                    stddev);
        log_append_here(broker->bus.log, LOG_INFO, 0, DBUS_BROKER_CATALOG_DISPATCH_STATS);
        r = log_commitf(broker->bus.log,
                       "Dispatched %"PRIu64" messages @ %"PRIu64"(±%.0f)μs / message.",
                       metrics->count,
                       metrics->average / 1000,
                       stddev / 1000);
        if (r)
                return error_fold(r);

        return 0;
}

int broker_run(Broker *broker) {
        sigset_t signew, sigold;
        int r, k;

#if defined(__linux__)
        sigemptyset(&signew);
        sigaddset(&signew, SIGTERM);
        sigaddset(&signew, SIGINT);

        sigprocmask(SIG_BLOCK, &signew, &sigold);
#endif

        r = connection_open(&broker->controller.connection);
        if (r == CONNECTION_E_EOF)
                return MAIN_EXIT;
        else if (r)
                return error_fold(r);

        do {
                r = dispatch_context_dispatch(&broker->dispatcher);
                if (r == DISPATCH_E_EXIT)
                        r = MAIN_EXIT;
                else if (r == DISPATCH_E_FAILURE)
                        r = MAIN_FAILED;
                else
                        r = error_fold(r);
        } while (!r);

        peer_registry_flush(&broker->bus.peers);

        k = broker_log_metrics(broker);
        if (k)
                r = error_fold(k);

#if defined(__linux__)
        sigprocmask(SIG_SETMASK, &sigold, NULL);
#endif
        return r;
}

int broker_update_environment(Broker *broker, const char * const *env, size_t n_env) {
        return error_fold(controller_dbus_send_environment(&broker->controller, env, n_env));
}

int broker_reload_config(Broker *broker, User *sender_user, uint64_t sender_id, uint32_t sender_serial) {
        int r;

        r = controller_request_reload(&broker->controller, sender_user, sender_id, sender_serial);
        if (r) {
                if (r == CONTROLLER_E_SERIAL_EXHAUSTED ||
                    r == CONTROLLER_E_QUOTA)
                        return BROKER_E_FORWARD_FAILED;

                return error_fold(r);
        }

        return 0;
}
