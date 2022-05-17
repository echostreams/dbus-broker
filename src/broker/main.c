/*
 * D-Bus Broker Main Entry
 */

#include <c-stdaux.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#if defined (__linux__)
#include <sys/prctl.h>
#endif
#include <sys/socket.h>
#include <sys/types.h>
#include "broker/broker.h"
#include "broker/main.h"
#include "util/audit.h"
#include "util/error.h"
#include "util/selinux.h"
#include "util/string.h"

#include <c-dvar-type.h>

bool main_arg_audit = false;
int main_arg_controller = 3;
int main_arg_log = -1;
const char *main_arg_machine_id = NULL;
uint64_t main_arg_max_bytes = 512 * 1024 * 1024;
uint64_t main_arg_max_fds = 128;
uint64_t main_arg_max_matches = 16 * 1024;
uint64_t main_arg_max_objects = 16 * 1024 * 1024;

#ifdef WIN32
#define program_invocation_name (__argv && __argv[0] ? __argv[0] : "?")
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

// Find a process with a given id in a snapshot
BOOL FindProcessID(HANDLE snap, DWORD id, LPPROCESSENTRY32 ppe)
{
    BOOL res;
    ppe->dwSize = sizeof(PROCESSENTRY32); // (mandatory)
    res = Process32First(snap, ppe);
    while (res) {
        if (ppe->th32ProcessID == id) {
            return TRUE;
        }
        res = Process32Next(snap, ppe);
    }
    return FALSE;
}

// Get the parent process id of the current process
BOOL GetParentProcessId(DWORD* parent_process_id)
{
    HANDLE hSnap;
    PROCESSENTRY32 pe;
    DWORD current_pid = GetCurrentProcessId();

    // Take a snapshot of all Windows processes
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnap) {
        return FALSE;
    }

    // Find the current process in the snapshot
    if (!FindProcessID(hSnap, current_pid, &pe)) {
        return FALSE;
    }

    // Close the snapshot
    if (!CloseHandle(hSnap)) {
        return FALSE;
    }

    *parent_process_id = pe.th32ParentProcessID;
    return TRUE;
}

SOCKET ConvertProcessSocket(SOCKET oldsocket, DWORD source_pid)
{
    HANDLE source_handle = OpenProcess(PROCESS_ALL_ACCESS,
        FALSE, source_pid);
    HANDLE newhandle;
    if (!DuplicateHandle(source_handle, (HANDLE)oldsocket,
        GetCurrentProcess(), &newhandle, 0, FALSE,
        DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS))
    {
        fprintf(stderr, "Could not duplicate handle\n");
        CloseHandle(source_handle);
        return INVALID_SOCKET;
    }
    else {
        fprintf(stderr, "DuplicateHandle(%llu -> %d)\n", oldsocket, newhandle);
    }
    CloseHandle(source_handle);

    int iResult;
    u_long iMode = 1;
    iResult = ioctlsocket((SOCKET)newhandle, FIONBIO, &iMode);
    if (iResult != NO_ERROR) {
        printf("ioctlsocket failed with error: %d\n", iResult);
    }
    if (!SetHandleInformation((HANDLE)newhandle, HANDLE_FLAG_INHERIT, 0)) {
        printf("SetHandleInformation failed with error: %lu\n", GetLastError());
    }

    return (SOCKET)newhandle;
}

int policy_c_dvar_test()
{
#ifdef WIN32

    /* D-Bus type 'a(btbs)' */
#define POLICY_TYPE_a_btbs              \
        C_DVAR_T_ARRAY(                 \
                C_DVAR_T_TUPLE4(        \
                        C_DVAR_T_b,     \
                        C_DVAR_T_t,     \
                        C_DVAR_T_b,     \
                        C_DVAR_T_s      \
                )                       \
        )

/* D-Bus type 'a(btssssuutt)' */
#define POLICY_TYPE_a_btssssuutt        \
        C_DVAR_T_ARRAY(                 \
                C_DVAR_T_TUPLE10(       \
                        C_DVAR_T_b,     \
                        C_DVAR_T_t,     \
                        C_DVAR_T_s,     \
                        C_DVAR_T_s,     \
                        C_DVAR_T_s,     \
                        C_DVAR_T_s,     \
                        C_DVAR_T_u,     \
                        C_DVAR_T_u,     \
                        C_DVAR_T_t,     \
                        C_DVAR_T_t      \
                )                       \
        )

/* D-Bus type that contains an entire policy dump */
#define POLICY_TYPE                                                             \
        C_DVAR_T_TUPLE4(                                                        \
                C_DVAR_T_ARRAY(                                                 \
                        C_DVAR_T_TUPLE2(                                        \
                                C_DVAR_T_u,                                     \
                                C_DVAR_T_TUPLE5(                                \
                                        C_DVAR_T_b,                             \
                                        C_DVAR_T_t,                             \
                                        POLICY_TYPE_a_btbs,                     \
                                        POLICY_TYPE_a_btssssuutt,               \
                                        POLICY_TYPE_a_btssssuutt                \
                                )                                               \
                        )                                                       \
                ),                                                              \
                C_DVAR_T_ARRAY(                                                 \
                        C_DVAR_T_TUPLE4(                                        \
                                C_DVAR_T_b,                                     \
                                C_DVAR_T_u,                                     \
                                C_DVAR_T_u,                                     \
                                C_DVAR_T_TUPLE5(                                \
                                        C_DVAR_T_b,                             \
                                        C_DVAR_T_t,                             \
                                        POLICY_TYPE_a_btbs,                     \
                                        POLICY_TYPE_a_btssssuutt,               \
                                        POLICY_TYPE_a_btssssuutt                \
                                )                                               \
                        )                                                       \
                ),                                                              \
                C_DVAR_T_ARRAY(                                                 \
                        C_DVAR_T_TUPLE2(                                        \
                                C_DVAR_T_s,                                     \
                                C_DVAR_T_s                                      \
                        )                                                       \
                ),                                                              \
                C_DVAR_T_b                                                      \
        )

    //static const CDVarType policy_type[] = {
    //    C_DVAR_T_INIT(POLICY_TYPE)
    //};

    int r;
    //ControllerListener* listener;
    PolicyRegistry* policy = NULL;
    r = policy_registry_new(&policy, /*broker->bus.seclabel*/"");
    if (r)
        return error_fold(r);
    /*
    const char policy_sig[] =
        "<("
        "a(u(bta(btbs)a(btssssuutt)a(btssssuutt)))"
        "a(buu(bta(btbs)a(btssssuutt)a(btssssuutt)))"
        "a(ss)"
        "b"
        ")>";
    */
    //const char policy_sig[] = "v";

    //CDVarType* type = NULL;
    size_t n_data;
    void* data;

    //r = c_dvar_type_new_from_string(&type, policy_sig);
    //c_assert(!r);
    _c_cleanup_(c_dvar_freep) CDVar* var = NULL;
    r = c_dvar_new(&var);
    c_assert(!r);
    c_dvar_begin_write(var, (__BYTE_ORDER == __BIG_ENDIAN), c_dvar_type_v, 1);

    c_dvar_write(var, "<([(u(", (const CDVarType[]) { C_DVAR_T_INIT(POLICY_TYPE) }, UINT32_C(-1));
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

    //controller_add_listener(&broker->controller,
    //    &listener,
    //    "/org/bus1/DBus/Listener/",
    //    listener_fd,
    //    policy);

    r = c_dvar_end_read(var);
    c_assert(!r);
    free(data);

    return 0;

#endif // WIN32
}

int CreateWinControllerSocket()
{
#ifdef WIN32
    int r;
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
    int status = getaddrinfo(NULL, "9000", &hints, &res);
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

    return listener_fd;

#endif // WIN32
}

#endif

static void help(void) {
        printf("%s [GLOBALS...] ...\n\n"
               "Linux/Windows D-Bus Message Broker\n\n"
               "  -h --help                     Show this help\n"
               "     --version                  Show package version\n"
               "     --audit                    Log to the audit subsystem\n"
               "     --controller FD            Specify controller file-descriptor\n"
               "     --log FD                   Provide logging socket\n"
               "     --machine-id MACHINE_ID    Machine ID of the current machine\n"
               "     --max-bytes BYTES          Maximum number of bytes each user may allocate in the broker\n"
               "     --max-fds FDS              Maximum number of file descriptors each user may allocate in the broker\n"
               "     --max-matches MATCHES      Maximum number of match rules each user may allocate in the broker\n"
               "     --max-objects OBJECTS      Maximum total number of names, peers, pending replies, etc each user may allocate in the broker\n"
#ifdef WIN32
               , __argv && __argv[0] ? __argv[0] : "?"                
#else
               , program_invocation_short_name
#endif

        );
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_AUDIT,
                ARG_CONTROLLER,
                ARG_LOG,
                ARG_MACHINE_ID,
                ARG_MAX_BYTES,
                ARG_MAX_FDS,
                ARG_MAX_MATCHES,
                ARG_MAX_OBJECTS,
        };
        static const struct option options[] = {
                { "help",               no_argument,            NULL,   'h'                     },
                { "version",            no_argument,            NULL,   ARG_VERSION             },
                { "audit",              no_argument,            NULL,   ARG_AUDIT               },
                { "controller",         required_argument,      NULL,   ARG_CONTROLLER          },
                { "log",                required_argument,      NULL,   ARG_LOG                 },
                { "machine-id",         required_argument,      NULL,   ARG_MACHINE_ID          },
                { "max-bytes",          required_argument,      NULL,   ARG_MAX_BYTES           },
                { "max-fds",            required_argument,      NULL,   ARG_MAX_FDS             },
                { "max-matches",        required_argument,      NULL,   ARG_MAX_MATCHES         },
                { "max-objects",        required_argument,      NULL,   ARG_MAX_OBJECTS         },
                {}
        };
        int r, c;

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        help();
                        return MAIN_EXIT;

                case ARG_VERSION:
                        printf("dbus-broker %d\n", PACKAGE_VERSION);
                        return MAIN_EXIT;

                case ARG_AUDIT:
                        main_arg_audit = true;
                        break;

                case ARG_CONTROLLER: {
                        unsigned long vul;
                        char *end;

                        errno = 0;
                        vul = strtoul(optarg, &end, 10);
                        if (errno != 0 || *end || optarg == end || vul > INT_MAX) {
                                fprintf(stderr, "%s: invalid controller file-descriptor -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_controller = vul;

#ifdef WIN32
                        DWORD parentPID;
                        if (!GetParentProcessId(&parentPID))
                        {
                            fprintf(stderr, "%s: could not get parent process id\n", program_invocation_name);
                            return MAIN_FAILED;
                        }
                        main_arg_controller = (int)ConvertProcessSocket((SOCKET)vul, parentPID);
#else
                        main_arg_controller = vul;
#endif

                        break;
                }

                case ARG_LOG: {
                        unsigned long vul;
                        char *end;

                        errno = 0;
                        vul = strtoul(optarg, &end, 10);
                        if (errno != 0 || *end || optarg == end || vul > INT_MAX) {
                                fprintf(stderr, "%s: invalid log file-descriptor -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_log = vul;
                        break;
                }

                case ARG_MACHINE_ID: {
                        if (strlen(optarg) != 32) {
                                fprintf(stderr, "%s: invalid machine ID -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        main_arg_machine_id = optarg;
                        break;
                }

                case ARG_MAX_BYTES:
                        r = util_strtou64(&main_arg_max_bytes, optarg);
                        if (r) {
                                fprintf(stderr, "%s: invalid max number of bytes -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        break;

                case ARG_MAX_FDS:
                        r = util_strtou64(&main_arg_max_fds, optarg);
                        if (r) {
                                fprintf(stderr, "%s: invalid max number of fds -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        break;

                case ARG_MAX_MATCHES:
                        r = util_strtou64(&main_arg_max_matches, optarg);
                        if (r) {
                                fprintf(stderr, "%s: invalid max number of matches -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        break;

                case ARG_MAX_OBJECTS:
                        r = util_strtou64(&main_arg_max_objects, optarg);
                        if (r) {
                                fprintf(stderr, "%s: invalid max number of objects -- '%s'\n", program_invocation_name, optarg);
                                return MAIN_FAILED;
                        }

                        break;

                case '?':
                        /* getopt_long() prints warning */
                        return MAIN_FAILED;

                default:
                        return error_origin(-EINVAL);
                }
        }

        if (optind != argc) {
                fprintf(stderr, "%s: invalid arguments -- '%s'\n", program_invocation_name, argv[optind]);
                return MAIN_FAILED;
        }

        /*
         * Verify that the passed FDs exist. Preferably, we would not care
         * and simply fail later on. However, the FD-number might be
         * used by one of our other FDs (signalfd, epollfd, ...), and thus we
         * might trigger assertions on their behavior, which we better avoid.
         */

        /* verify log-fd is DGRAM or STREAM */
        if (main_arg_log >= 0) {
                socklen_t n;
                int v1, v2;
#if defined SO_DOMAIN
                n = sizeof(v1);
                r = getsockopt(main_arg_log, SOL_SOCKET, SO_DOMAIN, &v1, &n);
#else
                r = 0;
#endif
                n = sizeof(v2);
                r = r ? r : getsockopt(main_arg_log, SOL_SOCKET, SO_TYPE, &v2, &n);

                if (r < 0) {
                        if (errno != EBADF && errno != ENOTSOCK)
                                return error_origin(-errno);

                        fprintf(stderr, "%s: log file-descriptor not a socket -- '%d'\n", program_invocation_name, main_arg_log);
                        return MAIN_FAILED;
                } else if (v1 != AF_UNIX || (v2 != SOCK_DGRAM && v2 != SOCK_STREAM)) {
                        fprintf(stderr, "%s: socket type of log file-descriptor not supported -- '%d'\n", program_invocation_name, main_arg_log);
                        return MAIN_FAILED;
                }
        }

        /* verify controller-fd is STREAM */
        {
                socklen_t n;
                int v1, v2 = 0;

#if defined SO_DOMAIN
                n = sizeof(v1);
                r = getsockopt(main_arg_controller, SOL_SOCKET, SO_DOMAIN, &v1, &n);
#else

#ifdef WIN32
                //main_arg_controller = CreateWinControllerSocket();
#endif
                WSAPROTOCOL_INFOW Info;
                INT InfoSize = sizeof(Info);
                r = getsockopt(main_arg_controller, SOL_SOCKET, SO_PROTOCOL_INFO, (PCHAR)&Info, &InfoSize);
                v1 = Info.iAddressFamily;
                fprintf(stderr, "controller socket family: %d %d\n", v1, r);
#endif
                n = sizeof(v2);
                r = r ? r : getsockopt(main_arg_controller, SOL_SOCKET, SO_TYPE, &v2, &n);
                fprintf(stderr, "controller socket type: %d %d\n", v2, r);

                if (r < 0) {
#ifdef WIN32
                        int err = WSAGetLastError();
                        fprintf(stderr, "%s: controller file-descriptor getsockopt(SO_TYPE) failed -- %d %d\n", program_invocation_name, err, errno);
                        if (err == WSAEBADF)
                                errno = EBADF;
                        else if (err == WSAENOTSOCK)
                                errno = ENOTSOCK;
                        else
                                errno = err;
#endif
                        if (errno != EBADF && errno != ENOTSOCK)
                                return error_origin(-errno);

                        fprintf(stderr, "%s: controller file-descriptor not a socket -- '%d'\n", program_invocation_name, main_arg_controller);
                        return MAIN_FAILED;
                } 
#ifdef WIN32
                else if (v1 != AF_INET || v2 != SOCK_STREAM)
#else
                else if (v1 != AF_UNIX || v2 != SOCK_STREAM) 
#endif
                {
                        fprintf(stderr, "%s: socket type of controller file-descriptor not supported -- '%d'\n", program_invocation_name, main_arg_controller);
                        return MAIN_FAILED;
                }
        }

        /* verify that a machine ID was passed */
        {
                if (!main_arg_machine_id) {
                        fprintf(stderr, "%s: the machine ID argument is mandatory\n", program_invocation_name);
                        return MAIN_FAILED;
                }
        }

        return 0;
}

static int setup(void) {
#if defined(__linux__)
        int r;

        /*
         * We never spawn external applications from within the broker itself,
         * so clear the ambient set, as it is never needed. This is meant as
         * safety measure to guarantee our capabilities are not inherited by
         * possible exploits.
         */
        r = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        if (r < 0)
                return error_origin(-errno);
#endif
        return 0;
}

static int run(void) {
        _c_cleanup_(broker_freep) Broker *broker = NULL;
        int r;

        r = broker_new(&broker, main_arg_machine_id, main_arg_log, main_arg_controller, main_arg_max_bytes, main_arg_max_fds, main_arg_max_matches, main_arg_max_objects);
        if (!r)
                r = broker_run(broker);

        return error_trace(r);
}

int main(int argc, char **argv) {

#ifdef WIN32

        policy_c_dvar_test();

        WSADATA wsaData;
        int iResult;
        // Initialize Winsock
        iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
                printf("WSAStartup failed: %d\n", iResult);
                return 1;
        }
#endif
        int r;

        r = parse_argv(argc, argv);
        if (r)
                goto exit;

        r = setup();
        if (r)
                goto exit;

        if (main_arg_audit) {
                r = util_audit_init_global();
                if (r) {
                        r = error_fold(r);
                        goto exit;
                }
        }

        r = bus_selinux_init_global();
        if (r) {
                r = error_fold(r);
                goto exit;
        }

        r = run();

exit:
        bus_selinux_deinit_global();
        util_audit_deinit_global();

        r = error_trace(r);

#ifdef WIN32
        WSACleanup();
#endif

        return (r == 0 || r == MAIN_EXIT) ? 0 : 1;
}
