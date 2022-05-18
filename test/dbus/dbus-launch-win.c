
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <process.h>    /* _beginthread, _endthread */
#include <stdbool.h>
int socketpair(int domain, int type, int protocol, int sv[2]);
int asprintf(char** strp, const char* fmt, ...);
int sockaddr_pretty(const struct sockaddr* _sa, socklen_t salen, 
    bool translate_ipv6, bool include_port, char** ret);

//#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>

#include "util-broker.h"

void log_set_max_level(int);

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

int main(int argc, char** argv)
{
    _c_cleanup_(win_broker_freep) Broker* broker = NULL;
    //void* value;
    DWORD r;

    log_set_max_level(7);

    // Initialize Winsock.
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        fwprintf(stderr, L"WSAStartup failed with error: %ld\n", iResult);
        return 1;
    }

    win_broker_new(&broker);
    win_broker_spawn(broker);

    //c_assert(broker->listener_fd >= 0 || broker->pipe_fds[0] >= 0);

    //r = pthread_join(broker->thread, &value);
    r = WaitForSingleObject(broker->thread, INFINITE);

    c_assert(r == WAIT_OBJECT_0);
    //c_assert(!value);

    c_assert(broker->listener_fd < 0);
    c_assert(broker->pipe_fds[0] < 0);

    WSACleanup();

    return 0;
}
