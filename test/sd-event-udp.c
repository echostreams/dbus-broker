/*
 * http://0pointer.net/blog/introducing-sd-event.html
 * Introducing sd-event
 * The Event Loop API of libsystemd
 * a short example how to use sd-event in a simple daemon
 * works for both windows and linux
 */

#if defined(__linux__)
#include <alloca.h>
#else
#define _WINSOCK_DEPRECATED_NO_WARNINGS
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

#define DEF_PORT 7777

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

int server()
{
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
    /*
     * libsystemd-mini doesn't support watchdog
     */
    //r = sd_event_set_watchdog(event, true);
    //if (r < 0)
    //    goto finish;

#ifdef WIN32
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    // set SOCK_NONBLOCK
    u_long iMode = 1;
    int status = ioctlsocket(fd, FIONBIO, &iMode);
    if (status != NO_ERROR) {
        fprintf(stderr, "ioctlsocket failed with error: %d\n", status);
    }
    // set SOCK_CLOEXEC
    if (!SetHandleInformation((HANDLE)(uintptr_t)fd, HANDLE_FLAG_INHERIT, 0))
    {
        fprintf(stderr, "SetHandleInformation failed with error: %lu\n", GetLastError());
    }    
#else
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#endif
    if (fd < 0) {
        r = -errno;
        goto finish;
    }

    sa.in = (struct sockaddr_in){
            .sin_family = AF_INET,
            .sin_port = htobe16(DEF_PORT),
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

int client()
{
#ifdef WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Client: WSAStartup failed with error %d\n", WSAGetLastError());
        // Clean up
        WSACleanup();
        // Exit with error
        return -1;
    }
    else {
        printf("Client: WSAStartup(%x): %s, Status: %s.\n", wsaData.wVersion, wsaData.szDescription, wsaData.szSystemStatus);
    }
    SOCKET SendingSocket;
#else
    int SendingSocket;
#endif

    
    SOCKADDR_IN ReceiverAddr, SrcInfo;
    char SendBuf[256] = {0};
    int len;
    int TotalByteSent = 0;

    // Create a new socket to receive datagrams on.
    SendingSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (SendingSocket == INVALID_SOCKET) {
        // Print error message
        printf("Client: Error at socket(): %d\n", WSAGetLastError());
        // Clean up
        WSACleanup();
        // Exit with error
        return -1;
    }
    else {
        printf("Client: socket() is OK!\n");
    }


    /*Set up a SOCKADDR_IN structure that will identify who we
    will send datagrams to.
    For demonstration purposes, let's assume our receiver's IP address is 127.0.0.1
    and waiting for datagrams on port 7777 */

    ReceiverAddr.sin_family = AF_INET;
    ReceiverAddr.sin_port = htons(DEF_PORT);
    //ReceiverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    inet_pton(AF_INET, "127.0.0.1", &ReceiverAddr.sin_addr.s_addr);


    // Send data packages to the receiver(Server).
    do {
        printf("\nPlease, type your message: "); //Ask user for message
        char* c = fgets(SendBuf, sizeof(SendBuf), stdin); //Read user's input

        //Print user's input and a progress message
        printf("Client: Data to be sent: %s\n", c);
        printf("Client: Sending data...\n");

        //Send message to receiver(Server)
        int ByteSent = sendto(SendingSocket, SendBuf, (int)strlen(SendBuf), 0, (SOCKADDR*)&ReceiverAddr, sizeof(ReceiverAddr));
        //Print success message
        printf("Client: Sent %d bytes\n", ByteSent);
        if (ByteSent == SOCKET_ERROR)
            break;

        TotalByteSent += ByteSent;

        if (memcmp(SendBuf, "EXIT", 4) == 0)
            break;
        /*Program is asking user for messages and sending the to Server,until you will close it.
        (You can replace while(1) with a condition to stop asking/sending messages.)*/
    } while (1);



    // Print some info on the receiver(Server) side...

    // Allocate the required resources

    memset(&SrcInfo, 0, sizeof(SrcInfo));

    len = sizeof(SrcInfo);

    getsockname(SendingSocket, (SOCKADDR*)&SrcInfo, &len);

    printf("Client: Sending IP(s) used: %s\n", inet_ntoa(SrcInfo.sin_addr));

    printf("Client: Sending port used: %d\n", htons(SrcInfo.sin_port));

    // Print some info on the sender(Client) side...
    getpeername(SendingSocket, (SOCKADDR*)&ReceiverAddr, (int*)sizeof(ReceiverAddr));

    printf("Client: Receiving IP used: %s\n", inet_ntoa(ReceiverAddr.sin_addr));

    printf("Client: Receiving port used: %d\n", htons(ReceiverAddr.sin_port));

    printf("Client: Total byte sent: %d\n", TotalByteSent);



    // When your application is finished receiving datagrams close the socket.

    printf("Client: Finished sending. Closing the sending socket...\n");

    if (closesocket(SendingSocket) != 0) {

        printf("Client: closesocket() failed! Error code: %d\n", WSAGetLastError());
    }
    else {
        printf("Server: closesocket() is OK\n");
    }


#ifdef WIN32
    WSACleanup();
#endif

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc > 1 && strcmp(argv[1], "client") == 0)
        return client();
    else
        return server();
}