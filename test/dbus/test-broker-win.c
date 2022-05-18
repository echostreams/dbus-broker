#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util-broker.h"

extern void log_set_max_level(int);

static void test_dummy(void) {
    _c_cleanup_(win_broker_freep) Broker* broker = NULL;

    /*
     * Simple dummy test that just spawns and terminates a broker,
     * verifying our infrastructure works as expected.
     */

    win_broker_new(&broker);
    win_broker_spawn(broker);
    win_broker_terminate(broker);
}

static void test_connect(void) {
    _c_cleanup_(win_broker_freep) Broker* broker = NULL;
    int r;

    /*
     * Connects to a broker and verifies the Hello call returned a valid
     * unique-name for the connection.
     */

    win_broker_new(&broker);
    win_broker_spawn(broker);

    {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
        const char* unique = NULL;

        util_broker_connect(broker, &bus);

        r = sd_bus_get_unique_name(bus, &unique);
        c_assert(!r);
        c_assert(unique);
        fprintf(stderr, "-- unique: %s\n", unique);
    }

    win_broker_terminate(broker);
}

static void test_self_ping(void) {
    _c_cleanup_(win_broker_freep) Broker* broker = NULL;
    int r;

    /*
     * Connects to the broker and sends Ping to itself, thus verifying most
     * basic message delivery.
     */

    win_broker_new(&broker);
    win_broker_spawn(broker);

    {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus* bus = NULL;
        const char* unique = NULL;

        util_broker_connect(broker, &bus);

        r = sd_bus_get_unique_name(bus, &unique);
        c_assert(!r);

        r = sd_bus_call_method(bus,
            unique,
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.Peer",
            "Ping",
            NULL,
            NULL,
            NULL);
        /* sd-bus detects self-calls and returns ELOOP */
        c_assert(r == -ELOOP);
    }

    win_broker_terminate(broker);
}

static int test_ping_pong_fn(sd_bus_message* m, void* userdata, sd_bus_error* error) {
    sd_event* event = userdata;
    const sd_bus_error* e;

    e = sd_bus_message_get_error(m);
    c_assert(!e);

    return sd_event_exit(event, 0);
}

static void test_ping_pong(void) {
    _c_cleanup_(win_broker_freep) Broker* broker = NULL;
    _c_cleanup_(sd_event_unrefp) sd_event* event = NULL;
    _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus* server = NULL, * client = NULL;
    int r;

    /*
     * This connects two clients to the broker and performs a basic
     * Ping/Pong test, using the built-in Peer interface of sd-bus.
     */

    win_broker_new(&broker);
    win_broker_spawn(broker);

    /* setup sd-event */
    {
        r = sd_event_new(&event);
        c_assert(!r);
    }

    /* setup server */
    {
        util_broker_connect(broker, &server);
        r = sd_bus_attach_event(server, event, SD_EVENT_PRIORITY_NORMAL);
        c_assert(!r);
    }

    /* setup client */
    {
        util_broker_connect(broker, &client);
        r = sd_bus_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL);
        c_assert(!r);
    }

    /* send PING */
    {
        const char* unique = NULL;

        r = sd_bus_get_unique_name(server, &unique);
        c_assert(!r);

        r = sd_bus_call_method_async(client,
            NULL,
            unique,
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.Peer",
            "Ping",
            test_ping_pong_fn,
            event,
            NULL);
        c_assert(r == 1);
    }

    /* loop */
    {
        r = sd_event_loop(event);
        c_assert(!r);
    }

    win_broker_terminate(broker);
}

int main(int argc, char** argv) {

    // Initialize Winsock.
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        wprintf(L"WSAStartup failed with error: %ld\n", iResult);
        return 1;
    }

    log_set_max_level(7);
    fprintf(stderr, "start...\n");
    test_dummy();
    //fprintf(stderr, "dummy...\n");
    test_connect();
    fprintf(stderr, "connect...\n");
    test_self_ping();
    fprintf(stderr, "self ping...\n");
    //test_ping_pong();
    //fprintf(stderr, "ping pong...\n");

    WSACleanup();

}