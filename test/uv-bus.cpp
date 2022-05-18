#include <systemd/sd-bus.h>
#include <uv.h>
#include <assert.h>
#include <poll.h>

typedef struct {
	uv_poll_t connection;
	uv_timer_t timer;
	sd_bus* bus;
	sd_bus_slot* slot;
} callback_data;

void handle_dbus(callback_data* data);

static int method_multiply(sd_bus_message* m, void* userdata, sd_bus_error* ret_error) {
	int64_t x, y;
	int r;

	/* Read the parameters */
	r = sd_bus_message_read(m, "xx", &x, &y);
	if (r < 0) {
		fprintf(stderr, "Failed to parse parameters: %s\n", strerror(-r));
		return r;
	}

	/* Reply with the response */
	return sd_bus_reply_method_return(m, "x", x * y);
}

static int method_divide(sd_bus_message* m, void* userdata, sd_bus_error* ret_error) {
	int64_t x, y;
	int r;

	/* Read the parameters */
	r = sd_bus_message_read(m, "xx", &x, &y);
	if (r < 0) {
		fprintf(stderr, "Failed to parse parameters: %s\n", strerror(-r));
		return r;
	}

	/* Return an error on division by zero */
	if (y == 0) {
		sd_bus_error_set_const(ret_error, "uv.poettering.DivisionByZero", "Sorry, can't allow division by zero.");
		return -EINVAL;
	}

	return sd_bus_reply_method_return(m, "x", x / y);
}

/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable calculator_vtable[] = {
		SD_BUS_VTABLE_START(0),
		SD_BUS_METHOD("Multiply", "xx", "x", method_multiply, SD_BUS_VTABLE_UNPRIVILEGED),
		SD_BUS_METHOD("Divide",   "xx", "x", method_divide,   SD_BUS_VTABLE_UNPRIVILEGED),
		SD_BUS_VTABLE_END
};

int poll_to_libuv_events(int pollflags) {
	int ret = 0;
	if (pollflags & (POLLIN | POLLPRI)) {
		ret |= UV_READABLE;
	}
	if (pollflags & POLLOUT) {
		ret |= UV_WRITABLE;
	}

	// we also have the non-corresponding UV_DISCONNECT

	return ret;
}

void update_events(callback_data *data) {

	// prepare the callback for calling us the next time.
	int new_events = poll_to_libuv_events(
		sd_bus_get_events(data->bus)
	);

	uint64_t usec;
	int r = sd_bus_get_timeout(data->bus, &usec);

	if (!r) {
		// if the timer is running already, it is stopped automatically
		// inside uv_timer_start.
		uv_timer_start(
			&data->timer,
			[](uv_timer_t* handle) {
				// yes, handle is not a poll_t, but
				// we just care for its -> data member anyway.
				handle_dbus((callback_data*)handle->data);
			},
			usec / 1000, // time in milliseconds, sd_bus provides µseconds
				0            // don't repeat
				);
	}

	// always watch for disconnects:
	new_events |= UV_DISCONNECT;

	// activate the socket watching and if active, handle dbus
	uv_poll_start(&data->connection, new_events, [](uv_poll_t* handle, int, int) {
		handle_dbus((callback_data*)handle->data);
		});
}

void handle_dbus(callback_data* data) {

	// let dbus handle the requests available
	while (true) {
		int r = sd_bus_process(data->bus, nullptr);
		if (r < 0) {
			fprintf(stderr, "[uv-dbus] Failed to process bus: %s\n", strerror(-r));
			break;
		}
		else if (r > 0) {
			// try to process another request!
			continue;
		}
		else {
			// no more progress, wait for the next callback.
			break;
		}
	}

	// update the events we watch for on the socket.
	update_events(data);
}


int run()
{
	fprintf(stderr, "[uv-bus] starting up connections...\n");
	int r;
	uv_loop_t loop;	
	callback_data data;

	uv_loop_init(&loop);
	r = sd_bus_open_user(&data.bus);
	assert(r >= 0);
	/* Install the object */
	r = sd_bus_add_object_vtable(data.bus,
		&data.slot,
		"/uv/poettering/Calculator",  /* object path */
		"uv.poettering.Calculator",   /* interface name */
		calculator_vtable,
		NULL);
	assert(r >= 0);
	/* Take a well-known service name so that clients can find us */
	r = sd_bus_request_name(data.bus, "uv.poettering.Calculator", 0);
	assert(r >= 0);

	// register the filedescriptor from
	// sd_bus_get_fd(bus) to libuv
	uv_poll_init(&loop, &data.connection, sd_bus_get_fd(data.bus));
	data.connection.data = &data;

	// init the dbus-event-timer
	uv_timer_init(&loop, &data.timer);
	data.timer.data = &data;

	// process initial events and set up the
	// events and timers for subsequent calls
	handle_dbus(&data);

	// let the event loop run forever.
	fprintf(stderr, "[uv-bus] Starting event loop\n");
	r = uv_run(&loop, UV_RUN_DEFAULT);
	fprintf(stderr, "[uv-bus] Stopping event loop\n");

	return r;
}

int main(int argc, char** argv)
{
	int ret = run();
	return ret;
}
