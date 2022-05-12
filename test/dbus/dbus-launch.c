
#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util-broker.h"

void log_set_max_level(int);

int main(int argc, char** argv)
{
        _c_cleanup_(util_broker_freep) Broker* broker = NULL;
        void* value;
        int r;

        log_set_max_level(7);

        util_broker_new(&broker);
        util_broker_spawn(broker);

        c_assert(broker->listener_fd >= 0 || broker->pipe_fds[0] >= 0);

        r = pthread_join(broker->thread, &value);
        c_assert(!r);
        c_assert(!value);

        c_assert(broker->listener_fd < 0);
        c_assert(broker->pipe_fds[0] < 0);

        return 0;
}
