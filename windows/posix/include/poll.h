#ifndef POLL_H
#define POLL_H

#include <winsock2.h>

typedef unsigned int nfds_t;

int poll(struct pollfd fds[], nfds_t nfds, int timeout);

#endif /* POLL_H */
