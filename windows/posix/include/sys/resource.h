#ifndef SYS_RESOURCE_H
#define SYS_RESOURCE_H

#include <WinSock2.h>	// struct timeval

#define RUSAGE_SELF	0
#define RUSAGE_THREAD	1

typedef unsigned long rlim_t;

struct rlimit {
	rlim_t rlim_cur;  /* Soft limit */
	rlim_t rlim_max;  /* Hard limit (ceiling for rlim_cur) */
};

struct rusage
{
	struct timeval ru_utime;
	struct timeval ru_stime;
	int ru_nvcsw;
	int ru_minflt;
	int ru_majflt;
	int ru_nivcsw;
};

int getrusage(int who, struct rusage *r_usage);

#endif /* SYS_RESOURCE_H */
