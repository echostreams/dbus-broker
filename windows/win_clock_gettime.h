#include <time.h>

/* Identifier for system-wide realtime clock.  */
# define CLOCK_REALTIME                        0
/* Monotonic system-wide clock.  */
# define CLOCK_MONOTONIC                1
/* High-resolution timer from the CPU.  */
# define CLOCK_PROCESS_CPUTIME_ID        2
/* Thread-specific CPU-time clock.  */
# define CLOCK_THREAD_CPUTIME_ID        3
/* Monotonic system-wide clock, not adjusted for frequency scaling.  */
# define CLOCK_MONOTONIC_RAW                4
/* Identifier for system-wide realtime clock, updated only on ticks.  */
# define CLOCK_REALTIME_COARSE                5
/* Monotonic system-wide clock, updated only on ticks.  */
# define CLOCK_MONOTONIC_COARSE                6
/* Monotonic system-wide clock that includes time spent in suspension.  */
# define CLOCK_BOOTTIME                        7
/* Like CLOCK_REALTIME but also wakes suspended system.  */
# define CLOCK_REALTIME_ALARM                8
/* Like CLOCK_BOOTTIME but also wakes suspended system.  */
# define CLOCK_BOOTTIME_ALARM                9
/* Like CLOCK_REALTIME but in International Atomic Time.  */
# define CLOCK_TAI                        11
/* Flag to indicate time is absolute.  */
# define TIMER_ABSTIME                        1


typedef int clockid_t;

extern int clock_gettime(clockid_t clock_id, struct timespec* tp);
