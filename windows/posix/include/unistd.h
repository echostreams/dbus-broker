//typedef int ssize_t;

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;

unsigned int getuid(void);

#endif