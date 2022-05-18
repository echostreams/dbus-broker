#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tchar.h>
#include <io.h>
#define close    _close
#define strdup   _strdup
#include <WinSock2.h>
#else
#include <fcntl.h>
#include <stdio_ext.h>
#include <unistd.h>
#endif

#include <sys/mman.h>


#include <stdio.h>
#include "log.h"
#include "macro.h"

#include "memory-util.h"

#ifdef __cplusplus
extern "C" {
#endif

    static inline int errno_or_else(int fallback) {
        /* To be used when invoking library calls where errno handling is not defined clearly: we return
         * errno if it is set, and the specified error otherwise. The idea is that the caller initializes
         * errno to zero before doing an API call, and then uses this helper to retrieve a somewhat useful
         * error code */
        if (errno > 0)
            return -errno;

        return -abs(fallback);
    }

    int fflush_and_check(FILE* f) {
        assert(f);

        errno = 0;
        fflush(f);

        if (ferror(f))
            return errno_or_else(EIO);

        return 0;
    }

    int close_nointr(int fd) {
        assert(fd >= 0);

#ifdef WIN32
        //if (CloseHandle((HANDLE)fd))
        //    return 0;
        if (closesocket((SOCKET)fd) != SOCKET_ERROR)
        {
            return 0;
        }
        int err = WSAGetLastError();
        return -err;
#else
        if (close(fd) >= 0)
            return 0;


        /*
         * Just ignore EINTR; a retry loop is the wrong thing to do on
         * Linux.
         *
         * http://lkml.indiana.edu/hypermail/linux/kernel/0509.1/0877.html
         * https://bugzilla.gnome.org/show_bug.cgi?id=682819
         * http://utcc.utoronto.ca/~cks/space/blog/unix/CloseEINTR
         * https://sites.google.com/site/michaelsafyan/software-engineering/checkforeintrwheninvokingclosethinkagain
         */
        if (errno == EINTR)
            return 0;

        return -errno;
#endif
    }

    int safe_close(int fd) {

        /*
         * Like close_nointr() but cannot fail. Guarantees errno is
         * unchanged. Is a NOP with negative fds passed, and returns
         * -1, so that it can be used in this syntax:
         *
         * fd = safe_close(fd);
         */

        if (fd >= 0) {
            //PROTECT_ERRNO;

            /* The kernel might return pretty much any error code
             * via close(), but the fd will be closed anyway. The
             * only condition we want to check for here is whether
             * the fd was invalid at all... */

            assert_se(close_nointr(fd) != -EBADF);
        }

        return -1;
    }

    void close_many(const int fds[], size_t n_fd) {
        assert(fds || n_fd <= 0);

        for (size_t i = 0; i < n_fd; i++)
            safe_close(fds[i]);
    }      

    int fclose_nointr(FILE* f) {
        assert(f);

        /* Same as close_nointr(), but for fclose() */

        errno = 0; /* Extra safety: if the FILE* object is not encapsulating an fd, it might not set errno
                    * correctly. Let's hence initialize it to zero first, so that we aren't confused by any
                    * prior errno here */
        if (fclose(f) == 0)
            return 0;

        if (errno == EINTR)
            return 0;

        return errno_or_else(EIO);
    }


    FILE* safe_fclose(FILE* f) {

        /* Same as safe_close(), but for fclose() */

        if (f) {
            //PROTECT_ERRNO;

            assert_se(fclose_nointr(f) != -EBADF);
        }

        return NULL;
    }

    int fputs_with_space(FILE* f, const char* s, const char* separator, bool* space) {
        int r;

        assert(s);

        /* Outputs the specified string with fputs(), but optionally prefixes it with a separator. The *space parameter
         * when specified shall initially point to a boolean variable initialized to false. It is set to true after the
         * first invocation. This call is supposed to be use in loops, where a separator shall be inserted between each
         * element, but not before the first one. */

        if (!f)
            f = stdout;

        if (space) {
            if (!separator)
                separator = " ";

            if (*space) {
                r = fputs(separator, f);
                if (r < 0)
                    return r;
            }

            *space = true;
        }

        return fputs(s, f);
    }

#ifdef WIN32
    //  ErrorMessage support function.
    //  Retrieves the system error message for the GetLastError() code.
    //  Note: caller must use LocalFree() on the returned LPCTSTR buffer.
    LPCTSTR ErrorMessage(DWORD error)
    {
        LPVOID lpMsgBuf;

        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
            | FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpMsgBuf,
            0,
            NULL);

        return((LPCTSTR)lpMsgBuf);
    }

    //  PrintError support function.
    //  Simple wrapper function for error output.
    void PrintError(LPCTSTR errDesc)
    {
        LPCTSTR errMsg = ErrorMessage(GetLastError());
        _ftprintf(stderr, TEXT("\n** ERROR ** %s: %s\n"), errDesc, errMsg);
        LocalFree((LPVOID)errMsg);
    }
#endif

    char *win_read_memstream_tempfile(FILE *fp, size_t* sizep) {
        size_t size; /*filesize*/
        char *buffer; /*buffer*/
        size_t bytes;

        if (!fp) {
            return NULL;
        }
        
        size = ftell(fp);         /*calc the size needed*/
        buffer = (char*)malloc(size + 1);  /*allocalte space on heap*/

        fseek(fp, 0, SEEK_SET);
        bytes = fread(buffer, 1, size, fp);
        fseek(fp, size, SEEK_SET);

        *sizep = bytes;
        return buffer;
    }

    FILE* open_memstream_unlocked(char** ptr, size_t* sizeloc)
    {

#ifdef WIN32
        DWORD dwRetVal = 0;
        UINT uRetVal = 0;
        TCHAR lpTempPathBuffer[MAX_PATH];
        TCHAR szTempFileName[MAX_PATH];
        //  Gets the temp path env string (no guarantee it's a valid path).
        dwRetVal = GetTempPath(MAX_PATH,          // length of the buffer
            lpTempPathBuffer); // buffer for path 
        if (dwRetVal > MAX_PATH || (dwRetVal == 0))
        {
            PrintError(TEXT("GetTempPath failed"));
            return NULL;
        }

        //  Generates a temporary file name. 
        uRetVal = GetTempFileName(lpTempPathBuffer, // directory for tmp files
            TEXT("_SD"),     // temp file name prefix 
            0,                // create unique name 
            szTempFileName);  // buffer for name 
        if (uRetVal == 0)
        {
            PrintError(TEXT("GetTempFileName failed"));
            return NULL;
        }

        fprintf(stderr, "create temp file: %s\n", szTempFileName);

        FILE* f = fopen(szTempFileName, "w+");
        if (!f)
            return NULL;
        // save the temp file name to i->introspect
        *ptr = _strdup(szTempFileName);
#else

        FILE* f = open_memstream(ptr, sizeloc);
        if (!f)
            return NULL;

        (void)__fsetlocking(f, FSETLOCKING_BYCALLER);

#endif
        return f;
    }

#ifdef __cplusplus
}
#endif