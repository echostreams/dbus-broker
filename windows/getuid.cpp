#include <stdint.h>
#include <stdlib.h>

#if defined(_WIN32) || defined(_WIN64)

#include <Windows.h>
#include <sddl.h>

#include <iostream>
#include <iomanip>
#include <memory>

struct heap_delete
{
    typedef LPVOID pointer;
    void operator()(LPVOID p)
    {
        ::HeapFree(::GetProcessHeap(), 0, p);
    }
};
typedef std::unique_ptr<LPVOID, heap_delete> heap_unique_ptr;

struct handle_delete
{
    typedef HANDLE pointer;
    void operator()(HANDLE p)
    {
        ::CloseHandle(p);
    }
};
typedef std::unique_ptr<HANDLE, handle_delete> handle_unique_ptr;

typedef uint32_t uid_t;

BOOL GetUserSID(HANDLE token, PSID* sid)
{
    if (
        token == nullptr || token == INVALID_HANDLE_VALUE
        || sid == nullptr
        )
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    DWORD tokenInformationLength = 0;
    ::GetTokenInformation(
        token, TokenUser, nullptr, 0, &tokenInformationLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        return FALSE;
    }
    heap_unique_ptr data(
        ::HeapAlloc(
            ::GetProcessHeap(), HEAP_ZERO_MEMORY,
            tokenInformationLength));
    if (data.get() == nullptr)
    {
        return FALSE;
    }
    BOOL getTokenInfo = ::GetTokenInformation(
        token, TokenUser, data.get(),
        tokenInformationLength, &tokenInformationLength);
    if (!getTokenInfo)
    {
        return FALSE;
    }
    PTOKEN_USER pTokenUser = (PTOKEN_USER)(data.get());
    DWORD sidLength = ::GetLengthSid(pTokenUser->User.Sid);
    heap_unique_ptr sidPtr(
        ::HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sidLength));
    PSID sidL = (PSID)(sidPtr.get());
    if (sidL == nullptr)
    {
        return FALSE;
    }
    BOOL copySid = ::CopySid(sidLength, sidL, pTokenUser->User.Sid);
    if (!copySid)
    {
        return FALSE;
    }
    if (!IsValidSid(sidL))
    {
        return FALSE;
    }
    *sid = sidL;
    sidPtr.release();
    return TRUE;
}

uid_t GetUID(HANDLE token)
{
    PSID sid = nullptr;
    BOOL getSID = GetUserSID(token, &sid);
    if (!getSID || !sid)
    {
        return -1;
    }
    heap_unique_ptr sidPtr((LPVOID)(sid));
    LPWSTR stringSid = nullptr;
    BOOL convertSid = ::ConvertSidToStringSidW(
        sid, &stringSid);
    if (!convertSid)
    {
        return -1;
    }
    uid_t ret = -1;
    LPCWSTR p = ::wcsrchr(stringSid, L'-');
    if (p && ::iswdigit(p[1]))
    {
        ++p;
        ret = ::_wtoi(p);
    }

    ::wprintf(L"SID: %s\n", stringSid);

    ::LocalFree(stringSid);
    return ret;
}

#ifdef __cplusplus
extern "C" {
#endif

    uid_t getuid()
    {
        HANDLE process = ::GetCurrentProcess();
        handle_unique_ptr processPtr(process);
        HANDLE token = nullptr;
        BOOL openToken = ::OpenProcessToken(
            process, TOKEN_READ | TOKEN_QUERY_SOURCE, &token);
        if (!openToken)
        {
            return -1;
        }
        handle_unique_ptr tokenPtr(token);
        uid_t ret = GetUID(token);
        return ret;
    }

    uid_t geteuid()
    {
        HANDLE process = ::GetCurrentProcess();
        HANDLE thread = ::GetCurrentThread();
        HANDLE token = nullptr;
        BOOL openToken = ::OpenThreadToken(
            thread, TOKEN_READ | TOKEN_QUERY_SOURCE, FALSE, &token);
        if (!openToken && ::GetLastError() == ERROR_NO_TOKEN)
        {
            openToken = ::OpenThreadToken(
                thread, TOKEN_READ | TOKEN_QUERY_SOURCE, TRUE, &token);
            if (!openToken && ::GetLastError() == ERROR_NO_TOKEN)
            {
                openToken = ::OpenProcessToken(
                    process, TOKEN_READ | TOKEN_QUERY_SOURCE, &token);
            }
        }
        if (!openToken)
        {
            return -1;
        }
        handle_unique_ptr tokenPtr(token);
        uid_t ret = GetUID(token);
        return ret;
    }

    char*
    secure_getenv(char const* name)
    {
#if HAVE___SECURE_GETENV /* glibc */
        return __secure_getenv(name);
#elif HAVE_ISSETUGID /* OS X, FreeBSD, NetBSD, OpenBSD */
        if (issetugid())
            return NULL;
        return getenv(name);
#elif HAVE_GETUID && HAVE_GETEUID && HAVE_GETGID && HAVE_GETEGID /* other Unix */
        if (geteuid() != getuid() || getegid() != getgid())
            return NULL;
        return getenv(name);
#elif defined _WIN32 && ! defined __CYGWIN__ /* native Windows */
        /* On native Windows, there is no such concept as setuid or setgid binaries.
           - Programs launched as system services have high privileges, but they don't
             inherit environment variables from a user.
           - Programs launched by a user with "Run as Administrator" have high
             privileges and use the environment variables, but the user has been asked
             whether he agrees.
           - Programs launched by a user without "Run as Administrator" cannot gain
             high privileges, therefore there is no risk. */
        return getenv(name);
#else
        return NULL;
#endif
    }

#ifdef __cplusplus
}
#endif

#ifdef GETUID_TEST
int main()
{
    uid_t uid = getuid();
    uid_t euid = geteuid();
    std::cout
        << "uid: " << std::setbase(10) << uid << std::endl
        << "euid: " << std::setbase(10) << euid << std::endl
        << std::endl;
    
    return EXIT_SUCCESS;
}
#endif



#endif // WIN32 || WIN64
