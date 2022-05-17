#if defined(_WIN32) || defined(_WIN64)

#include <stdint.h>
#include <stdlib.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <sddl.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <WS2tcpip.h>
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

BOOL _GetUserSID(HANDLE token, PSID* sid)
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

uid_t _GetUID(HANDLE token)
{
    PSID sid = nullptr;
    BOOL getSID = _GetUserSID(token, &sid);
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
    uid_t ret = _GetUID(token);
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
    uid_t ret = _GetUID(token);
    return ret;
}

static BOOL
is_winxp_sp3_or_lower(void)
{
    OSVERSIONINFOEX osvi;
    DWORDLONG dwlConditionMask = 0;
    int op = VER_LESS_EQUAL;

    // Initialize the OSVERSIONINFOEX structure.

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    osvi.dwMajorVersion = 5;
    osvi.dwMinorVersion = 1;
    osvi.wServicePackMajor = 3;
    osvi.wServicePackMinor = 0;

    // Initialize the condition mask.

    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, op);
    VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, op);
    VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMAJOR, op);
    VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMINOR, op);

    // Perform the test.

    return VerifyVersionInfo(
        &osvi,
        VER_MAJORVERSION | VER_MINORVERSION |
        VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR,
        dwlConditionMask);
}

void
_dbus_win_warn_win_error(const char* message,
    unsigned long code)
{
    //DBusError error;

    //dbus_error_init(&error);
    //_dbus_win_set_error_from_win_error(&error, code);
    char* msg;

    /* As we want the English message, use the A API */
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_IGNORE_INSERTS |
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, code, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
        (LPSTR)&msg, 0, NULL);
    if (msg)
    {
        //dbus_set_error(error, "win32.error", "%s", msg);
        printf("%s: %s\n", message, msg);
        LocalFree(msg);
    }
    else {
        //dbus_set_error(error, "win32.error", "Unknown error code %d or FormatMessage failed", code);
        printf("%s: Unknown error code %lu or FormatMessage failed\n", message, code);
    }
    //_dbus_warn("%s: %s", message, error.message);
    //dbus_error_free(&error);
}



    /** Gets our SID
     * @param sid points to sid buffer, need to be freed with LocalFree()
     * @param process_id the process id for which the sid should be returned (use 0 for current process)
     * @returns process sid
     */
     /** A process ID */
    typedef unsigned long dbus_pid_t;
    typedef uint32_t dbus_bool_t;
    #define _dbus_verbose printf
#define dbus_malloc malloc
#define dbus_free free

    dbus_bool_t
        _dbus_getsid(char** sid, dbus_pid_t process_id)
    {
        HANDLE process_token = INVALID_HANDLE_VALUE;
        TOKEN_USER* token_user = NULL;
        DWORD n;
        PSID psid;
        int retval = FALSE;

        HANDLE process_handle;
        if (process_id == 0)
            process_handle = GetCurrentProcess();
        else if (is_winxp_sp3_or_lower())
            process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, process_id);
        else
            process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);

        if (!OpenProcessToken(process_handle, TOKEN_QUERY, &process_token))
        {
            _dbus_win_warn_win_error("OpenProcessToken failed", GetLastError());
            goto failed;
        }
        if ((!GetTokenInformation(process_token, TokenUser, NULL, 0, &n)
            && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            || (token_user = (TOKEN_USER*)_malloca(n)) == NULL
            || !GetTokenInformation(process_token, TokenUser, token_user, n, &n))
        {
            _dbus_win_warn_win_error("GetTokenInformation failed", GetLastError());
            goto failed;
        }
        psid = token_user->User.Sid;
        if (!IsValidSid(psid))
        {
            _dbus_verbose("%s invalid sid\n", __FUNCTION__);
            goto failed;
        }
        if (!ConvertSidToStringSidA(psid, sid))
        {
            _dbus_verbose("%s invalid sid\n", __FUNCTION__);
            goto failed;
        }
        //okay:
        retval = TRUE;

    failed:
        CloseHandle(process_handle);
        if (process_token != INVALID_HANDLE_VALUE)
            CloseHandle(process_token);

        _dbus_verbose("_dbus_getsid() got '%s' and returns %d\n", *sid, retval);
        return retval;
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

    /*
     * _MIB_TCPROW_EX and friends are not available in system headers
     *  and are mapped to attribute identical ...OWNER_PID typedefs.
     */
    typedef MIB_TCPROW_OWNER_PID _MIB_TCPROW_EX;
    typedef MIB_TCPTABLE_OWNER_PID MIB_TCPTABLE_EX;
    typedef PMIB_TCPTABLE_OWNER_PID PMIB_TCPTABLE_EX;
    typedef DWORD(WINAPI* ProcAllocateAndGetTcpExtTableFromStack)(PMIB_TCPTABLE_EX*, BOOL, HANDLE, DWORD, DWORD);
    static ProcAllocateAndGetTcpExtTableFromStack lpfnAllocateAndGetTcpExTableFromStack = NULL;


    /**
 * AllocateAndGetTcpExTableFromStack() is undocumented and not exported,
 * but is the only way to do this in older XP versions.
 * @return true if the procedures could be loaded
 */
    static BOOL
    load_ex_ip_helper_procedures(void)
    {
        HMODULE hModule = LoadLibrary("iphlpapi.dll");
        if (hModule == NULL)
        {
            _dbus_verbose("could not load iphlpapi.dll\n");
            return FALSE;
        }

        lpfnAllocateAndGetTcpExTableFromStack = (ProcAllocateAndGetTcpExtTableFromStack)GetProcAddress(hModule, "AllocateAndGetTcpExTableFromStack");
        if (lpfnAllocateAndGetTcpExTableFromStack == NULL)
        {
            _dbus_verbose("could not find function AllocateAndGetTcpExTableFromStack in iphlpapi.dll\n");
            return FALSE;
        }
        return TRUE;
    }

    /**
     * get pid from localhost tcp connection using peer_port
     * This function is available on WinXP >= SP3
     * @param peer_port peers tcp port
     * @return process id or 0 if connection has not been found
     */
    static dbus_pid_t
        get_pid_from_extended_tcp_table(int peer_port)
    {
        dbus_pid_t result;
        DWORD errorCode, size = 0, i;
        MIB_TCPTABLE_OWNER_PID* tcp_table;

        if ((errorCode =
            GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == ERROR_INSUFFICIENT_BUFFER)
        {
            tcp_table = (MIB_TCPTABLE_OWNER_PID*)dbus_malloc(size);
            if (tcp_table == NULL)
            {
                _dbus_verbose("Error allocating memory\n");
                return 0;
            }
        }
        else
        {
            _dbus_win_warn_win_error("unexpected error returned from GetExtendedTcpTable", errorCode);
            return 0;
        }

        if ((errorCode = GetExtendedTcpTable(tcp_table, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) != NO_ERROR)
        {
            _dbus_verbose("Error fetching tcp table %d\n", (int)errorCode);
            dbus_free(tcp_table);
            return 0;
        }

        result = 0;
        for (i = 0; i < tcp_table->dwNumEntries; i++)
        {
            MIB_TCPROW_OWNER_PID* p = &tcp_table->table[i];
            int local_address = ntohl(p->dwLocalAddr);
            int local_port = ntohs(p->dwLocalPort);
            if (p->dwState == MIB_TCP_STATE_ESTAB
                && local_address == INADDR_LOOPBACK && local_port == peer_port)
                result = p->dwOwningPid;
        }

        dbus_free(tcp_table);
        _dbus_verbose("got pid %lu\n", result);
        return result;
    }

    /**
     * get pid from localhost tcp connection using peer_port
     * This function is available on all WinXP versions, but
     * not in wine (at least version <= 1.6.0)
     * @param peer_port peers tcp port
     * @return process id or 0 if connection has not been found
     */
    static dbus_pid_t
        get_pid_from_tcp_ex_table(int peer_port)
    {
        dbus_pid_t result;
        DWORD errorCode, i;
        PMIB_TCPTABLE_EX tcp_table = NULL;

        if (!load_ex_ip_helper_procedures())
        {
            _dbus_verbose
            ("Error not been able to load iphelper procedures\n");
            return 0;
        }

        errorCode = lpfnAllocateAndGetTcpExTableFromStack(&tcp_table, TRUE, GetProcessHeap(), 0, 2);

        if (errorCode != NO_ERROR)
        {
            _dbus_verbose
            ("Error not been able to call AllocateAndGetTcpExTableFromStack()\n");
            return 0;
        }

        result = 0;
        for (i = 0; i < tcp_table->dwNumEntries; i++)
        {
            _MIB_TCPROW_EX* p = &tcp_table->table[i];
            int local_port = ntohs(p->dwLocalPort);
            int local_address = ntohl(p->dwLocalAddr);
            if (local_address == INADDR_LOOPBACK && local_port == peer_port)
            {
                result = p->dwOwningPid;
                break;
            }
        }

        HeapFree(GetProcessHeap(), 0, tcp_table);
        _dbus_verbose("got pid %lu\n", result);
        return result;
    }

    /**
 * @brief return peer process id from tcp handle for localhost connections
 * @param handle tcp socket descriptor
 * @return process id or 0 in case the process id could not be fetched
 */
    dbus_pid_t
        _dbus_get_peer_pid_from_tcp_handle(int handle)
    {
        struct sockaddr_storage addr;
        socklen_t len = sizeof(addr);
        int peer_port;

        dbus_pid_t result;
        dbus_bool_t is_localhost = FALSE;

        getpeername(handle, (struct sockaddr*)&addr, &len);

        if (addr.ss_family == AF_INET)
        {
            struct sockaddr_in* s = (struct sockaddr_in*)&addr;
            peer_port = ntohs(s->sin_port);
            is_localhost = (ntohl(s->sin_addr.s_addr) == INADDR_LOOPBACK);
        }
        else if (addr.ss_family == AF_INET6)
        {
            _dbus_verbose("FIXME [61922]: IPV6 support not working on windows\n");
            return 0;
            /*
               struct sockaddr_in6 *s = (struct sockaddr_in6 * )&addr;
               peer_port = ntohs (s->sin6_port);
               is_localhost = (memcmp(s->sin6_addr.s6_addr, in6addr_loopback.s6_addr, 16) == 0);
               _dbus_verbose ("IPV6 %08x %08x\n", s->sin6_addr.s6_addr, in6addr_loopback.s6_addr);
             */
        }
        else
        {
            _dbus_verbose("no idea what address family %d is\n", addr.ss_family);
            return 0;
        }

        if (!is_localhost)
        {
            _dbus_verbose("could not fetch process id from remote process\n");
            return 0;
        }

        if (peer_port == 0)
        {
            _dbus_verbose
            ("Error not been able to fetch tcp peer port from connection\n");
            return 0;
        }

        _dbus_verbose("trying to get peer's pid\n");

        result = get_pid_from_extended_tcp_table(peer_port);
        if (result > 0)
            return result;
        result = get_pid_from_tcp_ex_table(peer_port);
        return result;
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

#endif