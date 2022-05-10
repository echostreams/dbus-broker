/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if defined(__linux__)
#include <sched.h>
#endif
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#if defined(__linux__)
#include <sys/mount.h>
#endif
#include <sys/wait.h>
#include <util.h>

/* When we include libgen.h because we need dirname() we immediately
 * undefine basename() since libgen.h defines it as a macro to the POSIX
 * version which is really broken. We prefer GNU basename(). */
#include <libgen.h>
#undef basename

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "env-file.h"
#include "env-util.h"
#include "fs-util.h"
#include "log.h"
#include "namespace-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "strv.h"
#include "tests.h"

#ifdef WIN32
#include <io.h>
#define F_OK 0

int setenv(const char* name, const char* value, int overwrite)
{
    int errcode = 0;
    if (!overwrite) {
        size_t envsize = 0;
        errcode = getenv_s(&envsize, NULL, 0, name);
        if (errcode || envsize) return errcode;
    }
    return _putenv_s(name, value);
}

int mlock(const void* addr, size_t len)
{
    SIZE_T min, max;
    BOOL success;
    HANDLE process = GetCurrentProcess();

    success = GetProcessWorkingSetSize(process, &min, &max);
    if (!success) {
        //errno = win_to_posix_error(GetLastError());
        return -1;
    }

    min += len;
    max += len;
    success = SetProcessWorkingSetSize(process, min, max);
    if (!success) {
        //errno = win_to_posix_error(GetLastError());
        return -1;
    }

    success = VirtualLock((LPVOID)addr, len);
    if (!success) {
        //errno = win_to_posix_error(GetLastError());
        return -1;
    }

    return 0;
}

int munlock(const void* addr, size_t len)
{
    BOOL success = VirtualUnlock((LPVOID)addr, len);

    if (!success) {
        //errno = win_to_posix_error(GetLastError());
        return -1;
    }

    return 0;
}

#include <sys/stat.h>
#if defined(_MSC_VER) || defined(__MINGW32__)
# include <io.h>
# include <process.h> // for getpid()
//# include <direct.h> // for mkdir()
# if defined(_MSC_VER)
/* MSVC is missing a few definitions from sys/types and sys/stat */
typedef int pid_t;
#  define S_ISDIR(m)  (((m) & _S_IFMT) == _S_IFDIR)
# endif
#else
# include <unistd.h> // for getpid()
#endif
#include <errno.h>
#include <stdio.h>

static int
do_mkdtemp(char* path)
{
    char* start, * trv;
    struct stat sbuf;
    pid_t pid;

    /* To guarantee multiple calls generate unique names even if
       the file is not created. 676 different possibilities with 7
       or more X's, 26 with 6 or less. */
    static char xtra[2] = { 'a', 'a' };
    int xcnt = 0;

    pid = getpid();

    /* Move to end of path and count trailing X's. */
    for (trv = path; *trv; ++trv)
        if (*trv == 'X')
            xcnt++;
        else
            xcnt = 0;

    /* Use at least one from xtra.  Use 2 if more than 6 X's. */
    if (*(trv - 1) == 'X')
        *--trv = xtra[0];
    if (xcnt > 6 && *(trv - 1) == 'X')
        *--trv = xtra[1];

    /* Set remaining X's to pid digits with 0's to the left. */
    while (*--trv == 'X')
    {
        *trv = (char)((pid % 10) + '0');
        pid /= 10;
    }

    /* update xtra for next call. */
    if (xtra[0] != 'z')
        xtra[0]++;
    else
    {
        xtra[0] = 'a';
        if (xtra[1] != 'z')
            xtra[1]++;
        else
            xtra[1] = 'a';
    }

    /*
     * check the target directory; if you have six X's and it
     * doesn't exist this runs for a *very* long time.
     */
    for (start = trv + 1;; --trv)
    {
        if (trv <= path)
            break;
        if (*trv == '/')
        {
            *trv = '\0';
            if (stat(path, &sbuf))
                return (0);
            if (!S_ISDIR(sbuf.st_mode))
            {
                errno = ENOTDIR;
                return (0);
            }
            *trv = '/';
            break;
        }
    }

    for (;;)
    {
#if !defined(_MSC_VER) && !defined(__MINGW32__)
        if (mkdir(path, 0700) >= 0)
#else
        if (_mkdir(path) >= 0)
#endif
            return (1);
        if (errno != EEXIST)
            return (0);

        /* tricky little algorithm for backward compatibility */
        for (trv = start;;)
        {
            if (!*trv)
                return (0);
            if (*trv == 'z')
                *trv++ = 'a';
            else
            {
                if (*trv >= '0' && *trv <= '9')
                    *trv = 'a';
                else
                    ++* trv;
                break;
            }
        }
    }
    /*NOTREACHED*/
}

char*
mkdtemp(char* path)
{
    return (do_mkdtemp(path) ? path : (char*)NULL);
}

#endif

char* setup_fake_runtime_dir(void) {
        char t[] = "/tmp/fake-xdg-runtime-XXXXXX", *p;

        assert_se(mkdtemp(t));
        assert_se(setenv("XDG_RUNTIME_DIR", t, 1) >= 0);
        assert_se(p = strdup(t));

        return p;
}

static void load_testdata_env(void) {
#if defined (__linux__)
        static bool called = false;
        _cleanup_free_ char *s = NULL;
        _cleanup_free_ char *envpath = NULL;
        _cleanup_strv_free_ char **pairs = NULL;
        char **k, **v;

        if (called)
                return;
        called = true;

        assert_se(readlink_and_make_absolute("/proc/self/exe", &s) >= 0);
        dirname(s);

        envpath = path_join(s, "systemd-runtest.env");
        if (load_env_file_pairs(NULL, envpath, &pairs) < 0)
                return;

        STRV_FOREACH_PAIR(k, v, pairs)
                setenv(*k, *v, 0);
#endif
}

int get_testdata_dir(const char *suffix, char **ret) {
        const char *dir;
        char *p;

        load_testdata_env();

        /* if the env var is set, use that */
        dir = getenv("SYSTEMD_TEST_DATA");
        if (!dir)
                dir = SYSTEMD_TEST_DATA;
        if (access(dir, F_OK) < 0)
                return log_error_errno(errno, "ERROR: $SYSTEMD_TEST_DATA directory [%s] not accessible: %m", dir);

        p = path_join(dir, suffix);
        if (!p)
                return log_oom();

        *ret = p;
        return 0;
}

const char* get_catalog_dir(void) {
        const char *env;

        load_testdata_env();

        /* if the env var is set, use that */
        env = getenv("SYSTEMD_CATALOG_DIR");
        if (!env)
                env = SYSTEMD_CATALOG_DIR;
        if (access(env, F_OK) < 0) {
                fprintf(stderr, "ERROR: $SYSTEMD_CATALOG_DIR directory [%s] does not exist\n", env);
                exit(EXIT_FAILURE);
        }
        return env;
}

bool slow_tests_enabled(void) {
    /*
        int r;
        
        r = getenv_bool("SYSTEMD_SLOW_TESTS");
        if (r >= 0)
                return r;

        if (r != -ENXIO)
                log_warning_errno(r, "Cannot parse $SYSTEMD_SLOW_TESTS, ignoring.");
        return SYSTEMD_SLOW_TESTS_DEFAULT;
    */
    return false;
}

void test_setup_logging(int level) {
        log_set_max_level(level);
        //log_parse_environment();
        //log_open();
}

#ifdef WIN32
/* https://msdn.microsoft.com/en-us/library/dn727674.aspx */ 
#define program_invocation_short_name (__argv && __argv[0] ? __argv[0] : "?")
#endif

int log_tests_skipped(const char *message) {
        log_notice("%s: %s, skipping tests.",
                   program_invocation_short_name, message);
        return EXIT_TEST_SKIP;
}

int log_tests_skipped_errno(int r, const char *message) {
        log_notice_errno(r, "%s: %s, skipping tests: %m",
                         program_invocation_short_name, message);
        return EXIT_TEST_SKIP;
}

bool have_namespaces(void) {

#if defined(__linux__)
        siginfo_t si = {};
        pid_t pid;

        /* Checks whether namespaces are available. In some cases they aren't. We do this by calling unshare(), and we
         * do so in a child process in order not to affect our own process. */

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                /* child */
                if (detach_mount_namespace() < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        assert_se(waitid(P_PID, pid, &si, WEXITED) >= 0);
        assert_se(si.si_code == CLD_EXITED);

        if (si.si_status == EXIT_SUCCESS)
                return true;

        if (si.si_status == EXIT_FAILURE)
                return false;

        assert_not_reached();
#else
    return false;
#endif
}

bool can_memlock(void) {
        /* Let's see if we can mlock() a larger blob of memory. BPF programs are charged against
         * RLIMIT_MEMLOCK, hence let's first make sure we can lock memory at all, and skip the test if we
         * cannot. Why not check RLIMIT_MEMLOCK explicitly? Because in container environments the
         * RLIMIT_MEMLOCK value we see might not match the RLIMIT_MEMLOCK value actually in effect. */

        void *p = mmap(NULL, CAN_MEMLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);
        if (p == MAP_FAILED)
                return false;

        bool b = mlock(p, CAN_MEMLOCK_SIZE) >= 0;
        if (b)
                assert_se(munlock(p, CAN_MEMLOCK_SIZE) >= 0);

        assert_se(munmap(p, CAN_MEMLOCK_SIZE) >= 0);
        return b;
}

static int allocate_scope(void) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *scope = NULL;
        const char *object;
        int r;

        /* Let's try to run this test in a scope of its own, with delegation turned on, so that PID 1 doesn't
         * interfere with our cgroup management. */

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_oom();

        if (asprintf(&scope, "%s-%" PRIx64 ".scope", program_invocation_short_name, random_u64()) < 0)
                return log_oom();

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        /* Name and Mode */
        r = sd_bus_message_append(m, "ss", scope, "fail");
        if (r < 0)
                return bus_log_create_error(r);

        /* Properties */
        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, (uint32_t) getpid_cached());
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "(sv)", "Delegate", "b", 1);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "(sv)", "CollectMode", "s", "inactive-or-failed");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        /* Auxiliary units */
        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start transient scope unit: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, false, NULL);
        if (r < 0)
                return r;

        return 0;
}

#if defined(__linux__)

static int enter_cgroup(char **ret_cgroup, bool enter_subroot) {
        _cleanup_free_ char *cgroup_root = NULL, *cgroup_subroot = NULL;
        CGroupMask supported;
        int r;

        r = allocate_scope();
        if (r < 0)
                log_warning_errno(r, "Couldn't allocate a scope unit for this test, proceeding without.");

        r = cg_pid_get_path(NULL, 0, &cgroup_root);
        if (r == -ENOMEDIUM)
                return log_warning_errno(r, "cg_pid_get_path(NULL, 0, ...) failed: %m");
        assert(r >= 0);

        if (enter_subroot)
                assert_se(asprintf(&cgroup_subroot, "%s/%" PRIx64, cgroup_root, random_u64()) >= 0);
        else {
                cgroup_subroot = strdup(cgroup_root);
                assert_se(cgroup_subroot != NULL);
        }

        assert_se(cg_mask_supported(&supported) >= 0);

        /* If this fails, then we don't mind as the later cgroup operations will fail too, and it's fine if
         * we handle any errors at that point. */

        r = cg_create_everywhere(supported, _CGROUP_MASK_ALL, cgroup_subroot);
        if (r < 0)
                return r;

        r = cg_attach_everywhere(supported, cgroup_subroot, 0, NULL, NULL);
        if (r < 0)
                return r;

        if (ret_cgroup) {
            //*ret_cgroup = TAKE_PTR(cgroup_subroot);
            *ret_cgroup = cgroup_subroot;
            cgroup_subroot = NULL;
        }
        return 0;
}

int enter_cgroup_subroot(char **ret_cgroup) {
        return enter_cgroup(ret_cgroup, true);
}

int enter_cgroup_root(char **ret_cgroup) {
        return enter_cgroup(ret_cgroup, false);
}

const char *ci_environment(void) {
        /* We return a string because we might want to provide multiple bits of information later on: not
         * just the general CI environment type, but also whether we're sanitizing or not, etc. The caller is
         * expected to use strstr on the returned value. */
        static const char *ans = POINTER_MAX;
        const char *p;
        int r;

        if (ans != POINTER_MAX)
                return ans;

        /* We allow specifying the environment with $CITYPE. Nobody uses this so far, but we are ready. */
        p = getenv("CITYPE");
        if (!isempty(p))
                return (ans = p);

        if (getenv_bool("TRAVIS") > 0)
                return (ans = "travis");
        if (getenv_bool("SEMAPHORE") > 0)
                return (ans = "semaphore");
        if (getenv_bool("GITHUB_ACTIONS") > 0)
                return (ans = "github-actions");
        if (getenv("AUTOPKGTEST_ARTIFACTS") || getenv("AUTOPKGTEST_TMP"))
                return (ans = "autopkgtest");

        FOREACH_STRING(p, "CI", "CONTINOUS_INTEGRATION") 
        {
                /* Those vars are booleans according to Semaphore and Travis docs:
                 * https://docs.travis-ci.com/user/environment-variables/#default-environment-variables
                 * https://docs.semaphoreci.com/ci-cd-environment/environment-variables/#ci
                 */
                r = getenv_bool(p);
                if (r > 0)
                        return (ans = "unknown"); /* Some other unknown thing */
                if (r == 0)
                        return (ans = NULL);
        }

        return (ans = NULL);
}

#endif