/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>
#include <tchar.h>

extern void dump_wsaprotocol_info(char ascii_or_wide, const void* proto_info, const void* provider_path_func);

typedef NTSTATUS(WINAPI* NTQUERYOBJECT)(HANDLE ObjectHandle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG Length,
	PULONG ResultLength);

static NTQUERYOBJECT              fp_NtQueryObject = NULL;

#define ObjectNameInformation 1

#endif

#include <errno.h>
#include <fcntl.h>
#if defined(__linux__)
#include <linux/btrfs.h>
#include <linux/magic.h>
#endif
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
//#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "macro.h"
#include "missing_fcntl.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "tmpfile-util.h"
#include "util.h"


int fd_nonblock(int fd, bool nonblock) {

#ifdef WIN32

	//-------------------------
	// Set the socket I/O mode: In this case FIONBIO
	// enables or disables the blocking mode for the 
	// socket based on the numerical value of iMode.
	// If iMode = 0, blocking is enabled; 
	// If iMode != 0, non-blocking mode is enabled.
	u_long iMode = 1;
	int iResult = ioctlsocket(fd, FIONBIO, &iMode);
	if (iResult != NO_ERROR) {
		fprintf(stderr, "ioctlsocket failed with error: %d\n", iResult);
		return RET_NERRNO(iResult);
	}

	fprintf(stderr, "Setting fd %d to non-blocking...\n", fd);

	return 0;

#else
	int flags, nflags;

	assert(fd >= 0);

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -errno;

	nflags = UPDATE_FLAG(flags, O_NONBLOCK, nonblock);
	if (nflags == flags)
		return 0;

	return RET_NERRNO(fcntl(fd, F_SETFL, nflags));

#endif

}

int fd_cloexec(int fd, bool cloexec) {
#ifdef WIN32
	if (
		!SetHandleInformation((HANDLE)fd,
			HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE,
			cloexec ? 0 /*disable both flags*/
			: HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE)
		)
	{
		//_dbus_win_warn_win_error("Disabling socket handle inheritance failed:", GetLastError());
		DWORD lastErr = GetLastError();
		return -lastErr;
	}
	else
		return 0;

#else
	int flags, nflags;

	assert(fd >= 0);

	flags = fcntl(fd, F_GETFD, 0);
	if (flags < 0)
		return -errno;

	nflags = UPDATE_FLAG(flags, FD_CLOEXEC, cloexec);
	if (nflags == flags)
		return 0;

	return RET_NERRNO(fcntl(fd, F_SETFD, nflags));
#endif
}

int fd_get_path(int fd, char** ret) {

#if defined(__linux__)
	int r;

	r = readlink_malloc(FORMAT_PROC_FD_PATH(fd), ret);
	if (r == -ENOENT) {
		/* ENOENT can mean two things: that the fd does not exist or that /proc is not mounted. Let's make
		 * things debuggable and distinguish the two. */
#if ENABLE_STATFS
		if (proc_mounted() == 0)
			return -ENOSYS;  /* /proc is not available or not set up properly, we're most likely in some chroot
			    			  * environment. */
#endif
		return -EBADF; /* The directory exists, hence it's the fd that doesn't. */
	}

	return r;
#else

#ifdef WIN32
	if (fd != SOCKET_ERROR) 
	{
		DWORD u32_ReqLength = 0;
		PVOID                    objectNameInfo;
		UNICODE_STRING           objectName = {};

		UNICODE_STRING* pk_Info = &objectName;
		pk_Info->Buffer = 0;
		pk_Info->Length = 0;

		if (!fp_NtQueryObject) {
			fp_NtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQueryObject");
		}

		objectNameInfo = malloc(0x1000);

		// Get required length
		fp_NtQueryObject(fd, ObjectNameInformation, objectNameInfo, 0x1000, &u32_ReqLength);

		// Reallocate the buffer and try again.
		objectNameInfo = realloc(objectNameInfo, u32_ReqLength);

		// IMPORTANT: The return value from NtQueryObject is bullshit! (driver bug?)
		// - The function may return STATUS_NOT_SUPPORTED although it has successfully written to the buffer.
		// - The function returns STATUS_SUCCESS although h_File == 0xFFFFFFFF
		fp_NtQueryObject(fd, ObjectNameInformation, objectNameInfo, u32_ReqLength, NULL);

		// Cast our buffer into an UNICODE_STRING.
		objectName = *(PUNICODE_STRING)objectNameInfo;
		// On error pk_Info->Buffer is NULL
		if (!pk_Info->Buffer || !pk_Info->Length)
			return ERROR_FILE_NOT_FOUND;

		//pk_Info->Buffer[pk_Info->Length / 2] = 0; // Length in Bytes!

		// ansiSizeInBytes is number of bytes needed to represent unicode string as ANSI
		int ansiSizeInBytes = WideCharToMultiByte(CP_ACP, 0, pk_Info->Buffer, -1, NULL, 0, NULL, NULL);
		char* asniName = (char*)malloc(ansiSizeInBytes);
		WideCharToMultiByte(CP_ACP, 0, pk_Info->Buffer, pk_Info->Length, asniName, ansiSizeInBytes, NULL, NULL);
		free(objectNameInfo);
		*ret = asniName;
		if (strcmp(asniName, "\\Device\\Afd") == 0) {
			INT r;
			SOCKADDR_IN sockAddr = {};
			INT nameLen = sizeof(SOCKADDR_IN);
			r = getpeername((SOCKET)fd, (PSOCKADDR)&sockAddr, &nameLen);
			if (r != 0) {
				fwprintf(stderr, L"Failed to retrieve address of peer: %d\n", r);
			}
			else {
				fwprintf(stderr, L"Address: %u.%u.%u.%u Port: %hu\n",
					sockAddr.sin_addr.S_un.S_un_b.s_b1,
					sockAddr.sin_addr.S_un.S_un_b.s_b2,
					sockAddr.sin_addr.S_un.S_un_b.s_b3,
					sockAddr.sin_addr.S_un.S_un_b.s_b4,
					ntohs(sockAddr.sin_port));
			}

#if DUMP_WSAPROTOCOL_INFO
			WSAPROTOCOL_INFO protinfo;
			socklen_t optlen = sizeof(protinfo);
			r = getsockopt(fd, SOL_SOCKET, SO_PROTOCOL_INFO, (char*)(&protinfo), &optlen);

			dump_wsaprotocol_info('A', (const void*)&protinfo, NULL);
#endif

		}
	}
#endif

	return 0;
#endif
}


void safe_close_pair(int p[/*static*/ 2]) {
	assert(p);

	if (p[0] == p[1]) {
		/* Special case pairs which use the same fd in both
		 * directions... */
		p[0] = p[1] = safe_close(p[0]);
		return;
	}

	p[0] = safe_close(p[0]);
	p[1] = safe_close(p[1]);
}

bool stat_inode_same(const struct stat* a, const struct stat* b) {

	/* Returns if the specified stat structure references the same (though possibly modified) inode. Does
	 * a thorough check, comparing inode nr, backing device and if the inode is still of the same type. */

	return a && b &&
		(a->st_mode & S_IFMT) != 0 && /* We use the check for .st_mode if the structure was ever initialized */
		((a->st_mode ^ b->st_mode) & S_IFMT) == 0 &&  /* same inode type */
		a->st_dev == b->st_dev &&
		a->st_ino == b->st_ino;
}
