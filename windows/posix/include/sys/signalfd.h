/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 *  include/linux/signalfd.h
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#ifndef _UAPI_LINUX_SIGNALFD_H
#define _UAPI_LINUX_SIGNALFD_H


#include <asm/types.h>

//#include <linux/types.h>
 /* For O_CLOEXEC and O_NONBLOCK */
//#include <linux/fcntl.h>

/* Flags for signalfd4.  */
#define SFD_CLOEXEC O_CLOEXEC
#define SFD_NONBLOCK O_NONBLOCK

struct signalfd_siginfo {
	__u32 ssi_signo;
	__s32 ssi_errno;
	__s32 ssi_code;
	__u32 ssi_pid;
	__u32 ssi_uid;
	__s32 ssi_fd;
	__u32 ssi_tid;
	__u32 ssi_band;
	__u32 ssi_overrun;
	__u32 ssi_trapno;
	__s32 ssi_status;
	__s32 ssi_int;
	__u64 ssi_ptr;
	__u64 ssi_utime;
	__u64 ssi_stime;
	__u64 ssi_addr;
	__u16 ssi_addr_lsb;
	__u16 __pad2;
	__s32 ssi_syscall;
	__u64 ssi_call_addr;
	__u32 ssi_arch;

	/*
	 * Pad strcture to 128 bytes. Remember to update the
	 * pad size when you add new members. We use a fixed
	 * size structure to avoid compatibility problems with
	 * future versions, and we leave extra space for additional
	 * members. We use fixed size members because this strcture
	 * comes out of a read(2) and we really don't want to have
	 * a compat on read(2).
	 */
	__u8 __pad[28];
};

/* Digital Unix defines 64 signals.  Most things should be clean enough
   to redefine this at will, if care is taken to make libc match.  */

#define _NSIG		64
#define _NSIG_BPW	64
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)
#define __user
typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;

typedef union sigval {
	int sival_int;
	void __user* sival_ptr;
} sigval_t;

#define SI_MAX_SIZE	128

/*
 * The default "si_band" type is "long", as specified by POSIX.
 * However, some architectures want to override this to "int"
 * for historical compatibility reasons, so we allow that.
 */
#ifndef __ARCH_SI_BAND_T
#define __ARCH_SI_BAND_T long
#endif

#ifndef __ARCH_SI_CLOCK_T
#define __ARCH_SI_CLOCK_T __kernel_clock_t
#endif

#ifndef __ARCH_SI_ATTRIBUTES
#define __ARCH_SI_ATTRIBUTES
#endif

#ifndef __kernel_long_t
typedef long		__kernel_long_t;
typedef unsigned long	__kernel_ulong_t;
#endif

#ifndef __kernel_pid_t
typedef int		__kernel_pid_t;
#endif

#ifndef __kernel_uid_t
typedef unsigned int	__kernel_uid_t;
typedef unsigned int	__kernel_gid_t;
#endif

#ifndef __kernel_uid32_t
typedef unsigned int	__kernel_uid32_t;
typedef unsigned int	__kernel_gid32_t;
#endif

typedef long long __kernel_time64_t;
typedef __kernel_long_t	__kernel_clock_t;
typedef int		__kernel_timer_t;
typedef int		__kernel_clockid_t;
typedef char* __kernel_caddr_t;
typedef unsigned short	__kernel_uid16_t;
typedef unsigned short	__kernel_gid16_t;

 /*
  * Be careful when extending this union.  On 32bit siginfo_t is 32bit
  * aligned.  Which means that a 64bit field or any other field that
  * would increase the alignment of siginfo_t will break the ABI.
  */
union __sifields {
	/* kill() */
	struct {
		__kernel_pid_t _pid;	/* sender's pid */
		__kernel_uid32_t _uid;	/* sender's uid */
	} _kill;

	/* POSIX.1b timers */
	struct {
		__kernel_timer_t _tid;	/* timer id */
		int _overrun;		/* overrun count */
		sigval_t _sigval;	/* same as below */
		int _sys_private;       /* not to be passed to user */
	} _timer;

	/* POSIX.1b signals */
	struct {
		__kernel_pid_t _pid;	/* sender's pid */
		__kernel_uid32_t _uid;	/* sender's uid */
		sigval_t _sigval;
	} _rt;

	/* SIGCHLD */
	struct {
		__kernel_pid_t _pid;	/* which child */
		__kernel_uid32_t _uid;	/* sender's uid */
		int _status;		/* exit code */
		__ARCH_SI_CLOCK_T _utime;
		__ARCH_SI_CLOCK_T _stime;
	} _sigchld;

	/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
	struct {
		void __user* _addr; /* faulting insn/memory ref. */
#ifdef __ia64__
		int _imm;		/* immediate value for "break" */
		unsigned int _flags;	/* see ia64 si_flags */
		unsigned long _isr;	/* isr */
#endif

#ifdef WIN32
#define __ADDR_BND_PKEY_PAD  (__alignof(void *) < sizeof(short) ? \
			      sizeof(short) : __alignof(void *))
#else
#define __ADDR_BND_PKEY_PAD  (__alignof__(void *) < sizeof(short) ? \
			      sizeof(short) : __alignof__(void *))
#endif
		union {
			/* used on alpha and sparc */
			int _trapno;	/* TRAP # which caused the signal */
			/*
			 * used when si_code=BUS_MCEERR_AR or
			 * used when si_code=BUS_MCEERR_AO
			 */
			short _addr_lsb; /* LSB of the reported address */
			/* used when si_code=SEGV_BNDERR */
			struct {
				char _dummy_bnd[__ADDR_BND_PKEY_PAD];
				void __user* _lower;
				void __user* _upper;
			} _addr_bnd;
			/* used when si_code=SEGV_PKUERR */
			struct {
				char _dummy_pkey[__ADDR_BND_PKEY_PAD];
				__u32 _pkey;
			} _addr_pkey;
			/* used when si_code=TRAP_PERF */
			struct {
				unsigned long _data;
				__u32 _type;
			} _perf;
		};
	} _sigfault;

	/* SIGPOLL */
	struct {
		__ARCH_SI_BAND_T _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
		int _fd;
	} _sigpoll;

	/* SIGSYS */
	struct {
		void __user* _call_addr; /* calling user insn */
		int _syscall;	/* triggering system call number */
		unsigned int _arch;	/* AUDIT_ARCH_* of syscall */
	} _sigsys;
};

#ifndef __ARCH_HAS_SWAPPED_SIGINFO
#define __SIGINFO 			\
struct {				\
	int si_signo;			\
	int si_errno;			\
	int si_code;			\
	union __sifields _sifields;	\
}
#else
#define __SIGINFO 			\
struct {				\
	int si_signo;			\
	int si_code;			\
	int si_errno;			\
	union __sifields _sifields;	\
}
#endif /* __ARCH_HAS_SWAPPED_SIGINFO */

/*
typedef struct siginfo {
	union {
		__SIGINFO;
		int _si_pad[SI_MAX_SIZE / sizeof(int)];
	};
} __ARCH_SI_ATTRIBUTES siginfo_t;
*/

typedef struct {
	int si_signo;
	int si_code;
	union sigval si_value;
	int si_errno;
	/*pid_t*/int si_pid;
	/*uid_t*/unsigned int si_uid;
	void* si_addr;
	int si_status;
	int si_band;
} siginfo_t;

#ifndef __KERNEL__
#define __SI_KILL	0
#define __SI_TIMER	0
#define __SI_POLL	0
#define __SI_FAULT	0
#define __SI_CHLD	0
#define __SI_RT		0
#define __SI_MESGQ	0
#define __SI_SYS	0
#define __SI_CODE(T,N)	(N)
#endif

/*
 * SIGCHLD si_codes
 */
#define CLD_EXITED	(__SI_CHLD|1)	/* child has exited */
#define CLD_KILLED	(__SI_CHLD|2)	/* child was killed */
#define CLD_DUMPED	(__SI_CHLD|3)	/* child terminated abnormally */
#define CLD_TRAPPED	(__SI_CHLD|4)	/* traced child has trapped */
#define CLD_STOPPED	(__SI_CHLD|5)	/* child has stopped */
#define CLD_CONTINUED	(__SI_CHLD|6)	/* stopped child has continued */
#define NSIGCHLD	6



#endif /* _UAPI_LINUX_SIGNALFD_H */