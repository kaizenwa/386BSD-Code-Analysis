# Walkthrough of 386BSD's System Call Interface

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
syscall
	syscall
		copyin
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

The first '+' means that I have read the code or have a general idea of what it does.
The second '+' means that I have read the code closely and heavily commented it.
The third '+' means that I have added it to this document's code walkthrough.


```txt
File: locore.s
	syscall			+++
	copyin			++-

File: trap.c
	syscall			+++
```

## Important Data Structures

### *syscframe* Structure

```c
/*
 * Call Gate/System Call Stack Frame
 */

struct syscframe {
	int	sf_edi;
	int	sf_esi;
	int	sf_ebp;
	int	:32;		/* redundant save of isp */
	int	sf_ebx;
	int	sf_edx;
	int	sf_ecx;
	int	sf_eax;
	int	sf_eflags;
	/* below portion defined in 386 hardware */
/*	int	sf_args[N]; 	/* if call gate copy args enabled!*/
	int	sf_eip;
	int	sf_cs;
	/* below only when transitting rings (e.g. user to kernel) */
	int	sf_esp;
	int	sf_ss;
};
```

### *sysent* Structure and *sysent* Table

```c
/* From /sys/sys/systm.h */

extern struct sysent {	/* system call table */
	int	sy_narg;		/* number of arguments */
	int	(*sy_call)();	/* implementing function */
} sysent[];

/* From /sys/kern/init_sysent.c */

struct sysent sysent[] = {
	0, nosys,			/* 0 = indir or out-of-range */
	1, rexit,			/* 1 = exit */
	0, fork,			/* 2 = fork */
	3, read,			/* 3 = read */
	3, write,			/* 4 = write */
	3, open,			/* 5 = open */
	1, close,			/* 6 = close */
	4, wait4,			/* 7 = wait4 */
	compat(2,creat),		/* 8 = old creat */
	2, link,			/* 9 = link */
	1, unlink,			/* 10 = unlink */
	0, nosys,			/* 11 = obsolete execv */
	1, chdir,			/* 12 = chdir */
	1, fchdir,			/* 13 = fchdir */
	3, mknod,			/* 14 = mknod */
	2, chmod,			/* 15 = chmod */
	3, chown,			/* 16 = chown */
	1, obreak,			/* 17 = break */
	3, getfsstat,			/* 18 = getfsstat */
	3, lseek,			/* 19 = lseek */
	0, getpid,			/* 20 = getpid */
	4, mount,			/* 21 = mount */
	2, unmount,			/* 22 = unmount */
	1, setuid,			/* 23 = setuid */
	0, getuid,			/* 24 = getuid */
	0, geteuid,			/* 25 = geteuid */
	4, ptrace,			/* 26 = ptrace */
	3, recvmsg,			/* 27 = recvmsg */
	3, sendmsg,			/* 28 = sendmsg */
	6, recvfrom,			/* 29 = recvfrom */
	3, accept,			/* 30 = accept */
	3, getpeername,			/* 31 = getpeername */
	3, getsockname,			/* 32 = getsockname */
	2, saccess,			/* 33 = access */
	2, chflags,			/* 34 = chflags */
	2, fchflags,			/* 35 = fchflags */
	0, sync,			/* 36 = sync */
	2, kill,			/* 37 = kill */
	2, stat,			/* 38 = stat */
	0, getppid,			/* 39 = getppid */
	2, lstat,			/* 40 = lstat */
	2, dup,			/* 41 = dup */
	0, pipe,			/* 42 = pipe */
	0, getegid,			/* 43 = getegid */
	4, profil,			/* 44 = profil */
#ifdef KTRACE
	4, ktrace,			/* 45 = ktrace */
#else
	0, nosys,			/* 45 = ktrace */
#endif
	3, sigaction,			/* 46 = sigaction */
	0, getgid,			/* 47 = getgid */
	2, sigprocmask,			/* 48 = sigprocmask */
	2, getlogin,			/* 49 = getlogin */
	1, setlogin,			/* 50 = setlogin */
	1, sysacct,			/* 51 = acct */
	0, sigpending,			/* 52 = sigpending */
#ifdef notyet
	3, sigaltstack,			/* 53 = sigaltstack */
#else
	0, nosys,			/* 53 = sigaltstack */
#endif
	3, ioctl,			/* 54 = ioctl */
	1, reboot,			/* 55 = reboot */
	1, revoke,			/* 56 = revoke */
	2, symlink,			/* 57 = symlink */
	3, readlink,			/* 58 = readlink */
	3, execve,			/* 59 = execve */
	1, umask,			/* 60 = umask */
	1, chroot,			/* 61 = chroot */
	2, fstat,			/* 62 = fstat */
	4, getkerninfo,			/* 63 = getkerninfo */
	0, getpagesize,			/* 64 = getpagesize */
	2, msync,			/* 65 = msync */
	0, vfork,			/* 66 = vfork */
	0, nosys,			/* 67 = obsolete vread */
	0, nosys,			/* 68 = obsolete vwrite */
	1, sbrk,			/* 69 = sbrk */
	1, sstk,			/* 70 = sstk */
	6, smmap,			/* 71 = mmap */
	1, ovadvise,			/* 72 = vadvise */
	2, munmap,			/* 73 = munmap */
	3, mprotect,			/* 74 = mprotect */
	3, madvise,			/* 75 = madvise */
	0, nosys,			/* 76 = obsolete vhangup */
	0, nosys,			/* 77 = obsolete vlimit */
	3, mincore,			/* 78 = mincore */
	2, getgroups,			/* 79 = getgroups */
	2, setgroups,			/* 80 = setgroups */
	1, getpgrp,			/* 81 = getpgrp */
	2, setpgid,			/* 82 = setpgid */
	3, setitimer,			/* 83 = setitimer */
	compat(0,wait),		/* 84 = old wait */
	1, swapon,			/* 85 = swapon */
	2, getitimer,			/* 86 = getitimer */
	2, gethostname,			/* 87 = gethostname */
	2, sethostname,			/* 88 = sethostname */
	0, getdtablesize,			/* 89 = getdtablesize */
	2, dup2,			/* 90 = dup2 */
	0, nosys,			/* 91 = getdopt */
	3, fcntl,			/* 92 = fcntl */
	5, select,			/* 93 = select */
	0, nosys,			/* 94 = setdopt */
	1, fsync,			/* 95 = fsync */
	3, setpriority,			/* 96 = setpriority */
	3, socket,			/* 97 = socket */
	3, connect,			/* 98 = connect */
	compat(3,accept),		/* 99 = old accept */
	2, getpriority,			/* 100 = getpriority */
	compat(4,send),		/* 101 = old send */
	compat(4,recv),		/* 102 = old recv */
	1, sigreturn,			/* 103 = sigreturn */
	3, bind,			/* 104 = bind */
	5, setsockopt,			/* 105 = setsockopt */
	2, listen,			/* 106 = listen */
	0, nosys,			/* 107 = obsolete vtimes */
	compat(3,sigvec),		/* 108 = old sigvec */
	compat(1,sigblock),		/* 109 = old sigblock */
	compat(1,sigsetmask),		/* 110 = old sigsetmask */
	1, sigsuspend,			/* 111 = sigsuspend */
	2, sigstack,			/* 112 = sigstack */
	compat(3,recvmsg),		/* 113 = old recvmsg */
	compat(3,sendmsg),		/* 114 = old sendmsg */
#ifdef TRACE
	2, vtrace,			/* 115 = vtrace */
#else
	0, nosys,			/* 115 = obsolete vtrace */
#endif
	2, gettimeofday,			/* 116 = gettimeofday */
	2, getrusage,			/* 117 = getrusage */
	5, getsockopt,			/* 118 = getsockopt */
#ifdef vax
	1, resuba,			/* 119 = resuba */
#else
	0, nosys,			/* 119 = nosys */
#endif
	3, readv,			/* 120 = readv */
	3, writev,			/* 121 = writev */
	2, settimeofday,			/* 122 = settimeofday */
	3, fchown,			/* 123 = fchown */
	2, fchmod,			/* 124 = fchmod */
	compat(6,recvfrom),		/* 125 = old recvfrom */
	compat(2,setreuid),		/* 126 = old setreuid */
	compat(2,setregid),		/* 127 = old setregid */
	2, rename,			/* 128 = rename */
	2, truncate,			/* 129 = truncate */
	2, ftruncate,			/* 130 = ftruncate */
	2, flock,			/* 131 = flock */
	2, mkfifo,			/* 132 = mkfifo */
	6, sendto,			/* 133 = sendto */
	2, shutdown,			/* 134 = shutdown */
	5, socketpair,			/* 135 = socketpair */
	2, mkdir,			/* 136 = mkdir */
	1, rmdir,			/* 137 = rmdir */
	2, utimes,			/* 138 = utimes */
	0, nosys,			/* 139 = obsolete 4.2 sigreturn */
	2, adjtime,			/* 140 = adjtime */
	compat(3,getpeername),		/* 141 = old getpeername */
	0, gethostid,			/* 142 = gethostid */
	1, sethostid,			/* 143 = sethostid */
	2, getrlimit,			/* 144 = getrlimit */
	2, setrlimit,			/* 145 = setrlimit */
	compat(2,killpg),		/* 146 = old killpg */
	0, setsid,			/* 147 = setsid */
	4, quotactl,			/* 148 = quotactl */
	compat(4,quota),		/* 149 = old quota */
	compat(3,getsockname),		/* 150 = old getsockname */
	0, nosys,			/* 151 = nosys */
	0, nosys,			/* 152 = nosys */
	0, nosys,			/* 153 = nosys */
	0, nosys,			/* 154 = nosys */
#ifdef NFS
	5, nfssvc,			/* 155 = nfssvc */
#else
	0, nosys,			/* 155 = nosys */
#endif
	4, getdirentries,			/* 156 = getdirentries */
	2, statfs,			/* 157 = statfs */
	2, fstatfs,			/* 158 = fstatfs */
	0, nosys,			/* 159 = nosys */
#ifdef NFS
	0, async_daemon,			/* 160 = async_daemon */
	2, getfh,			/* 161 = getfh */
#else
	0, nosys,			/* 160 = nosys */
	0, nosys,			/* 161 = nosys */
#endif
	0, nosys,			/* 162 = nosys */
	0, nosys,			/* 163 = nosys */
	0, nosys,			/* 164 = nosys */
	0, nosys,			/* 165 = nosys */
	0, nosys,			/* 166 = nosys */
	0, nosys,			/* 167 = nosys */
	0, nosys,			/* 168 = nosys */
	0, nosys,			/* 169 = nosys */
	0, nosys,			/* 170 = nosys */
#ifdef SYSVSHM
	4, shmsys,			/* 171 = shmsys */
#else
	0, nosys,			/* 171 = nosys */
#endif
	0, nosys,			/* 172 = nosys */
	0, nosys,			/* 173 = nosys */
	0, nosys,			/* 174 = nosys */
	0, nosys,			/* 175 = nosys */
	0, nosys,			/* 176 = nosys */
	0, nosys,			/* 177 = nosys */
	0, nosys,			/* 178 = nosys */
	0, nosys,			/* 179 = nosys */
	0, nosys,			/* 180 = nosys */
	1, setgid,			/* 181 = setgid */
	1, setegid,			/* 182 = setegid */
	1, seteuid,			/* 183 = seteuid */
	0, nosys,			/* 184 = nosys */
	0, nosys,			/* 185 = nosys */
	0, nosys,			/* 186 = nosys */
	0, nosys,			/* 187 = nosys */
	0, nosys,			/* 188 = nosys */
	0, nosys,			/* 189 = nosys */
	0, nosys,			/* 190 = nosys */
};
```

## Code Walkthrough

```c
#define	IDTVEC(name)	.align 4; .globl _X/**/name; _X/**/name:

/*
 * Call gate entry for syscall
 */

IDTVEC(syscall)
	pushfl	# only for stupid carry bit and more stupid wait3 cc kludge
	pushal	# only need eax,ecx,edx - trap resaves others
	nop
	movw	$0x10,%ax	# switch to kernel segments
	movw	%ax,%ds
	movw	%ax,%es
	call	_syscall
	call	_spl0
	movw	__udatasel,%ax	# switch back to user segments
	movw	%ax,%ds
	movw	%ax,%es
	popal
	nop
	popfl
	lret

/*
 * syscall(frame):
 *	System call request from POSIX system call gate interface to kernel.
 * Like trap(), argument is call by reference.
 */
/*ARGSUSED*/
syscall(frame)
	volatile struct syscframe frame;
{
	register int *locr0 = ((int *)&frame);
	register caddr_t params;
	register int i;
	register struct sysent *callp;
	register struct proc *p = curproc;
	struct timeval syst;
	int error, opc;
	int args[8], rval[2];	/* eight args, 2 retvals for pipe */
	int code;

#ifdef lint
	r0 = 0; r0 = r0; r1 = 0; r1 = r1;
#endif
	syst = p->p_stime;

	/* Fail if syscall was called from kernel space */
	if (ISPL(frame.sf_cs) != SEL_UPL)
		panic("syscall");

	/* Assign system call number */
	code = frame.sf_eax;

	curpcb->pcb_flags &= ~FM_TRAP;	/* used by sendsig */
	p->p_regs = (int *)&frame;

	/* Point params to syscall args on user stack */
	params = (caddr_t)frame.sf_esp + sizeof (int) ;

	/*
	 * Reconstruct old pc (opc), assuming lcall $X,y is 7 bytes,
	 * as it is always.
	 */
	opc = frame.sf_eip - 7;
	callp = (code >= nsysent) ? &sysent[63] : &sysent[code];
	if (callp == sysent) {
		i = fuword(params);
		params += sizeof (int);

		/* If syscall nb is too large, we default to 63 = getkerninfo */
		callp = (code >= nsysent) ? &sysent[63] : &sysent[code];
	}

	/* Copy in syscall args from user stack */
	if ((i = callp->sy_narg * sizeof (int)) &&
	    (error = copyin(params, (caddr_t)args, (u_int)i))) {
		/*
		 * If we failed to copy syscall args, set the CF,
		 * set %eax to error, and return.
		 */
		frame.sf_eax = error;
		frame.sf_eflags |= PSL_C;	/* carry bit */
#ifdef KTRACE
		if (KTRPOINT(p, KTR_SYSCALL))
			ktrsyscall(p->p_tracep, code, callp->sy_narg, &args);
#endif
		goto done;
	}
#ifdef KTRACE
	if (KTRPOINT(p, KTR_SYSCALL))
		ktrsyscall(p->p_tracep, code, callp->sy_narg, &args);
#endif

	/* Initialize return values */
	rval[0] = 0;
	rval[1] = frame.sf_edx;

	/* Call the syscall function */
	error = (*callp->sy_call)(p, args, rval);

	if (error == ERESTART)
		/* Set %eip to old pc if we need to restart */
		frame.sf_eip = opc;
	else if (error != EJUSTRETURN) {
		/* Syscall failed: set CF and set %eax to error */
		if (error) {
			frame.sf_eax = error;
			frame.sf_eflags |= PSL_C;	/* carry bit */
		} /* Success: set return values and clear CF */
		  else {
			frame.sf_eax = rval[0];
			frame.sf_edx = rval[1];
			frame.sf_eflags &= ~PSL_C;	/* carry bit */
		}
	}
done:
	/*
	 * Reinitialize proc pointer `p' as it may be different
	 * if this is a child returning from fork syscall.
	 */
	p = curproc;

	/* Handle any signals the process received during syscall */
	while (i = CURSIG(p))
		psig(i);

	/* Reset the process's priority back to default user priority */
	p->p_pri = p->p_usrpri;

	/* Search for the process with the highest priority to schedule */
	if (want_resched) {
		/*
		 * Since we are curproc, clock will normally just change
		 * our priority without moving us from one queue to another
		 * (since the running process is not on a queue.)
		 * If that happened after we setrq ourselves but before we
		 * swtch()'ed, we might not be on the queue indicated by
		 * our priority.
		 */
		(void) splclock();

		/* Add the process to the queue */
		setrq(p);
		p->p_stats->p_ru.ru_nivcsw++;

		/* Switch to the highest priority process */
		swtch();
		(void) splnone();

		/* Handle any signals received while the proc was not running */
		while (i = CURSIG(p))
			psig(i);
	}
	if (p->p_stats->p_prof.pr_scale) {
		int ticks;
		struct timeval *tv = &p->p_stime;

		ticks = ((tv->tv_sec - syst.tv_sec) * 1000 +
			(tv->tv_usec - syst.tv_usec) / 1000) / (tick / 1000);
		if (ticks) {
#ifdef PROFTIMER
			extern int profscale;
			addupc(frame.sf_eip, &p->p_stats->p_prof,
			    ticks * profscale);
#else
			addupc(frame.sf_eip, &p->p_stats->p_prof, ticks);
#endif
		}
	}
	/* Set proc prio */
	curpri = p->p_pri;
#ifdef KTRACE
	if (KTRPOINT(p, KTR_SYSRET))
		ktrsysret(p->p_tracep, code, error, rval[0]);
#endif
}
```
