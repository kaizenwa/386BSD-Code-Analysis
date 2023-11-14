#ifndef _OS_H_
#define _OS_H_
/*
 * OS specific settings for FreeBSD
 *
 * Copyright by UWM - comments to soft-eng@cs.uwm.edu
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This chould be used as an example when porting the driver to a new
 * operating systems.
 *
 * What you should do is to rewrite the soundcard.c and os.h (this file).
 * You should create a new subdirectory and put these two files there.
 * In addition you have to do a makefile.<OS>.
 *
 * If you have to make changes to other than these two files, please contact me
 * before making the changes. It's possible that I have already made the
 * change. 
 */

/*
 * Insert here the includes required by your kernel.
 */

#include "param.h"
#include "systm.h"
#include "ioctl.h"
#include "tty.h"
#include "proc.h"
#include "user.h"
#include "conf.h"
#include "file.h"
#include "uio.h"
#include "kernel.h"
#include "syslog.h"
#include "errno.h"
#include "malloc.h"
#include "buf.h"
#include "i386/isa/isa_device.h"

/*
 * Rest of the file is compiled only if the driver is really required.
 */
#ifdef CONFIGURE_SOUNDCARD

/* 
 * select() is currently implemented in Linux specific way. Don't enable.
 * I don't remember what the SHORT_BANNERS means so forget it.
 */

#undef ALLOW_SELECT
#define SHORT_BANNERS

/* The soundcard.h could be in a nonstandard place so inclyde it here. */
#include <machine/soundcard.h>

/*
 * Here is the first portability problem. Every OS has it's own way to
 * pass a pointer to the buffer in read() and write() calls. In Linux it's
 * just a char*. In BSD it's struct uio. This parameter is passed to
 * all functions called from read() or write(). Since nothing can be 
 * assumed about this structure, the driver uses set of macros for
 * accessing the user buffer. 
 *
 * The driver reads/writes bytes in the user buffer sequentially which
 * means that calls like uiomove() can be used.
 *
 * snd_rw_buf is the type which is passed to the device file specific
 * read() and write() calls.
 * 
 * The following macros are used to move date to and from the
 * user buffer. These macros should be used only when the 
 * target or source parameter has snd_rw_buf type.
 * The offs parameter is a offset relative to the beginning of
 * the user buffer. In Linux the offset is required but for example
 * BSD passes the offset info in the uio structure. It could be usefull
 * if these macros verify that the offs parameter and the value in
 * the snd_rw_buf structure are equal.
 */
typedef struct uio snd_rw_buf;

/*
 * Move bytes from the buffer which the application given in a
 * write() call.
 * offs is position relative to the beginning of the buffer in
 * user space. The count is number of bytes to be moved.
 */
#define COPY_FROM_USER(target, source, offs, count) \
	do { if (uiomove(target, count, (struct uio *)source)) { \
		printf ("sb: Bad copyin()!\n"); \
	} } while(0)
/* Like COPY_FOM_USER but for writes. */
#define COPY_TO_USER(target, offs, source, count) \
	do { if (uiomove(source, count, (struct uio *)target)) { \
		printf ("sb: Bad copyout()!\n"); \
	} } while(0)
/* 
 * The following macros are like COPY_*_USER but work just with one byte (8bit),
 * short (16 bit) or long (32 bit) at a time.
 * The same restrictions apply than for COPY_*_USER
 */
#define GET_BYTE_FROM_USER(target, addr, offs)	{uiomove((char*)&(target), 1, (struct uio *)addr);}
#define GET_SHORT_FROM_USER(target, addr, offs)	{uiomove((char*)&(target), 2, (struct uio *)addr);}
#define GET_WORD_FROM_USER(target, addr, offs)	{uiomove((char*)&(target), 4, (struct uio *)addr);}
#define PUT_WORD_TO_USER(addr, offs, data)	{uiomove((char*)&(data), 4, (struct uio *)addr);}

/*
 * The way how the ioctl arguments are passed is another nonportable thing.
 * In Linux the argument is just a pointer directly to the user segment. On
 * 386bsd the data is already moved to the kernel space. The following
 * macros should handle the difference.
 */

/*
 * IOCTL_FROM_USER is used to copy a record pointed by the argument to
 * a buffer in the kernel space. On 386bsd it can be done just by calling
 * memcpy. With Linux a memcpy_from_fs should be called instead.
 * Parameters of the following macros are like in the COPY_*_USER macros.
 */

/*
 * When the ioctl argument points to a record or array (longer than 32 bits),
 * the macros IOCTL_*_USER are used. It's assumed that the source and target
 * parameters are direct memory addresses.
 */
#define IOCTL_FROM_USER(target, source, offs, count) {memcpy(target, &((source)[offs]), count);}
#define IOCTL_TO_USER(target, offs, source, count) {memcpy(&((target)[offs]), source, count);}
/* The following macros are used if the ioctl argument points to 32 bit int */
#define IOCTL_IN(arg)			(*(int*)arg)
#define IOCTL_OUT(arg, ret)		*(int*)arg = ret

/*
 * When the driver displays something to the console, printk() will be called.
 * The name can be changed here.
 */
#define printk 		printf

/*
 * The following macros define an interface to the process management.
 */

struct snd_wait {
	  int mode; int aborting;
	};

/*
 * DEFINE_WAIT_QUEUE is used where a wait queue is required. It must define
 * a structure which can be passed as a parameter to a sleep(). The second
 * parameter is name of a flag variable (must be defined as int).
 */
#define DEFINE_WAIT_QUEUE(qname, flag) static int *qname = NULL; \
	static volatile struct snd_wait flag = {0}
/* Like the above but defines an array of wait queues and flags */
#define DEFINE_WAIT_QUEUES(qname, flag) static int *qname = {NULL}; \
	static volatile struct snd_wait flag = {{0}}

#define RESET_WAIT_QUEUE(q, f) {f.aborting = 0;f.mode = WK_NONE;}
#define SET_ABORT_FLAG(q, f) f.aborting = 1
#define TIMED_OUT(q, f) (f.mode & WK_TIMEOUT)
#define SOMEONE_WAITING(q, f) (f.mode & WK_SLEEP)
/*
 * This driver handles interrupts little bit nonstandard way. The following
 * macro is used to test if the current process has received a signal which
 * is aborts the process. This macro is called from close() to see if the
 * buffers should be discarded. If this kind info is not available, a constant
 * 1 or 0 could be returned (1 should be better than 0).
 * I'm not sure if the following is correct for FreeBSD.
 */
#define PROCESS_ABORTING(q, f) (f.aborting | curproc->p_sig)

/*
 * The following macro calls sleep. It should be implemented such that
 * the process is resumed if it receives a signal. The following is propably
 * not the way how it should be done on 386bsd.
 * The on_what parameter is a wait_queue defined with DEFINE_WAIT_QUEUE(),
 * and the second is a workarea parameter. The third is a timeout 
 * in ticks. Zero means no timeout.
 */
#define DO_SLEEP(q, f, time_limit)	\
	{ \
	  int flag, chn; \
	  f.mode = WK_SLEEP; \
	  q = &chn; \
	  flag=tsleep((caddr_t)&(chn), (PRIBIO-5)|PCATCH, "sndint", time_limit); \
	  if(flag == ERESTART) f.aborting = 1;\
	  else f.aborting = 0;\
	  f.mode &= ~WK_SLEEP; \
	}
/* An the following wakes up a process */
#define WAKE_UP(q, f)	{f.mode = WK_WAKEUP;wakeup((caddr_t)q);}

/*
 * Timing macros. This driver assumes that there is a timer running in the
 * kernel. The timer should return a value which is increased once at every
 * timer tick. The macro HZ should return the number of such ticks/sec.
 */

#ifndef HZ
extern int hz;
#define HZ	hz
#endif

/* 
 * GET_TIME() returns current value of the counter incremented at timer
 * ticks.  This can overflow, so the timeout might be real big...
 * 
 */
extern unsigned long get_time(void);
#define GET_TIME() get_time()
/*#define GET_TIME()	(lbolt)	*/ /* Returns current time (1/HZ secs since boot) */

/*
 * The following three macros are called before and after atomic
 * code sequences. The flags parameter has always type of unsigned long.
 * The macro DISABLE_INTR() should ensure that all interrupts which
 * may invoke any part of the driver (timer, soundcard interrupts) are
 * disabled.
 * RESTORE_INTR() should return the interrupt status back to the
 * state when DISABLE_INTR() was called. The flags parameter is
 * a variable which can carry 32 bits of state information between
 * DISABLE_INTR() and RESTORE_INTR() calls.
 */
#define DISABLE_INTR(flags)	flags = splhigh()
#define RESTORE_INTR(flags)	splx(flags)

/*
 * INB() and OUTB() should be obvious. NOTE! The order of
 * paratemeters of OUTB() is different than on some other
 * operating systems.
 */

#define INB			inb
/*  
 * The outb(0, 0x80) is just for slowdown. It's bit unsafe since
 * this address could be used for something usefull.
 */
#define OUTB(addr, data)	{outb(data, addr);outb(0, 0x80);}

/* memcpy() was not defined og 386bsd. Lets define it here */
#define memcpy(d, s, c)		bcopy(s, d, c)

/*
 * When a error (such as EINVAL) is returned by a function,
 * the following macro is used. The driver assumes that a
 * error is signalled by returning a negative value.
 */

#define RET_ERROR(err)		-(err)

/* 
   KERNEL_MALLOC() allocates requested number of memory  and 
   KERNEL_FREE is used to free it. 
   These macros are never called from interrupt, in addition the
   nbytes will never be more than 4096 bytes. Generally the driver
   will allocate memory in blocks of 4k. If the kernel has just a
   page level memory allocation, 4K can be safely used as the size
   (the nbytes parameter can be ignored).
*/
#define	KERNEL_MALLOC(nbytes)	malloc(nbytes, M_TEMP, M_WAITOK)
#define	KERNEL_FREE(addr)	free(addr, M_TEMP)

/*
 * The macro PERMANENT_MALLOC(typecast, mem_ptr, size, linux_ptr)
 * returns size bytes of
 * (kernel virtual) memory which will never get freed by the driver.
 * This macro is called only during boot. The linux_ptr is a linux specific
 * parameter which should be ignored in other operating systems.
 * The mem_ptr is a pointer variable where the macro assigns pointer to the
 * memory area. The type is the type of the mem_ptr.
 */
#define PERMANENT_MALLOC(typecast, mem_ptr, size, linux_ptr) \
	(mem_ptr) = (typecast)malloc((size), M_TEMP, M_WAITOK)

/*
 * The macro DEFINE_TIMER defines variables for the ACTIVATE_TIMER if
 * required. The name is the variable/name to be used and the proc is
 * the procedure to be called when the timer expires.
 */

#define DEFINE_TIMER(name, proc)

/*
 * The ACTIVATE_TIMER requests system to call 'proc' after 'time' ticks.
 */

#define ACTIVATE_TIMER(name, proc, time) \
	timeout((timeout_func_t)proc, 0, time);
/*
 * The rest of this file is not complete yet. The functions using these
 * macros will not work
 */
#define ALLOC_DMA_CHN(chn) ({ 0; })
#define RELEASE_DMA_CHN(chn) ({ 0; })
#define DMA_MODE_READ		0
#define DMA_MODE_WRITE		1
#define RELEASE_IRQ(irq_no)

#endif
#endif
