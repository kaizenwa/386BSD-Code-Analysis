/* 
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * The Mach Operating System project at Carnegie-Mellon University.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)vm_user.h	7.2 (Berkeley) 4/21/91
 *	$Id: vm_user.h,v 1.4 1993/12/19 00:56:16 wollman Exp $
 */

/*
 * Copyright (c) 1987, 1990 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Authors: Avadis Tevanian, Jr., Michael Wayne Young
 * 
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" 
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND 
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */

/*
 *	Kernel memory management definitions.
 */

#ifndef	_VM_USER_
#define	_VM_USER_

#ifdef KERNEL

#include "sys/cdefs.h"
#include "vm/vm_param.h"
#include "vm/vm_inherit.h"
#include "vm/vm_prot.h"

struct vm_map; struct vm_object; struct pager_struct;

extern int munmapfd(struct proc *, int);
extern int vm_mmap(struct vm_map *, vm_offset_t *, vm_size_t, vm_prot_t,
		   vm_prot_t, int, caddr_t, vm_offset_t);
extern int vm_region(struct vm_map *, vm_offset_t *, vm_size_t *, vm_prot_t *,
		     vm_prot_t *, vm_inherit_t *, boolean_t *, 
		     struct vm_object **,
		     vm_offset_t *);
extern int vm_allocate_with_pager(struct vm_map *, vm_offset_t *, vm_size_t,
				  boolean_t, struct pager_struct *, 
				  vm_offset_t, boolean_t);


extern int vm_allocate(struct vm_map *, vm_offset_t *, vm_size_t, boolean_t);
extern int vm_deallocate(struct vm_map *, vm_offset_t, vm_size_t);
extern int vm_inherit(struct vm_map *, vm_offset_t, vm_size_t, vm_inherit_t);
extern int vm_protect(struct vm_map *, vm_offset_t, vm_size_t, boolean_t,
		      vm_prot_t);

#else /* not KERNEL */
#include <sys/cdefs.h>
#include <vm/vm_param.h>
#include <vm/vm_inherit.h>
#include <vm/vm_prot.h>

__BEGIN_DECLS

int	vm_allocate __P((void *, vm_offset_t *, vm_size_t, boolean_t));
int	vm_deallocate __P((void *, vm_offset_t, vm_size_t));
int	vm_inherit __P((void *, vm_offset_t, vm_size_t, vm_inherit_t));
int	vm_protect __P((void *, vm_offset_t, vm_size_t, boolean_t, vm_prot_t));

__END_DECLS

#endif /* not KERNEL */
#endif /* _VM_USER_ */