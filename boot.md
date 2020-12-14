# Walthrough of 386BSD's Boot Process

## Contents

1. Code Flow
2. General Overview

## Code Flow

The first '+' means that I have read the code or I have a general idea of what it does.
The second '+' means that I have read the code closely and documented it as it relates to bootup.
The third '+' means that I have added it to this markdown document for reference.

```txt
_start()							+++
	_init386()						+++
		cninit()					++-
		ssdtosd()					++-
		setidt()					+--
		pmap_bootstrap()			++-
	_main()							--+
		startrtclock()				+--
		vm_mem_init()				++-
			vm_page_startup()		++-
			vm_object_init()		++-
			vm_map_startup()		++-
			kmem_init()				++-
			pmap_init()				++-
			vm_pager_init()			++-
		kmeminit()					++-
		cpu_startup()				---		(sets up data structures in user-space)
			bufinit()				---		(buffer cache; self-contained and easy)
			configure()				---		(isa and root dev; self-contained)
		rqinit()					---		(runqueues; very short and easy)
		vm_init_limits()			---		(default vm limits; very short/easy)
		vfsinit()					---		()
		mbinit()					---		()
		ifinit()					---		()
		domaininit()				---		()
		roundrobin()				---
		schedcpu()					---
		enablertclock()				---
		swapinit()					---
		siginit()					---
		sched()						---
```

## General Overview

```c
start:
	movw $0x1234,%ax
	movw %ax,0x472		# BIOS Data Area: set warm boot
						# According to IBM Technical Reference,
						# the address of the RESET_FLAG is 0040:0072,
						# where 40*f+72 = 472h. Online it is stated
						# that 1234h bypasses the memory test, but in the
						# IBM technical reference it states a keyboard
						# reset is underway.

						# The keyboard reset is a reference to the fact that
						# pressing ctrl+alt+delete on the IBM PC AT causes
						# the system to reset as a warm boot.
	jmp	1f
	.space	0x500		# skip over warm boot shit

	/*
	 * pass parameters on stack (howto, bootdev, unit, cyloffset)
	 * note: 0(%esp) is return address of boot
	 * ( if we want to hold onto /boot, it's physical %esp up to _end)
	 */

/* Copy stack variables to the appropriate low memory location;
   notice how we do not adjust physical addresses in 0.1 */
 1:	movl	4(%esp),%eax
	movl	%eax,_boothowto-SYSTEM
	movl	8(%esp),%eax
	movl	%eax,_bootdev-SYSTEM
	movl	12(%esp),%eax
	movl	%eax, _cyloffset-SYSTEM

#ifdef garbage
/* count up conventional memory 
 *   %eax = current address
 *   %ebx = original value at current address
 *   %ecx = counter; 160 iterations
 */
	xorl	%eax,%eax			# start with base memory at 0x0
	#movl	$ 0xA0000/NBPG,%ecx	# look every 4K up to 640K
	movl	$ 0xA0,%ecx			# look every 4K up to 640K
1:	movl	0(%eax),%ebx		# save location to check
	movl	$0xa55a5aa5,0(%eax)	# write test pattern

	/* flush stupid cache here! (with bcopy (0,0,512*1024) ) */

	/* Check whether the test pattern was written to curr addr */
	cmpl	$0xa55a5aa5,0(%eax)	# does not check yet for rollover,
								# which would be testing address 0
								# for each loop iteration

	jne	2f						# jump if pattern wasnt there
								# (memory unavailable)

	movl	%ebx,0(%eax)		# restore value at curr address
	addl	$ NBPG,%eax			# increment to next pg frame
	loop	1b					# loop until 0 (160 iterations)

2:	shrl	$12,%eax			# convert max mem to pg frame number
	movl	%eax,_Maxmem-SYSTEM

/* count up extended memory 
 *   %eax = current address
 *   %ebx = original value at current address
 *   %ecx = counter; 3839 iterations
 */

	movl	$0x100000,%eax		# next, talley remaining memory
	#movl	$((0xFFF000-0x100000)/NBPG),%ecx
	movl	$(0xFFF-0x100),%ecx	# EFFh = 3839 page frames to check
1:	movl	0(%eax),%ebx		# save location to check
	movl	$0xa55a5aa5,0(%eax)	# write test pattern
	cmpl	$0xa55a5aa5,0(%eax)	# does not check yet for rollover
	jne	2f						# jump if pattern wasnt there
								# (memory unavailable)
	movl	%ebx,0(%eax)		# restore value at curr addr
	addl	$ NBPG,%eax			# increment to next pg frame
	loop	1b					# loop until 0 (3839 iterations)

2:	shrl	$12,%eax			# convert max mem to pg frame number
	movl	%eax,_Maxmem-SYSTEM
#endif

/* find end of kernel image */
	movl	$_end-SYSTEM,%ecx
	addl	$ NBPG-1,%ecx
	andl	$~(NBPG-1),%ecx
	movl	%ecx,%esi				# %esi = end of kernel rounded to
									#        the nearest page frame

/* clear bss and memory for bootstrap pagetables. */
	movl	$_edata-SYSTEM,%edi		# %edi = end of init data segment
	subl	%edi,%ecx				# %ecx = length of bss
	addl	$(UPAGES+5)*NBPG,%ecx	# %ecx = data segment + 7 additional pages */

/*
 * Virtual address space of kernel:
 *                                      (swapper)
 *	text | data | bss | page dir | proc0 kernel stack | usr stk map | Sysmap
 *			     0               1       2       3             4
 *
 *  Sysmap according to D&I 4.3BSD:
 *  _____________________________
 *  |                           |
 *  | User Page Table Map       | -> maps user-process page tables into the
 *  |___________________________|    kernel's address space
 *  |                           |
 *  | I/O Map                   | -> maps the address I/O space so dev drivers
 *  |___________________________|    can access periph-dev registers
 *  |                           |
 *  | Utility Maps              | -> maps for dynamic alloc of kernel memory
 *  |___________________________|    and tmp access to main memory pages
 *  |                           |
 *  | Alternate Mappings        | -> maps in the user structures of procs not
 *  |___________________________|    currently executing
 *  |                           |
 *  | System Map                | -> maps kernel code, data, and tables alloc
 *  |___________________________|    at boot time
 *
 */

	xorl	%eax,%eax	# pattern = 0h
	cld					# increment string functions
	rep
	stosb				# Write 0h at ES:DI until %ecx = 0

	movl	%esi,_IdlePTD-SYSTEM 	# physical address of Idle Address space
									# at end of Sysmap
	movl	$ tmpstk-SYSTEM,%esp	# bootstrap stack end location
									# tmpstk is a 512 byte stack below text seg

/*
 * fillkpt (fill kernel page table):
 *   %eax = physical addr + visible bit
 *   %ebx = page table entry
 *   %ecx = counter; 
 */
#define	fillkpt		\
1:	movl	%eax,0(%ebx)	; \
	addl	$ NBPG,%eax	; /* increment physical address */ \
	addl	$4,%ebx		; /* next pte */ \
	loop	1b		;

/*
 * Map Kernel
 * N.B. don't bother with making kernel text RO, as 386
 * ignores R/W AND U/S bits on kernel access (only v works) !
 *
 * First step - build page tables
 */

/*
 *        Kern Image
 *  _______________________
 *  |                     |
 *  |     Free Memory     |
 *  |_____________________|<-- firstaddr (%esi+7)
 *  |                     |
 *  |                     |
 *  |   User Stack Map    |
 *  |  (two pages long)   |
 *  |                     |
 *  |_____________________| %esi+5
 *  |                     |
 *  | Kernel Page Table   |
 *  |      (KPT)          |
 *  |_____________________| %esi+4
 *  |                     |
 *  | User Page Table     |
 *  |_____________________| %esi+3       Kernel Page Table
 *  |                     |           _______________________
 *  |                     |           |                     | _end>>12 + 97
 *  | proc0 kernel stack  |           | proc0 kernel stack  |
 *  |  (two pages long)   |           |_____________________| _end>>12 + 96
 *  |                     |           |                     | _end>>12 + 95
 *  |_____________________| %esi+1    | I/O Pages           |
 *  |                     |           |_____________________| _end>>12 + 6
 *  | Page Directory      |           |                     | _end>>12 + 5
    |    (IdlePTD)        |           | Early Context       |
 *  |_____________________|<-- %esi   |_____________________| _end>>12
 *  |                     |           |                     | _end>>12 - 1
 *  | Data Segment        |           | Data Pages          |
 *  |_____________________|           |_____________________| _etext>>12
 *  |                     |           |                     | _etext>>12 - 1
 *  | Text Segment        |           | Text Pages          |
 *  |_____________________| 0h        |_____________________| 0
 */

	movl	%esi,%ecx				# this much memory, (%esi = &IdlePTD)
	shrl	$ PGSHIFT,%ecx			# for this many ptes  (convert addr to # of pg frames)
	addl	$ UPAGES+4,%ecx			# including our early context (plus 6 pages)
	movl	$ PG_V,%eax				# having these bits set, (1h; visible bit)
	lea	(4*NBPG)(%esi),%ebx			# physical address of KPT in proc 0, (4 pages ahead of IdlePTD)
	movl	%ebx,_KPTphys-SYSTEM	# in the kernel page table,
	fillkpt

/* map I/O memory map */

	movl	$0x100-0xa0,%ecx		# for this many pte s, (%ecx = 96)
	movl	$(0xa0000|PG_V),%eax	#  having these bits set, (perhaps URW?)
	movl	%ebx,_atdevphys-SYSTEM	#   remember phys addr of i/o ptes
	fillkpt

 /* map proc 0's kernel stack into user page table page */

	movl	$ UPAGES,%ecx			# for this many pte s, (%ecx = 2)
	lea	(1*NBPG)(%esi),%eax			# physical address in proc 0 (1 page ahead of IdlePTD)
	lea	(SYSTEM)(%eax),%edx			# %edx = vaddr of proc0 aka the swapper process
	movl	%edx,_proc0paddr-SYSTEM	# remember VA for 0th process init
	orl	$ PG_V|PG_URKW,%eax			#  having these bits set, (pg bits = 5h)
	lea	(3*NBPG)(%esi),%ebx			# physical addr of user pte
	addl	$(PPTEOFF*4),%ebx		# %ebx += 3FE; 1022n pte of user page table
	fillkpt

/*
 * Construct a page table directory
 * (of page directory elements - pde's)
 */

/*
 *          Kernel Page Directory
 * _____________________________________
 * |                                   |
 * |  Alternate Kernel Page Table      |
 * |___________________________________| 1022
 * |                                   |
 * |        Kernel Page Table          |
 * |___________________________________| 1016
 * |                                   |
 * |  Recursive Kernel Page Directory  |
 * |___________________________________| 1015
 * |                                   |
 * |       proc0 Kernel Stack          |
 * |___________________________________| 1014
 * |                                   |
 * |                .                  |
 * |                .                  |
 * |                .                  |
 * |___________________________________|
 * |                                   |
 * |       Kernel Page Table           |
 * |___________________________________| 0
 */

	/* install a pde for temporary double map of bottom of VA */
	lea	(4*NBPG)(%esi),%eax	# physical address of kernel page table
	orl	$ PG_V,%eax			# pde entry is valid
	movl	%eax,(%esi)		# which is where temp maps!

	/* kernel pde's */
	movl	$ 3,%ecx				# for this many pde s,	(%ecx = 3 -> 12MiB of memory mapped)
	lea	(SYSPDROFF*4)(%esi), %ebx	# offset of pde for kernel base (%ebx = %esi + FE0)
	fillkpt

	/* install a pde recursively mapping page directory as a page table! */
	movl	%esi,%eax		# phys address of ptd in proc 0
	orl	$ PG_V,%eax			# pde entry is valid
	movl	%eax, PDRPDROFF*4(%esi)	# which is where PTmap maps!

	/* install a pde to map kernel stack for proc 0 below recursive map entry */
	lea	(3*NBPG)(%esi),%eax			# physical address of pt in proc 0
	orl	$ PG_V,%eax					# pde entry is valid
	movl	%eax,PPDROFF*4(%esi)	# which is where kernel stack maps!

	/* load base of page directory, and enable mapping */
	movl	%esi,%eax		# %eax = phys address of ptd in proc 0
 	orl	$ I386_CR3PAT,%eax	# I386_CR3PAT = 0x0
	movl	%eax,%cr3		# load ptd addr into mmu
	movl	%cr0,%eax		# get control word
	orl	$0x80000001,%eax	# and let s page!
	movl	%eax,%cr0		# NOW!

	pushl	$begin			# jump to high mem!
	ret

begin: /* now running relocated at SYSTEM where the system is linked to run */

	.globl _Crtat
	movl	_Crtat,%eax
	subl	$0xfe0a0000,%eax	# offset of Crt wrt i/o base
	movl	_atdevphys,%edx		# get pte PA (paddr of i/o ptes)
	subl	_KPTphys,%edx		# remove base of ptes (offset of i/o ptes)
	shll	$ PGSHIFT-2,%edx	# corresponding to virt offset
	addl	$ SYSTEM,%edx		# add virtual base
	movl	%edx, _atdevbase	# vaddr of i/o memory
	addl	%eax,%edx			# add Crt offset to vaddr of i/o memory
	movl	%edx,_Crtat			# store vaddr of Crt

	/* set up bootstrap stack */
	movl	$ _kstack+UPAGES*NBPG-4*12,%esp	# bootstrap stack end location
											# %esp = fdbfff0h
	xorl	%eax,%eax						# mark end of frames
	movl	%eax,%ebp						# %ebp = 0h
	movl	_proc0paddr, %eax				# %eax = paddr of proc0's kern stack
	movl	%esi, PCB_CR3(%eax)				# The user struct is located at the
											# bottom of proc0's kernel stack,
											# and the first field of the user
											# struct is the pcb's TSS. 

											# According to Programming the 80386,
											# the CR3 field in the TSS is at offset
											# 28, which is what genassym.c sets
											# PCB_CR3 equal to. Hence, we are
											# manually filling in a field of the TSS.

	lea	7*NBPG(%esi),%esi		# skip past stack (user stack map)
								# address of first page

	pushl	%esi				# push paddr of user stack map
	
	call	_init386			# wire 386 chip for unix operation


init386(first) { extern ssdtosd(), lgdt(), lidt(), lldt(), etext;
	int x, *pi;
	unsigned biosbasemem, biosextmem;
	struct gate_descriptor *gdp;
	extern int sigcode,szsigcode;
	/* table descriptors - used to load tables by microp */
	struct region_descriptor r_gdt, r_idt;

	proc0.p_addr = proc0paddr;	/* vaddr of proc0; the swapper */

	/*
	 * Initialize the console before we print anything out.
	 */

	/* cninit is defined as having no arguments; how does this work?
	   Otherwise, it's a straightforward initialization */
	cninit (KERNBASE+0xa0000);

	/* make gdt memory segments:
	 * 
	 *    gdt_segs = an array of soft_segment_descriptors
	 *
	 *    gdt = an array of seven union descriptors
	 *
	 *    #define btoc(x) (((unsigned)(x)+(NBPG-1))>>PGSHIFT)  
	 */

	/* why do we add NBPG to &etext when btoc already does this? */
	gdt_segs[GCODE_SEL].ssd_limit = btoc((int) &etext + NBPG);

	/* ssdtosd is located in locore.s; NGDT = 7 in this version */
	for (x=0; x < NGDT; x++) ssdtosd(gdt_segs+x, gdt+x);

	/* make ldt memory segments */
	ldt_segs[LUCODE_SEL].ssd_limit = btoc(UPT_MIN_ADDRESS);	/* UPT_MIN_ADDRESS = FDC00000 */
	ldt_segs[LUDATA_SEL].ssd_limit = btoc(UPT_MIN_ADDRESS);

	/* Note. eventually want private ldts per process */
	for (x=0; x < 5; x++) ssdtosd(ldt_segs+x, ldt+x);

	/* exceptions */

	/*
	 * This code block is standard, but still has a lot of moving parts.
	 *
	 * In this source file (machdep.c) IDTVEC is defined as a following macro:
	 * #define IDTVEC(name)	__CONCAT(X,name)
	 *
	 * __CONCAT(x,y) is defined in cdefs.h as the following for traditional cpp:
	 *
	 * #define __CONCAT(x,v)	x/ ** / y
	 *
	 * Hence, IDTVEC(name) is used in setidt to create "&Xname", which is a
	 * label created and located in locore.s. This is a fancy way of obtaining
	 * the interrupt vector addresses/offset.
	 *
	 * SDT_SYS386TGT = 15; 80386 Trap Gate,  SEL_KPL = 0; Kernel Priority Level
	 * SDT_SYSTASKGT = 5; System Task Gate,  SEL_UPL = 3; User Priority Level
	 *
	 * GSEL(s, pl) = (((s)<<3) | pl) --> (s * 8 | pl) since IDT selectors are 8 bytes
	 *
	 * NOTE: GCODE_SEL = kernel code selector = 1
	 *
	 */
	setidt(0, &IDTVEC(div),  SDT_SYS386TGT, SEL_KPL);
	setidt(1, &IDTVEC(dbg),  SDT_SYS386TGT, SEL_KPL);
	setidt(2, &IDTVEC(nmi),  SDT_SYS386TGT, SEL_KPL);
 	setidt(3, &IDTVEC(bpt),  SDT_SYS386TGT, SEL_UPL);
	setidt(4, &IDTVEC(ofl),  SDT_SYS386TGT, SEL_KPL);
	setidt(5, &IDTVEC(bnd),  SDT_SYS386TGT, SEL_KPL);
	setidt(6, &IDTVEC(ill),  SDT_SYS386TGT, SEL_KPL);
	setidt(7, &IDTVEC(dna),  SDT_SYS386TGT, SEL_KPL);
	setidt(8, &IDTVEC(dble),  SDT_SYS386TGT, SEL_KPL);
	setidt(9, &IDTVEC(fpusegm),  SDT_SYS386TGT, SEL_KPL);
	setidt(10, &IDTVEC(tss),  SDT_SYS386TGT, SEL_KPL);
	setidt(11, &IDTVEC(missing),  SDT_SYS386TGT, SEL_KPL);
	setidt(12, &IDTVEC(stk),  SDT_SYS386TGT, SEL_KPL);
	setidt(13, &IDTVEC(prot),  SDT_SYS386TGT, SEL_KPL);
	setidt(14, &IDTVEC(page),  SDT_SYS386TGT, SEL_KPL);
	setidt(15, &IDTVEC(rsvd),  SDT_SYS386TGT, SEL_KPL);
	setidt(16, &IDTVEC(fpu),  SDT_SYS386TGT, SEL_KPL);
	setidt(17, &IDTVEC(rsvd0),  SDT_SYS386TGT, SEL_KPL);
	setidt(18, &IDTVEC(rsvd1),  SDT_SYS386TGT, SEL_KPL);
	setidt(19, &IDTVEC(rsvd2),  SDT_SYS386TGT, SEL_KPL);
	setidt(20, &IDTVEC(rsvd3),  SDT_SYS386TGT, SEL_KPL);
	setidt(21, &IDTVEC(rsvd4),  SDT_SYS386TGT, SEL_KPL);
	setidt(22, &IDTVEC(rsvd5),  SDT_SYS386TGT, SEL_KPL);
	setidt(23, &IDTVEC(rsvd6),  SDT_SYS386TGT, SEL_KPL);
	setidt(24, &IDTVEC(rsvd7),  SDT_SYS386TGT, SEL_KPL);
	setidt(25, &IDTVEC(rsvd8),  SDT_SYS386TGT, SEL_KPL);
	setidt(26, &IDTVEC(rsvd9),  SDT_SYS386TGT, SEL_KPL);
	setidt(27, &IDTVEC(rsvd10),  SDT_SYS386TGT, SEL_KPL);
	setidt(28, &IDTVEC(rsvd11),  SDT_SYS386TGT, SEL_KPL);
	setidt(29, &IDTVEC(rsvd12),  SDT_SYS386TGT, SEL_KPL);
	setidt(30, &IDTVEC(rsvd13),  SDT_SYS386TGT, SEL_KPL);
	setidt(31, &IDTVEC(rsvd14),  SDT_SYS386TGT, SEL_KPL);

#include	"isa.h"	/* include C wrappers for ISA Bus I/O */
#if	NISA >0
	isa_defaultirq();	/* standard 8259 PIC initialization */
#endif

	/*
	 * r_gdt and r_idt are C structures for the lgdt/lidt assembly instrs.
	 * Since we are setting up these descr tables in C, lgdt/lidt are macro
	 * wrappers for inline assembly code. These macros are located on line 146
	 * of segments.h.
	 *
	 * struct region_descriptor {
	 * 		unsigned __PACK(rd_limit:16);	// segment extent
	 * 		unsigned __PACK(rd_base:32);	// base address
	 * };
	 */
	r_gdt.rd_limit = sizeof(gdt)-1;
	r_gdt.rd_base = (int) gdt;
	lgdt(&r_gdt);
	r_idt.rd_limit = sizeof(idt)-1;
	r_idt.rd_base = (int) idt;
	lidt(&r_idt);
	lldt(GSEL(GLDT_SEL, SEL_KPL));

#include "ddb.h"
#if NDDB > 0
	kdb_init();
	if (boothowto & RB_KDB)
		Debugger();
#endif

	/*
	 * Use BIOS values stored in RTC CMOS RAM, since probing
	 * breaks certain 386 AT relics.
	 *
	 * rtcin() is located in locore.s and the RTC_* values are
	 * defined in /usr/src/sys.386bsd/i386/isa/rtc.h (real time clock header).
	 * These values are also found in the IBM Technical Reference PC AT.
	 */

	/* RTC_BASELO = 0x15, RTC_BASEHI = 0x16 
       RTC_EXTLO = 0x17, RTC_EXTHI = 0x18 */
	biosbasemem = rtcin(RTC_BASELO) + (rtcin(RTC_BASEHI)<<8);
	biosextmem = rtcin(RTC_EXTLO) + (rtcin(RTC_EXTHI)<<8);

	/* printf("bios base %d ext %d ", biosbasemem, biosextmem); */

	/* if either bad, just assume base memory */
	if (biosbasemem == 0xffff || biosextmem == 0xffff) {
		maxmem = min (maxmem, 640/4);
	} else if (biosextmem > 0 && biosbasemem == 640) {
		int pagesinbase, pagesinext;

		/* free pages in base memory */
		pagesinbase = 640/4 - first/NBPG;

		/* free pages in extended memory */
		pagesinext = biosextmem/4;
		/* use greater of either base or extended memory. do this
		 * until I reinstitue discontiguous allocation of vm_page
		 * array.
		 */
		if (pagesinbase > pagesinext)
			Maxmem = 640/4;
		else {
			Maxmem = pagesinext + 0x100000/NBPG;
			first = 0x100000; /* skip hole */
		}
	}
	maxmem = Maxmem - 1;	/* highest page of usable memory */
	physmem = maxmem;	/* number of pages of physmem addr space */

	/*printf("using first 0x%x to 0x%x\n ", first, maxmem*NBPG);*/

	if (maxmem < 2048/4)	/* < 512 pages? */
		printf("Too little RAM memory. Warning, running in degraded mode.\n");

	/* call pmap initialization to make new kernel address space */

	pmap_bootstrap (first, 0);	/* This function sets the kernel pg dir equ to 
								   the one in Sysmap and clears the identity
								   mapping in the original pg dir */

	/* now running on new page tables, configured,and u/iom is accessible */

	/* make a initial tss so microp can get interrupt stack on syscall! */
	proc0.p_addr->u_pcb.pcb_tss.tss_esp0 = (int) kstack + UPAGES*NBPG;
	proc0.p_addr->u_pcb.pcb_tss.tss_ss0 = GSEL(GDATA_SEL, SEL_KPL) ;
	_gsel_tss = GSEL(GPROC0_SEL, SEL_KPL);
	ltr(_gsel_tss);		/* load task-state segment */

	/* make a call gate to reenter kernel with */
	gdp = &ldt[LSYS5CALLS_SEL].gd;
	
	x = (int) &IDTVEC(syscall);
	gdp->gd_looffset = x++;
	gdp->gd_selector = GSEL(GCODE_SEL,SEL_KPL);
	gdp->gd_stkcpy = 0;
	gdp->gd_type = SDT_SYS386CGT;
	gdp->gd_dpl = SEL_UPL;
	gdp->gd_p = 1;
	gdp->gd_hioffset = ((int) &IDTVEC(syscall)) >>16;

	/* transfer to user mode */

	_ucodesel = LSEL(LUCODE_SEL, SEL_UPL);
	_udatasel = LSEL(LUDATA_SEL, SEL_UPL);

	/* setup proc 0's pcb */

	/* copy sigcode to the pcb. This function makes a lcall to the kernel
	   with arguments on the stack */
	bcopy(&sigcode, proc0.p_addr->u_pcb.pcb_sigc, szsigcode);
	proc0.p_addr->u_pcb.pcb_flags = 0;
	proc0.p_addr->u_pcb.pcb_ptd = IdlePTD;
}

	movl	$0,_PTD				# Sets base addr of kernel pg dir to 0
	call 	_main

/*
 * System startup; initialize the world, create process 0,
 * mount root filesystem, and fork to create init and pagedaemon.
 * Most of the hard work is done in the lower-level initialization
 * routines including startup(), which does memory initialization
 * and autoconfiguration.
 */
main()
{
	register int i;
	register struct proc *p;
	register struct filedesc0 *fdp;
	int s, rval[2];

	/*
	 * Initialize curproc before any possible traps/probes
	 * to simplify trap processing.
	 */
	p = &proc0;
	curproc = p;
	/*
	 * Attempt to find console and initialize
	 * in case of early panic or other messages.
	 */
	startrtclock();
	consinit();		/* empty function */

	printf("\033[3;15x%s\033[0x [0.1.%s]\n", copyright1, version+9);
	printf(copyright2);

	/*
	 * Initializes the mach vm system to support memory allocation and
	 * virtual address spaces. This involves:
	 *		1. Statically allocating an array of 10 vm_maps and 1500
	 *		   vm_map_entries for use by the kernel.
	 *		2. Creates the kernel_object and the kmem_object and adds
	 *		   them to the object_list queue.
	 *		3. Links the vm_map and vm_map_entry structures in memory.
	 *		4. Sets the first vm_map to the kernel_map and the first
	 *		   vm_map_entry's range to VM_MIN_KERNEL_ADDRESS - FF7FF000h
	 *		   (doesn't include the msgbuf in the range).
	 *		5. Allocates memory for the kernel pmap's pv_table, which is
	 *		   takes up the second static vm_map_entry.
	 *		6. Allocates memory for a kernel submap that traces get/put
	 *		   page mappings. This takes up the second vm_map and third
	 *		   vm_map_entry for the parent and its entry respectively.
	 *		7. Initializes the pagers (swap, vnode, and device)
	 */
	vm_mem_init();

	/* Initializes the kernel memory allocator by allocating an array of
	 * 512 kmemusage structures and allocating a submap 2MiB for its pool
	 * of available memory. This takes up the third vm_map and the fourth
	 * vm_map_entry respectively. The submap starts at offset &kmembase
	 * in ther kernel_object.
	 */
	kmeminit();

	/*
	 * 1. Create wired mappings for message buffers at the end of core
	 * 2. 
	 * 
	 * 
	 * 
	 * 
	 * 
	 * 
	 * 
	 * 
	 * 
	 */
	cpu_startup();

	/*
	 * set up system process 0 (swapper)
	 */
	p = &proc0;
	curproc = p;

	allproc = p;
	p->p_prev = &allproc;
	p->p_pgrp = &pgrp0;
	pgrphash[0] = &pgrp0;
	pgrp0.pg_mem = p;
	pgrp0.pg_session = &session0;
	session0.s_count = 1;
	session0.s_leader = p;

	p->p_flag = SLOAD|SSYS;
	p->p_stat = SRUN;
	p->p_nice = NZERO;
	bcopy("swapper", p->p_comm, sizeof ("swapper"));

	/*
	 * Setup credentials
	 */
	cred0.p_refcnt = 1;
	p->p_cred = &cred0;
	p->p_ucred = crget();
	p->p_ucred->cr_ngroups = 1;	/* group 0 */

	/*
	 * Create the file descriptor table for process 0.
	 */
	fdp = &filedesc0;
	p->p_fd = &fdp->fd_fd;
	fdp->fd_fd.fd_refcnt = 1;
	fdp->fd_fd.fd_cmask = cmask;
	fdp->fd_fd.fd_ofiles = fdp->fd_dfiles;
	fdp->fd_fd.fd_ofileflags = fdp->fd_dfileflags;
	fdp->fd_fd.fd_nfiles = NDFILE;

	/*
	 * Set initial limits
	 */
	p->p_limit = &limit0;
	for (i = 0; i < sizeof(p->p_rlimit)/sizeof(p->p_rlimit[0]); i++)
		limit0.pl_rlimit[i].rlim_cur =
		    limit0.pl_rlimit[i].rlim_max = RLIM_INFINITY;
	limit0.pl_rlimit[RLIMIT_OFILE].rlim_cur = NOFILE;
	limit0.pl_rlimit[RLIMIT_NPROC].rlim_cur = MAXUPRC;
	limit0.p_refcnt = 1;

	/*
	 * Allocate a prototype map so we have something to fork
	 */
	p->p_vmspace = &vmspace0;
	vmspace0.vm_refcnt = 1;
	pmap_pinit(&vmspace0.vm_pmap);
	vm_map_init(&p->p_vmspace->vm_map, round_page(VM_MIN_ADDRESS),
	    trunc_page(VM_MAX_ADDRESS), TRUE);
	vmspace0.vm_map.pmap = &vmspace0.vm_pmap;
	p->p_addr = proc0paddr;				/* XXX */

	/*
	 * We continue to place resource usage info
	 * and signal actions in the user struct so they're pageable.
	 */
	p->p_stats = &p->p_addr->u_stats;
	p->p_sigacts = &p->p_addr->u_sigacts;

	rqinit();

	/*
	 * configure virtual memory system,
	 * set vm rlimits
	 */
	vm_init_limits(p);

	/*
	 * Initialize the file systems.
	 *
	 * Get vnodes for swapdev and rootdev.
	 */
	vfsinit();
	if (bdevvp(swapdev, &swapdev_vp) || bdevvp(rootdev, &rootvp))
		panic("can't setup bdevvp's");

#if defined(vax)
#include "kg.h"
#if NKG > 0
	startkgclock();
#endif
#endif

	/*
	 * Initialize tables, protocols, and set up well-known inodes.
	 */
	mbinit();
#ifdef SYSVSHM
	shminit();
#endif
#include "sl.h"
#if NSL > 0
	slattach();			/* XXX */
#endif
#include "loop.h"
#if NLOOP > 0
	loattach();			/* XXX */
#endif
	/*
	 * Block reception of incoming packets
	 * until protocols have been initialized.
	 */
	s = splimp();
	ifinit();
	domaininit();
	splx(s);

#ifdef GPROF
	kmstartup();
#endif

	/* kick off timeout driven events by calling first time */
	roundrobin();
	schedcpu();
	enablertclock();		/* enable realtime clock interrupts */

	/*
	 * Set up the root file system and vnode.
	 */
	if ((*mountroot)())
		panic("cannot mount root");
	/*
	 * Get vnode for '/'.
	 * Setup rootdir and fdp->fd_fd.fd_cdir to point to it.
	 */
	if (VFS_ROOT(rootfs, &rootdir))
		panic("cannot find root vnode");
	fdp->fd_fd.fd_cdir = rootdir;
	VREF(fdp->fd_fd.fd_cdir);
	VOP_UNLOCK(rootdir);
	fdp->fd_fd.fd_rdir = NULL;
	swapinit();

	/*
	 * Now can look at time, having had a chance
	 * to verify the time from the file system.
	 */
	boottime = p->p_stats->p_start = time;

	/*
	 * make init process
	 */
	siginit(p);
	if (fork(p, (void *) NULL, rval))
		panic("fork init");
	if (rval[1]) {
		static char initflags[] = "-sf";
		char *ip = initflags + 1;
		vm_offset_t addr = 0;
		extern int icode[];		/* user init code */
		extern int szicode;		/* size of icode */

		/*
		 * Now in process 1.  Set init flags into icode,
		 * get a minimal address space, copy out "icode",
		 * and return to it to do an exec of init.
		 */
		p = curproc;
		initproc = p;
		if (boothowto&RB_SINGLE)
			*ip++ = 's';
#ifdef notyet
		if (boothowto&RB_FASTBOOT)
			*ip++ = 'f';
#endif
		*ip++ = '\0';

		if (vm_allocate(&p->p_vmspace->vm_map, &addr,
		    round_page(szicode + sizeof(initflags)), FALSE) != 0 ||
		    addr != 0)
			panic("init: couldn't allocate at zero");

		/* need just enough stack to exec from */
		addr = trunc_page(USRSTACK - MAXSSIZ);
		if (vm_allocate(&p->p_vmspace->vm_map, &addr,
		    MAXSSIZ, FALSE) != KERN_SUCCESS)
			panic("vm_allocate init stack");
		p->p_vmspace->vm_maxsaddr = (caddr_t)addr;
		p->p_vmspace->vm_ssize = 1;
		(void) copyout((caddr_t)icode, (caddr_t)0, (unsigned)szicode);
		(void) copyout(initflags, (caddr_t)szicode, sizeof(initflags));
		return;			/* returns to icode */
	}

	/*
	 * Start up pageout daemon (process 2).
	 */
	if (fork(p, (void *) NULL, rval))
		panic("fork pager");
	if (rval[1]) {
		/*
		 * Now in process 2.
		 */
		p = curproc;
		pageproc = p;
		p->p_flag |= SLOAD|SSYS;		/* XXX */
		bcopy("pagedaemon", curproc->p_comm, sizeof ("pagedaemon"));
		vm_pageout();
		/*NOTREACHED*/
	}

	/*
	 * enter scheduling loop
	 */
	sched();
}
```
