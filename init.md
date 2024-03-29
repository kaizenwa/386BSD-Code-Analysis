## Walkthrough of 386BSD 0.1's Kernel Initialization Process

### Contents

1. Code Flow
2. Source Code Commentary

### Code Flow

```txt
start
    init386
        cninit
        ssdtosd
        setidt
        pmap_bootstrap
    main
        startrtclock
        vm_mem_init
            vm_page_startup
            vm_object_init
            vm_map_startup
            kmem_init
            pmap_init
            vm_pager_init
        kmeminit
        cpu_startup
            bufinit
            configure
        rqinit
        vm_init_limits
        vfsinit
        mbinit
        ifinit
        domaininit
        roundrobin
        schedcpu
        enablertclock
        swapinit
        siginit
        sched
```

### Source Code Commentary

#### start (386bsd-0.1/sys/i386/i386/locore.s:121)

```txt
121-122: BIOS Data Area: set warm boot

         According to IBM Technical Reference, the address of the
         RESET_FLAG is 0040:0072, where 40*10+72 = 472h. Online
         it is stated that 1234h bypasses the memory test, but in the
         IBM technical reference it states a keyboard
         reset is underway.

         The keyboard reset is a reference to the fact that pressing
         ctrl+alt+delete on the IBM PC AT causes the system to reset as
         a warm boot.

132-137: Copies stack variables to the appropriate low memory location.
         Notice how we do not adjust physical addresses in 0.1.

139-154: Counts up conventional memory, where:

         %eax = current address
         %ebx = original value at current address
         %ecx = counter; 160 iterations

148: Checks whether the test pattern was written to the current
     address.

149: Jumps if the test pattern wasn't there (memory unavailable).

150: Restores value at current address

151: Increments to the next page frame.

151: Decrements %ecx and loops until %ecx equals 0 (160 iterations).

153-154: Converts the current address to a page frame number and
         assigns it to _Maxmem. This corresponds to the maximum
         page frame number for conventional memory (< 1MB).
         

156-167: Counts up extended memory, where:

         %eax = current address
         %ebx = original value at address
         %ecx = counter; 3839 iterations

161: Checks whether the test pattern was written to the current
     address. 

162: Jumps if the test pattern wasn't there (memory unavailable).

163: Restores value at current address

164: Increments to the next page frame.

165: Decrements %ecx and loops until %ecx equals 0 (3839 iterations).

166-167: Converts the current address to a page frame number and
         assigns it to _Maxmem. This corresponds to the maximum
         page frame number for extended memory (> 1MB).

176-189: Clears the bss and the seven page tables that follow it
         for the bootstrap page tables. To understand why we are
         doing this, we need to understand the virtual address
         space of the kernel.

                     Virtual address space of kernel:
                                    (swapper)
 text | data | bss | page dir | proc0 kernel stack | usr stk map | Sysmap
             0                1         2          3             4
  
  Sysmap according to D&I 4.3BSD:
  _____________________________
  |                           |
  | User Page Table Map       | -> maps user-process page tables into the
  |___________________________|    kernel's address space
  |                           |
  | I/O Map                   | -> maps the address I/O space so dev drivers
  |___________________________|    can access periph-dev registers
  |                           |
  | Utility Maps              | -> maps for dynamic alloc of kernel memory
  |___________________________|    and tmp access to main memory pages
  |                           |
  | Alternate Mappings        | -> maps in the user structures of procs not
  |___________________________|    currently executing
  |                           |
  | System Map                | -> maps kernel code, data, and tables alloc
  |___________________________|    at boot time

170-174: Rounds _end to the nearest page frame number and assigns
         it to %esi.

177-178: Calculates _end - _edata and assigns it to %ecx.
         This is equivalent to the length of bss.

179: Adds seven additional page frames to %ecx, making %ecx point
     to the 8th page frame following _end.

186-189: Bzeroes bss and the seven page frames that follow it.

         xorl %eax,%eax # pattern = 0h
         cld            # increment string functions
         rep
         stosb          # Write 0h at ES:DI until %ecx = 0


191: Assigns the rounded address of _end to IdlePTD.

192: Sets %esp to tmpstk, where tmpstk is a 512 byte stack
     located below the text segment.

     tmpstk is defined on line 118 of /sys/i386/i386/locore.s.

194-198: fillkpt (fill kernel page table):
           %eax = physical addr + visible bit
           %ebx = page table entry
           %ecx = counter 

207-256: Builds the kernel page tables.

        Kern Image
  _______________________
  |                     |
  |     Free Memory     |
  |_____________________|<-- firstaddr (%esi+7)
  |                     |
  |                     |
  |   User Stack Map    |
  |  (two pages long)   |
  |                     |
  |_____________________| %esi+5
  |                     |
  | Kernel Page Table   |
  |      (KPT)          |
  |_____________________| %esi+4
  |                     |
  | User Page Table     |
  |_____________________| %esi+3       Kernel Page Table
  |                     |           _______________________
  |                     |           |                     | _end>>12 + 97
  | proc0 kernel stack  |           | proc0 kernel stack  |
  |  (two pages long)   |           |_____________________| _end>>12 + 96
  |                     |           |                     | _end>>12 + 95
  |_____________________| %esi+1    | I/O Pages           |
  |                     |           |_____________________| _end>>12 + 6
  | Page Directory      |           |                     | _end>>12 + 5
  |    (IdlePTD)        |           | Early Context       |
  |_____________________|<-- %esi   |_____________________| _end>>12
  |                     |           |                     | _end>>12 - 1
  | Data Segment        |           | Data Pages          |
  |_____________________|           |_____________________| _etext>>12
  |                     |           |                     | _etext>>12 - 1
  | Text Segment        |           | Text Pages          |
  |_____________________| 0h        |_____________________| 0


226: %edx = vaddr of proc0 aka the swapper process.

228: Page bits = 5h = 0101.

229: Physical address of user PTE.

230: Physical address of stack pointer in proc 0.

233-255: Constructs a page table directory of
         page directory elements - pde's.

          Kernel Page Directory
   _____________________________________
   |                                   |
   |  Alternate Kernel Page Table      |
   |___________________________________| 1022
   |                                   |
   |        Kernel Page Table          |
   |___________________________________| 1016
   |                                   |
   |  Recursive Kernel Page Directory  |
   |___________________________________| 1015
   |                                   |
   |       proc0 Kernel Stack          |
   |___________________________________| 1014
   |                                   |
   |                .                  |
   |                .                  |
   |                .                  |
   |___________________________________|
   |                                   |
   |       Kernel Page Table           |
   |___________________________________| 0

243: %ecx = 3 -> 12MiB of memory mapped

244: %ebx = %esi + FE0

252: Installs a pde to map kernel stack for proc 0 below recursive
     map entry.

258: %eax = physical address of PTD in proc 0

259: I386_CR3PAT = 0x0

272: Offset of Crt with respect to i/o base.

274: %edx = Offset of i/o ptes.

277: Assigns virtual address of i/o memory to _atdevbase.

278: Adds Crt offset to virtual address of i/o memory.

279: Assigns virtual address of Crt to _Crtat.

282: %esp = FDBFF0h

284: %ebp = 0h

285: %eax = physical address of proc0's kernel stack

286: The user struct is located at the bottom of proc0's kernel
     stack, and the first field of the user struct is the pcb's
     TSS.

     According to Programming the 80386, the CR3 field in the
     TSS is at offset 28, which is what genassym.c sets PCB_CR3
     equal to. Hence, we are manually filling in a field of the
     TSS.

288: %esi = physical address of first page.

289: Pushes physical address of user stack map and or firstaddr.

291: Calls init386.

293: Sets base address of the kernel page directory to 0.

294: Calls main.
```

#### init386 (386bsd-0.1/sys/i386/i386/machdep.c:790)

```txt
799: Virtual address of proc0 (the swapper process).

805: cninit is defined as having no arguments - how does this work?
     Otherwise, it's a straightforward initialization.

807-810: gdt_segs = an array of soft_segment_descriptors.

         gdt = an array of seven union descriptors

         #define btoc(x) (((unsigned)(x)+(NBPG-1))>>PGSHIFT)  

808: Why do we add NBPG to &etext when btoc already does this?

809: _ssdtosd is defined on line 858 of /sys/i386/i386/locore.s.

     Note: NGDT = 7 in this version

811: UPT_MIN_ADDRESS = FDC00000

817-848:

  This code block is standard, but still has a lot of moving parts.

  In this source file (machdep.c) IDTVEC is defined as a following macro:
      #define IDTVEC(name) __CONCAT(X,name)

  __CONCAT(x,y) is defined in cdefs.h as the following for traditional cpp:
       #define __CONCAT(x,v)    x/ ## / y

  Hence, IDTVEC(name) is used in setidt to create "&Xname", which is a label
  created and located in locore.s. This is a fancy way of obtaining the
  interrupt vector addresses and offset.

    SDT_SYS386TGT = 15; 80386 Trap Gate,  SEL_KPL = 0; Kernel Priority Level
    SDT_SYSTASKGT = 5; System Task Gate,  SEL_UPL = 3; User Priority Level

    GSEL(s, pl) = (((s)<<3) | pl) --> (s * 8 | pl) since IDT selectors are
                                                   8 bytes

    NOTE: GCODE_SEL = kernel code selector = 1

850: Include C wrappers for ISA Bus I/O

852: Calls isa_defaultirq to initialize the 8259 PIC.

855-861: r_gdt and r_idt are region descriptor structures used for the
         lgdt/lidt assembly instructions. Since we are setting up these
         descriptor tables in C, lgdt/lidt are macro wrappers for inline
         assembly code. These macros are located on line 146 of segments.h.

             struct region_descriptor {
                 unsigned __PACK(rd_limit:16);  // segment extent
                 unsigned __PACK(rd_base:32);   // base address
             };

873-874: rtcin() is located in /sys/i386/i386/locore.s and the RTC_* values
         are defined in /usr/src/sys.386bsd/i386/isa/rtc.h. Note that "rtc"
         stands for real time clock.

         The RTC_* values can also be found in the IBM Technical Reference PC
         AT, where they have the following values:
         
         RTC_BASELO = 0x15      RTC_EXTLO = 0x17
         RTC_BASEHI = 0x16      RTC_EXTHI = 0x18

883: Free pages in base memory.

884: Free pages in extended memory.

903: Calls pmap_boostrap.

910: Loads task-state segment.
	
930: Copies sigcode to the pcb. This function makes a lcall to the kernel
     with arguments on the stack.
```

#### cninit (386bsd-0.1/sys/i386/i386/cons.c:79)

```txt
Control Flow:
start
    init386
        cninit <-- Here

87-91: Searches the console table constab (cons.c:64) for the
       console with the greatest priority.

102: Initializes the console we found in 87-91.
```

#### comprobe (386bsd-0.1/sys/i386/isa/com.c:113)

```txt
Control Flow:
start
    init386
        cninit
            comprobe <-- Here

608-610: Searches the cdevsw (/i386/i386/conf.c:173) for the
         com console, which is the eighth entry in the table.

614: Sets the first entry of com_addr to 0x3f8, which is a
     well known COM port.

619: Uses the macro makedev (sys/sys/types.h:66) to assign the
     COM console's device number.
```

#### cominit (386bsd-0.1/sys/i386/isa/com.c:639)

```txt
Control FLow:
start
    init386
        cninit
            comprobe
            cominit <-- Here

https://docs.freebsd.org/en/articles/serial-uart/
```

#### isa\_defaultirq (386bsd-0.1/sys/i386/isa/isa.c:236)

```txt
Control Flow:
start
    init386
        cninit
        isa_defaultirq <-- Here

https://wiki.osdev.org/PIC#Programming_the_PIC_chips
```

#### pmap\_bootstrap (386bsd-0.1/sys/i386/i386/pmap.c:214)

```txt
Control Flow:
start
    init386
        cninit
        isa_defaultirq
        pmap_bootstrap <-- Here

225-233: Assigns the physical and virtual memory ranges to the
         kernel's pmap. Note: Idk why we skip an additional
         10 page frames when assigning virtual_avail.

234: Assigns 4096 as the vm system's page size.

246: Links kernel_pmap with the statically allocated kernel
     pmap structure.

265: Assigns the IdlePTD as the kernel pmap's page directory.
```

#### i386\_protection\_init (386bsd-0.1/sys/i386/i386/pmap.c:1461)

```txt
Control Flow:
start
    init386
        cninit
        isa_defaultirq
        pmap_bootstrap
            i386_protection_init <-- Here

1465-1481: Populates the protection_codes array defined on
           line 169 of pmap.c.
```

#### main (386bsd-0.1/sys/kern/init\_main.c:94)

```txt
111: Calls startrtclock.

112: No-op.

116: Calls vm_mem_init.

117: Calls kmeminit.

118: Calls cpu_startup.

175: Calls pmap_pinit.

176: Calls vm_map_init.

188: Calls rqinit.

194: Calls vm_init_limits.

201: Calls vfsinit.

215: Calls mbinit.

232: Calls ifinit.

233: Calls domaininit.

241: Calls roundrobin.

242: Calls schedcpu.

243: Calls enablertclock.

248: Calls nfs_mountroot.

260: Calls swapinit.

271: Calls siginit.

333: Calls sched.
```

#### startrtclock (386bsd-0.1/sys/i386/isa/clock.c:53)

```txt
Control Flow:
start
    init386
    main
        startrtclock <-- Here

http://bos.asmhackers.net/docs/timer/docs/cmos.pdf
https://wiki.osdev.org/RTC
```

#### vm\_mem\_init (/386bsd-0.1/sys/vm/vm\_init.c:82)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init <-- Here

93: Calls vm_page_startup.

97: Calls vm_object_init.

98: Calls vm_map_startup.

99: Calls kmem_init.

100: Calls pmap_init.

101: Calls vm_pager_init.
```

#### vm\_page\_startup (386bsd-0.1/sys/vm/vm\_page.c:144)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
            vm_page_startup <-- Here

192-193: Sets vm_page_bucket_count to log2((end-start)>>12).

202-203: Allocates physical memory for the vm_page buckets
         and maps them into the kernel address space with
         read/write protections.

210-212: Initializes the vm_page bucket queues.

235-239: Allocates 10 vm_map structures and 1500 vm_map_entry
         structures.

246: Maps the vm_map and vm_map_entry structures into the
     kernel address space read/write protections.

257: Calculates the number of pages available to the system
     while taking into account the overhead from the
     corresponding vm_page structures.

265: Assigns the base of the vm_page structures to
     vm_page_array.

266-272: Calculates the physical addresses of the first and
         last page of memory and assigns them to
         first_phys_addr and last_phys_addre respectively.

278: Allocates the vm_page structures and their corresponding
     pages of memory.

279: Maps the vm_page structures and their corresponding pages
     of memory in the kernel address space with read/write
     protections.

288-299: Initializes the vm_page structures, links them with
         with their corresponding page frame, and inserts
         them into the vm_page_queue_free.

308: Returns the new value of virtual_avail.
```

#### vm\_object\_init (386bsd-0.1/sys/vm/vm\_object.c:117)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
            vm_page_startup
            vm_object_init <-- Here

127-128: Initializes the queue of each hash table entry in the
         vm_object_hashtable (vm_object.c:107).

130: Links kernel_boject with the statically defined
     kernel_object_store.

134: Points kmem_object to the statically allocated
     kernel object.
```

#### vm\_map\_startup (/386bsd-0.1/sys/vm/vm\_map.c:138)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
            vm_page_startup
            vm_object_init
            vm_map_startup <-- Here
```

#### kmem\_init (386bsd-0.1/sys/vm/vm\_kern.c:587)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
            vm_page_startup
            vm_object_init
            vm_map_startup
            kmem_init <-- Here

595: Creates a vm_map of the remaining virtual address space
     for the kernel using the first statically allocated
     vm_map structure.

596: Creates a vm_map_entry of the remaining virtual address
     space for the kernel using the first statically
     allocated vm_map_entry structure.
```

#### pmap\_init (386bsd-0.1/sys/i386/i386/pmap.c:312)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
            vm_page_startup
            vm_object_init
            vm_map_startup
            kmem_init
            pmap_init <-- Here

328-335: Marks the kernel page tables and IO memory as
         unavailable. Also note that we increment the
         reference count of kernel_object.

341-344: Allocates the pv_entry array.

345: Assigns the allocated memory to pv_table.

359: Enables pv_table recording by setting pmap_initialized
     to true.
```

#### vm\_pager\_init (386bsd-0.1/sys/vm/vm\_pager.c:115)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
            vm_page_startup
            vm_object_init
            vm_map_startup
            kmem_init
            pmap_init
            vm_pager_init <-- Here

122: Allocates a submap for tracking get/put page mappings.

127-128: Initializes each entry in the pagertab, which
         includes:
          * swappagerops   (/vm/swap_pager.h:98)
          * vnodepagerops  (/vm/vnode_pager.h:67)
          * devicepagerops (/vm/device_pager.h:67)
```

#### swap\_pager\_init (386bsd-0.1/sys/vm/swap\_pager.c:128)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
            vm_page_startup
            vm_object_init
            vm_map_startup
            kmem_init
            pmap_init
            vm_pager_init
                swap_pager_init <-- Here
```

#### vnode\_pager\_init (386bsd-0.1/sys/vm/vnode\_pager.c:79)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
            vm_page_startup
            vm_object_init
            vm_map_startup
            kmem_init
            pmap_init
            vm_pager_init
                swap_pager_init
                vnode_pager_init <-- Here
```

#### dev\_pager\_init (386bsd-0.1/sys/vm/device\_pager.c:69)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
            vm_page_startup
            vm_object_init
            vm_map_startup
            kmem_init
            pmap_init
            vm_pager_init
                swap_pager_init
                vnode_pager_init
                dev_pager_init <-- Here
```

#### kmeminit (386bsd-0.1/sys/kern/kern\_malloc.c:226)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit <-- Here

Ill do this later
```

#### cpu\_startup (386bsd-0.1/sys/i386/i386/machdep.c:100)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup <-- Here

118-119: Maps the message buffers into the kernel's address
         space.

155: Calculates the size of ncallout callout structures.

165-169: Sets bufpages to either 5% or 10% of total physical
         memory.

171-174: Sets nbuf to the minimum of bufpages/2 and 16.

176: Assigns the byte size of bufpages to freebufspace.

177-180: Sets nswbuf to the minimum of nbuf/2 &~1 and 256.

182-183: Calculates the size of nswbuf + nbuf buf structures.

190: Allocates memory for the callout and buf structures.

203-209: Allocates a submap for buffer space allocations and
         physio.

215-219: Allocates a submap for the mbuf pool.

224-225: Initializes the callout structures.
```

#### bufinit (386bsd-0.1/sys/kern/vfs\_\_bio.c:67)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
            bufinit <-- Here

73-76: Initializes the buffer header table (/sys/sys/buf.h:127)
       as empty.

80=85: Initializes the buffer header free list(buf.h:128) as
       empty.

89-94: Initialies each buffer header and inserts them on an
       empty queue.
```

#### configure (386bsd-0.1/sys/i386/i386/autoconf.c:69)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
            bufinit
            configure <-- Here
```

#### isa\_configure (386bsd-0.1/sys/i386/isa/isa.c:157)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
            bufinit
            configure
                isa_configure <-- Here

All isa device tables are located in /sys/compile/GENERICISA/ioconf.c.
```

#### config\_isadev (386bsd-0.1/sys/i386/isa/isa.c:180)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
            bufinit
            configure
                isa_configure
                    config_isadev <-- Here
```

#### setroot (386bsd-0.1/sys/i386/i386/autoconf.c:143)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
            bufinit
            configure
                isa_configure
                setroot <-- Here

153-160: Assigns the boot device's adaptor, partition, unit,
         and partition offset (mindev).

162: Creates the rootdev from the boot device and partition
     offset.

167-168: We assume the boot device will be the same as the
         root device, so this if statement exits the function.
```

#### swapconf (386bsd-0.1/sys/i386/i386/autoconf.c:95)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
            bufinit
            configure
                isa_configure
                setroot
                swapconf <-- Here
```

#### pmap\_pinit (386bsd-0.1/sys/i386/i386/pmap.c:436)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit <-- Here
```

#### pmap\_extract (386bsd-0.1/sys/i386/i386/pmap.c:1136)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
            pmap_extract <-- Here
```

#### vm\_map\_init (386bsd-0.1/sys/vm/vm\_map.c:244)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init <-- Here
```

#### rqinit (386bsd-0.1/sys/kern/kern\_synch.c:503)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit <-- Here

507-508: Initializes the run queues qs (/sys/sys/proc.h:243)
         to be empty, which is equivalent to pointing to
         themselves.
```

#### vm\_init\_limits (386bsd-0.1/sys/vm/vm\_glue.c:239)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits <-- Here

250-254: Sets the data and stack resource limits to their
         default sizes.
```

#### vfsinit (386bsd-0.1/sys/kern/vfs\_subr.c:188)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit <-- Here

200-203: Initializes each virtual filesystem type contained in
         vfssw (/kern/vfs_conf.c:70). The vfssw can include the
         following filesystems:
             * ufs_vfsops (/ufs/ufs_vfsops.c:57)
             * nfs_vfsops (/nfs/nfs_vfsops.c:67)
             * mfs_vfsops
             * isofs_vfsops
```

#### nchinit (386bsd-0.1/sys/kern/vfs\_cache.c:242)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
            nchinit <-- Here

251: Allocates the namecache hash table and assigns it to
     nchashtbl.

253-255: Sets nchash to the size of the namecache hash table
         minus one.

256-258: Initializes nchashtbl as empty (each entry points to
         itself).
```

#### ufs\_init (386bsd-0.1/sys/ufs/ufs\_inode.c:68)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
            nchinit
                ufs_init <-- Here

77-79: Initializes the hash link table defined on line 61
       of ufs_inode.c as empty.
```

#### nfs\_init (386bsd-0.1/sys/nfs/nfs\_subs.c:505)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
            nchinit
                ufs_init
                nfs_init <-- Here
```

#### mbinit (386bsd-0.1/sys/kern/uipc\_mbuf.c:51)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
        mbinit <-- Here
```

#### ifinit (386bsd-0.1/sys/usr/include/net/if.c:62)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
        mbinit
        ifinit <-- Here

66-68: Initializes the ifq_maxlen of each ifnet structure
       linked with ifnet (/usr/include/net/if.h:249).
```

#### domaininit (386bsd-0.1/sys/kern/uipc\_domain.c:51)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
        mbinit
        ifinit
        domaininit <-- Here
```

#### roundrobin (386bsd-0.1/sys/kern/kern\_synch.c:52)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
        mbinit
        ifinit
        domaininit
        roundrobin <-- Here

55: Sets want_resched via need_resched, which is defined as:

    sys/i386/include/cpu.h:#define	need_resched()	{ want_resched++; aston(); }
```

#### timeout (386bsd-0.1/sys/kern/kern\_clock.c:354)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
        mbinit
        ifinit
        domaininit
        roundrobin
            timeout <-- Here
```

#### schedcpu (386bsd-0.1/sys/kern/kern\_synch.c:147)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
        mbinit
        ifinit
        domaininit
        roundrobin
        schedcpu <-- Here
```

#### wakeup (386bsd-0.1/sys/kern\_synch.c:454)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
        mbinit
        ifinit
        domaininit
        roundrobin
        schedcpu
            wakeup <-- Here
```

#### enablertclock (386bsd-0.1/sys/i386/isa/clock.c:201)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
        mbinit
        ifinit
        domaininit
        roundrobin
        schedcpu
        enablertclock <-- Here
```

#### nfs\_mountroot (386bsd-0.1/sys/nfs/nfs\_vfsops.c:152)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
        mbinit
        ifinit
        domaininit
        roundrobin
        schedcpu
        enablertclock
        nfs_mountroot <-- Here
```

#### swapinit (386bsd-0.1/sys/vm/vm\_swap.c:62)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
        mbinit
        ifinit
        domaininit
        roundrobin
        schedcpu
        enablertclock
        nfs_mountroot
        swapinit <-- Here
```

#### siginit (386bsd-0.1/sys/kern/kern\_sig.c:170)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
        mbinit
        ifinit
        domaininit
        roundrobin
        schedcpu
        enablertclock
        nfs_mountroot
        swapinit
        siginit <-- Here
```

#### sched (386bsd-0.1/sys/vm/vm\_glue.c:275)

```txt
Control Flow:
start
    init386
    main
        startrtclock
        vm_mem_init
        kmeminit
        cpu_startup
        pmap_pinit
        vm_map_init
        rqinit
        vm_init_limits
        vfsinit
        mbinit
        ifinit
        domaininit
        roundrobin
        schedcpu
        enablertclock
        nfs_mountroot
        swapinit
        siginit
        sched <-- Here
```

