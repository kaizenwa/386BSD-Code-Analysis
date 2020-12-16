# Walkthrough of 386BSD's Memory Map System Call

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
smmap
	vm_mmap
		vm_pager_allocate
			vnode_pager_alloc
				vm_object_allocate
					_vm_object_allocate
		vm_object_lookup
		vm_allocate_with_pager
		pager_cache
		vm_map_find
			vm_map_lookup_entry
			vm_map_insert
		vm_map_create
			vm_map_init
		vm_map_copy
		vm_map_lookup
		vm_map_lookup_done
		vm_object_pmap_copy
		vm_map_deallocate
		vm_map_protect
		vm_inherit
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

The first '+' means that I have read the code or have a general idea of what it does.
The second '+' means that I have read the code closely and heavily commented it.
The third '+' means that I have added it to this document's code walkthrough.

```txt
File: vm_mmap.c
	smmap
	vm_mmap
	vm_allocate_with_pager

File: vm_pager.c
	vm_pager_allocate
	pager_cache

File: vnode_pager.c
	vnode_pager_alloc

File: vm_object.c
	vm_object_allocate
	_vm_object_allocate
	vm_object_enter
	vm_object_setpager
	vm_object_lookup
	vm_object_pmap_copy

File: vm_map.c
	vm_map_find
	vm_map_lookup_entry
	vm_map_insert
	vm_map_create
	vm_map_init
	vm_map_copy
	vm_map_lookup
	vm_map_lookup_done
	vm_map_deallocate
	vm_map_protect
```

## Important Data Structures


## Code Walkthrough

```c
```
