# Walkthrough of 386BSD's Open System Call

## Contents

1. Code Flow
2. Reading Checklist
3. Important Data Structures
4. Code Walkthrough

## Code Flow

```txt
open
	falloc
		fdalloc
			MALLOC
	vn_open
		namei
			copystr
			copyinstr
				fubyte
			lookup
				ufs_lookup
		ufs_create
		ufs_open
	VOP_UNLOCK
```

## Reading Checklist

This section lists the relevant functions for the walkthrough by filename,
where each function per filename is listed in the order that it is called.

The first '+' means that I have read the code or have a general idea of what it does.
The second '+' means that I have read the code closely and heavily commented it.
The third '+' means that I have added it to this document's code walkthrough.

```txt
File: vfs_syscalls.c
	open					+++

File: kern_descrip.c
	falloc					++-
	fdalloc					++-

File: vfs_vnops.c
	vn_open					+++

File: vfs_lookup.c
	namei					+++
	lookup					+++

File: machdep.c
	copystr					++-
	copyinstr				++-

File: locore.s
	fubyte					++-

File: ufs_lookup.c
	ufs_lookup				+++
	ufs_open				+++
```

## Important Data Structures

### *filedesc* Structure

```c
struct filedesc {
	struct	file **fd_ofiles;	/* file structures for open files */
	char	*fd_ofileflags;		/* per-process open file flags */
	struct	vnode *fd_cdir;		/* current directory */
	struct	vnode *fd_rdir;		/* root directory */
	int	fd_nfiles;		/* number of open files allocated */
	u_short	fd_lastfile;		/* high-water mark of fd_ofiles */
	u_short	fd_freefile;		/* approx. next free file */
	u_short	fd_cmask;		/* mask for file creation */
	u_short	fd_refcnt;		/* reference count */
};
```

### *file* Structure

```c
/*
 * Kernel descriptor table.
 * One entry for each open kernel vnode and socket.
 */
struct file {
	struct	file *f_filef;	/* list of active files */
	struct	file **f_fileb;	/* list of active files */
	short	f_flag;		/* see fcntl.h */
#define	DTYPE_VNODE	1	/* file */
#define	DTYPE_SOCKET	2	/* communications endpoint */
	short	f_type;		/* descriptor type */
	short	f_count;	/* reference count */
	short	f_msgcount;	/* references from message queue */
	struct	ucred *f_cred;	/* credentials associated with descriptor */
	struct	fileops {
		int	(*fo_read)	__P((struct file *fp, struct uio *uio,
					    struct ucred *cred));
		int	(*fo_write)	__P((struct file *fp, struct uio *uio,
					    struct ucred *cred));
		int	(*fo_ioctl)	__P((struct file *fp, int com,
					    caddr_t data, struct proc *p));
		int	(*fo_select)	__P((struct file *fp, int which,
					    struct proc *p));
		int	(*fo_close)	__P((struct file *fp, struct proc *p));
	} *f_ops;
	off_t	f_offset;
	caddr_t	f_data;		/* vnode or socket */
};
```

### *vnode* Structure

```c
/* From /sys/sys/vnode.h */

struct vnode {
	u_long		v_flag;			/* vnode flags (see below) */
	short		v_usecount;		/* reference count of users */
	short		v_writecount;		/* reference count of writers */
	long		v_holdcnt;		/* page & buffer references */
	off_t		v_lastr;		/* last read (read-ahead) */
	u_long		v_id;			/* capability identifier */
	struct mount	*v_mount;		/* ptr to vfs we are in */
	struct vnodeops	*v_op;			/* vnode operations */
	struct vnode	*v_freef;		/* vnode freelist forward */
	struct vnode	**v_freeb;		/* vnode freelist back */
	struct vnode	*v_mountf;		/* vnode mountlist forward */
	struct vnode	**v_mountb;		/* vnode mountlist back */
	struct buf	*v_cleanblkhd;		/* clean blocklist head */
	struct buf	*v_dirtyblkhd;		/* dirty blocklist head */
	long		v_numoutput;		/* num of writes in progress */
	enum vtype	v_type;			/* vnode type */
	union {
		struct mount	*vu_mountedhere;/* ptr to mounted vfs (VDIR) */
		struct socket	*vu_socket;	/* unix ipc (VSOCK) */
		caddr_t		vu_vmdata;	/* private data for vm (VREG) */
		struct specinfo	*vu_specinfo;	/* device (VCHR, VBLK) */
		struct fifoinfo	*vu_fifoinfo;	/* fifo (VFIFO) */
	} v_un;
	enum vtagtype	v_tag;			/* type of underlying data */
	char v_data[VN_MAXPRIVATE];		/* private data for fs */
};
#define	v_mountedhere	v_un.vu_mountedhere
#define	v_socket	v_un.vu_socket
#define	v_vmdata	v_un.vu_vmdata
#define	v_specinfo	v_un.vu_specinfo
#define	v_fifoinfo	v_un.vu_fifoinfo
```

### *mount* Structure

```c
/*
 * Structure per mounted file system.
 * Each mounted file system has an array of
 * operations and an instance record.
 * The file systems are put on a doubly linked list.
 */
struct mount {
	struct mount	*mnt_next;		/* next in mount list */
	struct mount	*mnt_prev;		/* prev in mount list */
	struct vfsops	*mnt_op;		/* operations on fs */
	struct vnode	*mnt_vnodecovered;	/* vnode we mounted on */
	struct vnode	*mnt_mounth;		/* list of vnodes this mount */
	int		mnt_flag;		/* flags */
	uid_t		mnt_exroot;		/* exported mapping for uid 0 */
	struct statfs	mnt_stat;		/* cache of filesystem stats */
	qaddr_t		mnt_data;		/* private data */
};
```

### *vnodeops* Structure

```c
/* From /sys/ufs/ufs_vnops.c */

/*
 * Global vfs data structures for ufs
 */
struct vnodeops ufs_vnodeops = {
	ufs_lookup,		/* lookup */
	ufs_create,		/* create */
	ufs_mknod,		/* mknod */
	ufs_open,		/* open */
	ufs_close,		/* close */
	ufs_access,		/* access */
	ufs_getattr,		/* getattr */
	ufs_setattr,		/* setattr */
	ufs_read,		/* read */
	ufs_write,		/* write */
	ufs_ioctl,		/* ioctl */
	ufs_select,		/* select */
	ufs_mmap,		/* mmap */
	ufs_fsync,		/* fsync */
	ufs_seek,		/* seek */
	ufs_remove,		/* remove */
	ufs_link,		/* link */
	ufs_rename,		/* rename */
	ufs_mkdir,		/* mkdir */
	ufs_rmdir,		/* rmdir */
	ufs_symlink,		/* symlink */
	ufs_readdir,		/* readdir */
	ufs_readlink,		/* readlink */
	ufs_abortop,		/* abortop */
	ufs_inactive,		/* inactive */
	ufs_reclaim,		/* reclaim */
	ufs_lock,		/* lock */
	ufs_unlock,		/* unlock */
	ufs_bmap,		/* bmap */
	ufs_strategy,		/* strategy */
	ufs_print,		/* print */
	ufs_islocked,		/* islocked */
	ufs_advlock,		/* advlock */
};
```

### *namei* Structure

```c
/*
 * Encapsulation of namei parameters.
 */
struct nameidata {
	/*
	 * Arguments to namei.
	 */
	caddr_t	ni_dirp;		/* pathname pointer */
	enum	uio_seg ni_segflg;	/* location of pathname */
	u_long	ni_nameiop;		/* see below */
	/*
	 * Arguments to lookup.
	 */
	struct	ucred *ni_cred;		/* credentials */
	struct	vnode *ni_startdir;	/* starting directory */
	struct	vnode *ni_rootdir;	/* logical root directory */
	/*
	 * Results
	 */
	struct	vnode *ni_vp;		/* vnode of result */
	struct	vnode *ni_dvp;		/* vnode of intermediate directory */
	/*
	 * Shared between namei, lookup routines, and commit routines.
	 */
	char	*ni_pnbuf;		/* pathname buffer */
	long	ni_pathlen;		/* remaining chars in path */
	char	*ni_ptr;		/* current location in pathname */
	long	ni_namelen;		/* length of current component */
	char	*ni_next;		/* next location in pathname */
	u_long	ni_hash;		/* hash value of current component */
	u_char	ni_loopcnt;		/* count of symlinks encountered */
	u_char	ni_makeentry;		/* 1 => add entry to name cache */
	u_char	ni_isdotdot;		/* 1 => current component name is .. */
	u_char	ni_more;		/* 1 => symlink needs interpretation */
	/*
	 * Side effects.
	 */
	struct ufs_specific {		/* saved info for new dir entry */
		off_t	ufs_endoff;	/* end of useful directory contents */
		long	ufs_offset;	/* offset of free space in directory */
		long	ufs_count;	/* size of free slot in directory */
		ino_t	ufs_ino;	/* inode number of found directory */
		u_long	ufs_reclen;	/* size of found directory entry */
	} ni_ufs;
};
```

## Code Walkthrough

### Pseudo Code Overview

**open**:

**falloc**:

**fdalloc**:

**vn_open**:

**namei**:

**lookup**:

**ufs_lookup**:

**ufs_create**:

**ufs_open**:

**ufs_unlock**:

### Documented Code

```c
/*
 * Open system call.
 * Check permissions, allocate an open file structure,
 * and call the device open routine if any.
 */
open(p, uap, retval)
	struct proc *p;
	register struct args {
		char	*fname;
		int	mode;
		int	crtmode;
	} *uap;
	int *retval;
{
	struct nameidata *ndp;
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;
	register struct vnode *vp;
	int fmode, cmode;
	struct file *nfp;
	int type, indx, error;
	struct flock lf;
	struct nameidata nd;
	extern struct fileops vnops;

	if (error = falloc(p, &nfp, &indx))
		return (error);
	fp = nfp;

	/* Copy file flags from arg */
	fmode = FFLAGS(uap->mode);

	/* S_ISVTX = save swapped text even after use */
	cmode = ((uap->crtmode &~ fdp->fd_cmask) & 07777) &~ S_ISVTX;

	/* Point ndp to stack allocated namei data structure */
	ndp = &nd;

	/* I/O originating from user space */
	ndp->ni_segflg = UIO_USERSPACE;

	/* Set dirp to the path arg */
	ndp->ni_dirp = uap->fname;
	p->p_dupfd = -indx - 1;			/* XXX check for fdopen */

	/* Call vn_open by passing the stack allocated args */
	if (error = vn_open(ndp, p, fmode, cmode)) {
		ffree(fp);
		if (error == ENODEV &&		/* XXX from fdopen */
		    p->p_dupfd >= 0 &&
		    (error = dupfdopen(fdp, indx, p->p_dupfd, fmode)) == 0) {
			*retval = indx;
			return (0);
		}
		if (error == ERESTART)
			error = EINTR;
		fdp->fd_ofiles[indx] = NULL;
		return (error);
	}
	/* Assign vp to the newly created vnode */
	vp = ndp->ni_vp;
	fp->f_flag = fmode & FMASK;

	/* If we have a lock on the file, set the file lock's fields */
	if (fmode & (O_EXLOCK | O_SHLOCK)) {
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		if (fmode & O_EXLOCK)
			/* Exclusive locks are write locks */
			lf.l_type = F_WRLCK;
		else
			lf.l_type = F_RDLCK;
		type = F_FLOCK;
		if ((fmode & FNONBLOCK) == 0)
			type |= F_WAIT;
		if (error = VOP_ADVLOCK(vp, (caddr_t)fp, F_SETLK, &lf, type)) {
			VOP_UNLOCK(vp);
			(void) vn_close(vp, fp->f_flag, fp->f_cred, p);
			ffree(fp);
			fdp->fd_ofiles[indx] = NULL;
			return (error);
		}
		fp->f_flag |= FHASLOCK;
	}
	VOP_UNLOCK(vp);
	fp->f_type = DTYPE_VNODE;

	/* Assign vnops as the file's fileops */
	fp->f_ops = &vnops;
	fp->f_data = (caddr_t)vp;

	/* Assign the opened file's fd as the return value and return */
	*retval = indx;
	return (0);
}

/*
 * Common code for vnode open operations.
 * Check permissions, and call the VOP_OPEN or VOP_CREATE routine.
 */
vn_open(ndp, p, fmode, cmode)
	register struct nameidata *ndp;
	struct proc *p;
	int fmode, cmode;
{
	register struct vnode *vp;
	register struct ucred *cred = p->p_ucred;
	struct vattr vat;
	struct vattr *vap = &vat;
	int error;

	/* Creating a File Case: */
	if (fmode & O_CREAT) {
		/*
		 * Set the namei operation for creation. Lock the parent
		 * and the child by default. 
		 */
		ndp->ni_nameiop = CREATE | LOCKPARENT | LOCKLEAF;
		if ((fmode & O_EXCL) == 0)
			ndp->ni_nameiop |= FOLLOW;

		/*
		 * Call namei to retrieve the vnode of the path. Since we 
		 * are creating a new file, namei should return NULL unless
		 * the file already exists.
		 */
		if (error = namei(ndp, p))
			return (error);

		/* The file doesn't exist as expected, so we create it */
		if (ndp->ni_vp == NULL) {
			/* Create a vnode attributes structure */
			VATTR_NULL(vap);

			/* Initialize vnode attrs */
			vap->va_type = VREG;
			vap->va_mode = cmode;

			/* Call ufs_create to create a new file */
			if (error = VOP_CREATE(ndp, vap, p))
				return (error);
			fmode &= ~O_TRUNC;

			/* Set vp to NULL for future use in ufs_open */
			vp = ndp->ni_vp;
		} /* The file already exists, set EEXIST and return */
		  else {
			VOP_ABORTOP(ndp);

			/* Release locks on the parent directory */
			if (ndp->ni_dvp == ndp->ni_vp)
				vrele(ndp->ni_dvp);
			else
				vput(ndp->ni_dvp);
			ndp->ni_dvp = NULL;
			vp = ndp->ni_vp;

			/* If wanted an exclusive open, set EEXIST and return */
			if (fmode & O_EXCL) {
				error = EEXIST;
				goto bad;
			}
			/* Clear the create flag since the file already exists */
			fmode &= ~O_CREAT;
		}
	} /* Looking Up a File Case: */
	  else {
		ndp->ni_nameiop = LOOKUP | FOLLOW | LOCKLEAF;
		if (error = namei(ndp, p))
			return (error);
		vp = ndp->ni_vp;
	}

	/* We don't support opening sockets with open */
	if (vp->v_type == VSOCK) {
		error = EOPNOTSUPP;
		goto bad;
	}

	/*
	 * If namei did a lookup operation, check if the
	 * file permissions match the open permissions.
	 */
	if ((fmode & O_CREAT) == 0) {
		/* Check read permissions */
		if (fmode & FREAD) {
			if (error = VOP_ACCESS(vp, VREAD, cred, p))
				goto bad;
		}
		if (fmode & (FWRITE | O_TRUNC)) {
			/* We cannot open directories for writing */
			if (vp->v_type == VDIR) {
				error = EISDIR;
				goto bad;
			}
			/* Check write permissions */
			if ((error = vn_writechk(vp)) ||
			    (error = VOP_ACCESS(vp, VWRITE, cred, p)))
				goto bad;
		}
	}
	/*
	 * If the file mode is set to truncate, set its
	 * size to 0.
	 */
	if (fmode & O_TRUNC) {
		VATTR_NULL(vap);
		vap->va_size = 0;
		if (error = VOP_SETATTR(vp, vap, cred, p))
			goto bad;
	}
	/* Call ufs_open to open the actual file */
	if (error = VOP_OPEN(vp, fmode, cred, p))
		goto bad;
	if (fmode & FWRITE)
		vp->v_writecount++;
	return (0);
bad:
	vput(vp);
	return (error);
}

/*
 * Convert a pathname into a pointer to a locked inode.
 *
 * The FOLLOW flag is set when symbolic links are to be followed
 * when they occur at the end of the name translation process.
 * Symbolic links are always followed for all other pathname
 * components other than the last.
 *
 * The segflg defines whether the name is to be copied from user
 * space or kernel space.
 *
 * Overall outline of namei:
 *
 *	copy in name
 *	get starting directory
 *	while (!done && !error) {
 *		call lookup to search path.
 *		if symbolic link, massage name in buffer and continue
 *	}
 */
namei(ndp, p)
	register struct nameidata *ndp;
	struct proc *p;
{
	register struct filedesc *fdp;	/* pointer to file descriptor state */
	register char *cp;				/* pointer into pathname argument */
	register struct vnode *dp;		/* the directory we are searching */
	struct iovec aiov;				/* uio for reading symbolic links */
	struct uio auio;
	int error, linklen;

	ndp->ni_cred = p->p_ucred;
	fdp = p->p_fd;

	/*
	 * Get a buffer for the name to be translated, and copy the
	 * name into the buffer.
	 */
	if ((ndp->ni_nameiop & HASBUF) == 0)
		MALLOC(ndp->ni_pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);

	/*
	 * Copy the pathname from the namei data structure to the allocated
	 * buffer.
	 */
	if (ndp->ni_segflg == UIO_SYSSPACE)
		error = copystr(ndp->ni_dirp, ndp->ni_pnbuf,
			    MAXPATHLEN, &ndp->ni_pathlen);
	else
		error = copyinstr(ndp->ni_dirp, ndp->ni_pnbuf,
			    MAXPATHLEN, &ndp->ni_pathlen);

	/*
	 * Free the buffer and return the error if we could not copy the 
	 * pathname to the buffer.
	 */
	if (error) {
		free(ndp->ni_pnbuf, M_NAMEI);
		ndp->ni_vp = NULL;
		return (error);
	}

	/* Initialize to loop count to detect sym link loops */
	ndp->ni_loopcnt = 0;
#ifdef KTRACE
	if (KTRPOINT(p, KTR_NAMEI))
		ktrnamei(p->p_tracep, ndp->ni_pnbuf);
#endif
	/*
	 * Get starting point for the translation.
	 *
	 * If the filedesc's root dir is NULL, we use the
	 * absolute root directory as the starting point.
	 */
	if ((ndp->ni_rootdir = fdp->fd_rdir) == NULL)
		ndp->ni_rootdir = rootdir;

	/* Set dir ptr to the filedesc's curr dir */
	dp = fdp->fd_cdir;
	VREF(dp);

	for (;;) {
		/*
		 * Check if root directory should replace current directory.
		 * Done at start of translation and after symbolic link.
		 */
		/* Set namei pathname ptr to the namei pathname buf */
		ndp->ni_ptr = ndp->ni_pnbuf;

		/* Handle '/' in an absolute pathname */
		if (*ndp->ni_ptr == '/') {
			vrele(dp);
			/* Skip all forward slashes in the pathname */
			while (*ndp->ni_ptr == '/') {
				ndp->ni_ptr++;
				ndp->ni_pathlen--;
			}
			/* Set dir ptr to the rootdir and obtain a ref */
			dp = ndp->ni_rootdir;
			VREF(dp);
		}

		/* Assign the starting directory */
		ndp->ni_startdir = dp;

		/*
		 * Call lookup to descend through the pathname and return
		 * when it is either completed or we encounter a sym link.
		 */
		if (error = lookup(ndp, p)) {
			FREE(ndp->ni_pnbuf, M_NAMEI);
			return (error);
		}
		/*
		 * Check for symbolic link
		 */
		/*
		 * If ni_more is clear, we finished looking up the pathname
		 * and are done.
		 */
		if (ndp->ni_more == 0) {
			/*
			 * If SAVENAME or SAVESTART aren't set we can free the pathname
			 * buffer and return to evaluate the sym link. Otherwise, we
			 * set HASBUF and return.
			 */
			if ((ndp->ni_nameiop & (SAVENAME | SAVESTART)) == 0)
				FREE(ndp->ni_pnbuf, M_NAMEI);
			else
				ndp->ni_nameiop |= HASBUF;
			return (0);
		}

		/* Handle '.' case when LOCKPARENT is set. Don't want to lock twice */
		if ((ndp->ni_nameiop & LOCKPARENT) && ndp->ni_pathlen == 1)
			VOP_UNLOCK(ndp->ni_dvp);

		/* If we are in a sym link loop, set ELOOP and break */
		if (ndp->ni_loopcnt++ >= MAXSYMLINKS) {
			error = ELOOP;
			break;
		}

		/*
		 * Allocate a new buf for all pathnames > 1 char so that
		 * we can read in the sym link and append the remaining
		 * characters in the pathname to it.
		 * 
		 * Otherwise, we use the existing buffer. 
		 */
		if (ndp->ni_pathlen > 1)
			MALLOC(cp, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
		else
			cp = ndp->ni_pnbuf;
		/*
		 * Initialize the stack allocated iovec and uio data structs.
		 * We use proc 0 and set resid to MAXPATHLEN.
		 */
		aiov.iov_base = cp;
		aiov.iov_len = MAXPATHLEN;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_procp = (struct proc *)0;
		auio.uio_resid = MAXPATHLEN;

		/*
		 * Call ufs_readlink to copy in the contents of the sym link
		 * into the buffer.
		 */
		if (error = VOP_READLINK(ndp->ni_vp, &auio, p->p_ucred)) {
			if (ndp->ni_pathlen > 1)
				free(cp, M_NAMEI);
			break;
		}
		/*
		 * Calculate the length of the sym link's contents and
		 * determine if there is enough space to fit it in a
		 * MAXPATHLEN buffer with the remainder of the pathname
		 * appended.
		 */
		linklen = MAXPATHLEN - auio.uio_resid;

		/* If the sym link's contents are too long, return ENAMETOOLONG */
		if (linklen + ndp->ni_pathlen >= MAXPATHLEN) {
			if (ndp->ni_pathlen > 1)
				free(cp, M_NAMEI);
			error = ENAMETOOLONG;
			break;
		}
		/* Copy the remainder of the pathname to the buffer for non trivial
		 * pathnames. Otherwise, overwrite "." pathnames with '\0'.
		if (ndp->ni_pathlen > 1) {
			bcopy(ndp->ni_next, cp + linklen, ndp->ni_pathlen);
			FREE(ndp->ni_pnbuf, M_NAMEI);
			ndp->ni_pnbuf = cp;
		} else
			ndp->ni_pnbuf[linklen] = '\0';
		ndp->ni_pathlen += linklen;
		vput(ndp->ni_vp);
		dp = ndp->ni_dvp;
	}
	/*
	 * We make it here if either there was an error or we did not
	 * find a vnode.
	 */
	FREE(ndp->ni_pnbuf, M_NAMEI);
	vrele(ndp->ni_dvp);
	vput(ndp->ni_vp);

	/* Set the namei vp to NULL */
	ndp->ni_vp = NULL;
	return (error);
}

/*
 * Search a pathname.
 * This is a very central and rather complicated routine.
 *
 * The pathname is pointed to by ni_ptr and is of length ni_pathlen.
 * The starting directory is taken from ni_startdir. The pathname is
 * descended until done, or a symbolic link is encountered. The variable
 * ni_more is clear if the path is completed; it is set to one if a
 * symbolic link needing interpretation is encountered.
 *
 * The flag argument is LOOKUP, CREATE, RENAME, or DELETE depending on
 * whether the name is to be looked up, created, renamed, or deleted.
 * When CREATE, RENAME, or DELETE is specified, information usable in
 * creating, renaming, or deleting a directory entry may be calculated.
 * If flag has LOCKPARENT or'ed into it, the parent directory is returned
 * locked. If flag has WANTPARENT or'ed into it, the parent directory is
 * returned unlocked. Otherwise the parent directory is not returned. If
 * the target of the pathname exists and LOCKLEAF is or'ed into the flag
 * the target is returned locked, otherwise it is returned unlocked.
 * When creating or renaming and LOCKPARENT is specified, the target may not
 * be ".".  When deleting and LOCKPARENT is specified, the target may be ".".
 * NOTE: (LOOKUP | LOCKPARENT) currently returns the parent vnode unlocked.
 * 
 * Overall outline of lookup:
 *
 * dirloop:
 *	identify next component of name at ndp->ni_ptr
 *	handle degenerate case where name is null string
 *	if .. and crossing mount points and on mounted filesys, find parent
 *	call VOP_LOOKUP routine for next component name
 *	    directory vnode returned in ni_dvp, unlocked unless LOCKPARENT set
 *	    component vnode returned in ni_vp (if it exists), locked.
 *	if result vnode is mounted on and crossing mount points,
 *	    find mounted on vnode
 *	if more components of name, do next level at dirloop
 *	return the answer in ni_vp, locked if LOCKLEAF set
 *	    if LOCKPARENT set, return locked parent in ni_dvp
 *	    if WANTPARENT set, return unlocked parent in ni_dvp
 */
lookup(ndp, p)
	register struct nameidata *ndp;
	struct proc *p;
{
	register char *cp;				/* pointer into pathname argument */
	register struct vnode *dp = 0;	/* the directory we are searching */
	struct vnode *tdp;				/* saved dp */
	struct mount *mp;				/* mount table entry */
	int docache;					/* == 0 do not cache last component */
	int flag;						/* LOOKUP, CREATE, RENAME or DELETE */
	int wantparent;					/* 1 => wantparent or lockparent flag */
	int rdonly;						/* mounted read-only flag bit(s) */
	int error = 0;

	/*
	 * Setup: break out flag bits into variables.
	 */
	flag = ndp->ni_nameiop & OPMASK;
	wantparent = ndp->ni_nameiop & (LOCKPARENT|WANTPARENT);
	docache = (ndp->ni_nameiop & NOCACHE) ^ NOCACHE;
	if (flag == DELETE || (wantparent && flag != CREATE))
		docache = 0;
	rdonly = MNT_RDONLY;
	if (ndp->ni_nameiop & REMOTE)
		rdonly |= MNT_EXRDONLY;
	ndp->ni_dvp = NULL;
	ndp->ni_more = 0;
	dp = ndp->ni_startdir;
	ndp->ni_startdir = NULLVP;
	VOP_LOCK(dp);

dirloop:
	/*
	 * Search a new directory.
	 *
	 * The ni_hash value is for use by vfs_cache.
	 * The last component of the filename is left accessible via
	 * ndp->ptr for callers that need the name. Callers needing
	 * the name set the SAVENAME flag. When done, they assume
	 * responsibility for freeing the pathname buffer.
	 */
	ndp->ni_hash = 0;

	/* Obtain the length of the next component */
	for (cp = ndp->ni_ptr; *cp != 0 && *cp != '/'; cp++)
		ndp->ni_hash += (unsigned char)*cp;
	ndp->ni_namelen = cp - ndp->ni_ptr;

	/* Handle component name that is too large */
	if (ndp->ni_namelen >= NAME_MAX) {
		error = ENAMETOOLONG;
		goto bad;
	}

	/* Decr component length from pathname len */
	ndp->ni_pathlen -= ndp->ni_namelen;

	/* Set the ptr to the next component */
	ndp->ni_next = cp;
	ndp->ni_makeentry = 1;

	if (*cp == '\0' && docache == 0)
		ndp->ni_makeentry = 0;

	/* Is the component the parent dir? */
	ndp->ni_isdotdot = (ndp->ni_namelen == 2 &&
		ndp->ni_ptr[1] == '.' && ndp->ni_ptr[0] == '.');
	/*
	 * Check for degenerate name (e.g. / or "")
	 * which is a way of talking about a directory,
	 * e.g. like "/." or ".".
	 */
	if (ndp->ni_ptr[0] == '\0') {
		/* Cannot RENAME, CREATE, or DELETE an empty pathname */
		if (flag != LOOKUP || wantparent) {
			error = EISDIR;
			goto bad;
		}
		if (dp->v_type != VDIR) {
			error = ENOTDIR;
			goto bad;
		}
		/* Unlock the leaf node if necessary */
		if (!(ndp->ni_nameiop & LOCKLEAF))
			VOP_UNLOCK(dp);
		ndp->ni_vp = dp;
		if (ndp->ni_nameiop & SAVESTART)
			panic("lookup: SAVESTART");
		return (0);
	}
	/*
	 * Handle "..": two special cases.
	 * 1. If at root directory (e.g. after chroot)
	 *    then ignore it so can't get out.
	 * 2. If this vnode is the root of a mounted
	 *    filesystem, then replace it with the
	 *    vnode which was mounted on so we take the
	 *    .. in the other file system.
	 */
	if (ndp->ni_isdotdot) {
		for (;;) {
			/*  chrooted root dir  || absolute root dir */
			if (dp == ndp->ni_rootdir || dp == rootdir) {
				ndp->ni_dvp = dp;
				ndp->ni_vp = dp;
				VREF(dp);
				goto nextname;
			}

			/* Break if dp is not a root dir or we set NOCROSSMOUNT */
			if ((dp->v_flag & VROOT) == 0 ||
			    (ndp->ni_nameiop & NOCROSSMOUNT))
				break;

			/* Save current dir ptr */
			tdp = dp;

			/* Obtain the vnode of the filesystem we are mounted on. */
			dp = dp->v_mount->mnt_vnodecovered;
			vput(tdp);

			/* Acquire a reference and lock on the mountpoint vnode */
			VREF(dp);
			VOP_LOCK(dp);
		}
	}
	/*
	 * We now have a segment name to search for, and a directory to search.
	 * 
	 * Call ufs_lookup to obtain the vnode of the component.
	 */
	if (error = VOP_LOOKUP(dp, ndp, p)) {
	/*
	 * We make it inside the loop if ufs_lookup did not a vnode.
	 */
		if (flag == LOOKUP || flag == DELETE ||
		    error != ENOENT || *cp != 0)
			goto bad;
		/*
		 * If creating and at end of pathname, then can consider
		 * allowing file to be created.
		 */
		if (ndp->ni_dvp->v_mount->mnt_flag & rdonly) {
			error = EROFS;
			goto bad;
		}
		/*
		 * We return with ni_vp NULL to indicate that the entry
		 * doesn't currently exist, leaving a pointer to the
		 * (possibly locked) directory inode in ndp->ni_dvp.
		 */
		if (ndp->ni_nameiop & SAVESTART) {
			ndp->ni_startdir = ndp->ni_dvp;
			VREF(ndp->ni_startdir);
		}
		return (0);
	}
	/*
	 * We make it here if ufs_lookup found the vnode of the component.
	 */
	dp = ndp->ni_vp;
	/*
	 * Check for symbolic link. Set ni_more and return 0 if the vnode
	 * we just found is a sym link.
	 */
	if ((dp->v_type == VLNK) &&
	    ((ndp->ni_nameiop & FOLLOW) || *ndp->ni_next == '/')) {
		ndp->ni_more = 1;
		return (0);
	}
	/*
	 * Check to see if the vnode has been mounted on;
	 * if so find the root of the mounted file system.
	 */
mntloop:
	while (dp->v_type == VDIR && (mp = dp->v_mountedhere) &&
	       (ndp->ni_nameiop & NOCROSSMOUNT) == 0)
	{
		while(mp->mnt_flag & MNT_MLOCK) {
			mp->mnt_flag |= MNT_MWAIT;
			sleep((caddr_t)mp, PVFS);
			goto mntloop;
		}
		/*
		 * Call VFS_ROOT to obtain the root of the mounted
		 * filesystem.
		 */
		if (error = VFS_ROOT(dp->v_mountedhere, &tdp))
			goto bad2;
		vput(dp);
		ndp->ni_vp = dp = tdp;
	}

nextname:
	/*
	 * Not a symbolic link.  If more pathname,
	 * continue at next component, else return.
	 */
	if (*ndp->ni_next == '/') {
		ndp->ni_ptr = ndp->ni_next;
		while (*ndp->ni_ptr == '/') {
			ndp->ni_ptr++;
			ndp->ni_pathlen--;
		}
		vrele(ndp->ni_dvp);
		goto dirloop;
	}
	/*
	 * Check for read-only file systems.
	 */
	if (flag == DELETE || flag == RENAME) {
		/*
		 * Disallow directory write attempts on read-only
		 * file systems.
		 */
		if ((dp->v_mount->mnt_flag & rdonly) ||
		    (wantparent && (ndp->ni_dvp->v_mount->mnt_flag & rdonly))) {
			error = EROFS;
			goto bad2;
		}
	}
	/* Save the parent dir ptr for SAVESTART */
	if (ndp->ni_nameiop & SAVESTART) {
		ndp->ni_startdir = ndp->ni_dvp;
		VREF(ndp->ni_startdir);
	}
	if (!wantparent)
		vrele(ndp->ni_dvp);
	if ((ndp->ni_nameiop & LOCKLEAF) == 0)
		VOP_UNLOCK(dp);
	return (0);

bad2:
	if ((ndp->ni_nameiop & LOCKPARENT) && *ndp->ni_next == '\0')
		VOP_UNLOCK(ndp->ni_dvp);
	vrele(ndp->ni_dvp);
bad:
	vput(dp);
	ndp->ni_vp = NULL;
	return (error);
}

/*
 * Convert a component of a pathname into a pointer to a locked inode.
 * This is a very central and rather complicated routine.
 * If the file system is not maintained in a strict tree hierarchy,
 * this can result in a deadlock situation (see comments in code below).
 *
 * The flag argument is LOOKUP, CREATE, RENAME, or DELETE depending on
 * whether the name is to be looked up, created, renamed, or deleted.
 * When CREATE, RENAME, or DELETE is specified, information usable in
 * creating, renaming, or deleting a directory entry may be calculated.
 * If flag has LOCKPARENT or'ed into it and the target of the pathname
 * exists, lookup returns both the target and its parent directory locked.
 * When creating or renaming and LOCKPARENT is specified, the target may
 * not be ".".  When deleting and LOCKPARENT is specified, the target may
 * be "."., but the caller must check to ensure it does an vrele and iput
 * instead of two iputs.
 *
 * Overall outline of ufs_lookup:
 *
 *	check accessibility of directory
 *	look for name in cache, if found, then if at end of path
 *	  and deleting or creating, drop it, else return name
 *	search for name in directory, to found or notfound
 * notfound:
 *	if creating, return locked directory, leaving info on available slots
 *	else return error
 * found:
 *	if at end of path and deleting, return information to allow delete
 *	if at end of path and rewriting (RENAME and LOCKPARENT), lock target
 *	  inode and return info to allow rewrite
 *	if not at end, add name to cache; if at end and neither creating
 *	  nor deleting, add name to cache
 *
 * NOTE: (LOOKUP | LOCKPARENT) currently returns the parent inode unlocked.
 */
ufs_lookup(vdp, ndp, p)
	register struct vnode *vdp;
	register struct nameidata *ndp;
	struct proc *p;
{
	register struct inode *dp;	/* the directory we are searching */
	register struct fs *fs;		/* file system that directory is in */
	struct buf *bp = 0;		/* a buffer of directory entries */
	register struct direct *ep;	/* the current directory entry */
	int entryoffsetinblock;		/* offset of ep in bp's buffer */
	enum {NONE, COMPACT, FOUND} slotstatus;
	int slotoffset = -1;		/* offset of area with free space */
	int slotsize;			/* size of area at slotoffset */
	int slotfreespace;		/* amount of space free in slot */
	int slotneeded;			/* size of the entry we're seeking */
	int numdirpasses;		/* strategy for directory search */
	int endsearch;			/* offset to end directory search */
	int prevoff;			/* ndp->ni_ufs.ufs_offset of previous entry */
	struct inode *pdp;		/* saved dp during symlink work */
	struct inode *tdp;		/* returned by iget */
	off_t enduseful;		/* pointer past last used dir slot */
	int flag;			/* LOOKUP, CREATE, RENAME, or DELETE */
	int lockparent;			/* 1 => lockparent flag is set */
	int wantparent;			/* 1 => wantparent or lockparent flag */
	int error;

	ndp->ni_dvp = vdp;
	ndp->ni_vp = NULL;
	dp = VTOI(vdp);
	fs = dp->i_fs;
	lockparent = ndp->ni_nameiop & LOCKPARENT;
	flag = ndp->ni_nameiop & OPMASK;
	wantparent = ndp->ni_nameiop & (LOCKPARENT|WANTPARENT);

	/*
	 * Check accessiblity of directory.
	 */
	if ((dp->i_mode&IFMT) != IFDIR)
		return (ENOTDIR);
	if (error = ufs_access(vdp, VEXEC, ndp->ni_cred, p))
		return (error);

	/*
	 * We now have a segment name to search for, and a directory to search.
	 *
	 * Before tediously performing a linear scan of the directory,
	 * check the name cache to see if the directory/name pair
	 * we are looking for is known already.
	 */
	if (error = cache_lookup(ndp)) {
		int vpid;	/* capability number of vnode */

		if (error == ENOENT)
			return (error);
#ifdef PARANOID
		if (vdp == ndp->ni_rdir && ndp->ni_isdotdot)
			panic("ufs_lookup: .. through root");
#endif
		/*
		 * Get the next vnode in the path.
		 * See comment below starting `Step through' for
		 * an explaination of the locking protocol.
		 */
		pdp = dp;
		dp = VTOI(ndp->ni_vp);
		vdp = ndp->ni_vp;
		vpid = vdp->v_id;
		if (pdp == dp) {
			VREF(vdp);
			error = 0;
		} else if (ndp->ni_isdotdot) {
			IUNLOCK(pdp);
			error = vget(vdp);
			if (!error && lockparent && *ndp->ni_next == '\0')
				ILOCK(pdp);
		} else {
			error = vget(vdp);
			if (!lockparent || error || *ndp->ni_next != '\0')
				IUNLOCK(pdp);
		}
		/*
		 * Check that the capability number did not change
		 * while we were waiting for the lock.
		 */
		if (!error) {
			if (vpid == vdp->v_id)
				return (0);
			iput(dp);
			if (lockparent && pdp != dp && *ndp->ni_next == '\0')
				IUNLOCK(pdp);
		}
		ILOCK(pdp);
		dp = pdp;
		vdp = ITOV(dp);
		ndp->ni_vp = NULL;
	}

	/*
	 * Suppress search for slots unless creating
	 * file and at end of pathname, in which case
	 * we watch for a place to put the new file in
	 * case it doesn't already exist.
	 */
	slotstatus = FOUND;
	if ((flag == CREATE || flag == RENAME) && *ndp->ni_next == 0) {
		slotstatus = NONE;
		slotfreespace = 0;
		slotneeded = ((sizeof (struct direct) - (MAXNAMLEN + 1)) +
			((ndp->ni_namelen + 1 + 3) &~ 3));
	}

	/*
	 * If there is cached information on a previous search of
	 * this directory, pick up where we last left off.
	 * We cache only lookups as these are the most common
	 * and have the greatest payoff. Caching CREATE has little
	 * benefit as it usually must search the entire directory
	 * to determine that the entry does not exist. Caching the
	 * location of the last DELETE or RENAME has not reduced
	 * profiling time and hence has been removed in the interest
	 * of simplicity.
	 */
	if (flag != LOOKUP || dp->i_diroff == 0 || dp->i_diroff > dp->i_size) {
		ndp->ni_ufs.ufs_offset = 0;
		numdirpasses = 1;
	} else {
		ndp->ni_ufs.ufs_offset = dp->i_diroff;
		entryoffsetinblock = blkoff(fs, ndp->ni_ufs.ufs_offset);
		if (entryoffsetinblock != 0) {
			if (error = blkatoff(dp, ndp->ni_ufs.ufs_offset,
			    (char **)0, &bp))
				return (error);
		}
		numdirpasses = 2;
		nchstats.ncs_2passes++;
	}
	endsearch = roundup(dp->i_size, DIRBLKSIZ);
	enduseful = 0;

searchloop:
	while (ndp->ni_ufs.ufs_offset < endsearch) {
		/*
		 * If offset is on a block boundary,
		 * read the next directory block.
		 * Release previous if it exists.
		 */
		if (blkoff(fs, ndp->ni_ufs.ufs_offset) == 0) {
			if (bp != NULL)
				brelse(bp);
			if (error = blkatoff(dp, ndp->ni_ufs.ufs_offset,
			    (char **)0, &bp))
				return (error);
			entryoffsetinblock = 0;
		}
		/*
		 * If still looking for a slot, and at a DIRBLKSIZE
		 * boundary, have to start looking for free space again.
		 */
		if (slotstatus == NONE &&
		    (entryoffsetinblock & (DIRBLKSIZ - 1)) == 0) {
			slotoffset = -1;
			slotfreespace = 0;
		}
		/*
		 * Get pointer to next entry.
		 * Full validation checks are slow, so we only check
		 * enough to insure forward progress through the
		 * directory. Complete checks can be run by patching
		 * "dirchk" to be true.
		 */
		ep = (struct direct *)(bp->b_un.b_addr + entryoffsetinblock);
		if (ep->d_reclen == 0 ||
		    dirchk && dirbadentry(ep, entryoffsetinblock)) {
			int i;

			dirbad(dp, ndp->ni_ufs.ufs_offset, "mangled entry");
			i = DIRBLKSIZ - (entryoffsetinblock & (DIRBLKSIZ - 1));
			ndp->ni_ufs.ufs_offset += i;
			entryoffsetinblock += i;
			continue;
		}

		/*
		 * If an appropriate sized slot has not yet been found,
		 * check to see if one is available. Also accumulate space
		 * in the current block so that we can determine if
		 * compaction is viable.
		 */
		if (slotstatus != FOUND) {
			int size = ep->d_reclen;

			if (ep->d_ino != 0)
				size -= DIRSIZ(ep);
			if (size > 0) {
				if (size >= slotneeded) {
					slotstatus = FOUND;
					slotoffset = ndp->ni_ufs.ufs_offset;
					slotsize = ep->d_reclen;
				} else if (slotstatus == NONE) {
					slotfreespace += size;
					if (slotoffset == -1)
						slotoffset =
						      ndp->ni_ufs.ufs_offset;
					if (slotfreespace >= slotneeded) {
						slotstatus = COMPACT;
						slotsize =
						      ndp->ni_ufs.ufs_offset +
						      ep->d_reclen - slotoffset;
					}
				}
			}
		}

		/*
		 * Check for a name match.
		 */
		if (ep->d_ino) {
			if (ep->d_namlen == ndp->ni_namelen &&
			    !bcmp(ndp->ni_ptr, ep->d_name,
				(unsigned)ep->d_namlen)) {
				/*
				 * Save directory entry's inode number and
				 * reclen in ndp->ni_ufs area, and release
				 * directory buffer.
				 */
				ndp->ni_ufs.ufs_ino = ep->d_ino;
				ndp->ni_ufs.ufs_reclen = ep->d_reclen;
				goto found;
			}
		}
		prevoff = ndp->ni_ufs.ufs_offset;
		ndp->ni_ufs.ufs_offset += ep->d_reclen;
		entryoffsetinblock += ep->d_reclen;
		if (ep->d_ino)
			enduseful = ndp->ni_ufs.ufs_offset;
	}
/* notfound: */
	/*
	 * If we started in the middle of the directory and failed
	 * to find our target, we must check the beginning as well.
	 */
	if (numdirpasses == 2) {
		numdirpasses--;
		ndp->ni_ufs.ufs_offset = 0;
		endsearch = dp->i_diroff;
		goto searchloop;
	}
	if (bp != NULL)
		brelse(bp);
	/*
	 * If creating, and at end of pathname and current
	 * directory has not been removed, then can consider
	 * allowing file to be created.
	 */
	if ((flag == CREATE || flag == RENAME) &&
	    *ndp->ni_next == 0 && dp->i_nlink != 0) {
		/*
		 * Access for write is interpreted as allowing
		 * creation of files in the directory.
		 */
		if (error = ufs_access(vdp, VWRITE, ndp->ni_cred, p))
			return (error);
		/*
		 * Return an indication of where the new directory
		 * entry should be put.  If we didn't find a slot,
		 * then set ndp->ni_ufs.ufs_count to 0 indicating
		 * that the new slot belongs at the end of the
		 * directory. If we found a slot, then the new entry
		 * can be put in the range from ndp->ni_ufs.ufs_offset
		 * to ndp->ni_ufs.ufs_offset + ndp->ni_ufs.ufs_count.
		 */
		if (slotstatus == NONE) {
			ndp->ni_ufs.ufs_offset = roundup(dp->i_size, DIRBLKSIZ);
			ndp->ni_ufs.ufs_count = 0;
			enduseful = ndp->ni_ufs.ufs_offset;
		} else {
			ndp->ni_ufs.ufs_offset = slotoffset;
			ndp->ni_ufs.ufs_count = slotsize;
			if (enduseful < slotoffset + slotsize)
				enduseful = slotoffset + slotsize;
		}
		ndp->ni_ufs.ufs_endoff = roundup(enduseful, DIRBLKSIZ);
		dp->i_flag |= IUPD|ICHG;
		/*
		 * We return with the directory locked, so that
		 * the parameters we set up above will still be
		 * valid if we actually decide to do a direnter().
		 * We return ni_vp == NULL to indicate that the entry
		 * does not currently exist; we leave a pointer to
		 * the (locked) directory inode in ndp->ni_dvp.
		 * The pathname buffer is saved so that the name
		 * can be obtained later.
		 *
		 * NB - if the directory is unlocked, then this
		 * information cannot be used.
		 */
		ndp->ni_nameiop |= SAVENAME;
		if (!lockparent)
			IUNLOCK(dp);
	}
	/*
	 * Insert name into cache (as non-existent) if appropriate.
	 */
	if (ndp->ni_makeentry && flag != CREATE)
		cache_enter(ndp);
	return (ENOENT);

found:
	if (numdirpasses == 2)
		nchstats.ncs_pass2++;
	/*
	 * Check that directory length properly reflects presence
	 * of this entry.
	 */
	if (entryoffsetinblock + DIRSIZ(ep) > dp->i_size) {
		dirbad(dp, ndp->ni_ufs.ufs_offset, "i_size too small");
		dp->i_size = entryoffsetinblock + DIRSIZ(ep);
		dp->i_flag |= IUPD|ICHG;
	}

	brelse(bp);

	/*
	 * Found component in pathname.
	 * If the final component of path name, save information
	 * in the cache as to where the entry was found.
	 */
	if (*ndp->ni_next == '\0' && flag == LOOKUP)
		dp->i_diroff = ndp->ni_ufs.ufs_offset &~ (DIRBLKSIZ - 1);

	/*
	 * If deleting, and at end of pathname, return
	 * parameters which can be used to remove file.
	 * If the wantparent flag isn't set, we return only
	 * the directory (in ndp->ni_dvp), otherwise we go
	 * on and lock the inode, being careful with ".".
	 */
	if (flag == DELETE && *ndp->ni_next == 0) {
		/*
		 * Write access to directory required to delete files.
		 */
		if (error = ufs_access(vdp, VWRITE, ndp->ni_cred, p))
			return (error);
		/*
		 * Return pointer to current entry in ndp->ni_ufs.ufs_offset,
		 * and distance past previous entry (if there
		 * is a previous entry in this block) in ndp->ni_ufs.ufs_count.
		 * Save directory inode pointer in ndp->ni_dvp for dirremove().
		 */
		if ((ndp->ni_ufs.ufs_offset&(DIRBLKSIZ-1)) == 0)
			ndp->ni_ufs.ufs_count = 0;
		else
			ndp->ni_ufs.ufs_count = ndp->ni_ufs.ufs_offset - prevoff;
		if (dp->i_number == ndp->ni_ufs.ufs_ino) {
			VREF(vdp);
			ndp->ni_vp = vdp;
			return (0);
		}
		if (error = iget(dp, ndp->ni_ufs.ufs_ino, &tdp))
			return (error);
		/*
		 * If directory is "sticky", then user must own
		 * the directory, or the file in it, else she
		 * may not delete it (unless she's root). This
		 * implements append-only directories.
		 */
		if ((dp->i_mode & ISVTX) &&
		    ndp->ni_cred->cr_uid != 0 &&
		    ndp->ni_cred->cr_uid != dp->i_uid &&
		    tdp->i_uid != ndp->ni_cred->cr_uid) {
			iput(tdp);
			return (EPERM);
		}
		ndp->ni_vp = ITOV(tdp);
		if (!lockparent)
			IUNLOCK(dp);
		return (0);
	}

	/*
	 * If rewriting (RENAME), return the inode and the
	 * information required to rewrite the present directory
	 * Must get inode of directory entry to verify it's a
	 * regular file, or empty directory.
	 */
	if (flag == RENAME && wantparent && *ndp->ni_next == 0) {
		if (error = ufs_access(vdp, VWRITE, ndp->ni_cred, p))
			return (error);
		/*
		 * Careful about locking second inode.
		 * This can only occur if the target is ".".
		 */
		if (dp->i_number == ndp->ni_ufs.ufs_ino)
			return (EISDIR);
		if (error = iget(dp, ndp->ni_ufs.ufs_ino, &tdp))
			return (error);
		ndp->ni_vp = ITOV(tdp);
		ndp->ni_nameiop |= SAVENAME;
		if (!lockparent)
			IUNLOCK(dp);
		return (0);
	}

	/*
	 * Step through the translation in the name.  We do not `iput' the
	 * directory because we may need it again if a symbolic link
	 * is relative to the current directory.  Instead we save it
	 * unlocked as "pdp".  We must get the target inode before unlocking
	 * the directory to insure that the inode will not be removed
	 * before we get it.  We prevent deadlock by always fetching
	 * inodes from the root, moving down the directory tree. Thus
	 * when following backward pointers ".." we must unlock the
	 * parent directory before getting the requested directory.
	 * There is a potential race condition here if both the current
	 * and parent directories are removed before the `iget' for the
	 * inode associated with ".." returns.  We hope that this occurs
	 * infrequently since we cannot avoid this race condition without
	 * implementing a sophisticated deadlock detection algorithm.
	 * Note also that this simple deadlock detection scheme will not
	 * work if the file system has any hard links other than ".."
	 * that point backwards in the directory structure.
	 */
	pdp = dp;
	if (ndp->ni_isdotdot) {
		IUNLOCK(pdp);	/* race to get the inode */
		if (error = iget(dp, ndp->ni_ufs.ufs_ino, &tdp)) {
			ILOCK(pdp);
			return (error);
		}
		if (lockparent && *ndp->ni_next == '\0')
			ILOCK(pdp);
		ndp->ni_vp = ITOV(tdp);
	} else if (dp->i_number == ndp->ni_ufs.ufs_ino) {
		VREF(vdp);	/* we want ourself, ie "." */
		ndp->ni_vp = vdp;
	} else {
		if (error = iget(dp, ndp->ni_ufs.ufs_ino, &tdp))
			return (error);
		if (!lockparent || *ndp->ni_next != '\0')
			IUNLOCK(pdp);
		ndp->ni_vp = ITOV(tdp);
	}

	/*
	 * Insert name into cache if appropriate.
	 */
	if (ndp->ni_makeentry)
		cache_enter(ndp);
	return (0);
}

/*
 * Open called.
 *
 * Nothing to do.
 */
/* ARGSUSED */
ufs_open(vp, mode, cred, p)
	struct vnode *vp;
	int mode;
	struct ucred *cred;
	struct proc *p;
{

	return (0);
}
```
