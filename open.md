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
			lookup
				ufs_lookup
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
	namei					--+
	lookup					--+

File: ufs_lookup.c
	ufs_lookup				---
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

## Code Walkthrough

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
	register char *cp;		/* pointer into pathname argument */
	register struct vnode *dp;	/* the directory we are searching */
	struct iovec aiov;		/* uio for reading symbolic links */
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
	if (ndp->ni_segflg == UIO_SYSSPACE)
		error = copystr(ndp->ni_dirp, ndp->ni_pnbuf,
			    MAXPATHLEN, &ndp->ni_pathlen);
	else
		error = copyinstr(ndp->ni_dirp, ndp->ni_pnbuf,
			    MAXPATHLEN, &ndp->ni_pathlen);
	if (error) {
		free(ndp->ni_pnbuf, M_NAMEI);
		ndp->ni_vp = NULL;
		return (error);
	}
	ndp->ni_loopcnt = 0;
#ifdef KTRACE
	if (KTRPOINT(p, KTR_NAMEI))
		ktrnamei(p->p_tracep, ndp->ni_pnbuf);
#endif

	/*
	 * Get starting point for the translation.
	 */
	if ((ndp->ni_rootdir = fdp->fd_rdir) == NULL)
		ndp->ni_rootdir = rootdir;
	dp = fdp->fd_cdir;
	VREF(dp);
	for (;;) {
		/*
		 * Check if root directory should replace current directory.
		 * Done at start of translation and after symbolic link.
		 */
		ndp->ni_ptr = ndp->ni_pnbuf;
		if (*ndp->ni_ptr == '/') {
			vrele(dp);
			while (*ndp->ni_ptr == '/') {
				ndp->ni_ptr++;
				ndp->ni_pathlen--;
			}
			dp = ndp->ni_rootdir;
			VREF(dp);
		}
		ndp->ni_startdir = dp;
		if (error = lookup(ndp, p)) {
			FREE(ndp->ni_pnbuf, M_NAMEI);
			return (error);
		}
		/*
		 * Check for symbolic link
		 */
		if (ndp->ni_more == 0) {
			if ((ndp->ni_nameiop & (SAVENAME | SAVESTART)) == 0)
				FREE(ndp->ni_pnbuf, M_NAMEI);
			else
				ndp->ni_nameiop |= HASBUF;
			return (0);
		}
		if ((ndp->ni_nameiop & LOCKPARENT) && ndp->ni_pathlen == 1)
			VOP_UNLOCK(ndp->ni_dvp);
		if (ndp->ni_loopcnt++ >= MAXSYMLINKS) {
			error = ELOOP;
			break;
		}
		if (ndp->ni_pathlen > 1)
			MALLOC(cp, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
		else
			cp = ndp->ni_pnbuf;
		aiov.iov_base = cp;
		aiov.iov_len = MAXPATHLEN;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_procp = (struct proc *)0;
		auio.uio_resid = MAXPATHLEN;
		if (error = VOP_READLINK(ndp->ni_vp, &auio, p->p_ucred)) {
			if (ndp->ni_pathlen > 1)
				free(cp, M_NAMEI);
			break;
		}
		linklen = MAXPATHLEN - auio.uio_resid;
		if (linklen + ndp->ni_pathlen >= MAXPATHLEN) {
			if (ndp->ni_pathlen > 1)
				free(cp, M_NAMEI);
			error = ENAMETOOLONG;
			break;
		}
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
	FREE(ndp->ni_pnbuf, M_NAMEI);
	vrele(ndp->ni_dvp);
	vput(ndp->ni_vp);
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
	register char *cp;		/* pointer into pathname argument */
	register struct vnode *dp = 0;	/* the directory we are searching */
	struct vnode *tdp;		/* saved dp */
	struct mount *mp;		/* mount table entry */
	int docache;			/* == 0 do not cache last component */
	int flag;			/* LOOKUP, CREATE, RENAME or DELETE */
	int wantparent;			/* 1 => wantparent or lockparent flag */
	int rdonly;			/* mounted read-only flag bit(s) */
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
	for (cp = ndp->ni_ptr; *cp != 0 && *cp != '/'; cp++)
		ndp->ni_hash += (unsigned char)*cp;
	ndp->ni_namelen = cp - ndp->ni_ptr;
	if (ndp->ni_namelen >= NAME_MAX) {
		error = ENAMETOOLONG;
		goto bad;
	}
#ifdef NAMEI_DIAGNOSTIC
	{ char c = *cp;
	*cp = '\0';
	printf("{%s}: ", ndp->ni_ptr);
	*cp = c; }
#endif
	ndp->ni_pathlen -= ndp->ni_namelen;
	ndp->ni_next = cp;
	ndp->ni_makeentry = 1;
	if (*cp == '\0' && docache == 0)
		ndp->ni_makeentry = 0;
	ndp->ni_isdotdot = (ndp->ni_namelen == 2 &&
		ndp->ni_ptr[1] == '.' && ndp->ni_ptr[0] == '.');

	/*
	 * Check for degenerate name (e.g. / or "")
	 * which is a way of talking about a directory,
	 * e.g. like "/." or ".".
	 */
	if (ndp->ni_ptr[0] == '\0') {
		if (flag != LOOKUP || wantparent) {
			error = EISDIR;
			goto bad;
		}
		if (dp->v_type != VDIR) {
			error = ENOTDIR;
			goto bad;
		}
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
			if (dp == ndp->ni_rootdir || dp == rootdir) {
				ndp->ni_dvp = dp;
				ndp->ni_vp = dp;
				VREF(dp);
				goto nextname;
			}
			if ((dp->v_flag & VROOT) == 0 ||
			    (ndp->ni_nameiop & NOCROSSMOUNT))
				break;
			tdp = dp;
			dp = dp->v_mount->mnt_vnodecovered;
			vput(tdp);
			VREF(dp);
			VOP_LOCK(dp);
		}
	}

	/*
	 * We now have a segment name to search for, and a directory to search.
	 */
	if (error = VOP_LOOKUP(dp, ndp, p)) {
#ifdef DIAGNOSTIC
		if (ndp->ni_vp != NULL)
			panic("leaf should be empty");
#endif
#ifdef NAMEI_DIAGNOSTIC
		printf("not found\n");
#endif
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
#ifdef NAMEI_DIAGNOSTIC
	printf("found\n");
#endif

	dp = ndp->ni_vp;
	/*
	 * Check for symbolic link
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
	       (ndp->ni_nameiop & NOCROSSMOUNT) == 0) {
		while(mp->mnt_flag & MNT_MLOCK) {
			mp->mnt_flag |= MNT_MWAIT;
			sleep((caddr_t)mp, PVFS);
			goto mntloop;
		}
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
