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
		ufs_create
			maknode
				ialloc
				iupdat
				direnter
				iput
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
	lookup					++-

File: machdep.c
	copystr					++-
	copyinstr				++-

File: locore.s
	fubyte					++-

File: ufs_vnops.c
	ufs_create				+++
	maknode					--+

File: ufs_alloc.c
	ialloc					---

File: ufs_inode.c
	iupdat					++-
	iput					++-
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

**ufs_create**:

**maknod**:

**ialloc**:

**iput**:

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
 * Create a regular file
 */
ufs_create(ndp, vap, p)
	struct nameidata *ndp;
	struct vattr *vap;
	struct proc *p;
{
	struct inode *ip;
	int error;

	/* Create or obtain an inode for the new file */
	if (error = maknode(MAKEIMODE(vap->va_type, vap->va_mode), ndp, &ip))
		return (error);

	/* Assign the inode's vnode ptr to namei data structure */
	ndp->ni_vp = ITOV(ip);
	return (0);
}

/*
 * Allocate a new inode.
 */
maknode(mode, ndp, ipp)
	int mode;
	register struct nameidata *ndp;
	struct inode **ipp;
{
	register struct inode *ip;
	struct inode *tip;
	register struct inode *pdir = VTOI(ndp->ni_dvp);
	ino_t ipref;
	int error;

#ifdef DIANOSTIC
	if ((ndp->ni_nameiop & HASBUF) == 0)
		panic("maknode: no name");
#endif
	*ipp = 0;

	/* Regular file by default */
	if ((mode & IFMT) == 0)
		mode |= IFREG;
	/* Use an inode associated with the parent's fs */
	if ((mode & IFMT) == IFDIR)
		ipref = dirpref(pdir->i_fs);
	else
		ipref = pdir->i_number;

	/* Allocate an inode for the new file */
	if (error = ialloc(pdir, ipref, mode, ndp->ni_cred, &tip)) {
		/* Free pathname buf upon failure */
		free(ndp->ni_pnbuf, M_NAMEI);
		iput(pdir);
		return (error);
	}
	/* Set the uid and gid for the new inode */
	ip = tip;
	ip->i_uid = ndp->ni_cred->cr_uid;
	ip->i_gid = pdir->i_gid;
#ifdef QUOTA
	if ((error = getinoquota(ip)) ||
	    (error = chkiq(ip, 1, ndp->ni_cred, 0))) {
		free(ndp->ni_pnbuf, M_NAMEI);
		ifree(ip, ip->i_number, mode);
		iput(ip);
		iput(pdir);
		return (error);
	}
#endif
	/*
	 * Set the following flags:
	 *
	 * IACC = inode atime needs to be updated
	 * IUPD = file has been modified
	 * ICHG = inode has been changed
	 */
	ip->i_flag |= IACC|IUPD|ICHG;
	ip->i_mode = mode;

	/* IFTOVT(mode) (iftovt_tab[((mode) & IFMT) >> 12]) */
	ITOV(ip)->v_type = IFTOVT(mode);	/* Rest init'd in iget() */

	/* Single reference equal to the pathname we provided for open */
	ip->i_nlink = 1;

	/* Handle the setgid bit in the inode */
	if ((ip->i_mode & ISGID) && !groupmember(ip->i_gid, ndp->ni_cred) &&
	    suser(ndp->ni_cred, NULL))
		ip->i_mode &= ~ISGID;
	/*
	 * Make sure inode goes to disk before directory entry.
	 */
	if (error = iupdat(ip, &time, &time, 1))
		goto bad;

	/* Insert the new inode into the directory */
	if (error = direnter(ip, ndp))
		goto bad;

	/* Clear the pathname buf if we didn't ask to save it */
	if ((ndp->ni_nameiop & SAVESTART) == 0)
		FREE(ndp->ni_pnbuf, M_NAMEI);

	/* Release the dir's inode */
	iput(pdir);
	*ipp = ip;
	return (0);

bad:
	/*
	 * Write error occurred trying to update the inode
	 * or the directory so must deallocate the inode.
	 */
	free(ndp->ni_pnbuf, M_NAMEI);

	/* Release the dir's inode */
	iput(pdir);
	ip->i_nlink = 0;
	ip->i_flag |= ICHG;

	/* Release the new inode */
	iput(ip);
	return (error);
}
```
