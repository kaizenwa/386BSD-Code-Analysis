#	from: @(#)Makefile	5.11 (Berkeley) 5/21/91
#	$Id: Makefile,v 1.76 1994/06/29 21:19:38 jkh Exp $

# disktab may be wrong -- hcx9 is a tahoe, but gets its own.
# -rw-r--r--
BINOWN= root
BINGRP= wheel
BIN1=	aliases csh.cshrc csh.login csh.logout dm.conf \
	ftpusers gettytab group hosts host.conf hosts.equiv hosts.lpd \
	inetd.conf login.access motd myname netstart \
	networks phones printcap protocols rc rc.local remote \
	security services shells skey.access \
	syslog.conf ttys etc.${MACHINE}/disktab rpc make.conf \
	${.CURDIR}/../gnu/usr.bin/man/manpath/manpath.config \
	${.CURDIR}/../usr.bin/mail/misc/mail.rc

# -rw-rw-rw-
BIN2=	motd

# -rwxr-xr-x root.wheel, for the new cron root.wheel
BIN3=	daily weekly monthly

CLEANFILES+= *.o *.lo *.c *.cache *.mk kcopy filesystem

ZIPNSPLIT=	gzip --no-name -9 -c | split -b 240640 -

MTREE=	BSD.local.dist BSD.root.dist BSD.usr.dist BSD.var.dist
NAMEDB=	localhost.rev named.boot root.cache
PCS=	pcs750.bin
WCS1=	wcs fppwcs poc poc1 poc2 fppoc
WCS2=	fpevent fppwcs fppwcs_dual hdcwcs load_diags start_fpp wcs wcs_dual

# Special top level files for FreeBSD
COPYRIGHT=	COPYRIGHT.386BSD COPYRIGHT.FreeBSD
FREEBSD=	CONTRIB.386BSD CONTRIB.FreeBSD ROSTER.FreeBSD
FREEBSD+=	MIRROR.SITES PERSONAL.ACKS RELNOTES.FreeBSD SUPPORT.TXT
FREEBSD+=	${COPYRIGHT}
#
# Floppy drive name and files for building FreeBSD Floppies
FLOPPY?=	fd0
MOUNT?=		/mnt
FLOPPY_TYPE?=	fd1440
#
MDEC=		usr/mdec/bootfd usr/mdec/fdboot
MDEC+=		usr/mdec/bootsd usr/mdec/sdboot
MDEC+=		usr/mdec/bootwd usr/mdec/wdboot
#
KC_DIRS=	bin dev mnt sbin
KC_FILES=	${COPYRIGHT}
KC_LINKS=	bin/[ bin/cp bin/echo bin/sh bin/test
KC_LINKS+=	sbin/fsck sbin/halt sbin/init
KC_LINKS+=	sbin/mount sbin/mount_isofs
KC_LINKS+=	sbin/umount
#
CD_DIRS=	etc usr
#
FILESYSTEM_DIRS=	bin dev etc mnt proc sbin usr usr/bin usr/mdec usr/sbin
FILESYSTEM_TREES=	dev
FILESYSTEM_FILES=	${COPYRIGHT}
FILESYSTEM_FILES+=	dev/MAKEDEV
FILESYSTEM_FILES+=	etc/group
FILESYSTEM_FILES+=	etc/master.passwd etc/passwd etc/pwd.db
FILESYSTEM_FILES+=	${MDEC}
FILESYSTEM_LINKS=	bin/[ bin/expr bin/ls bin/mkdir bin/rm
FILESYSTEM_LINKS+=	bin/sh bin/sync bin/test
FILESYSTEM_LINKS+=	sbin/disklabel sbin/fdisk sbin/halt sbin/init
FILESYSTEM_LINKS+=	sbin/mount sbin/mount_pcfs
FILESYSTEM_LINKS+=	sbin/newfs
FILESYSTEM_LINKS+=	sbin/umount
FILESYSTEM_LINKS+=	usr/bin/cpio
FILESYSTEM_LINKS+=	usr/bin/gunzip usr/bin/gzcat usr/bin/gzip usr/bin/zcat
FILESYSTEM_LINKS+=	usr/sbin/bad144
FILESYSTEM_CPIO=	.profile
FILESYSTEM_CPIO+=	root/.profile
FILESYSTEM_CPIO+=	bin/[
FILESYSTEM_CPIO+=	bin/chmod bin/cat bin/cp bin/df bin/expr bin/ls
FILESYSTEM_CPIO+=	bin/ln bin/mkdir bin/mv bin/rm bin/sync
FILESYSTEM_CPIO+=	bin/test
FILESYSTEM_CPIO+=	etc/spwd.db
FILESYSTEM_CPIO+=	sbin/disklabel sbin/fdisk sbin/halt sbin/init
FILESYSTEM_CPIO+=	sbin/mount sbin/mount_pcfs
FILESYSTEM_CPIO+=	sbin/newfs
FILESYSTEM_CPIO+=	sbin/umount
FILESYSTEM_CPIO_DIRS=	root

CPIO_FILES=	${COPYRIGHT}
CPIO_CPIO=	bin/dd bin/ps bin/pwd bin/stty
CPIO_CPIO+=	etc/protocols etc/remote etc/services
CPIO_CPIO+=	etc/termcap
CPIO_CPIO+=	sbin/dmesg
CPIO_CPIO+=	sbin/ifconfig sbin/fsck sbin/mknod sbin/mount_isofs
CPIO_CPIO+=	sbin/mount_procfs
CPIO_CPIO+=	sbin/reboot sbin/route sbin/slattach
CPIO_CPIO+=	usr/bin/awk usr/bin/chgrp usr/bin/cpio usr/bin/ex usr/bin/ftp
CPIO_CPIO+=	usr/bin/gunzip usr/bin/gzcat usr/bin/gzip
CPIO_CPIO+=	usr/bin/more usr/bin/tar usr/bin/tip
CPIO_CPIO+=	usr/bin/vi usr/bin/view usr/bin/zcat
CPIO_CPIO+=	usr/lib/libc.so.1.1
CPIO_CPIO+=	usr/lib/libcurses.so.1.1
CPIO_CPIO+=	usr/lib/libgcc.so.1.1
CPIO_CPIO+=	usr/lib/libm.so.1.1
CPIO_CPIO+=	usr/lib/libtermlib.so.1.1
CPIO_CPIO+=	usr/lib/libtermcap.so.1.1
CPIO_CPIO+=	usr/lib/libutil.so.1.1
CPIO_CPIO+=	usr/libexec/ld.so
CPIO_CPIO+=	usr/sbin/bad144 usr/sbin/chown
CPIO_CPIO+=	usr/share/misc/termcap
CPIO_CPIO_DIRS=		tmp usr/lib usr/libexec usr/share usr/share/misc
CPIO_CPIO_DIRS+=	var var/tmp var/run var/spool var/spool/lock

CRYPT_LIB=	lib/libcrypt
CRYPT_SRCS=	bin/ed bin/rcp
CRYPT_SRCS+=	libexec/ftpd libexec/makekey libexec/rexecd libexec/rlogind
CRYPT_SRCS+=	libexec/rshd libexec/telnetd libexec/uucpd
CRYPT_SRCS+=	sbin/init.bsdi
CRYPT_SRCS+=	usr.bin/bdes usr.bin/lock usr.bin/login usr.bin/passwd
CRYPT_SRCS+=	usr.bin/rlogin usr.bin/rsh usr.bin/su usr.bin/telnet
CRYPT_DIRS=	bin sbin usr usr/bin usr/lib usr/libexec 

all depend etc install lint:

crypt:
	rm -f /usr/lib/libcrypt*
	(cd ${.CURDIR}/../${CRYPT_LIB}; \
		${MAKE} cleandir obj depend all install)
	for i in ${CRYPT_SRCS}; do \
		cd ${.CURDIR}/../$$i; \
		${MAKE} cleandir obj depend all; \
	done
	
non-crypt:
	rm -f /usr/lib/libcrypt*
	for i in ${CRYPT_SRCS}; do \
		cd ${.CURDIR}/../$$i; \
		${MAKE} cleandir obj depend all; \
	done
	
distribution: distrib-dirs
	(cd ${.CURDIR}; \
	install -c -o ${BINOWN} -g ${BINGRP} -m 644 ${BIN1} ${DESTDIR}/etc; \
	install -c -o ${BINOWN} -g ${BINGRP} -m 666 ${BIN2} ${DESTDIR}/etc; \
	install -c -o ${BINOWN} -g ${BINGRP} -m 755 ${BIN3} ${DESTDIR}/etc; \
	install -c -o ${BINOWN} -g ${BINGRP} -m 644 crontab ${DESTDIR}/etc; \
	install -c -o ${BINOWN} -g ${BINGRP} -m 600 /dev/null \
	    ${DESTDIR}/var/cron/log; \
	install -c -o ${BINOWN} -g ${BINGRP} -m 600 \
	    master.passwd ${DESTDIR}/etc; \
	pwd_mkdb -p -d ${DESTDIR}/etc ${DESTDIR}/etc/master.passwd; \
	install -c -o ${BINOWN} -g ${BINGRP} -m 555 \
	     MAKEDEV.local etc.${MACHINE}/MAKEDEV ${DESTDIR}/dev )
.if defined(CDROMDIST)
	(cd ${DESTDIR}/dev; sh MAKEDEV all) ;
.endif
	(cd ${.CURDIR}/root; \
		install -c -o ${BINOWN} -g ${BINGRP} -m 644 dot.cshrc \
		    ${DESTDIR}/root/.cshrc; \
		install -c -o ${BINOWN} -g ${BINGRP} -m 644 dot.klogin \
		    ${DESTDIR}/root/.klogin; \
		install -c -o ${BINOWN} -g ${BINGRP} -m 644 dot.login \
		    ${DESTDIR}/root/.login; \
		install -c -o ${BINOWN} -g ${BINGRP} -m 644 dot.profile \
		    ${DESTDIR}/root/.profile; \
		rm -f ${DESTDIR}/.cshrc ${DESTDIR}/.profile; \
		ln ${DESTDIR}/root/.cshrc ${DESTDIR}/.cshrc; \
		ln ${DESTDIR}/root/.profile ${DESTDIR}/.profile)
	cd ${.CURDIR}/mtree; install -c -o ${BINOWN} -g ${BINGRP} -m 444 \
	    ${MTREE} ${DESTDIR}/etc/mtree
	cd ${.CURDIR}/namedb; install -c -o ${BINOWN} -g ${BINGRP} -m 644 \
	    ${NAMEDB} ${DESTDIR}/etc/namedb
	install -c -o ${BINOWN} -g operator -m 664 /dev/null \
	    ${DESTDIR}/etc/dumpdates
	install -c -o nobody -g ${BINGRP} -m 664 /dev/null \
	    ${DESTDIR}/var/db/locate.database
	install -c -o ${BINOWN} -g ${BINGRP} -m 664 /dev/null \
	    ${DESTDIR}/var/log/lpd-errs
	install -c -o ${BINOWN} -g ${BINGRP} -m 664 /dev/null \
	    ${DESTDIR}/var/log/maillog
	install -c -o ${BINOWN} -g ${BINGRP} -m 664 /dev/null \
	    ${DESTDIR}/var/log/lastlog
	install -c -o ${BINOWN} -g ${BINGRP} -m 664 /dev/null \
	    ${DESTDIR}/var/log/messages
	install -c -o ${BINOWN} -g ${BINGRP} -m 664 /dev/null \
	    ${DESTDIR}/var/log/wtmp
	install -c -o ${BINOWN} -g ${BINGRP} -m 664 /dev/null \
	    ${DESTDIR}/var/run/utmp
	install -c -o ${BINOWN} -g ${BINGRP} -m 664 ${.CURDIR}/minfree \
	    ${DESTDIR}/var/crash
	(cd ${.CURDIR}/etc.${MACHINE}; install -c -o ${BINOWN} -g ${BINGRP} \
	    -m 444 fstab.* ${DESTDIR}/etc)
.if defined(NOCRYPT)
	(cd ${.CURDIR}; ${MAKE} non-crypt)
	(cd ${.CURDIR}/..; NOCRYPT=nocrypt; export NOCRYPT; ${MAKE} install)
.else
	(cd ${.CURDIR}; ${MAKE} crypt)
	(cd ${.CURDIR}/..; ${MAKE} install)
.endif
	(cd ${.CURDIR}/../usr.sbin/sendmail/src; \
	    ${MAKE} install; \
	 cd ../cf/cf; \
	    ${MAKE} obj; \
	    ${MAKE} freefall.cf; \
	    install -o ${BINOWN} -g ${BINGRP} -m 644 obj/freefall.cf \
	        ${DESTDIR}/etc/sendmail.cf)
	(cd ${.CURDIR}/..; \
	    install -c -o ${BINOWN} -g ${BINGRP} -m 444 ${FREEBSD} ${DESTDIR}/)
	(cd ${.CURDIR}/..; ${MAKE} mdec; )
	(cd ${.CURDIR}/../share/man; ${MAKE} makedb; )
.if ${MACHINE} == "tahoe"
	(cd ${.CURDIR}/etc.tahoe; install -c -o ${BINOWN} -g ${BINGRP} \
	    -m 444 ${WCS1} ${DESTDIR}/)
.endif
.if ${MACHINE} == "vax"
	(cd ${.CURDIR}/etc.vax; install -c -o ${BINOWN} -g ${BINGRP} \
	    -m 444 ${PCS} ${DESTDIR}/)
.endif

crunch:
	crunchgen ${.CURDIR}/../contrib/crunch/examples/kcopy.conf
	${MAKE} -f kcopy.mk objs exe
	crunchgen ${.CURDIR}/../contrib/crunch/examples/filesystem.conf
	${MAKE} -f filesystem.mk objs exe

extract:
	install -c -o ${BINOWN} -g ${BINGRP} -m 555 \
	    ${.CURDIR}/etc.i386/EXTRACT_bin.sh \
	    ${RELEASEDIR}/tarballs/bindist/EXTRACT.sh
	install -c -o ${BINOWN} -g ${BINGRP} -m 555 \
	    ${.CURDIR}/etc.i386/EXTRACT_src.sh \
	    ${RELEASEDIR}/tarballs/srcdist/EXTRACT.sh
	install -c -o ${BINOWN} -g ${BINGRP} -m 555 \
	    ${.CURDIR}/etc.i386/EXTRACT_secr.sh \
	    ${RELEASEDIR}/tarballs/secrdist/EXTRACT.sh

hcx9-distribution:
	(cd ${.CURDIR}/etc.tahoe; install -c -o ${BINOWN} -g ${BINGRP} \
	    -m 444 ${WCS2} ${DESTDIR}/)

kcopy-kernels: ${.CURDIR}/../sys/i386/conf/GENERICAH ${.CURDIR}/../sys/i386/conf/GENERICBT
	(cd ${.CURDIR}/../sys/compile; rm -rf GENERICAH GENERICBT)
	(cd ${.CURDIR}/../sys/i386/conf; config GENERICAH; config GENERICBT)
	(cd ${.CURDIR}/../sys/compile/GENERICAH; ${MAKE} depend; ${MAKE} all; \
	    install -c -o ${BINOWN} -g ${BINGRP} -m 755 386bsd \
	        ${DESTDIR}/386bsd.GENERICAH)
	(cd ${.CURDIR}/../sys/compile/GENERICBT; ${MAKE} depend; ${MAKE} all; \
	    install -c -o ${BINOWN} -g ${BINGRP} -m 755 386bsd \
	        ${DESTDIR}/386bsd.GENERICBT)

kcopy-floppy:
	disklabel -w -r ${FLOPPY} ${FLOPPY_TYPE} \
		${DESTDIR}/usr/mdec/fdboot ${DESTDIR}/usr/mdec/bootfd
	newfs -b 4096 -c 80 -f 512 -i 8192 -m 0 -o space \
		r${FLOPPY} ${FLOPPY_TYPE}
	mount /dev/${FLOPPY} ${MOUNT}
	chown ${BINOWN}.${BINGRP} ${MOUNT}/.
	chmod 755 ${MOUNT}/.
	(cd ${DESTDIR}/; \
	    ls -d ${KC_DIRS} | cpio -pdamuv ${MOUNT})
	(cd ${MOUNT}/dev; \
	    sh ${DESTDIR}/dev/MAKEDEV std; \
	    rm -rf fd; \
	    sh ${DESTDIR}/dev/MAKEDEV fd0 fd1 wd0 wd1 sd0 sd1; \
	    rm -rf fd0?* rfd0?* fd1?* rfd1?*; \
	    sh ${DESTDIR}/dev/MAKEDEV cd0 mcd0 mcd1; \
	    rm -rf rmcd*)
	(cd ${DESTDIR}/; \
	    ls ${KC_FILES} | cpio -pdamuv ${MOUNT})
	install -c -o ${BINOWN} -g ${BINGRP} -m 755 \
	    ${.CURDIR}/etc.i386/kc.profile ${MOUNT}/.profile
	install -c -o ${BINOWN} -g ${BINGRP} -m 755 \
	    kcopy ${MOUNT}/bin/kcopy
	(cd ${MOUNT}/; \
	    for i in ${KC_LINKS}; do \
		ln bin/kcopy $$i; \
	    done)

kcopy_ah.flp:
	${MAKE} kcopy-floppy
	(cd ${.CURDIR}/../sys/compile/GENERICAH; \
	    install -c -o ${BINOWN} -g ${BINGRP} -m 755 386bsd ${MOUNT}/)
	df -ik ${MOUNT}
	umount /dev/${FLOPPY}
	fsck /dev/r${FLOPPY}
	dd if=/dev/r${FLOPPY} of=${RELEASEDIR}/floppies/kcopy_ah.flp \
		bs=15b count=160
	gzip --no-name -9 -c ${RELEASEDIR}/floppies/kcopy_ah.flp \
		>${RELEASEDIR}/floppies/kcopy_ah.flp.gz &

kcopy_bt.flp:
	${MAKE} kcopy-floppy
	(cd ${.CURDIR}/../sys/compile/GENERICBT; \
	    install -c -o ${BINOWN} -g ${BINGRP} -m 755 386bsd ${MOUNT}/)
	df -ik ${MOUNT}
	umount /dev/${FLOPPY}
	fsck /dev/r${FLOPPY}
	dd if=/dev/r${FLOPPY} of=${RELEASEDIR}/floppies/kcopy_bt.flp \
		bs=15b count=160
	gzip --no-name -9 -c ${RELEASEDIR}/floppies/kcopy_bt.flp \
		>${RELEASEDIR}/floppies/kcopy_bt.flp.gz &

cdins-floppy:
	${MAKE} kcopy-floppy
	(cd ${DESTDIR}/; \
	    ls -d ${CD_DIRS} | cpio -pdamuv ${MOUNT})
	(cd ${MOUNT}/usr; \
	    ln -s /cdrom/filesys/usr/libexec libexec; \
	    ln -s /cdrom/filesys/usr/lib lib)
	mkdir ${MOUNT}/cdrom
	chown ${BINOWN}.${BINGRP} ${MOUNT}/cdrom
	chmod 755 ${MOUNT}/cdrom
	install -c -o ${BINOWN} -g ${BINGRP} -m 755 \
	    ${.CURDIR}/etc.i386/cdinst1.profile ${MOUNT}/.profile
	install -c -o ${BINOWN} -g ${BINGRP} -m 755 \
	    ${.CURDIR}/etc.i386/cdinst1.install ${MOUNT}/install
	
cdins_ah.flp:
	${MAKE} cdins-floppy
	(cd ${.CURDIR}/../sys/compile/GENERICAH; \
	    install -c -o ${BINOWN} -g ${BINGRP} -m 755 386bsd ${MOUNT}/)
	df -ik ${MOUNT}
	umount /dev/${FLOPPY}
	fsck /dev/r${FLOPPY}
	dd if=/dev/r${FLOPPY} of=${RELEASEDIR}/floppies/cdins_ah.flp \
		bs=15b count=160
	gzip --no-name -9 -c ${RELEASEDIR}/floppies/cdins_ah.flp \
		>${RELEASEDIR}/floppies/cdins_ah.flp.gz &

cdins_bt.flp:
	${MAKE} cdins-floppy
	(cd ${.CURDIR}/../sys/compile/GENERICBT; \
	    install -c -o ${BINOWN} -g ${BINGRP} -m 755 386bsd ${MOUNT}/)
	df -ik ${MOUNT}
	umount /dev/${FLOPPY}
	fsck /dev/r${FLOPPY}
	dd if=/dev/r${FLOPPY} of=${RELEASEDIR}/floppies/cdins_bt.flp \
		bs=15b count=160
	gzip --no-name -9 -c ${RELEASEDIR}/floppies/cdins_bt.flp \
		>${RELEASEDIR}/floppies/cdins_bt.flp.gz &

filesyst.flp:
	disklabel -w -r ${FLOPPY} ${FLOPPY_TYPE} \
		${DESTDIR}/usr/mdec/fdboot ${DESTDIR}/usr/mdec/bootfd
	newfs -b 4096 -c 80 -f 512 -i 10240 -m 0 -o space \
		r${FLOPPY}  ${FLOPPY_TYPE}
	mount /dev/${FLOPPY}  ${MOUNT}
	chown ${BINOWN}.${BINGRP} ${MOUNT}/.
	chmod 755 ${MOUNT}/.
	(cd ${DESTDIR}/; \
	    ls -d ${FILESYSTEM_DIRS} | cpio -pdamuv ${MOUNT})
	(cd ${MOUNT}/dev; \
	    sh ${DESTDIR}/dev/MAKEDEV std; \
	    rm -rf fd; \
	    sh ${DESTDIR}/dev/MAKEDEV fd0 fd1 wd0 wd1 sd0 sd1; \
	    rm -f fd0?* fd1?* rfd0?* rfd1?*)
	(cd ${DESTDIR}/; \
	    ls ${FILESYSTEM_FILES} | cpio -pdamuv ${MOUNT}; \
	    (find ${FILESYSTEM_CPIO}; ls -d ${FILESYSTEM_CPIO_DIRS}) | \
		cpio -H newc --block-size=16 -oav | \
		gzip -9 >${MOUNT}/inst1.cpio.gz)
	install -c -o ${BINOWN} -g ${BINGRP} -m 755 \
	    ${.CURDIR}/etc.i386/inst1.profile ${MOUNT}/.profile
	install -c -o ${BINOWN} -g ${BINGRP} -m 755 \
	    ${.CURDIR}/etc.i386/inst1.install ${MOUNT}/install
	install -c -o ${BINOWN} -g ${BINGRP} -m 755 \
	    filesystem ${MOUNT}/bin/filesystem
	(cd ${MOUNT}/; \
	    for i in ${FILESYSTEM_LINKS}; do \
		ln bin/filesystem $$i; \
	    done)
	(cd ${MOUNT}/; \
	    ls ${FILESYSTEM_FILES} >/tmp/filelist; \
	    ls ${FILESYSTEM_LINKS} >>/tmp/filelist; \
	    ls -d ${FILESYSTEM_DIRS} >>/tmp/filelist; \
	    find ${FILESYSTEM_TREES} >>/tmp/filelist; \
	    sort -u -r /tmp/filelist >filelist; \
	    rm /tmp/filelist)
	df -ik ${MOUNT}
	umount /dev/${FLOPPY}
	fsck /dev/r${FLOPPY}
	dd if=/dev/r${FLOPPY} of=${RELEASEDIR}/floppies/filesyst.flp \
		bs=15b count=160
	gzip --no-name -9 -c ${RELEASEDIR}/floppies/filesyst.flp \
		>${RELEASEDIR}/floppies/filesyst.flp.gz &

cpio.flp:
	disklabel -w -r ${FLOPPY} ${FLOPPY_TYPE} \
		${DESTDIR}/usr/mdec/fdboot ${DESTDIR}/usr/mdec/bootfd
	newfs -b 4096 -c 80 -f 512 -i 65536 -m 0 -o space \
			r${FLOPPY}  ${FLOPPY_TYPE}
	mount /dev/${FLOPPY} ${MOUNT}
	chown ${BINOWN}.${BINGRP} ${MOUNT}/.
	chmod 755 ${MOUNT}/.
	(cd ${DESTDIR}/; \
		ls ${CPIO_FILES} | cpio -pdamuv ${MOUNT})
	# This ugliness is because the default termcap file is simply too
	# big and we don't need such a hugh one for the initial installation,
	# yet we want the symlink in /etc to point to the right place so we
	# need to install the smaller one in the same location.  Same goes
	# for the elvis hackery; just trying to bum as many bytes as we can
	# here, and that's rarely a very pretty process.
	mv ${DESTDIR}/usr/share/misc/termcap ${DESTDIR}/usr/share/misc/otermcap
	install -c -o ${BINOWN} -g ${BINGRP} -m 755 \
	    ${.CURDIR}/termcap.small ${DESTDIR}/usr/share/misc/termcap
	# Use cp so we don't destroy the links.
	cp ${DESTDIR}/usr/bin/ex ${DESTDIR}/usr/bin/ex.bak
	cp ${DESTDIR}/usr/bin/elvis ${DESTDIR}/usr/bin/ex
	(cd ${DESTDIR}/; \
	    (find ${CPIO_CPIO}; ls -d ${CPIO_CPIO_DIRS}) | \
		cpio -H newc --block-size=16 -oav | \
		gzip -9 >${MOUNT}/inst2.cpio.gz)
	# cpio is done, put everything back in shape for the bindist.
	mv ${DESTDIR}/usr/share/misc/otermcap ${DESTDIR}/usr/share/misc/termcap
	cp ${DESTDIR}/usr/bin/ex.bak ${DESTDIR}/usr/bin/ex
	rm ${DESTDIR}/usr/bin/ex.bak
	install -c -o ${BINOWN} -g ${BINGRP} -m 755 \
	    ${.CURDIR}/etc.i386/cpio.rc ${MOUNT}/rc
	install -c -o ${BINOWN} -g ${BINGRP} -m 755 \
	    ${.CURDIR}/etc.i386/cpio.install ${MOUNT}/install
	install -c -o ${BINOWN} -g ${BINGRP} -m 755 \
	    ${.CURDIR}/etc.i386/cpio.magic ${MOUNT}/magic
	df -ik ${MOUNT}
	umount /dev/${FLOPPY}
	fsck /dev/r${FLOPPY}
	dd if=/dev/r${FLOPPY} of=${RELEASEDIR}/floppies/cpio.flp \
		bs=15b count=160
	gzip --no-name -9 -c ${RELEASEDIR}/floppies/cpio.flp \
		>${RELEASEDIR}/floppies/cpio.flp.gz &

bin-tarball:
	(cd ${DESTDIR}; \
		tar cf - . | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/bindist/bin_tgz.)

src-clean:
	(cd ${DESTDIR}/usr/src; make cleandist)
	find ${DESTDIR}/usr/src -name obj | xargs -n30 rm -rf
	rm -rf ${DESTDIR}/usr/src/sys/compile/GENERIC*
	chown -R bin:bin ${DESTDIR}/usr/src
	chmod -R og-w ${DESTDIR}/usr/src

srcbase-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/[A-Z]* | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/base.)

srcbin-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/bin | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/srcbin.)

srccontrib-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/contrib | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/contrib.)

srcetc-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/etc | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/etc.)

srcgames-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/games | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/games.)

srcgnu-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/gnu | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/gnu.)

srcinclude-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/include | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/include.)

srclib-tarball:
	(cd ${DESTDIR}; \
		tar --exclude usr/src/${CRYPT_LIB} --exclude CVS -cf - \
		usr/src/lib | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/lib.)

srclibcrypt-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/${CRYPT_LIB} | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/secrdist/libcrypt.)

srclibexec-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/libexec | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/libexec.)

srcsbin-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/sbin | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/sbin.)

srcshare-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/share | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/share.)

srcsys-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/sys | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/sys.)

srcusrbin-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/usr.bin | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/usrbin.)

srcusrsbin-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/usr.sbin | \
		${ZIPNSPLIT} ${RELEASEDIR}/tarballs/srcdist/usrsbin.)

srckrb-tarball:
	(cd ${DESTDIR}; \
		tar --exclude CVS -cf - usr/src/kerberosIV | \
		 ${ZIPNSPLIT} ${RELEASEDIR}/tarballs/secrdist/kerberos.)

src-tarball: src-clean srcbase-tarball srcbin-tarball srccontrib-tarball \
	srcetc-tarball srcgames-tarball srcgnu-tarball srcinclude-tarball \
	srclib-tarball srclibcrypt-tarball srclibexec-tarball srcsbin-tarball \
	srcshare-tarball srcsys-tarball srcusrbin-tarball srcusrsbin-tarball \
	srckrb-tarball

des-tarball:
	rm -rf ${RELEASEDIR}/tmpdes
	mkdir ${RELEASEDIR}/tmpdes
	for i in ${CRYPT_DIRS}; do \
		cd ${RELEASEDIR}/tmpdes; \
		mkdir $$i; \
		chown ${BINOWN}.${GRPOWN} $$i; \
		chmod 755 $$i; \
	done
	# This is ugly, it force installs a /usr/lib/libcrypt.a so
	# that the other makes will be built with des.
	#
	(cd ${.CURDIR}/../${CRYPT_LIB}; \
		unset NOCRYPT; \
		DESTDIR=; export DESTDIR; \
		${MAKE} cleandir obj depend all install; \
		NOMAN=noman; export NOMAN; \
		DESTDIR=${RELEASEDIR}/tmpdes; export DESTDIR; \
		${MAKE} cleandir obj depend all install)
	for i in ${CRYPT_SRCS}; do \
		unset NOCRYPT; \
		DESTDIR=${RELEASEDIR}/tmpdes; export DESTDIR; \
		NOMAN=noman; export NOMAN; \
		cd ${.CURDIR}/../$$i; \
		${MAKE} cleandir obj depend all install; \
	done
	(cd ${RELEASEDIR}/tmpdes; \
		tar cf - . | \
			${ZIPNSPLIT} ${RELEASEDIR}/tarballs/secrdist/des_tgz.)
	rm -rf ${RELEASEDIR}/tmpdes

distrib-dirs:
	mtree -u -f ${.CURDIR}/mtree/BSD.root.dist -p ${DESTDIR}/
	mtree -u -f ${.CURDIR}/mtree/BSD.var.dist -p ${DESTDIR}/var
	mtree -u -f ${.CURDIR}/mtree/BSD.usr.dist -p ${DESTDIR}/usr
.if defined(CDROMDIST)
	mtree -u -f ${.CURDIR}/mtree/BSD.local.dist -p ${DESTDIR}/usr/local
.endif
	cd ${DESTDIR}/; rm -f ${DESTDIR}/sys; ln -s usr/src/sys sys

floppies:	kcopy_ah.flp kcopy_bt.flp filesyst.flp cpio.flp \
		cdins_ah.flp cdins_bt.flp

release:	release-dirs distribution crunch extract kcopy-kernels \
		floppies bin-tarball des-tarball clean

release-dirs:
	rm -rf ${RELEASEDIR}/filesys
	mkdir ${RELEASEDIR}/filesys
	chown ${BINOWN}.${BINGRP} ${RELEASEDIR}/filesys
	chmod 755 ${RELEASEDIR}/filesys
	rm -rf ${RELEASEDIR}/tarballs
	mkdir ${RELEASEDIR}/tarballs
	mkdir ${RELEASEDIR}/tarballs/bindist
	mkdir ${RELEASEDIR}/tarballs/objdist
	mkdir ${RELEASEDIR}/tarballs/secrdist
	mkdir ${RELEASEDIR}/tarballs/srcdist
	chown -R ${BINOWN}.${BINGRP} ${RELEASEDIR}/tarballs
	chmod -R 755 ${RELEASEDIR}/tarballs
	rm -rf ${RELEASEDIR}/floppies
	mkdir ${RELEASEDIR}/floppies
	chown ${BINOWN}.${BINGRP} ${RELEASEDIR}/floppies
	chmod 755 ${RELEASEDIR}/floppies

.include <bsd.prog.mk>
