#!/bin/sh
#
# This file will extract all of the FreeBSD sources into
# ${EXTRACT_TARGET}/usr/src if it is set, or /usr/src otherwise.
# If you do not want all the sources you can copy this file to your
# disk and edit it to comment out the ones you do not want.  You
# will need to change the setting of SOURCEDIR to reflect where the srcdist
# directory is (dependent on where your cdrom is mounted,
# it might be /cdrom/tarballs/srcdist) .
#
if [ X"${SOURCEDIR}" = X"" ]; then
	SOURCEDIR=.
fi
if [ X"${EXTRACT_TARGET}" = X"" ]; then
	EXTRACT_TARGET=/
fi

cd $SOURCEDIR

# Note that base.aa is REQUIRED to be able to use the source tree for
# building in.
#
cat base.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -

#
# The following are optional
#
cat srcbin.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
cat contrib.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
cat etc.aa	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
cat games.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
cat gnu.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
cat include.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
cat lib.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
#NO_EXPORT#cat libcrypt.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
cat libexec.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
cat sbin.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
cat share.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
cat sys.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
cat usrbin.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
cat usrsbin.*	| gunzip | tar --unlink --directory ${EXTRACT_TARGET} -xpf -
