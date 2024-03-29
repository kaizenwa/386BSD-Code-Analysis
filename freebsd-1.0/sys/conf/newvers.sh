#!/bin/sh -
#
# Copyright (c) 1984, 1986, 1990 The Regents of the University of California.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#	This product includes software developed by the University of
#	California, Berkeley and its contributors.
# 4. Neither the name of the University nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#	from: @(#)newvers.sh	7.4 (Berkeley) 12/7/90
#	$Id: newvers.sh,v 1.10 1994/06/28 10:39:08 jkh Exp $
#

if [ ! -r version ]
then
	echo 0 > version
else
	expr `cat version` + 1 > version
fi

touch version

ostype="FreeBSD"
osrelease="1.1.5.1(RELEASE)"
kernvers="${ostype} ${osrelease}"
v=`cat version` t=`date "+ %m/%d/%y %H:%M"`
t=`date`
user=${USER-root}
host=`hostname`
dir=`pwd`
(
  echo "const char version[] = \"${kernvers} ($1) #${v}: ${t}\\n  ${user}@${host}:${dir}\\n\";"
  echo "const char ostype[] = \"${ostype}\";"
  echo "const char osrelease[] = \"${osrelease}\";"
  echo "const int osbuild = ${v};"
  echo "const char osconfig[] = \"$1\";"
) > vers.c
