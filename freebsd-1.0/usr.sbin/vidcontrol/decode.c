/*-
 * Copyright (c) 1994 S�ren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software withough specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *	$Id: decode.c,v 1.1 1994/05/20 12:20:37 sos Exp $
 */

#include <stdio.h>

int decode(FILE *fd, char *buffer)
{
	int n, pos = 0;
	char *p;
	char temp[128];

#define	DEC(c)	(((c) - ' ') & 0x3f)

	do {
		if (!fgets(temp, sizeof(temp), fd)) 
			return(0);
	} while (strncmp(temp, "begin ", 6));
	sscanf(temp, "begin %o %s", &n, temp);
	for (;;) {
		if (!fgets(p = temp, sizeof(temp), fd))
			return(0);
		if ((n = DEC(*p)) <= 0)
			break;
		for (++p; n > 0; p += 4, n -= 3)
			if (n >= 3) {
				buffer[pos++] = DEC(p[0])<<2 | DEC(p[1])>>4;
				buffer[pos++] = DEC(p[1])<<4 | DEC(p[2])>>2;
				buffer[pos++] = DEC(p[2])<<6 | DEC(p[3]);
			}
			else {
				if (n >= 1) {
					buffer[pos++] =
						DEC(p[0])<<2 | DEC(p[1])>>4;
				}
				if (n >= 2) {
					buffer[pos++] = 
						DEC(p[1])<<4 | DEC(p[2])>>2;
				}
				if (n >= 3) {
					buffer[pos++] =
						DEC(p[2])<<6 | DEC(p[3]);
				}
			}
	}
	if (!fgets(temp, sizeof(temp), fd) || strcmp(temp, "end\n"))
		return(0);
	return(pos);
}
