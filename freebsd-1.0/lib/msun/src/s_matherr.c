/* @(#)s_matherr.c 5.1 93/09/24 */
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice 
 * is preserved.
 * ====================================================
 */

#ifndef lint
static char rcsid[] = "$Id: s_matherr.c,v 1.1.1.1 1994/05/06 00:20:06 gclarkii Exp $";
#endif

#include "math.h"

#ifdef __STDC__
	int matherr(struct exception *x)
#else
	int matherr(x)
	struct exception *x;
#endif
{
	int n=0;
	if(x->arg1!=x->arg1) return 0;
	return n;
}
