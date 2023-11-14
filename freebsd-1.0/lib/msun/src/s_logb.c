/* @(#)s_logb.c 5.1 93/09/24 */
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
static char rcsid[] = "$Id: s_logb.c,v 1.1.1.1 1994/05/06 00:20:06 gclarkii Exp $";
#endif

/*
 * double logb(x)
 * IEEE 754 logb. Included to pass IEEE test suite. Not recommend.
 * Use ilogb instead.
 */

#include "math.h"
#include <machine/endian.h>

#if BYTE_ORDER == LITTLE_ENDIAN
#define n0	1
#else
#define n0	0
#endif

#ifdef __STDC__
	double logb(double x)
#else
	double logb(x)
	double x;
#endif
{
	int lx,ix;
	ix = (*(n0+(int*)&x))&0x7fffffff;	/* high |x| */
	lx = *(1-n0+(int*)&x);			/* low x */
	if((ix|lx)==0) return -1.0/fabs(x);
	if(ix>=0x7ff00000) return x*x;
	if((ix>>=20)==0) 			/* IEEE 754 logb */
		return -1022.0; 
	else
		return (double) (ix-1023); 
}
