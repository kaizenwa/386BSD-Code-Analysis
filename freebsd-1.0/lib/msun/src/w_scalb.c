/* @(#)w_scalb.c 5.1 93/09/24 */
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
static char rcsid[] = "$Id: w_scalb.c,v 1.1.1.1 1994/05/06 00:20:14 gclarkii Exp $";
#endif

/*
 * wrapper scalb(double x, double fn) is provide for
 * passing various standard test suite. One 
 * should use scalbn() instead.
 */

#include "math.h"

#include <errno.h>

#ifdef __STDC__
#ifdef _SCALB_INT
	double scalb(double x, int fn)		/* wrapper scalb */
#else
	double scalb(double x, double fn)	/* wrapper scalb */
#endif
#else
	double scalb(x,fn)			/* wrapper scalb */
#ifdef _SCALB_INT
	double x; int fn;
#else
	double x,fn;
#endif
#endif
{
#ifdef _IEEE_LIBM
	return __ieee754_scalb(x,fn);
#else
	double z;
	z = __ieee754_scalb(x,fn);
	if(_LIB_VERSION == _IEEE_) return z;
	if(!(finite(z)||isnan(z))&&finite(x)) {
	    return __kernel_standard(x,(double)fn,32); /* scalb overflow */
	}
	if(z==0.0&&z!=x) {
	    return __kernel_standard(x,(double)fn,33); /* scalb underflow */
	} 
#ifndef _SCALB_INT
	if(!finite(fn)) errno = ERANGE;
#endif
	return z;
#endif 
}
