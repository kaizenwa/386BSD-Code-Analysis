/* @(#)w_cosh.c 5.1 93/09/24 */
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
static char rcsid[] = "$Id: w_cosh.c,v 1.1.1.1 1994/05/06 00:20:09 gclarkii Exp $";
#endif

/* 
 * wrapper cosh(x)
 */

#include "math.h"

#ifdef __STDC__
	double cosh(double x)		/* wrapper cosh */
#else
	double cosh(x)			/* wrapper cosh */
	double x;
#endif
{
#ifdef _IEEE_LIBM
	return __ieee754_cosh(x);
#else
	double z;
	z = __ieee754_cosh(x);
	if(_LIB_VERSION == _IEEE_ || isnan(x)) return z;
	if(fabs(x)>7.10475860073943863426e+02) {	
	        return __kernel_standard(x,x,5); /* cosh overflow */
	} else
	    return z;
#endif
}
