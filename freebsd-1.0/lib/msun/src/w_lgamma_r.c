/* @(#)w_lgamma_r.c 5.1 93/09/24 */
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
static char rcsid[] = "$Id: w_lgamma_r.c,v 1.1.1.1 1994/05/06 00:20:12 gclarkii Exp $";
#endif

/* 
 * wrapper double lgamma_r(double x, int *signgamp)
 */

#include "math.h"


#ifdef __STDC__
	double lgamma_r(double x, int *signgamp) /* wrapper lgamma_r */
#else
	double lgamma_r(x,signgamp)              /* wrapper lgamma_r */
        double x; int *signgamp;
#endif
{
#ifdef _IEEE_LIBM
	return __ieee754_lgamma_r(x,signgamp);
#else
        double y;
        y = __ieee754_lgamma_r(x,signgamp);
        if(_LIB_VERSION == _IEEE_) return y;
        if(!finite(y)&&finite(x)) {
            if(floor(x)==x&&x<=0.0)
                return __kernel_standard(x,x,15); /* lgamma pole */
            else
                return __kernel_standard(x,x,14); /* lgamma overflow */
        } else
            return y;
#endif
}             
