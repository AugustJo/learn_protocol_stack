/* $Id: atomic.S,v 1.4 2001/11/18 00:12:56 davem Exp $
 * atomic.S: These things are too big to do inline.
 *
 * Copyright (C) 1999 David S. Miller (davem@redhat.com)
 */

#include <asm/asi.h>

	.text
	.align	64

	.globl	__atomic_add
	.type	__atomic_add,#function
__atomic_add: /* %o0 = increment, %o1 = atomic_ptr */
	lduw	[%o1], %g5
	add	%g5, %o0, %g7
	cas	[%o1], %g5, %g7
	cmp	%g5, %g7
	bne,pn	%icc, __atomic_add
	 membar	#StoreLoad | #StoreStore
	retl
	 add	%g7, %o0, %o0
	.size	__atomic_add, .-__atomic_add

	.globl	__atomic_sub
	.type	__atomic_sub,#function
__atomic_sub: /* %o0 = increment, %o1 = atomic_ptr */
	lduw	[%o1], %g5
	sub	%g5, %o0, %g7
	cas	[%o1], %g5, %g7
	cmp	%g5, %g7
	bne,pn	%icc, __atomic_sub
	 membar	#StoreLoad | #StoreStore
	retl
	 sub	%g7, %o0, %o0
	.size	__atomic_sub, .-__atomic_sub

	.globl	__atomic64_add
	.type	__atomic64_add,#function
__atomic64_add: /* %o0 = increment, %o1 = atomic_ptr */
	ldx	[%o1], %g5
	add	%g5, %o0, %g7
	casx	[%o1], %g5, %g7
	cmp	%g5, %g7
	bne,pn	%xcc, __atomic64_add
	 membar	#StoreLoad | #StoreStore
	retl
	 add	%g7, %o0, %o0
	.size	__atomic64_add, .-__atomic64_add

	.globl	__atomic64_sub
	.type	__atomic64_sub,#function
__atomic64_sub: /* %o0 = increment, %o1 = atomic_ptr */
	ldx	[%o1], %g5
	sub	%g5, %o0, %g7
	casx	[%o1], %g5, %g7
	cmp	%g5, %g7
	bne,pn	%xcc, __atomic64_sub
	 membar	#StoreLoad | #StoreStore
	retl
	 sub	%g7, %o0, %o0
	.size	__atomic64_sub, .-__atomic64_sub
