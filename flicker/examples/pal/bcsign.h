/* bcsign.h - definitions for bcsign.c
 *
 * Copyright (C) 2012-2013 Hal Finney
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 */

#ifndef _BCSIGN_H_
#define _BCSIGN_H_

#define     MAX_VALUE   ((21LL * 1000LL * 1000LL) * (10000LL * 10000LL))

int bc_output_data(uint64_t *pvalue, uint8_t **pscript, size_t *pscriptlen, int nth,
        uint8_t *tx, size_t txlen);
extern int bc_inputs(int *pinputs, uint8_t *tx, size_t txlen);
extern int bc_input_data(int *pindex, uint8_t **phash, int nth, uint8_t *tx, size_t txlen);
extern int bc_signature_hash(uint8_t *hash, uint8_t *script, size_t scriptlen, int nth,
        uint8_t *tx, size_t txlen);
extern int bc_signature(uint8_t *psig, size_t *psiglen, uint8_t *hash, uint8_t *x, uint8_t *k);

#endif /* _BCSIGN_H_ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
