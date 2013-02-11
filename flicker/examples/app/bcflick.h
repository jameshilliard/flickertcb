/* bcflick.h - definitions for bcflick.c
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

#ifndef _BCFLICK_H_
#define _BCFLICK_H_

#ifdef __cplusplus
extern "C" {
#endif

int flicker_init(unsigned char *key, int keylen, unsigned long long daylimit,
        const char *datadir);
void flicker_setchange(int changeindex, unsigned char *pk, unsigned pksize,
        unsigned char *ctext, unsigned ctextsize);
int flicker_sign(unsigned char *txto, int txtolen,
       unsigned char *txfrom, int txfromlen, unsigned char *iv, unsigned char *ctxt, int ctxtlen,
       int nth, int ninputs, const char *datadir);
int flicker_retrievesig(unsigned char *psig);
char *flicker_error(void);
int flicker_keygen(int compressed, unsigned char *ctext, unsigned char *pk, const char *datadir);

#ifdef __cplusplus
}
#endif
#endif /* _BCFLICK_H_ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
