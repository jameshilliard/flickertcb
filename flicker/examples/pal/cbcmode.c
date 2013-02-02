/*
 * cbcmode.c: implement aes cbc mode
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

#include "aes.h"
#include "cbcmode.h"

static unsigned char tbuf[N_BLOCK];
static unsigned char okey[2*N_BLOCK];


static void xor_block(unsigned char *out, const unsigned char *in1, const unsigned char *in2)
{
    int n = N_BLOCK;
    while (n--)
        *out++ = *in1++ ^ *in2++;
}

void aes_cbc_encrypt(unsigned char *out, const unsigned char *in, int blocks, 
       const unsigned char *iv,  const unsigned char *key)
{
    while (blocks--) {
        xor_block(tbuf, in, iv);
        aes_encrypt_256(tbuf, out, key, okey);
        iv = out;
        out += N_BLOCK;
        in += N_BLOCK;
    }
}

void aes_cbc_decrypt(unsigned char *out, const unsigned char *in, int blocks, 
       const unsigned char *iv,  const unsigned char *key)
{
    while (blocks--) {
        aes_decrypt_256(in, out, key, okey);
        xor_block(out, out, iv);
        iv = in;
        out += N_BLOCK;
        in += N_BLOCK;
    }
}



/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
