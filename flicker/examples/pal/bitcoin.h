/* bitcoin.h - definitions for bitcoin.c
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

#ifndef _BITCOIN_H_
#define _BITCOIN_H_

enum {
    tag_cmd = 0x40000000,
    tag_rslt,
    tag_blob,
    tag_daylimit,
    tag_key,
    tag_delay,
    tag_ciphertext,
    tag_pk,
    tag_signtrans,
    tag_changeindex,
    tag_changepk,
    tag_changectext,
    tag_inputtrans    = 0x100,
    tag_signctxt      = 0x200,
    tag_signiv        = 0x300,
    tag_signature     = 0x400,
};

enum {
    cmd_init,
    cmd_sign,
    cmd_keygen_comp,
    cmd_keygen_uncomp,
};

enum {
    rslt_ok,
    rslt_fail,
    rslt_badparams,
    rslt_disallowed,
    rslt_inconsistentstate,
};


#endif /* _BITCOIN_H_ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
