/*
 * bcsign.c: signatures for bitcoin transactions
 *
 * Copyright (C) 2012 Hal Finney
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

#include <stdarg.h>
#include "malloc.h"
#include "tpm.h"
#include "string.h"
#include "util.h"
#include "sha256.h"
#include "bcsign.h"

static int parse_uint64(uint64_t *val, uint8_t **buf, size_t *len)
{
    if (*len < sizeof(*val))
        return false;
    *val = *(uint64_t *)*buf;
    *buf += sizeof(*val);
    *len -= sizeof(*val);
    return true;
}

static int parse_uint32(uint32_t *val, uint8_t **buf, size_t *len)
{
    if (*len < sizeof(*val))
        return false;
    *val = *(uint32_t *)*buf;
    *buf += sizeof(*val);
    *len -= sizeof(*val);
    return true;
}

static int parse_uint16(uint16_t *val, uint8_t **buf, size_t *len)
{
    if (*len < sizeof(*val))
        return false;
    *val = *(uint16_t *)*buf;
    *buf += sizeof(*val);
    *len -= sizeof(*val);
    return true;
}

static int parse_uint8(uint8_t *val, uint8_t **buf, size_t *len)
{
    if (*len < sizeof(*val))
        return false;
    *val = *(uint8_t *)*buf;
    *buf += sizeof(*val);
    *len -= sizeof(*val);
    return true;
}

static int parse_skip(size_t skip, uint8_t **buf, size_t *len)
{
    if (*len < skip)
        return false;
    *buf += skip;
    *len -= skip;
    return true;
}

static int parse_varlen(int *val, uint8_t **buf, size_t *len)
{
    uint8_t l;
    uint16_t x;
    uint32_t y;

    if (!parse_uint8(&l, buf, len))
        return false;
    if (l < 253) {
        *val = l;
    } else if (l == 253) {
        if (!parse_uint16(&x, buf, len))
            return false;
        *val = x;
    } else if (l == 254) {
        if (!parse_uint32(&y, buf, len))
            return false;
        *val = y;
    } else
        return false;

    return true;
}

int nth_output(uint64_t *value, uint8_t **script, size_t *script_len, int nth,
        uint8_t **buf, size_t *len)
{
    uint32_t version;
    int nin;
    uint8_t *hashin;
    uint32_t nthin;
    int sslen;
    uint32_t sequence;
    int nout;
    uint64_t val;
    int sklen;
    uint32_t locktime;
    int i;

    if (!parse_uint32(&version, buf, len))
        return false;
    if (nth < 0)log_event(LOG_LEVEL_INFORMATION, "version: %x\n", version);

    if (!parse_varlen(&nin, buf, len))
        return false;
    if (nth < 0)log_event(LOG_LEVEL_INFORMATION, "nin: %d\n", nin);
    for (i=0; i<nin; i++) {
        hashin = *buf;
        if (!parse_skip(256/8, buf, len))
            return false;
        if (nth < 0)log_event(LOG_LEVEL_INFORMATION, "hashin: %02x%02x%02x%02x\n", hashin[0], hashin[1], hashin[2], hashin[3]);
        if (!parse_uint32(&nthin, buf, len))
            return false;
        if (nth < 0)log_event(LOG_LEVEL_INFORMATION, "nthin: %d\n", nthin);
        if (!parse_varlen(&sslen, buf, len))
            return false;
        if (!parse_skip(sslen, buf, len))
            return false;
        if (nth < 0)log_event(LOG_LEVEL_INFORMATION, "sslen: %d\n", sslen);
        if (!parse_uint32(&sequence, buf, len))
            return false;
        if (nth < 0)log_event(LOG_LEVEL_INFORMATION, "sequence: %d\n", sequence);
    }

    if (!parse_varlen(&nout, buf, len))
        return false;
    if (nth < 0)log_event(LOG_LEVEL_INFORMATION, "nout: %d\n", nout);
    if (nth >= nout)
        return false;
    for (i=0; i<nout; i++) {
        if (!parse_uint64(&val, buf, len))
            return false;
        if (nth < 0)log_event(LOG_LEVEL_INFORMATION, "val: %lld\n", val);
        if (i == nth) {
            *value = val;
            *script = *buf;
        }
        if (!parse_varlen(&sklen, buf, len))
            return false;
        if (!parse_skip(sklen, buf, len))
            return false;
        if (nth < 0)log_event(LOG_LEVEL_INFORMATION, "sklen: %d\n", sklen);
        if (i == nth) {
            *script_len = *buf - *script;
            break;
        }
    }

    if (nth < 0) {
        if (!parse_uint32(&locktime, buf, len))
            return false;
        log_event(LOG_LEVEL_INFORMATION, "locktime: %d\n", locktime);
    }

    return true;
}


int bc_output_data(uint64_t *pvalue, uint8_t **pscript, size_t *pscriptlen, int nth,
        uint8_t *tx, size_t txlen)
{
    uint64_t value;
    uint8_t *script;
    size_t scriptlen;

    if (!nth_output(&value, &script, &scriptlen, nth, &tx, &txlen))
        return false;
    if (value > MAX_VALUE)
        return false;
    if (pvalue)
        *pvalue = value;
    if (pscript)
        *pscript = script;
    if (pscriptlen)
        *pscriptlen = scriptlen;
    return true;
}

int bc_inputs(int *pinputs, uint8_t *tx, size_t txlen)
{
    uint32_t version;

    if (!parse_uint32(&version, &tx, &txlen))
        return false;
    return parse_varlen(pinputs, &tx, &txlen);
}

int bc_input_data(int *pindex, uint8_t **phash, int nth, uint8_t *tx, size_t txlen)
{
    uint8_t **buf = &tx;
    size_t *len = &txlen;
    uint32_t version;
    int nin;
    uint8_t *hash = 0;
    uint32_t nthin;
    int sslen;
    uint32_t sequence;
    int i;

    if (!parse_uint32(&version, buf, len))
        return false;

    if (!parse_varlen(&nin, buf, len))
        return false;

    if (nth >= nin)
        return false;

    for (i=0; i<nin; i++) {
        hash = *buf;
        if (!parse_skip(256/8, buf, len))
            return false;
        if (!parse_uint32(&nthin, buf, len))
            return false;
        if (i == nth)
            break;
        if (!parse_varlen(&sslen, buf, len))
            return false;
        if (!parse_skip(sslen, buf, len))
            return false;
        if (!parse_uint32(&sequence, buf, len))
            return false;
    }

    if (pindex)
        *pindex = nthin;
    if (phash)
        *phash = hash;
    return true;
}


int bc_signature_hash(uint8_t *hash, uint8_t *script, size_t scriptlen, int nth,
        uint8_t *tx, size_t txlen)
{
    sha256_context _ctx, *ctx=&_ctx;
    uint32_t hashtype = 1;
    uint8_t *itx = tx;
    uint8_t **buf = &tx;
    size_t *len = &txlen;
    uint32_t version;
    int nin;
    uint32_t nthin;
    int sslen;
    uint32_t sequence;
    int i;

    if (!parse_uint32(&version, buf, len))
        return false;

    if (!parse_varlen(&nin, buf, len))
        return false;

    if (nth >= nin)
        return false;

    for (i=0; i<nin; i++) {
        if (!parse_skip(256/8, buf, len))
            return false;
        if (!parse_uint32(&nthin, buf, len))
            return false;
        if (!parse_varlen(&sslen, buf, len))
            return false;
        if (sslen != 0)
            return false;
        if (i == nth)
            break;
        if (!parse_uint32(&sequence, buf, len))
            return false;
    }

    sha256_starts(ctx);
    sha256_update(ctx, itx, tx-itx-1);
    sha256_update(ctx, script, scriptlen);
    sha256_update(ctx, tx, txlen);
    sha256_update(ctx, (uint8_t *)&hashtype, sizeof(hashtype));
    sha256_finish(ctx, hash);
    sha256(hash, 32, hash);

    return true;
}

extern int ecsign(uint8_t *rr, size_t *rsize, uint8_t *ss, size_t *ssize, uint8_t *hash, uint8_t *xx, uint8_t *kk);

int bc_signature(uint8_t *psig, size_t *psiglen, uint8_t *hash, uint8_t *x, uint8_t *k)
{
    uint8_t r[32];
    uint8_t s[32];
    size_t r_size;
    size_t s_size;
    uint8_t *p = psig;
    uint8_t hashtype = 1;
    int r_pad;
    int s_pad;

    if (ecsign(r, &r_size, s, &s_size, hash, x, k) != 0)
        return false;

    r_pad = !!(r[0] & 0x80);
    s_pad = !!(s[0] & 0x80);

    *p++ = 0x30;
    *p++ = r_size + 2 + r_pad + s_size + 2 + s_pad;
    *p++ = 0x02;
    *p++ = r_size + r_pad;
    if (r_pad)
        *p++ = 0x00;
    memcpy(p, r, r_size);
    p += r_size;
    *p++ = 0x02;
    *p++ = s_size + s_pad;
    if (s_pad)
        *p++ = 0x00;
    memcpy(p, s, s_size);
    p += s_size;
    *p++ = hashtype;

    *psiglen = p - psig;
    return true;
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
