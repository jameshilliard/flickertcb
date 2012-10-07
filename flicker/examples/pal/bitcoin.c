/*
 * bitcoin.c: sign transactions for bitcoin under policy
 *
 * Copyright (C) 2006-2011 Jonathan M. McCune
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
#include "printk.h"
#include "params.h"
#include "tpm.h"
#include "string.h"
#include "sha1.h"
#include "aes.h"
#include "cbcmode.h"
#include "bitcoin.h"

struct state {
    tpm_current_ticks_t ticks;
    int interval_secs;
    tpm_counter_value_t counter;
    unsigned char key[32];
    unsigned char dkey[32];
};

static int do_init_cmd(int cmd);
static int do_work_cmd(int cmd);
static int do_bitcoin(int cmd, struct state *pstate);
static void dumphex(unsigned char *bytes, int len);

int pal_main(void) __attribute__ ((section (".text.slb")));
int pal_main(void)
{
    char *inptr;
    int cmd;
    int rslt = rslt_ok;

    if (pm_get_addr(tag_cmd, &inptr) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no command\n");
        rslt = rslt_badparams;
        goto rslt;
    }

    cmd = *(int *)inptr;
    switch (cmd) {
        case cmd_init:
            rslt = do_init_cmd(cmd);
            break;
        case cmd_encrypt_key:
        case cmd_decrypt_key:
            rslt = do_work_cmd(cmd);
            break;
        default:
            log_event(LOG_LEVEL_ERROR, "error: unknown command %d\n", cmd);
            rslt = rslt_badparams;
            goto rslt;
    }

rslt:
    pm_append(tag_rslt, (char *)&rslt, sizeof(rslt));
    return rslt_ok;
}

static uint8_t blob[400];

static const tpm_authdata_t ctr_authdata =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static uint32_t counter_id = 0xab336c2;

static int do_init_cmd(int cmd)
{
    struct state state;
    char *inptr;
    int inlen;
    uint8_t pcrs[3] = {17, 18, 19};
    tpm_pcr_value_t pcr17, pcr18, pcr19;
    const tpm_pcr_value_t *pcr_values[3] = {&pcr17, &pcr18, &pcr19};
    uint32_t blobsize = sizeof(blob);
    unsigned char inblk[16], outblk[16];

    if ((inlen=pm_get_addr(tag_key, &inptr)) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no key\n");
        return rslt_badparams;
    }

    if (inlen != sizeof(state.key)) {
        log_event(LOG_LEVEL_ERROR, "error: key wrong length\n");
        return rslt_badparams;
    }

    memcpy(state.key, inptr, sizeof(state.key));

    /* dummy encryption to get the decrypt key */
    aes_encrypt_256(inblk, outblk, state.key, state.dkey);

    if (pm_get_addr(tag_interval, &inptr) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no interval\n");
        return rslt_badparams;
    }

    state.interval_secs = *(int *)inptr;
    tpm_read_current_ticks(2, &state.ticks);
    tpm_increment_counter(2, counter_id, &ctr_authdata, &state.counter);

    tpm_pcr_read(2, 17, &pcr17);
    tpm_pcr_read(2, 18, &pcr18);
    tpm_pcr_read(2, 19, &pcr19);

    if (tpm_seal(2, TPM_LOC_TWO, sizeof(pcrs), pcrs, sizeof(pcrs), pcrs, pcr_values,
            sizeof(state), (uint8_t *)&state, &blobsize, blob) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: seal failed\n");
        return rslt_fail;
    }
    pm_append(tag_blob, (char *)blob, blobsize);

    log_event(LOG_LEVEL_INFORMATION, "successfully sealed state\n");

    return rslt_ok;
}


static int do_work_cmd(int cmd)
{
    struct state state;
    tpm_current_ticks_t ticks;
    tpm_counter_value_t counter;
    char *inptr;
    uint8_t pcrs[3] = {17, 18, 19};
    uint32_t blobsize;
    uint32_t statesize;
    tpm_pcr_value_t pcr17, pcr18, pcr19;
    const tpm_pcr_value_t *pcr_values[3] = {&pcr17, &pcr18, &pcr19};
    int interval_secs;
    int rslt = rslt_ok;

    if ((blobsize = pm_get_addr(tag_blob, &inptr)) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no blob\n");
        return rslt_badparams;
    }

    tpm_pcr_read(2, 17, &pcr17);
    tpm_pcr_read(2, 18, &pcr18);
    tpm_pcr_read(2, 19, &pcr19);

    if(!tpm_cmp_creation_pcrs(sizeof(pcrs), pcrs, pcr_values, blobsize, (uint8_t *)inptr)) {
        log_event(LOG_LEVEL_ERROR, "error: creation pcrs mismatch\n");
        return rslt_inconsistentstate;
    }

    statesize = sizeof(state);
    if (tpm_unseal(2, blobsize, (uint8_t *)inptr, &statesize, (uint8_t *)&state) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: unseal failed\n");
        return rslt_fail;
    }

    log_event(LOG_LEVEL_INFORMATION, "state unsealed successfully\n");

    tpm_read_counter(2, counter_id, &counter);
    if (memcmp(&counter, &state.counter, sizeof(counter)) != 0) {
        log_event(LOG_LEVEL_ERROR, "anti rollback counter error: %d should be %d\n",
                state.counter.counter, counter.counter );
        return rslt_inconsistentstate;
    }
    
    tpm_read_current_ticks(2, &ticks);
    if (memcmp(ticks.tick_nonce.nonce, state.ticks.tick_nonce.nonce,
                sizeof(ticks.tick_nonce.nonce)) != 0) {
        log_event(LOG_LEVEL_WARNING, "tick timer got reset\n");
        return rslt_inconsistentstate;
    }

    interval_secs = (ticks.current_ticks - state.ticks.current_ticks)
        / (1000000 / ticks.tick_rate);
    log_event(LOG_LEVEL_INFORMATION, "interval = %d secs\n", interval_secs);
    if (interval_secs < state.interval_secs) {
        log_event(LOG_LEVEL_WARNING, "error: interval too short\n");
        interval_secs = state.interval_secs - interval_secs;
        pm_append(tag_delay, (char *)&interval_secs, sizeof(interval_secs));
        return rslt_disallowed;
    }

    log_event(LOG_LEVEL_INFORMATION, "work authorized!\n", interval_secs);

    if ((rslt = do_bitcoin(cmd, &state)) != 0) {
        log_event(LOG_LEVEL_ERROR, "error: bitcoin processing failed\n");
        return rslt;
    }

    state.ticks = ticks;
    tpm_increment_counter(2, counter_id, &ctr_authdata, &state.counter);

    blobsize = sizeof(blob);
    if (tpm_seal(2, TPM_LOC_TWO, sizeof(pcrs), pcrs, sizeof(pcrs), pcrs, pcr_values,
            sizeof(state), (uint8_t *)&state, &blobsize, blob) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: seal failed\n");
        return rslt_fail;
    }
    pm_append(tag_blob, (char *)blob, blobsize);
    
    return rslt;
}

static unsigned char padded[3*N_BLOCK], obuf[3*N_BLOCK];

static int do_bitcoin(int cmd, struct state *pstate)
{
    int rslt = rslt_ok;
    char *inptr;
    int inlen;
    unsigned char *iv;
    unsigned char *ptxt;
    unsigned char *ctxt;
    int padlen;
    int i;

    if ((inlen=pm_get_addr(tag_iv, &inptr)) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no iv\n");
        return rslt_badparams;
    }

    if (inlen != N_BLOCK) {
        log_event(LOG_LEVEL_ERROR, "error: iv wrong length\n");
        return rslt_badparams;
    }

    iv = (unsigned char *)inptr;

    if (cmd == cmd_encrypt_key) {
        if ((inlen=pm_get_addr(tag_plaintext, &inptr)) < 0) {
            log_event(LOG_LEVEL_ERROR, "error: no plaintext\n");
            return rslt_badparams;
        }

        if (inlen > sizeof(padded) - N_BLOCK) {
            log_event(LOG_LEVEL_ERROR, "error: plaintext wrong length\n");
            return rslt_badparams;
        }

        ptxt = (unsigned char *)inptr;

        padlen = N_BLOCK - (inlen % N_BLOCK);
        memcpy(padded, ptxt, inlen);
        memset(padded+inlen, padlen, padlen);

        aes_cbc_encrypt(obuf, padded, (inlen+padlen)/N_BLOCK, iv, pstate->key);

        pm_append(tag_ciphertext, (char *)obuf, inlen+padlen);

    } else if (cmd == cmd_decrypt_key) {

        if ((inlen=pm_get_addr(tag_ciphertext, &inptr)) < 0) {
            log_event(LOG_LEVEL_ERROR, "error: no ciphertext\n");
            return rslt_badparams;
        }

        if (inlen > sizeof(padded) || (inlen % N_BLOCK) != 0) {
            log_event(LOG_LEVEL_ERROR, "error: ciphertext wrong length\n");
            return rslt_badparams;
        }

        ctxt = (unsigned char *)inptr;

        aes_cbc_decrypt(padded, ctxt, inlen, iv, pstate->dkey);

        log_event(LOG_LEVEL_INFORMATION, "padded ctxt:\n");
        dumphex(padded, inlen);

        padlen = padded[inlen-1];
        i = 0;
        if (padlen > 0 || padlen <= N_BLOCK) {
            for (; i<padlen; i++) {
                if (padded[inlen-padlen+i] != padlen)
                    break;
            }
        }
        
        if (i==0 || i<padlen) {
            log_event(LOG_LEVEL_ERROR, "error: ciphertext wrongly padded\n");
            return rslt_badparams;
        }

        pm_append(tag_plaintext, (char *)padded, inlen-padlen);
    }

    return rslt;
}

static void dumphex(unsigned char *bytes, int len)
{
    int i;
    if(!bytes) return;

    for (i=0; i<len; i++)
        log_event(LOG_LEVEL_INFORMATION, "%02x%s", bytes[i], ((i+1)%16)?"":"\n");
    if(len%16)
        log_event(LOG_LEVEL_INFORMATION, "\n");
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
