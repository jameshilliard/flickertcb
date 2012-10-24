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
#include "util.h"
#include "aes.h"
#include "cbcmode.h"
#include "bitcoin.h"
 
#define     NMEM        5
#define     MYCOUNTER   "BITC"

struct state {
    uint8_t state2_hash[SHA_DIGEST_LENGTH];
    uint8_t state2_key[2*N_BLOCK];
    uint8_t state2_dkey[2*N_BLOCK];
uint8_t state2[0];
    tpm_nonce_t tick_nonce;
    int interval_secs;
    uint32_t counter_id;
    uint32_t counter;
    uint8_t key[2*N_BLOCK];
    uint8_t dkey[2*N_BLOCK];
    uint8_t ct_mem[NMEM][SHA_DIGEST_LENGTH];
    uint64_t current_ticks[NMEM];
    uint8_t pad[N_BLOCK];
};

static int do_init_cmd(int cmd);
static int do_encrypt(int cmd);
static int do_decrypt(int cmd);
static void dumphex(uint8_t *bytes, int len);
static int find_counter(struct state *pstate);
static int state_seal(struct state *pstate);
static int state_unseal(struct state *pstate);

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
    log_event(LOG_LEVEL_INFORMATION, "command: %x\n", cmd);
    switch (cmd) {
        case cmd_init:
            rslt = do_init_cmd(cmd);
            break;
        case cmd_encrypt:
            rslt = do_encrypt(cmd);
            break;
        case cmd_decrypt:
            rslt = do_decrypt(cmd);
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

static struct state state;

static uint8_t blob[400], blob2[sizeof(struct state)];

static const tpm_authdata_t ctr_authdata =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static int do_init_cmd(int cmd)
{
    tpm_current_ticks_t ticks;
    char *inptr;
    int inlen;
    uint8_t inblk[N_BLOCK], outblk[N_BLOCK];
    uint32_t keysize;
    int rslt;

    if ((rslt = find_counter(&state)) != rslt_ok)
        return rslt;

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

    keysize = sizeof(state.state2_key);
    if (tpm_get_random(2, state.state2_key, &keysize) != 0
            || keysize != sizeof(state.state2_key)) {
        log_event(LOG_LEVEL_ERROR, "error: get_random failed\n");
        return rslt_fail;
    }
    aes_encrypt_256(inblk, outblk, state.state2_key, state.state2_dkey);

    /* iv */
    keysize = N_BLOCK;
    tpm_get_random(2, blob2, &keysize);

    if (pm_get_addr(tag_interval, &inptr) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no interval\n");
        return rslt_badparams;
    }

    state.interval_secs = *(int *)inptr;
    tpm_read_current_ticks(2, &ticks);
    memset(state.current_ticks, 0, sizeof(state.current_ticks));
    memcpy(state.tick_nonce.nonce, ticks.tick_nonce.nonce, sizeof(state.tick_nonce.nonce));
    memset(state.ct_mem, 0, sizeof(state.ct_mem));

    if ((rslt = state_seal(&state)) != rslt_ok)
        return rslt;

    return rslt_ok;
}


static uint8_t padded[3*N_BLOCK], obuf[3*N_BLOCK];

static int do_encrypt(int cmd)
{
    tpm_counter_value_t counter;
    char *inptr;
    int rslt = rslt_ok;
    int inlen;
    uint8_t *iv;
    uint8_t *ptxt;
    int padlen;

    if ((rslt = state_unseal(&state)) != rslt_ok)
        return rslt;

    tpm_read_counter(2, state.counter_id, &counter);
    if (counter.counter != state.counter) {
        log_event(LOG_LEVEL_ERROR, "anti rollback counter error: %d should be %d\n",
                state.counter, counter.counter );
        return rslt_inconsistentstate;
    }

    if ((inlen=pm_get_addr(tag_iv, &inptr)) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no iv\n");
        return rslt_badparams;
    }

    if (inlen != N_BLOCK) {
        log_event(LOG_LEVEL_ERROR, "error: iv wrong length\n");
        return rslt_badparams;
    }

    iv = (uint8_t *)inptr;

    if ((inlen=pm_get_addr(tag_plaintext, &inptr)) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no plaintext\n");
        return rslt_badparams;
    }

    if (inlen > sizeof(padded) - N_BLOCK) {
        log_event(LOG_LEVEL_ERROR, "error: plaintext wrong length\n");
        return rslt_badparams;
    }

    ptxt = (uint8_t *)inptr;

    padlen = N_BLOCK - (inlen % N_BLOCK);
    memcpy(padded, ptxt, inlen);
    memset(padded+inlen, padlen, padlen);

    aes_cbc_encrypt(obuf, padded, (inlen+padlen)/N_BLOCK, iv, state.key);

    pm_append(tag_ciphertext, (char *)obuf, inlen+padlen);

    return rslt;
}

static int do_decrypt(int cmd)
{
    tpm_current_ticks_t ticks;
    tpm_counter_value_t counter;
    char *inptr;
    int interval_secs;
    int rslt = rslt_ok;
    int inlen;
    uint8_t *iv;
    uint8_t *ctxt;
    int padlen;
    int i;
    int duplicate = false;
    uint8_t md[SHA_DIGEST_LENGTH];

    if ((rslt = state_unseal(&state)) != rslt_ok)
        return rslt;

    tpm_read_counter(2, state.counter_id, &counter);
    if (counter.counter != state.counter) {
        log_event(LOG_LEVEL_ERROR, "anti rollback counter error: %d should be %d\n",
                state.counter, counter.counter );
        return rslt_inconsistentstate;
    }

    if ((inlen=pm_get_addr(tag_iv, &inptr)) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no iv\n");
        return rslt_badparams;
    }

    if (inlen != N_BLOCK) {
        log_event(LOG_LEVEL_ERROR, "error: iv wrong length\n");
        return rslt_badparams;
    }

    iv = (uint8_t *)inptr;

    if ((inlen=pm_get_addr(tag_ciphertext, &inptr)) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no ciphertext\n");
        return rslt_badparams;
    }

    if (inlen > sizeof(padded) || (inlen % N_BLOCK) != 0) {
        log_event(LOG_LEVEL_ERROR, "error: ciphertext wrong length\n");
        return rslt_badparams;
    }

    ctxt = (uint8_t *)inptr;

    log_event(LOG_LEVEL_INFORMATION, "ctxt:\n");
    dumphex(ctxt, inlen);

    sha1_buffer(ctxt, inlen, md);

    for (i=0; i<NMEM; i++) {
        if (memcmp(md, state.ct_mem[i], SHA_DIGEST_LENGTH) == 0) {
            log_event(LOG_LEVEL_INFORMATION, "duplicate decryption found, allowed\n");
            duplicate = true;
            break;
        }
    }

    if (!duplicate) {
        tpm_read_current_ticks(2, &ticks);
        if (memcmp(ticks.tick_nonce.nonce, state.tick_nonce.nonce,
                    sizeof(ticks.tick_nonce.nonce)) != 0) {
            log_event(LOG_LEVEL_WARNING, "tick timer got reset\n");
            return rslt_inconsistentstate;
        }

        interval_secs = (ticks.current_ticks - state.current_ticks[0])
            / (1000000 / ticks.tick_rate);
        log_event(LOG_LEVEL_INFORMATION, "interval = %d secs\n", interval_secs);
        if (interval_secs < state.interval_secs * NMEM) {
            log_event(LOG_LEVEL_WARNING, "error: interval too short\n");
            interval_secs = state.interval_secs * NMEM - interval_secs;
            pm_append(tag_delay, (char *)&interval_secs, sizeof(interval_secs));
            return rslt_disallowed;
        }

        log_event(LOG_LEVEL_INFORMATION, "work authorized!\n");
    }

    aes_cbc_decrypt(padded, ctxt, inlen, iv, state.dkey);

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

    if (!duplicate) {
        for (i=1; i<NMEM; i++)
            memcpy(state.ct_mem[i-1], state.ct_mem[i], SHA_DIGEST_LENGTH);
        memcpy(state.ct_mem[NMEM-1], md, SHA_DIGEST_LENGTH);

        for (i=1; i<NMEM; i++)
            state.current_ticks[i-1] = state.current_ticks[i];
        state.current_ticks[NMEM-1] = ticks.current_ticks;

        tpm_increment_counter(2, state.counter_id, &ctr_authdata, &counter);
        state.counter = counter.counter;

        if ((rslt = state_seal(&state)) != rslt_ok)
            return rslt;
    }

    return rslt;
}


static int find_counter(struct state *pstate)
{
    tpm_counter_value_t counter;
    uint32_t subcap;
    uint32_t capsize;
    uint8_t caparea[4];
    uint8_t subcaparea[4];
    uint32_t max_counters;
    uint8_t *chandles;
    uint16_t nctrs;
    uint32_t ctrid;
    int chsize;
    int tryreboot;
    int i;

    pstate->counter_id = 0;

    /* check active monotonic counter */
    capsize = sizeof(caparea);
    subcap = TPM_CAP_PROP_ACTIVE_COUNTER;
    reverse_copy(subcaparea, (uint8_t *)&subcap, sizeof(subcaparea));
    if (tpm_get_capability(2, TPM_CAP_PROPERTY, sizeof(subcaparea), subcaparea,
                &capsize, (uint8_t *)&caparea) != 0  ||  capsize != sizeof(caparea)) {
        log_event(LOG_LEVEL_ERROR, "error: read active counter\n");
        return rslt_fail;
    }

    reverse_copy((uint8_t *)&ctrid, caparea, sizeof(ctrid));
    log_event(LOG_LEVEL_INFORMATION, "active ctrid: 0x%x\n", ctrid);

    if (tpm_increment_counter(2, ctrid, &ctr_authdata, &counter) == 0) {
        //log_event(LOG_LEVEL_INFORMATION, "label: %c%c%c%c\n", counter.label[0],
                //counter.label[1], counter.label[2], counter.label[3]);
        if (memcmp(counter.label, MYCOUNTER, sizeof(counter.label)) == 0) {
            log_event(LOG_LEVEL_INFORMATION, "active ctrid successful\n");
            pstate->counter_id = ctrid;
            pstate->counter = counter.counter;
            return rslt_ok;
        }
    }

    /* search for monotonic counter */
    capsize = sizeof(caparea);
    subcap = TPM_CAP_PROP_MAX_COUNTERS;
    reverse_copy(subcaparea, (uint8_t *)&subcap, sizeof(subcaparea));
    if (tpm_get_capability(2, TPM_CAP_PROPERTY, sizeof(subcaparea), subcaparea,
                &capsize, (uint8_t *)&caparea) != 0  ||  capsize != sizeof(caparea)) {
        log_event(LOG_LEVEL_ERROR, "error: read max counters\n");
        return rslt_fail;
    }

    reverse_copy((uint8_t *)&max_counters, caparea, sizeof(max_counters));
    log_event(LOG_LEVEL_INFORMATION, "max_counters: %d\n", max_counters);

    chsize = sizeof(nctrs) + sizeof(ctrid) * max_counters;
    if ((chandles = malloc(chsize)) == NULL) {
        log_event(LOG_LEVEL_ERROR, "error: malloc\n");
        return rslt_fail;
    }

    capsize = chsize;
    subcap = TPM_RT_COUNTER;
    reverse_copy(subcaparea, (uint8_t *)&subcap, sizeof(subcaparea));
    if (tpm_get_capability(2, TPM_CAP_HANDLE, sizeof(subcaparea), subcaparea,
                &capsize, chandles) != 0) {
        free(chandles);
        log_event(LOG_LEVEL_ERROR, "error: read counter handles\n");
        return rslt_fail;
    }

    reverse_copy((uint8_t *)&nctrs, chandles, sizeof(nctrs));
    log_event(LOG_LEVEL_INFORMATION, "nctrs: %d\n", nctrs);

    tryreboot = false;
    for (i=0; i<nctrs; i++) {
        reverse_copy((uint8_t *)&ctrid, chandles+sizeof(nctrs)+sizeof(ctrid)*i, sizeof(ctrid));
        log_event(LOG_LEVEL_INFORMATION, "ctrid: 0x%x\n", ctrid);
        if (tpm_read_counter(2, ctrid, &counter) != 0)
            continue;
        log_event(LOG_LEVEL_INFORMATION, "label: %c%c%c%c\n", counter.label[0],
                counter.label[1], counter.label[2], counter.label[3]);
        if (memcmp(counter.label, MYCOUNTER, sizeof(counter.label)) == 0) {
            if (tpm_increment_counter(2, ctrid, &ctr_authdata, &counter) == 0) {
                log_event(LOG_LEVEL_INFORMATION, "this ctrid successful\n");
                pstate->counter_id = ctrid;
                free(chandles);
                pstate->counter = counter.counter;
                return rslt_ok;
            } else {
                tryreboot = true;
            }
        }
    }
    free(chandles);

    if (tryreboot)
        log_event(LOG_LEVEL_INFORMATION,
                "unable to use anti rollback counter, try rebooting\n");
    else
        log_event(LOG_LEVEL_INFORMATION,
                "no usable anti rollback counter, create one with label: %s\n", MYCOUNTER);
    return rslt_fail;
}


static int state_seal(struct state *pstate)
{
    uint8_t pcrs[3] = {17, 18, 19};
    tpm_pcr_value_t pcr17, pcr18, pcr19;
    const tpm_pcr_value_t *pcr_values[3] = {&pcr17, &pcr18, &pcr19};
    uint32_t blobsize1;
    uint32_t blobsize2;
    uint32_t statesize1;
    uint32_t statesize2;
    char *outptr;

    tpm_pcr_read(2, 17, &pcr17);
    tpm_pcr_read(2, 18, &pcr18);
    tpm_pcr_read(2, 19, &pcr19);

    blobsize1 = sizeof(blob);
    statesize1 = (uint8_t *)pstate->state2 - (uint8_t *)pstate;
    statesize2 = ((sizeof(state) - statesize1) / N_BLOCK) * N_BLOCK;
    blobsize2 = statesize2 + N_BLOCK;

    /*recycle iv */
    sha1_buffer(blob2, N_BLOCK, blob2);

    record_timestamp("state2 encrypt start");
    aes_cbc_encrypt(blob2+N_BLOCK, (uint8_t *)pstate->state2, statesize2/N_BLOCK,
            blob2, pstate->state2_key);
    record_timestamp("state2 encrypt end");

    sha1_buffer(blob2, blobsize2, pstate->state2_hash);

    record_timestamp("state seal start");
    if (tpm_seal(2, TPM_LOC_TWO, sizeof(pcrs), pcrs, sizeof(pcrs), pcrs, pcr_values,
                statesize1, (uint8_t *)pstate, &blobsize1, blob) != 0) {
        log_event(LOG_LEVEL_ERROR, "error: seal failed\n");
        return rslt_fail;
    }
    record_timestamp("state seal end");

    outptr = pm_reserve(tag_blob, blobsize1+blobsize2);
    memcpy(outptr, blob, blobsize1);
    memcpy(outptr+blobsize1, blob2, blobsize2);

    log_event(LOG_LEVEL_INFORMATION, "successfully sealed state, size: %d\n",
        blobsize1+blobsize2);
    return rslt_ok;
}


static int state_unseal(struct state *pstate)
{
    char *inptr;
    uint8_t pcrs[3] = {17, 18, 19};
    uint32_t blobsize;
    uint32_t blobsize1;
    uint32_t blobsize2;
    uint32_t statesize1;
    uint32_t statesize2;
    tpm_pcr_value_t pcr17, pcr18, pcr19;
    const tpm_pcr_value_t *pcr_values[3] = {&pcr17, &pcr18, &pcr19};
    uint8_t md[SHA_DIGEST_LENGTH];

    if ((blobsize = pm_get_addr(tag_blob, &inptr)) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no blob\n");
        return rslt_badparams;
    }

    if (blobsize < sizeof(tpm_stored_data12_header_t))
        return rslt_badparams;
    if (((const tpm_stored_data12_header_t *)inptr)->tag != TPM_TAG_STORED_DATA12)
        return rslt_badparams;

    if (((const tpm_stored_data12_header_t *)inptr)->seal_info_size == 0) {
        const tpm_stored_data12_short_t *data12_s;

        if (blobsize < sizeof(*data12_s))
            return rslt_badparams;
        data12_s = (const tpm_stored_data12_short_t *)inptr;
        blobsize1 = sizeof(*data12_s) + data12_s->enc_data_size;
        if (blobsize < blobsize1)
            return rslt_badparams;
    } else {
        const tpm_stored_data12_t *data12;

        if (blobsize < sizeof(*data12))
            return rslt_badparams;
        data12 = (const tpm_stored_data12_t *)inptr;
        blobsize1 = sizeof(*data12) + data12->enc_data_size;
        if (blobsize < blobsize1)
            return rslt_badparams;
    }

    blobsize2 = blobsize - blobsize1;

    tpm_pcr_read(2, 17, &pcr17);
    tpm_pcr_read(2, 18, &pcr18);
    tpm_pcr_read(2, 19, &pcr19);

    if(!tpm_cmp_creation_pcrs(sizeof(pcrs), pcrs, pcr_values, blobsize1, (uint8_t *)inptr)) {
        log_event(LOG_LEVEL_ERROR, "error: creation pcrs mismatch\n");
        return rslt_inconsistentstate;
    }

    record_timestamp("state unseal start");
    statesize1 = sizeof(*pstate);
    if (tpm_unseal(2, blobsize1, (uint8_t *)inptr, &statesize1, (uint8_t *)pstate) != 0) {
        log_event(LOG_LEVEL_ERROR, "error: unseal failed\n");
        return rslt_badparams;
    }
    record_timestamp("state unseal end");

    if (statesize1 != (uint8_t *)pstate->state2 - (uint8_t *)pstate) {
        log_event(LOG_LEVEL_ERROR, "error: unseal wrong size\n");
        return rslt_badparams;
    }

    sha1_buffer((uint8_t *)inptr+blobsize1, blobsize2, md);
    if (memcmp(md, pstate->state2_hash, sizeof(md)) != 0) {
        log_event(LOG_LEVEL_ERROR, "error: state2 wrong hash\n");
        return rslt_badparams;
    }

    statesize2 = ((sizeof(state) - statesize1) / N_BLOCK) * N_BLOCK;

    if (blobsize2 != statesize2 + N_BLOCK) {
        log_event(LOG_LEVEL_ERROR, "error: state2 wrong size\n");
        return rslt_fail;
    }

    /* save iv for seal */
    memcpy(blob2, (uint8_t *)inptr+blobsize1, N_BLOCK);

    record_timestamp("state2 decrypt start");
    aes_cbc_decrypt((uint8_t *)pstate->state2, (uint8_t *)inptr+blobsize1+N_BLOCK,
           statesize2/N_BLOCK, blob2, state.state2_dkey);
    record_timestamp("state2 decrypt end");

    log_event(LOG_LEVEL_INFORMATION, "state unsealed successfully\n");

    return rslt_ok;
}


static void dumphex(uint8_t *bytes, int len)
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
