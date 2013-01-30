/*
 * bitcoin.c: sign transactions for bitcoin under policy
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
#include "printk.h"
#include "params.h"
#include "tpm.h"
#include "string.h"
#include "sha1.h"
#include "util.h"
#include "aes.h"
#include "cbcmode.h"
#include "sha256.h"
#include "rmd160.h"
#include "bcsign.h"
#include "bitcoin.h"

#define     NMEM        5
#define     MYCOUNTER   "BITC"

struct state {
    uint8_t state2_hash[SHA_DIGEST_LENGTH];
    uint8_t state2_key[2*N_BLOCK];
    uint8_t state2_dkey[2*N_BLOCK];
uint8_t state2[0];
    tpm_nonce_t tick_nonce;
    uint64_t init_ticks;
    uint64_t day_limit;
    int day_number;
    uint64_t day_value;
    uint32_t counter_id;
    uint32_t counter;
    uint8_t key[2*N_BLOCK];
    uint8_t dkey[2*N_BLOCK];
    uint8_t pad[N_BLOCK];
};

static int do_init_cmd(int cmd);
static int do_encrypt(int cmd);
static int do_sign(int cmd);
static int do_decrypt(int cmd);
static int do_keygen(int cmd);
void dumphex(uint8_t *bytes, int len);
static int get_value(uint64_t *pvalue);
static int get_change(uint64_t *pchange, uint8_t *tx, int txlen);
static int get_signatures();
static int find_counter(struct state *pstate);
static int state_seal(struct state *pstate);
static int state_unseal(struct state *pstate);
static void bchash(void *inptr, uint32_t len, uint8_t *md);
static void bchash160(void *inptr, uint32_t len, uint8_t *md);

extern int sectopub(uint8_t *sec, uint8_t *pub);

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
        case cmd_sign:
            rslt = do_sign(cmd);
            break;
        case cmd_keygen_uncomp:
        case cmd_keygen_comp:
            rslt = do_keygen(cmd);
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

#if 1
    extern int testmath(void);
    testmath();
#endif

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
    record_timestamp("get_random start");
    if (tpm_get_random(2, state.state2_key, &keysize) != 0
            || keysize != sizeof(state.state2_key)) {
        log_event(LOG_LEVEL_ERROR, "error: get_random failed\n");
        return rslt_fail;
    }
    record_timestamp("get_random end");
    aes_encrypt_256(inblk, outblk, state.state2_key, state.state2_dkey);

    /* iv */
    keysize = N_BLOCK;
    tpm_get_random(2, blob2, &keysize);

    if (pm_get_addr(tag_daylimit, &inptr) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no day limit\n");
        return rslt_badparams;
    }

    state.day_limit = *(uint64_t *)inptr;
    state.day_number = 0;
    state.day_value = 0;

    log_event(LOG_LEVEL_INFORMATION, "day limit = %lld\n", state.day_limit);

    tpm_read_current_ticks(2, &ticks);
    state.init_ticks = ticks.current_ticks;
    memcpy(state.tick_nonce.nonce, ticks.tick_nonce.nonce, sizeof(state.tick_nonce.nonce));

    if ((rslt = state_seal(&state)) != rslt_ok)
        return rslt;

    memset(&state, 0, sizeof(state));

    return rslt_ok;
}


static uint8_t padded[3*N_BLOCK], obuf[3*N_BLOCK];
static uint8_t md256[32];

static int do_encrypt(int cmd)
{
    tpm_counter_value_t counter;
    char *inptr;
    int rslt = rslt_ok;
    int inlen;
    uint8_t *iv;
    uint8_t *ptxt;
    uint8_t pk[65];
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

    if (sectopub(ptxt, pk+1) != 0) {
        log_event(LOG_LEVEL_ERROR, "error: sectopub failed\n");
        return rslt_fail;
    }
    pk[0] = 0x04;
    pm_append(tag_pk, (char *)pk, sizeof(pk));
    //log_event(LOG_LEVEL_INFORMATION, "pk:\n");
    //dumphex(pk, sizeof(pk));

    padlen = N_BLOCK - (inlen % N_BLOCK);
    memcpy(padded, ptxt, inlen);
    memset(padded+inlen, padlen, padlen);

    aes_cbc_encrypt(obuf, padded, (inlen+padlen)/N_BLOCK, iv, state.key);
    pm_append(tag_ciphertext, (char *)obuf, inlen+padlen);

    pk[0] = 0x02 + (pk[64]&1);
    bchash(pk, 33, md256);
    if (memcmp(md256, iv, N_BLOCK) != 0) {
        log_event(LOG_LEVEL_WARNING, "WARNING: IV VERIFY FAILED\n");
    }

    memset(&state, 0, sizeof(state));
    memset(padded, 0, sizeof(padded));

    return rslt;
}


static int do_decrypt(int cmd)
{
    tpm_current_ticks_t ticks;
    tpm_counter_value_t counter;
    char *inptr;
    int interval_secs;
    int day_number;
    int rslt = rslt_ok;
    int inlen;
    uint8_t *iv;
    uint8_t *ctxt;
    uint8_t pk[65];
    int padlen;
    int i;

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

    //log_event(LOG_LEVEL_INFORMATION, "ctxt:\n");
    //dumphex(ctxt, inlen);

    tpm_read_current_ticks(2, &ticks);
    if (memcmp(ticks.tick_nonce.nonce, state.tick_nonce.nonce,
                sizeof(ticks.tick_nonce.nonce)) != 0) {
        log_event(LOG_LEVEL_WARNING, "tick timer got reset\n");
        return rslt_inconsistentstate;
    }

    interval_secs = (ticks.current_ticks - state.init_ticks)
        / (1000000 / ticks.tick_rate);
    day_number = interval_secs / 86400;
    log_event(LOG_LEVEL_INFORMATION, "day number = %d\n", day_number);

#if 0
    if (state.day_number != day_number) {
        state.day_number = day_number;
        state.day_count = 1;
        log_event(LOG_LEVEL_INFORMATION, "new day! day count = %d\n", state.day_count);
    } else if (++state.day_count > state.day_limit) {
        log_event(LOG_LEVEL_WARNING, "error: day limit exceeded\n");
        interval_secs = (day_number + 1) * 86400 - interval_secs;
        pm_append(tag_delay, (char *)&interval_secs, sizeof(interval_secs));
        return rslt_disallowed;
    }
    else log_event(LOG_LEVEL_INFORMATION, "day count = %d\n", state.day_count);
#endif

    log_event(LOG_LEVEL_INFORMATION, "work authorized!\n");

    aes_cbc_decrypt(padded, ctxt, inlen/N_BLOCK, iv, state.dkey);

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

    if (sectopub(padded, pk+1) != 0) {
        log_event(LOG_LEVEL_ERROR, "error: sectopub failed\n");
        return rslt_fail;
    }
    pk[0] = 0x04;
    pm_append(tag_pk, (char *)pk, sizeof(pk));
    //log_event(LOG_LEVEL_INFORMATION, "pk:\n");
    //dumphex(pk, sizeof(pk));

    pk[0] = 0x02 + (pk[64]&1);
    bchash(pk, 33, md256);
    if (memcmp(md256, iv, N_BLOCK) != 0) {
        log_event(LOG_LEVEL_WARNING, "WARNING: IV VERIFY FAILED\n");
    }

    tpm_increment_counter(2, state.counter_id, &ctr_authdata, &counter);
    state.counter = counter.counter;

    if ((rslt = state_seal(&state)) != rslt_ok)
        return rslt;

    memset(&state, 0, sizeof(state));
    memset(padded, 0, sizeof(padded));

    return rslt;
}


static int do_keygen(int cmd)
{
    tpm_counter_value_t counter;
    int rslt = rslt_ok;
    int inlen;
    uint8_t pk[65];
    uint8_t *iv;
    uint32_t keysize;
    int padlen;
    int pklen;

    if ((rslt = state_unseal(&state)) != rslt_ok)
        return rslt;

    tpm_read_counter(2, state.counter_id, &counter);
    if (counter.counter != state.counter) {
        log_event(LOG_LEVEL_ERROR, "anti rollback counter error: %d should be %d\n",
                state.counter, counter.counter );
        return rslt_inconsistentstate;
    }

    inlen = keysize = 32;
    if (tpm_get_random(2, padded, &keysize) != 0
            || keysize != inlen) {
        log_event(LOG_LEVEL_ERROR, "error: get_random failed\n");
        return rslt_fail;
    }

    if (sectopub(padded, pk+1) != 0) {
        log_event(LOG_LEVEL_ERROR, "error: sectopub failed\n");
        return rslt_fail;
    }
    //log_event(LOG_LEVEL_INFORMATION, "pk:\n");
    //dumphex(pk, sizeof(pk));

    pk[0] = 0x04;
    pklen = sizeof(pk);
    if (cmd == cmd_keygen_comp) {
        pklen = 33;
        pk[0] = 0x02 + (pk[64]&1);
    }
    bchash(pk, pklen, md256);
    iv = md256;

    pm_append(tag_pk, (char *)pk, pklen);

    padlen = N_BLOCK - (inlen % N_BLOCK);
    memset(padded+inlen, padlen, padlen);

    aes_cbc_encrypt(obuf, padded, (inlen+padlen)/N_BLOCK, iv, state.key);

    pm_append(tag_ciphertext, (char *)obuf, inlen+padlen);

    memset(&state, 0, sizeof(state));
    memset(padded, 0, sizeof(padded));

    return rslt;
}


static int do_sign(int cmd)
{
    tpm_current_ticks_t ticks;
    tpm_counter_value_t counter;
//    char *inptr;
//    int inlen;
    int interval_secs;
    int day_number;
    uint64_t value;
    int rslt = rslt_ok;

    if ((rslt = state_unseal(&state)) != rslt_ok)
        return rslt;

    tpm_read_counter(2, state.counter_id, &counter);
    if (counter.counter != state.counter) {
        log_event(LOG_LEVEL_ERROR, "anti rollback counter error: %d should be %d\n",
                state.counter, counter.counter );
        return rslt_inconsistentstate;
    }

    if ((rslt = get_value(&value)) != rslt_ok)
        return rslt;

    tpm_read_current_ticks(2, &ticks);
    if (memcmp(ticks.tick_nonce.nonce, state.tick_nonce.nonce,
                sizeof(ticks.tick_nonce.nonce)) != 0) {
        log_event(LOG_LEVEL_WARNING, "tick timer got reset\n");
        return rslt_inconsistentstate;
    }

    interval_secs = (ticks.current_ticks - state.init_ticks)
        / (1000000 / ticks.tick_rate);
    day_number = interval_secs / 86400;
    log_event(LOG_LEVEL_INFORMATION, "day number = %d\n", day_number);

    if (state.day_number != day_number) {
        state.day_number = day_number;
        state.day_value = 0;
        log_event(LOG_LEVEL_INFORMATION, "new day! day value = %lld\n", state.day_value);
    }
    if ((state.day_value+=value) > state.day_limit) {
        log_event(LOG_LEVEL_WARNING, "error: day limit exceeded\n");
        interval_secs = (day_number + 1) * 86400 - interval_secs;
        if (value <= state.day_value)
            pm_append(tag_delay, (char *)&interval_secs, sizeof(interval_secs));
        return rslt_disallowed;
    }
    else log_event(LOG_LEVEL_INFORMATION, "day value = %lld\n", state.day_value);

    log_event(LOG_LEVEL_INFORMATION, "work authorized!\n");

    if ((rslt = get_signatures()) != rslt_ok)
        return rslt;

    tpm_increment_counter(2, state.counter_id, &ctr_authdata, &counter);
    state.counter = counter.counter;

    if ((rslt = state_seal(&state)) != rslt_ok)
        return rslt;

    memset(&state, 0, sizeof(state));

    return rslt_ok;
}


static int get_value(uint64_t *pvalue)
{
    int inindex;
    uint64_t change;
    uint64_t sum;
    uint64_t value;
    uint8_t *tx;
    int txlen;
    uint8_t *txin;
    int txinlen;
    uint8_t *hash;
    int ninputs;
    int rslt;
    int i;

    if ((txlen=pm_get_addr(tag_signtrans, (char **)&tx)) < 1) {
        log_event(LOG_LEVEL_ERROR, "error: no signtrans\n");
        return rslt_badparams;
    }
    if (!bc_inputs(&ninputs, tx, txlen)) {
        log_event(LOG_LEVEL_ERROR, "error: illegal tx\n");
        return rslt_fail;
    }

    sum = 0;
    for (i=0; i<ninputs; i++) {
        if ((txinlen=pm_get_addr(tag_inputtrans+i, (char **)&txin)) < 0) {
            log_event(LOG_LEVEL_ERROR, "error: no inputtrans\n");
            return rslt_badparams;
        }

        if (!bc_input_data(&inindex, &hash, i, tx, txlen)) {
            log_event(LOG_LEVEL_ERROR, "error: illegal tx\n");
            return rslt_fail;
        }

        bchash(txin, txinlen, md256);

        if (memcmp(hash, md256, sizeof(md256)) != 0) {
            log_event(LOG_LEVEL_ERROR, "error: input hash %d doesn't match\n", i);
            return rslt_fail;
        }

        if (!bc_output_data(&value, NULL, NULL, inindex, txin, txinlen)) {
            log_event(LOG_LEVEL_ERROR, "error: illegal tx\n");
            return rslt_fail;
        }

        log_event(LOG_LEVEL_INFORMATION, "value: %lld\n", value);

        sum += value;
        if (sum > MAX_VALUE) {
            log_event(LOG_LEVEL_ERROR, "error: illegal tx\n");
            return rslt_fail;
        }
    }

    log_event(LOG_LEVEL_INFORMATION, "sum: %lld\n", sum);

    if ((rslt = get_change(&change, tx, txlen)) != rslt_ok)
        return rslt;

    log_event(LOG_LEVEL_INFORMATION, "change: %lld\n", change);

    sum -= change;
    if (sum > MAX_VALUE) {
        log_event(LOG_LEVEL_ERROR, "error: illegal tx\n");
        return rslt_fail;
    }

    log_event(LOG_LEVEL_INFORMATION, "net value: %lld\n", sum);

    *pvalue = sum;
    return rslt_ok;
}

static uint8_t change_script[] = {
    0x19, 0x76, 0xA9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xAC
};

static int get_change(uint64_t *pchange, uint8_t *tx, int txlen)
{
    int chindex;
    uint8_t *pk;
    int pklen;
    uint8_t pkc[65];
    uint8_t *ctxt;
    int ctxtlen;
    uint8_t *script;
    size_t scriptlen;
    char *inptr;
    int inlen;
    int padlen;
    int i;

    if ((inlen=pm_get_addr(tag_changeindex, &inptr)) != sizeof(int)) {
        log_event(LOG_LEVEL_ERROR, "error: no changeindex\n");
        return rslt_badparams;
    }

    chindex = *(int *)inptr;
    if (chindex < 0) {
        *pchange = 0;
        return rslt_ok;
    }

    if ((pklen=pm_get_addr(tag_changepk, (char **)&pk)) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no changepk\n");
        return rslt_badparams;
    }

    if (pklen != 65 && pklen != 33) {
        log_event(LOG_LEVEL_ERROR, "error: changepk wrong length\n");
        return rslt_badparams;
    }
    
    if ((ctxtlen=pm_get_addr(tag_changectext, (char **)&ctxt)) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no changectext\n");
        return rslt_badparams;
    }

    if (ctxtlen != 3*N_BLOCK) {
        log_event(LOG_LEVEL_ERROR, "error: changectext wrong length\n");
        return rslt_badparams;
    }

    bchash(pk, pklen, md256);
    aes_cbc_decrypt(padded, ctxt, ctxtlen/N_BLOCK, md256, state.dkey);

    padlen = padded[ctxtlen-1];
    i = 0;
    if (padlen > 0 || padlen <= N_BLOCK) {
        for (; i<padlen; i++) {
            if (padded[ctxtlen-padlen+i] != padlen)
                break;
        }
    }

    if (i==0 || i<padlen) {
        log_event(LOG_LEVEL_ERROR, "error: ciphertext wrongly padded\n");
        return rslt_badparams;
    }

    if ((ctxtlen -= padlen) != sizeof(md256)) {
        log_event(LOG_LEVEL_ERROR, "error: decrypted changectext wrong length\n");
        return rslt_badparams;
    }

    if (sectopub(padded, pkc+1) != 0) {
        log_event(LOG_LEVEL_ERROR, "error: sectopub failed\n");
        return rslt_fail;
    }

    if (pklen == 65) {
        pkc[0] = 0x04;
    } else {
        pkc[0] = 0x02 + (pkc[64]&1);
    }

    if (memcmp(pk, pkc, pklen) != 0) {
        log_event(LOG_LEVEL_ERROR, "error: changepk does not match changectext\n");
        return rslt_badparams;
    }

    bchash160(pk, pklen, change_script+4);

    if (!bc_output_data(pchange, &script, &scriptlen, chindex, tx, txlen)) {
        log_event(LOG_LEVEL_ERROR, "error: illegal changeindex\n");
        return rslt_fail;
    }

    if (scriptlen != sizeof(change_script)
            || memcmp(script, change_script, scriptlen) != 0) {
        log_event(LOG_LEVEL_ERROR, "error: changepk does not match change script\n");
        return rslt_badparams;
    }

    log_event(LOG_LEVEL_INFORMATION, "successfully verified change script\n");

    return rslt_ok;
}

static int get_signatures()
{
    int inindex;
    uint8_t *tx;
    int txlen;
    uint8_t *txin;
    int txinlen;
    uint8_t *script;
    uint32_t scriptlen;
    int ninputs;
    uint8_t *ctxt;
    int ctxtlen;
    uint8_t *iv;
    int ivlen;
    int padlen;
    uint32_t keysize;
    uint8_t k[32];
    uint8_t sig[73];
    size_t siglen;
    int i, j;

    txlen=pm_get_addr(tag_signtrans, (char **)&tx);
    bc_inputs(&ninputs, tx, txlen);

    for (i=0; i<ninputs; i++) {
        txinlen=pm_get_addr(tag_inputtrans+i, (char **)&txin);
        bc_input_data(&inindex, NULL, i, tx, txlen);
        bc_output_data(NULL, &script, &scriptlen, inindex, txin, txinlen);

        if (!bc_signature_hash(md256, script, scriptlen, i, tx, txlen)) {
            log_event(LOG_LEVEL_ERROR, "error: illegal signature hash\n");
            return rslt_fail;
        }
        if (i == 0)
            dumphex(md256, sizeof(md256));

        if ((ctxtlen=pm_get_addr(tag_signctxt+i, (char **)&ctxt)) < 0) {
            log_event(LOG_LEVEL_ERROR, "error: no signctxt\n");
            return rslt_badparams;
        }

        if (ctxtlen != 3*N_BLOCK) {
            log_event(LOG_LEVEL_ERROR, "error: signctxt wrong length\n");
            return rslt_badparams;
        }

        if ((ivlen=pm_get_addr(tag_signiv+i, (char **)&iv)) < 0) {
            log_event(LOG_LEVEL_ERROR, "error: no signiv\n");
            return rslt_badparams;
        }

        if (ivlen != N_BLOCK) {
            log_event(LOG_LEVEL_ERROR, "error: signiv wrong length\n");
            return rslt_badparams;
        }

        aes_cbc_decrypt(padded, ctxt, ctxtlen/N_BLOCK, iv, state.dkey);

        padlen = padded[ctxtlen-1];
        j = 0;
        if (padlen > 0 || padlen <= N_BLOCK) {
            for (; j<padlen; j++) {
                if (padded[ctxtlen-padlen+j] != padlen)
                    break;
            }
        }

        if (j==0 || j<padlen) {
            log_event(LOG_LEVEL_ERROR, "error: signctxt wrongly padded\n");
            return rslt_badparams;
        }

        if ((ctxtlen -= padlen) != sizeof(md256)) {
            log_event(LOG_LEVEL_ERROR, "error: decrypted signctxt wrong length\n");
            return rslt_badparams;
        }

        keysize = sizeof(k);
        if (tpm_get_random(2, k, &keysize) != 0  ||  keysize != sizeof(k)) {
            log_event(LOG_LEVEL_ERROR, "error: get_random failed\n");
            return rslt_fail;
        }

        if (!bc_signature(sig, &siglen, md256, padded, k)) {
            log_event(LOG_LEVEL_ERROR, "error: signature failed\n");
            return rslt_fail;
        }

        log_event(LOG_LEVEL_INFORMATION, "siglen %d: %d\n", i, siglen);
        pm_append(tag_signature+i, (char *)sig, siglen);
    }

    return rslt_ok;
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

    record_timestamp("increment counter start");
    if (tpm_increment_counter(2, ctrid, &ctr_authdata, &counter) == 0) {
        record_timestamp("increment counter end");
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
            record_timestamp("increment counter start");
            if (tpm_increment_counter(2, ctrid, &ctr_authdata, &counter) == 0) {
                record_timestamp("increment counter end");
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


void dumphex(uint8_t *bytes, int len)
{
    int i;
    if(!bytes) return;

    for (i=0; i<len; i++)
        log_event(LOG_LEVEL_INFORMATION, "%02x%s", bytes[i], ((i+1)%32)?"":"\n");
    if(len%32)
        log_event(LOG_LEVEL_INFORMATION, "\n");
}


static void bchash(void *inptr, uint32_t len, uint8_t *md)
{
    uint8_t _md[32];
    sha256(inptr, len, _md);
    sha256(_md, sizeof(_md), md);
}


static void bchash160(void *inptr, uint32_t len, uint8_t *md)
{
    uint8_t _md[32];
    sha256(inptr, len, _md);
    RMD160(_md, sizeof(_md), md);
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
