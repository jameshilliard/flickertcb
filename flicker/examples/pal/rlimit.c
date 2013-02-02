/*
 * rlimit.c: rate limit work
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

#include <stdarg.h>
#include "malloc.h"
#include "printk.h"
#include "params.h"
#include "tpm.h"
#include "string.h"
#include "sha1.h"
#include "rlimit.h"

struct state {
    tpm_current_ticks_t ticks;
    int interval_secs;
    tpm_counter_value_t counter;
};

static int do_init_cmd(void);
static int do_work_cmd(void);

int pal_main(void) __attribute__ ((section (".text.slb")));
int pal_main(void)
{
    char *inptr;
    int cmd;
    int rslt = 0;

    if (pm_get_addr(tag_cmd, &inptr) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no command\n");
        rslt = 1;
        goto rslt;
    }

    cmd = *(int *)inptr;
    switch (cmd) {
        case cmd_init:
            rslt = do_init_cmd();
            break;
        case cmd_work:
            rslt = do_work_cmd();
            break;
        default:
            log_event(LOG_LEVEL_ERROR, "error: unknown command %d\n", cmd);
            rslt = 1;
            goto rslt;
    }

rslt:
    pm_append(tag_rslt, (char *)&rslt, sizeof(rslt));
    return 0;
}

static uint8_t blob[400];

static const tpm_authdata_t ctr_authdata =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static uint32_t counter_id = 0xab336c2;

SHA1_HASH hash_correct =
    {{0x5b,0xaa,0x61,0xe4,0xc9,0xb9,0x3f,0x3f,0x06,0x82,0x25,0x0b,0x6c,0xf8,0x33,0x1b,0x7e,0xe6,0x8f,0xd8}};

static int do_init_cmd()
{
    struct state state;
    char *inptr;
    int inlen;
    uint8_t pcrs[3] = {17, 18, 19};
    uint32_t blobsize = sizeof(blob);
    SHA1_HASH hash;

    if ((inlen=pm_get_addr(tag_passphrase, &inptr)) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no passphrase\n");
        return 1;
    }

    sha1_buffer((unsigned char*)inptr, inlen, hash.h);
    if (memcmp(&hash, &hash_correct, sizeof(hash)) != 0) {
        int i;
        log_event(LOG_LEVEL_ERROR, "error: incorrect passphrase\n");
        log_event(LOG_LEVEL_INFORMATION, "hash\n");
        for (i=0; i<sizeof(hash);i++) {
            log_event(LOG_LEVEL_INFORMATION, "0x%02x,", hash.h[i]);
        }
        log_event(LOG_LEVEL_INFORMATION, "\n");
        return 1;
    }

    log_event(LOG_LEVEL_INFORMATION, "successfully verified passphrase\n");

    if (pm_get_addr(tag_interval, &inptr) < -1) {
        log_event(LOG_LEVEL_ERROR, "error: no interval\n");
        return 1;
    }

    state.interval_secs = *(int *)inptr;
    tpm_read_current_ticks(2, &state.ticks);
    tpm_increment_counter(2, counter_id, &ctr_authdata, &state.counter);

    if (tpm_seal(2, TPM_LOC_TWO, sizeof(pcrs), pcrs, 0, NULL, NULL,
            sizeof(state), (uint8_t *)&state, &blobsize, blob) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: seal failed\n");
        return 1;
    }
    pm_append(tag_blob, (char *)blob, blobsize);

    log_event(LOG_LEVEL_INFORMATION, "successfully sealed state\n");

    return 0;
}


static int do_work_cmd()
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
    int rslt = 0;

    if ((blobsize = pm_get_addr(tag_blob, &inptr)) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: no blob\n");
        return 1;
    }

    tpm_pcr_read(2, 17, &pcr17);
    tpm_pcr_read(2, 18, &pcr18);
    tpm_pcr_read(2, 19, &pcr19);

    if(!tpm_cmp_creation_pcrs(sizeof(pcrs), pcrs, pcr_values, blobsize, (uint8_t *)inptr)) {
        log_event(LOG_LEVEL_ERROR, "error: creation pcrs mismatch\n");
        return 1;
    }

    statesize = sizeof(state);
    if (tpm_unseal(2, blobsize, (uint8_t *)inptr, &statesize, (uint8_t *)&state) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: unseal failed\n");
        return 1;
    }

    log_event(LOG_LEVEL_INFORMATION, "state unsealed successfully\n");

    tpm_read_counter(2, counter_id, &counter);
    if (memcmp(&counter, &state.counter, sizeof(counter)) != 0) {
        log_event(LOG_LEVEL_ERROR, "anti rollback counter error: %d should be %d\n",
                state.counter.counter, counter.counter );
        return 4;
    }
    
    tpm_read_current_ticks(2, &ticks);
    if (memcmp(ticks.tick_nonce.nonce, state.ticks.tick_nonce.nonce,
                sizeof(ticks.tick_nonce.nonce)) != 0) {
        log_event(LOG_LEVEL_WARNING, "tick timer got reset\n");
        return 2;
    }

    interval_secs = (ticks.current_ticks - state.ticks.current_ticks)
        / (1000000 / ticks.tick_rate);
    log_event(LOG_LEVEL_INFORMATION, "interval = %d secs\n", interval_secs);
    if (interval_secs < state.interval_secs) {
        log_event(LOG_LEVEL_WARNING, "error: interval too short\n");
        return 3;
    }

    log_event(LOG_LEVEL_INFORMATION, "work authorized!\n", interval_secs);

    state.ticks = ticks;
    tpm_increment_counter(2, counter_id, &ctr_authdata, &state.counter);

    blobsize = sizeof(blob);
    if (tpm_seal(2, TPM_LOC_TWO, sizeof(pcrs), pcrs, 0, NULL, NULL,
            sizeof(state), (uint8_t *)&state, &blobsize, blob) < 0) {
        log_event(LOG_LEVEL_ERROR, "error: seal failed\n");
        return 1;
    }
    pm_append(tag_blob, (char *)blob, blobsize);
    
    return rslt;
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
