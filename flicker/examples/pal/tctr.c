/*
 * tpal.c: trivial pal
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
#include "sha1.h"

static const tpm_authdata_t ctr_authdata =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

int pal_main(void) __attribute__ ((section (".text.slb")));
int pal_main(void)
{
    int ret;
    tpm_counter_value_t counter;
    uint32_t counter_id = 0xab336c2;

    printk("Hello from pal_main()\n");
    //ret = tpm_read_counter(2, counter_id, &counter);
    ret = tpm_increment_counter(2, counter_id, &ctr_authdata, &counter);
    log_event(LOG_LEVEL_INFORMATION, "tpm increment counter value return: %x\n", ret);

    if (ret == 0) {
        log_event(LOG_LEVEL_INFORMATION, "counter value: %u\n", counter.counter);
        log_event(LOG_LEVEL_INFORMATION, "label: %c%c%c%c\n", counter.label[0], counter.label[1],
                counter.label[2], counter.label[3]);
    }
    else {
        extern uint8_t     cmd_buf[TPM_CMD_SIZE_MAX];
        extern uint8_t     rsp_buf[TPM_CMD_SIZE_MAX];
        unsigned char *v = cmd_buf;
        pm_append(0xaaaaaaaa, (char *)cmd_buf, 59);
        pm_append(0xbbbbbbbb, (char *)rsp_buf, 32);
        return 0;
        log_event(LOG_LEVEL_INFORMATION,
              "cmdbuf: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x"
              " %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
              v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9],
              v[10], v[11], v[12], v[13], v[14], v[15], v[16], v[17], v[18], v[19]);
        v = rsp_buf;
        log_event(LOG_LEVEL_INFORMATION,
              "rspbuf: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x"
              " %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
              v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9],
              v[10], v[11], v[12], v[13], v[14], v[15], v[16], v[17], v[18], v[19]);
        v = (unsigned char *)&counter;
        log_event(LOG_LEVEL_INFORMATION,
              "counter: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
              v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9]);
    }
    return 0;
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
