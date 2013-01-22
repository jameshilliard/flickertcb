/*
 * txt.c: Intel(r) TXT support functions, including initiating measured
 *        launch, post-launch, AP wakeup, etc.
 *
 * Copyright (c) 2003-2011, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 *  txt.c: Modified for use with Flicker
 */


#include "config_regs.h"
#include "heap.h"
#include "malloc.h"
#include "mtrrs.h"

static int txt_post_launch_verify_platform(uint32_t base);

int txt_post_launch(uint32_t base) __attribute__ ((section (".text.slb")));
int txt_post_launch(uint32_t base)
{

    /* This is the full txt_post_launch function used by tboot
     * Commented lines are not needed for restoring the MTRRs but
     * have been left here in case they are useful for anything else.
     */

    txt_heap_t *txt_heap;
    os_mle_data_t *os_mle_data;

    int err;

    /* verify MTRRs, VT-d settings, TXT heap, etc. */
    err = txt_post_launch_verify_platform(base);
//    /* don't return the error yet, because we need to restore settings */
//    if ( err != TB_ERR_NONE )
//        printk("failed to verify platform\n");

    /* get saved OS state (os_mvmm_data_t) from LT heap */
    txt_heap = get_txt_heap();
    os_mle_data = get_os_mle_data_start(txt_heap);

//    /* clear error registers so that we start fresh */
//    write_priv_config_reg(TXTCR_ERRORCODE, 0x00000000);
//    write_priv_config_reg(TXTCR_ESTS, 0xffffffff);  /* write 1's to clear */
//
//    /* bring RLPs into environment (do this before restoring MTRRs to ensure */
//    /* SINIT area is mapped WB for MONITOR-based RLP wakeup) */
//    txt_wakeup_cpus();
//
//    /* restore pre-SENTER IA32_MISC_ENABLE_MSR (no verification needed)
//       (do after AP wakeup so that if restored MSR has MWAIT clear it won't
//       prevent wakeup) */
//    printk("saved IA32_MISC_ENABLE = 0x%08x\n",
//           os_mle_data->saved_misc_enable_msr);
//    wrmsr(MSR_IA32_MISC_ENABLE, os_mle_data->saved_misc_enable_msr);
//    if ( use_mwait() ) {
//        /* set MONITOR/MWAIT support */
//        uint64_t misc;
//        misc = rdmsr(MSR_IA32_MISC_ENABLE);
//        misc |= MSR_IA32_MISC_ENABLE_MONITOR_FSM;
//        wrmsr(MSR_IA32_MISC_ENABLE, misc);
//    }

    /* restore pre-SENTER MTRRs that were overwritten for SINIT launch */
    restore_mtrrs(&(os_mle_data->saved_mtrr_state));

//    /* now, if there was an error, apply policy */
//    apply_policy(err);
//
//    /* always set the TXT.CMD.SECRETS flag */
//    write_priv_config_reg(TXTCR_CMD_SECRETS, 0x01);
//    read_priv_config_reg(TXTCR_E2STS);   /* just a fence, so ignore return */
//    printk("set TXT.CMD.SECRETS flag\n");
//
//    /* open TPM locality 1 */
//    write_priv_config_reg(TXTCR_CMD_OPEN_LOCALITY1, 0x01);
//    read_priv_config_reg(TXTCR_E2STS);   /* just a fence, so ignore return */
//    printk("opened TPM locality 1\n");

    return err;
}


static bool verify_saved_mtrrs(txt_heap_t *txt_heap) __attribute__ ((section (".text.slb")));
static bool verify_saved_mtrrs(txt_heap_t *txt_heap)
{
    os_mle_data_t *os_mle_data;
    os_mle_data = get_os_mle_data_start(txt_heap);

    return validate_mtrrs(&(os_mle_data->saved_mtrr_state));
}


static bool verify_vtd_pmrs(txt_heap_t *txt_heap, uint32_t base) __attribute__ ((section (".text.slb")));
static bool verify_vtd_pmrs(txt_heap_t *txt_heap, uint32_t base)
{
    os_sinit_data_t *os_sinit_data;
    os_sinit_data = get_os_sinit_data_start(txt_heap);
    uint32_t base_aligned = base & ~0x1fffff;

    if (base - 3*PAGE_SIZE != base_aligned)
        return false;

    if (os_sinit_data->vtd_pmr_lo_base != (base & ~0x1fffff)
            || os_sinit_data->vtd_pmr_lo_size != 0x200000)
        return false;

    return true;
}



int txt_post_launch_verify_platform(uint32_t base) __attribute__ ((section (".text.slb")));
int txt_post_launch_verify_platform(uint32_t base)
{
    txt_heap_t *txt_heap;

    /*
     * verify some of the heap structures
     */
    txt_heap = get_txt_heap();

//    if ( !verify_txt_heap(txt_heap, false) )
//        return -1;

    /* verify the saved MTRRs */
    if ( !verify_saved_mtrrs(txt_heap) )
        return -1;

    /* verify that VT-d PMRs were really set as required */
    if ( !verify_vtd_pmrs(txt_heap, base) )
        return -1;

    return 0;
}

