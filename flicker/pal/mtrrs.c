/*
 * mtrrs.c: support functions for manipulating MTRRs
 *
 * Copyright (c) 2003-2007, Intel Corporation
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
 *  mtrrs.c: Modified for Flicker
 */

#ifndef _WIN32
#include <asm/msr.h> /* for MSR_MTRRcap */
#else  // _WIN32
#include "wintypes.h"
#include "msr.h"
#endif // _WIN32


#include "mtrrs.h"
#include "config_regs.h"
#include "tpm.h"


#define MTRR_TYPE_UNCACHABLE     0
#define MTRR_TYPE_WRTHROUGH      4
#define MTRR_TYPE_WRBACK         6
#define MTRR_TYPE_MIXED         -1
#define MMIO_APIC_BASE          0xFEE00000
#define NR_MMIO_APIC_PAGES      1
#define NR_MMIO_IOAPIC_PAGES    1
#define NR_MMIO_PCICFG_PAGES    1
#define SINIT_MTRR_MASK         0xFFFFFF  /* SINIT requires 36b mask */


void restore_mtrrs(mtrr_state_t *saved_state) __attribute__ ((section (".text.slb")));
void restore_mtrrs(mtrr_state_t *saved_state)
{
    int ndx;

    /* disable all MTRRs first */
    set_all_mtrrs(false);

    /* physmask's and physbase's */
    for ( ndx = 0; ndx < saved_state->num_var_mtrrs; ndx++ ) {
        wrmsrl(MTRR_PHYS_MASK0_MSR + ndx*2,
               saved_state->mtrr_physmasks[ndx].raw);
        wrmsrl(MTRR_PHYS_BASE0_MSR + ndx*2,
               saved_state->mtrr_physbases[ndx].raw);
    }

    /* IA32_MTRR_DEF_TYPE MSR */
    wrmsrl(MSR_MTRRdefType, saved_state->mtrr_def_type.raw);

}



/* enable/disable all MTRRs */
void set_all_mtrrs(bool enable) __attribute__ ((section (".text.slb")));
void set_all_mtrrs(bool enable)
{
    mtrr_def_type_t mtrr_def_type;

    rdmsrl(MSR_MTRRdefType, mtrr_def_type.raw);
    mtrr_def_type.e = enable ? 1 : 0;
    wrmsrl(MSR_MTRRdefType, mtrr_def_type.raw);
}


static uint64_t get_maxphyaddr_mask(void) __attribute__ ((section (".text.slb")));
static uint64_t get_maxphyaddr_mask(void)
{
    union {
        uint32_t raw;
        struct {
	    uint32_t num_pa_bits  : 8;
	    uint32_t num_la_bits  : 8;
	    uint32_t reserved     : 16;
	};
    } num_addr_bits;

    /* does CPU support 0x80000008 CPUID leaf? (all TXT CPUs should) */
    uint32_t max_ext_fn = cpuid_eax(0x80000000);
    if ( max_ext_fn < 0x80000008 )
        return 0xffffff;      /* if not, default is 36b support */

    num_addr_bits.raw = cpuid_eax(0x80000008);
    return ((1ULL << num_addr_bits.num_pa_bits) - 1) >> PAGE_SHIFT;
}

/* base should be 4k-bytes aligned, no invalid overlap combination */
static int get_page_type(const mtrr_state_t *saved_state, uint32_t base) __attribute__ ((section (".text.slb")));
static int get_page_type(const mtrr_state_t *saved_state, uint32_t base)
{
    int type = -1;
    bool wt = false;
    uint64_t maxphyaddr_mask = get_maxphyaddr_mask();

    /* omit whether the fix mtrrs are enabled, just check var mtrrs */

    base >>= PAGE_SHIFT;
    for ( unsigned int i = 0; i < saved_state->num_var_mtrrs; i++ ) {
        const mtrr_physbase_t *base_i = &saved_state->mtrr_physbases[i];
        const mtrr_physmask_t *mask_i = &saved_state->mtrr_physmasks[i];

        if ( mask_i->v == 0 )
            continue;
        if ( (base & mask_i->mask & maxphyaddr_mask) !=
             (base_i->base & mask_i->mask & maxphyaddr_mask) )
            continue;

        type = base_i->type;
        if ( type == MTRR_TYPE_UNCACHABLE )
            return MTRR_TYPE_UNCACHABLE;
        if ( type == MTRR_TYPE_WRTHROUGH )
            wt = true;
    }
    if ( wt )
        return MTRR_TYPE_WRTHROUGH;
    if ( type != -1 )
        return type;

    return saved_state->mtrr_def_type.type;
}

static int get_region_type(const mtrr_state_t *saved_state,
                           uint32_t base, uint32_t pages) __attribute__ ((section (".text.slb")));
static int get_region_type(const mtrr_state_t *saved_state,
                           uint32_t base, uint32_t pages)
{
    int type;
    uint32_t end;

    if ( pages == 0 )
        return MTRR_TYPE_MIXED;

    /* wrap the 4G address space */
    if ( ((uint32_t)(~0) - base) < (pages << PAGE_SHIFT) )
        return MTRR_TYPE_MIXED;

    if ( saved_state->mtrr_def_type.e == 0 )
        return MTRR_TYPE_UNCACHABLE;

    /* align to 4k page boundary */
    base &= PAGE_MASK;
    end = base + (pages << PAGE_SHIFT);

    type = get_page_type(saved_state, base);
    base += PAGE_SIZE;
    for ( ; base < end; base += PAGE_SIZE )
        if ( type != get_page_type(saved_state, base) )
            return MTRR_TYPE_MIXED;

    return type;
}

static bool validate_mmio_regions(const mtrr_state_t *saved_state) __attribute__ ((section (".text.slb")));
static bool validate_mmio_regions(const mtrr_state_t *saved_state)
{
//    acpi_table_mcfg_t *acpi_table_mcfg;
//    acpi_table_ioapic_t *acpi_table_ioapic;

    /* mmio space for TXT private config space should be UC */
    if ( get_region_type(saved_state, TXT_PRIV_CONFIG_REGS_BASE,
                         TXT_CONFIG_REGS_SIZE >> PAGE_SHIFT)
           != MTRR_TYPE_UNCACHABLE ) {
//        printk("MMIO space for TXT private config space should be UC\n");
        return false;
    }

    /* mmio space for TXT public config space should be UC */
    if ( get_region_type(saved_state, TXT_PUB_CONFIG_REGS_BASE,
                         TXT_CONFIG_REGS_SIZE >> PAGE_SHIFT)
           != MTRR_TYPE_UNCACHABLE ) {
//        printk("MMIO space for TXT public config space should be UC\n");
        return false;
    }

    /* mmio space for TPM should be UC */
    if ( get_region_type(saved_state, TPM_LOCALITY_BASE,
                         NR_TPM_LOCALITY_PAGES * TPM_NR_LOCALITIES)
           != MTRR_TYPE_UNCACHABLE ) {
//        printk("MMIO space for TPM should be UC\n");
        return false;
    }

//    /* mmio space for APIC should be UC */
//    if ( get_region_type(saved_state, MMIO_APIC_BASE, NR_MMIO_APIC_PAGES)
//           != MTRR_TYPE_UNCACHABLE ) {
//        printk("MMIO space for APIC should be UC\n");
//        return false;
//    }
//
//    /* TBD: is this check useful if we aren't DMA protecting ACPI? */
//    /* mmio space for IOAPIC should be UC */
//    acpi_table_ioapic = (acpi_table_ioapic_t *)get_acpi_ioapic_table();
//    if ( acpi_table_ioapic == NULL) {
//        printk("acpi_table_ioapic == NULL\n");
//        return false;
//    }
//    printk("acpi_table_ioapic @ %p, .address = %x\n",
//           acpi_table_ioapic, acpi_table_ioapic->address);
//    if ( get_region_type(saved_state, acpi_table_ioapic->address,
//                         NR_MMIO_IOAPIC_PAGES)
//           != MTRR_TYPE_UNCACHABLE ) {
//        printk("MMIO space(%x) for IOAPIC should be UC\n",
//               acpi_table_ioapic->address);
//        return false;
//    }
//
//    /* TBD: is this check useful if we aren't DMA protecting ACPI? */
//    /* mmio space for PCI config space should be UC */
//    acpi_table_mcfg = (acpi_table_mcfg_t *)get_acpi_mcfg_table();
//    if ( acpi_table_mcfg == NULL) {
//        printk("acpi_table_mcfg == NULL\n");
//        return false;
//    }
//    printk("acpi_table_mcfg @ %p, .base_address = %x\n",
//           acpi_table_mcfg, acpi_table_mcfg->base_address);
//    if ( get_region_type(saved_state, acpi_table_mcfg->base_address,
//                         NR_MMIO_PCICFG_PAGES)
//           != MTRR_TYPE_UNCACHABLE ) {
//        printk("MMIO space(%x) for PCI config space should be UC\n",
//               acpi_table_mcfg->base_address);
//        return false;
//    }

    return true;
}

bool validate_mtrrs(const mtrr_state_t *saved_state) __attribute__ ((section (".text.slb")));
bool validate_mtrrs(const mtrr_state_t *saved_state)
{
    mtrr_cap_t mtrr_cap;
    uint64_t maxphyaddr_mask = get_maxphyaddr_mask();
    uint64_t max_pages = maxphyaddr_mask + 1;  /* max # 4k pages supported */

    /* check is meaningless if MTRRs were disabled */
    if ( saved_state->mtrr_def_type.e == 0 )
        return true;

    /* number variable MTRRs */
    rdmsrl(MSR_MTRRcap, mtrr_cap.raw);
    if ( mtrr_cap.vcnt < saved_state->num_var_mtrrs ) {
//        printk("actual # var MTRRs (%d) < saved # (%d)\n",
//               mtrr_cap.vcnt, saved_state->num_var_mtrrs);
        return false;
    }

    /* variable MTRRs describing non-contiguous memory regions */
    for ( unsigned int ndx = 0; ndx < saved_state->num_var_mtrrs; ndx++ ) {
        uint64_t tb;

        if ( saved_state->mtrr_physmasks[ndx].v == 0 )
            continue;

        for ( tb = 1; tb != max_pages; tb = tb << 1 ) {
            if ( (tb & saved_state->mtrr_physmasks[ndx].mask & maxphyaddr_mask)
                 != 0 )
                break;
        }
        for ( ; tb != max_pages; tb = tb << 1 ) {
            if ( (tb & saved_state->mtrr_physmasks[ndx].mask & maxphyaddr_mask)
                 == 0 )
                break;
        }
        if ( tb != max_pages ) {
//	    printk("var MTRRs with non-contiguous regions: base=0x%Lx, mask=0x%Lx\n",
//                   (uint64_t)saved_state->mtrr_physbases[ndx].base
//                                  & maxphyaddr_mask,
//                   (uint64_t)saved_state->mtrr_physmasks[ndx].mask
//                                  & maxphyaddr_mask);
//            print_mtrrs(saved_state);
            return false;
        }
    }

    /* overlaping regions with invalid memory type combinations */
    for ( unsigned int ndx = 0; ndx < saved_state->num_var_mtrrs; ndx++ ) {
        const mtrr_physbase_t *base_ndx = &saved_state->mtrr_physbases[ndx];
        const mtrr_physmask_t *mask_ndx = &saved_state->mtrr_physmasks[ndx];

        if ( mask_ndx->v == 0 )
            continue;

        for ( unsigned int i = ndx + 1; i < saved_state->num_var_mtrrs; i++ ) {
            const mtrr_physbase_t *base_i = &saved_state->mtrr_physbases[i];
            const mtrr_physmask_t *mask_i = &saved_state->mtrr_physmasks[i];

            if ( mask_i->v == 0 )
                continue;

            if ( (base_ndx->base & mask_ndx->mask & mask_i->mask & maxphyaddr_mask)
                    != (base_i->base & mask_i->mask & maxphyaddr_mask) &&
                 (base_i->base & mask_i->mask & mask_ndx->mask & maxphyaddr_mask)
                    != (base_ndx->base & mask_ndx->mask & maxphyaddr_mask) )
                continue;

            if ( base_ndx->type == base_i->type )
                continue;
            if ( base_ndx->type == MTRR_TYPE_UNCACHABLE
                 || base_i->type == MTRR_TYPE_UNCACHABLE )
                continue;
            if ( base_ndx->type == MTRR_TYPE_WRTHROUGH
                 && base_i->type == MTRR_TYPE_WRBACK )
                continue;
            if ( base_ndx->type == MTRR_TYPE_WRBACK
                 && base_i->type == MTRR_TYPE_WRTHROUGH )
                continue;

            /* 2 overlapped regions have invalid mem type combination, */
            /* need to check whether there is a third region which has type */
            /* of UNCACHABLE and contains at least one of these two regions. */
            /* If there is, then the combination of these 3 region is valid */
            unsigned int j;
            for ( j = 0; j < saved_state->num_var_mtrrs; j++ ) {
                const mtrr_physbase_t *base_j
                        = &saved_state->mtrr_physbases[j];
                const mtrr_physmask_t *mask_j
                        = &saved_state->mtrr_physmasks[j];

                if ( mask_j->v == 0 )
                    continue;

                if ( base_j->type != MTRR_TYPE_UNCACHABLE )
                    continue;

                if ( (base_ndx->base & mask_ndx->mask & mask_j->mask & maxphyaddr_mask)
                        == (base_j->base & mask_j->mask & maxphyaddr_mask)
                     && (mask_j->mask & ~mask_ndx->mask & maxphyaddr_mask) == 0 )
                    break;

                if ( (base_i->base & mask_i->mask & mask_j->mask & maxphyaddr_mask)
                        == (base_j->base & mask_j->mask & maxphyaddr_mask)
                     && (mask_j->mask & ~mask_i->mask & maxphyaddr_mask) == 0 )
                    break;
            }
            if ( j < saved_state->num_var_mtrrs )
                continue;

//            printk("var MTRRs overlaping regions, invalid type combinations\n");
//            print_mtrrs(saved_state);
            return false;
        }
    }

    if ( !validate_mmio_regions(saved_state) ) {
//        printk("Some mmio region should be UC type\n");
//        print_mtrrs(saved_state);
        return false;
    }

//    print_mtrrs(saved_state);
    return true;
}


