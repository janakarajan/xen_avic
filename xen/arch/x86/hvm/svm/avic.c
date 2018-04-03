/*
 * avic.c: implements AMD Advanced Virtual Interrupt Controller (AVIC) support
 * Copyright (c) 2016, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/domain_page.h>
#include <xen/sched.h>
#include <xen/stdbool.h>
#include <asm/acpi.h>
#include <asm/apic.h>
#include <asm/apicdef.h>
#include <asm/atomic.h>
#include <asm/event.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/avic.h>
#include <asm/hvm/vlapic.h>
#include <asm/p2m.h>
#include <asm/page.h>

/* Note: Current max index allowed for physical APIC ID table is 255. */
#define AVIC_PHY_APIC_ID_MAX    0xFF

#define AVIC_VAPIC_BAR_MASK     (((1ULL << 40) - 1) << PAGE_SHIFT)

#define AVIC_UNACCEL_ACCESS_OFFSET_MASK    0xFF0

/*
 * Note:
 * Currently, svm-avic mode is not supported with nested virtualization.
 * Therefore, it is not yet currently enabled by default. Once the support
 * is in-place, this should be enabled by default.
 */
bool svm_avic = false;

static union avic_physical_id_entry*
avic_get_physical_id_entry(struct svm_domain *d, unsigned int index)
{
    if ( !d->avic_physical_id_table )
        return NULL;

    /*
    * Note: APIC ID = 0xFF is used for broadcast.
    *       APIC ID > 0xFF is reserved.
    */
    ASSERT(index < AVIC_PHY_APIC_ID_MAX);

    if ( index >= AVIC_PHY_APIC_ID_MAX )
        return NULL;

    return &d->avic_physical_id_table[index];
}

int svm_avic_dom_init(struct domain *d)
{
    int ret = 0;
    struct page_info *pg;

    if ( !svm_avic || !has_vlapic(d) )
        return 0;

    /*
     * Note:
     * AVIC hardware walks the nested page table to check permissions,
     * but does not use the SPA address specified in the leaf page
     * table entry since it uses  address in the AVIC_BACKING_PAGE pointer
     * field of the VMCB. Therefore, we set up a dummy page for APIC _mfn(0).
     */
    set_mmio_p2m_entry(d, paddr_to_pfn(APIC_DEFAULT_PHYS_BASE),
                       _mfn(0), PAGE_ORDER_4K,
                       p2m_get_hostp2m(d)->default_access);

    /* Init AVIC logical APIC ID table */
    pg = alloc_domheap_page(d, MEMF_no_owner);
    if ( !pg )
    {
        ret = -ENOMEM;
        goto err_out;
    }
    clear_domain_page(_mfn(page_to_mfn(pg)));
    d->arch.hvm_domain.svm.avic_logical_id_table_pg = pg;
    d->arch.hvm_domain.svm.avic_logical_id_table = __map_domain_page_global(pg);

    /* Init AVIC physical APIC ID table */
    pg = alloc_domheap_page(d, MEMF_no_owner);
    if ( !pg )
    {
        ret = -ENOMEM;
        goto err_out;
    }
    clear_domain_page(_mfn(page_to_mfn(pg)));
    d->arch.hvm_domain.svm.avic_physical_id_table_pg = pg;
    d->arch.hvm_domain.svm.avic_physical_id_table = __map_domain_page_global(pg);

    spin_lock_init(&d->arch.hvm_domain.svm.avic_dfr_mode_lock);

    return ret;
 err_out:
    svm_avic_dom_destroy(d);
    return ret;
}

void svm_avic_dom_destroy(struct domain *d)
{
    if ( !svm_avic || !has_vlapic(d) )
        return;

    if ( d->arch.hvm_domain.svm.avic_physical_id_table )
    {
        unmap_domain_page_global(d->arch.hvm_domain.svm.avic_physical_id_table);
        free_domheap_page(d->arch.hvm_domain.svm.avic_physical_id_table_pg);
        d->arch.hvm_domain.svm.avic_physical_id_table_pg = NULL;
        d->arch.hvm_domain.svm.avic_physical_id_table = NULL;
    }

    if ( d->arch.hvm_domain.svm.avic_logical_id_table)
    {
        unmap_domain_page_global(d->arch.hvm_domain.svm.avic_logical_id_table);
        free_domheap_page(d->arch.hvm_domain.svm.avic_logical_id_table_pg);
        d->arch.hvm_domain.svm.avic_logical_id_table_pg = NULL;
        d->arch.hvm_domain.svm.avic_logical_id_table = NULL;
    }
}

bool svm_avic_vcpu_enabled(const struct vcpu *v)
{
    const struct arch_svm_struct *s = &v->arch.hvm_svm;
    const struct vmcb_struct *vmcb = s->vmcb;

    return vmcb->_vintr.fields.avic_enable;
}

int svm_avic_init_vmcb(struct vcpu *v)
{
    u32 apic_id;
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    struct vmcb_struct *vmcb = s->vmcb;
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    const struct vlapic *vlapic = vcpu_vlapic(v);
    struct physical_id *entry;

    if ( !svm_avic || !has_vlapic(v->domain) )
        return 0;

    if ( !vlapic || !vlapic->regs_page )
        return -EINVAL;

    apic_id = vlapic_read_aligned(vcpu_vlapic(v), APIC_ID);
    s->avic_last_phy_id = avic_get_physical_id_entry(d, GET_xAPIC_ID(apic_id));
    if ( !s->avic_last_phy_id )
        return -EINVAL;

    vmcb->avic_bk_pg_pa = page_to_maddr(vlapic->regs_page);
    vmcb->avic_logical_id_table_pa = domain_page_map_to_mfn(d->avic_logical_id_table) << PAGE_SHIFT;
    vmcb->avic_physical_id_table_pa = domain_page_map_to_mfn(d->avic_physical_id_table) << PAGE_SHIFT;

    /* Set Physical ID Table Pointer [7:0] to max apic id of the domain */
    vmcb->avic_logical_id_table_pa &= ~AVIC_PHY_APIC_ID_MAX;
    vmcb->avic_physical_id_table_pa |= (v->domain->max_vcpus * 2) & 0xFF;

    entry = &s->avic_last_phy_id->phy_id_entry;
    entry->bk_pg_ptr_mfn = (vmcb->avic_bk_pg_pa) >> PAGE_SHIFT;
    entry->is_running = 0;
    entry->valid = 1;

    vmcb->avic_vapic_bar = APIC_DEFAULT_PHYS_BASE & AVIC_VAPIC_BAR_MASK;
    vmcb->cleanbits.fields.avic = 0;

    vmcb->_vintr.fields.avic_enable = 1;

    return 0;
}

/*
 * Note:
 * This function handles the AVIC_INCOMP_IPI #vmexit when AVIC is enabled.
 * The hardware generates this fault when an IPI could not be delivered
 * to all targeted guest virtual processors because at least one guest
 * virtual processor was not allocated to a physical core at the time.
 */
void svm_avic_vmexit_do_incomp_ipi(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    struct vmcb_struct *vmcb = curr->arch.hvm_svm.vmcb;
    u32 icrh = vmcb->exitinfo1 >> 32;
    u32 icrl = vmcb->exitinfo1;
    u32 id = vmcb->exitinfo2 >> 32;
    u32 index = vmcb->exitinfo2 && 0xFF;

    switch ( id )
    {
    case AVIC_INCMP_IPI_ERR_INVALID_INT_TYPE:
        /*
         * AVIC hardware handles the delivery of
         * IPIs when the specified Message Type is Fixed
         * (also known as fixed delivery mode) and
         * the Trigger Mode is edge-triggered. The hardware
         * also supports self and broadcast delivery modes
         * specified via the Destination Shorthand(DSH)
         * field of the ICRL. Logical and physical APIC ID
         * formats are supported. All other IPI types cause
         * a #VMEXIT, which needs to emulated.
         */
        vlapic_reg_write(curr, APIC_ICR2, icrh);
        vlapic_reg_write(curr, APIC_ICR, icrl);
        break;

    case AVIC_INCMP_IPI_ERR_TARGET_NOT_RUN:
    {
        /*
         * At this point, we expect that the AVIC HW has already
         * set the appropriate IRR bits on the valid target
         * vcpus. So, we just need to kick the appropriate vcpu.
         */
        struct vcpu *v;
        uint32_t dest = GET_xAPIC_DEST_FIELD(icrh);
        uint32_t short_hand = icrl & APIC_SHORT_MASK;
        bool dest_mode = !!(icrl & APIC_DEST_MASK);

        for_each_vcpu ( currd,  v )
        {
            if ( v != curr &&
                 vlapic_match_dest(vcpu_vlapic(v), vcpu_vlapic(curr),
                                   short_hand, dest, dest_mode) )
            {
                vcpu_kick(v);
                break;
            }
        }
        break;
    }

    case AVIC_INCMP_IPI_ERR_INV_TARGET:
        gprintk(XENLOG_ERR,
                "SVM: %s: Invalid IPI target (icr=%#08x:%08x, idx=%u)\n",
                __func__, icrh, icrl, index);
        domain_crash(currd);
        break;

    case AVIC_INCMP_IPI_ERR_INV_BK_PAGE:
        gprintk(XENLOG_ERR,
                "SVM: %s: Invalid bk page (icr=%#08x:%08x, idx=%u)\n",
                __func__, icrh, icrl, index);
        domain_crash(currd);
        break;

    default:
        gprintk(XENLOG_ERR, "SVM: %s: Unknown IPI interception (%#x)\n",
                __func__, id);
        domain_crash(currd);
    }
}

static struct avic_logical_id_entry *
avic_get_logical_id_entry(struct svm_domain *d, u32 ldr, bool flat)
{
    unsigned int index;
    unsigned int dest_id = GET_xAPIC_LOGICAL_ID(ldr);

    if ( !dest_id )
        return NULL;

    if ( flat )
    {
        index = ffs(dest_id) - 1;
        if ( index > 7 )
            return NULL;
    }
    else
    {
        unsigned int cluster = (dest_id & 0xf0) >> 4;
        int apic = ffs(dest_id & 0x0f) - 1;

        if ( (apic < 0) || (apic > 7) || (cluster >= 0xf) )
            return NULL;
        index = (cluster << 2) + apic;
    }

    ASSERT(index <= 255);

    return &d->avic_logical_id_table[index];
}

static int avic_ldr_write(struct vcpu *v, u8 g_phy_id, u32 ldr, bool valid)
{
    struct avic_logical_id_entry *entry, new_entry;
    u32 dfr = vlapic_read_aligned(vcpu_vlapic(v), APIC_DFR);

    entry = avic_get_logical_id_entry(&v->domain->arch.hvm_domain.svm,
                                      ldr, (dfr == APIC_DFR_FLAT));
    if (!entry)
        return -EINVAL;

    new_entry = *entry;
    smp_rmb();
    new_entry.guest_phy_apic_id = g_phy_id;
    new_entry.valid = valid;
    *entry = new_entry;
    smp_wmb();

    return 0;
}

static int avic_handle_ldr_update(struct vcpu *v)
{
    int ret = 0;
    u32 ldr = vlapic_read_aligned(vcpu_vlapic(v), APIC_LDR);
    u32 apic_id = vlapic_read_aligned(vcpu_vlapic(v), APIC_ID);

    if ( !ldr )
        return -EINVAL;

    ret = avic_ldr_write(v, GET_xAPIC_ID(apic_id), ldr, true);
    if ( ret && v->arch.hvm_svm.avic_last_ldr )
    {
        /*
         * Note:
         * In case of failure to update LDR register,
         * we set the guest physical APIC ID to 0,
         * and set the entry logical APID ID entry
         * to invalid (false).
         */
        avic_ldr_write(v, 0, v->arch.hvm_svm.avic_last_ldr, false);
        v->arch.hvm_svm.avic_last_ldr = 0;
    }
    else
    {
        /*
         * Note:
         * This saves the last valid LDR so that we
         * know which entry in the local APIC ID
         * to clean up when the LDR is updated.
         */
        v->arch.hvm_svm.avic_last_ldr = ldr;
    }

    return ret;
}

static int avic_handle_dfr_update(struct vcpu *v)
{
    u32 mod;
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    u32 dfr = vlapic_read_aligned(vcpu_vlapic(v), APIC_DFR);

    mod = (dfr >> 28) & 0xFu;

    spin_lock(&d->avic_dfr_mode_lock);
    if ( d->avic_dfr_mode != mod )
    {
        /*
         * We assume that all local APICs are using the same type.
         * If DFR mode changes, we need to flush the domain AVIC logical
         * APIC id table.
         */
        clear_domain_page(_mfn(page_to_mfn(d->avic_logical_id_table_pg)));
        d->avic_dfr_mode = mod;
    }
    spin_unlock(&d->avic_dfr_mode_lock);

    if ( v->arch.hvm_svm.avic_last_ldr )
        avic_handle_ldr_update(v);

    return 0;
}

static int avic_unaccel_trap_write(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 offset = vmcb->exitinfo1 & AVIC_UNACCEL_ACCESS_OFFSET_MASK;
    u32 reg = vlapic_read_aligned(vcpu_vlapic(v), offset);

    switch ( offset )
    {
    case APIC_ID:
        /*
         * Currently, we do not support APIC_ID update while
         * the vcpus are running, which might require updating
         * AVIC max APIC ID in all VMCBs. This would require
         * synchronize update on all running VCPUs.
         */
        return X86EMUL_UNHANDLEABLE;
    case APIC_LDR:
        if ( avic_handle_ldr_update(v) )
            return X86EMUL_UNHANDLEABLE;
        break;

    case APIC_DFR:
        if ( avic_handle_dfr_update(v) )
            return X86EMUL_UNHANDLEABLE;
        break;

    default:
        break;
    }

    vlapic_reg_write(v, offset, reg);

    return X86EMUL_OKAY;
}

static inline bool avic_is_trap(u32 offset)
{
    u32 pos = offset >> 4;
    static const unsigned long avic_trap[] =
        {
#define REG(x) (1UL << (APIC_ ## x >> 4))
            REG(ID)   | REG(EOI)     | REG(RRR)   | REG(LDR)  |
            REG(DFR)  | REG(SPIV)    | REG(ESR)   | REG(ICR)  |
            REG(LVTT) | REG(LVTTHMR) | REG(LVTPC) | REG(LVT0) |
            REG(LVT1) | REG(LVTERR)  | REG(TMICT) | REG(TDCR)
#undef REG
        };

    if ( !test_bit(pos, avic_trap) )
        return false;
    return true;
}

/*
 * Note:
 * This function handles the AVIC_NOACCEL #vmexit when AVIC is enabled.
 * The hardware generates this fault when :
 * -  A guest access to an APIC register that is not accelerated
 *    by AVIC hardware.
 * - EOI is attempted when the highest priority in-service interrupt
 *   is level-triggered.
 */
void svm_avic_vmexit_do_noaccel(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct vmcb_struct *vmcb = curr->arch.hvm_svm.vmcb;
    u32 offset = vmcb->exitinfo1 & 0xFF0;
    u32 rw = (vmcb->exitinfo1 >> 32) & 0x1;

    if ( avic_is_trap(offset) )
    {
        /* Handling AVIC Trap (intercept right after the access). */
        if ( !rw )
        {
            /*
             * If a read trap happens, the CPU microcode does not
             * implement the spec.
             */
            gprintk(XENLOG_ERR, "%s: Invalid #VMEXIT due to trap read (%#x)\n",
                    __func__, offset);
            domain_crash(curr->domain);
        }

        if ( avic_unaccel_trap_write(curr) != X86EMUL_OKAY )
        {
            gprintk(XENLOG_ERR, "%s: Failed to handle trap write (%#x)\n",
                    __func__, offset);
            domain_crash(curr->domain);
        }
    }
    else
        /* Handling AVIC Fault (intercept before the access). */
        hvm_emulate_one_vm_event(EMUL_KIND_NORMAL, TRAP_invalid_op,
                                 X86_EVENT_NO_EC);
    return;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
