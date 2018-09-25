/*
 * avic.c: implements AMD Advanced Virtual Interrupt Controller (AVIC) support
 * Copyright (c) 2018, Advanced Micro Devices, Inc.
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

#include <xen/sched.h>
#include <asm/apicdef.h>
#include <asm/event.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/avic.h>
#include <asm/hvm/vlapic.h>

/* Note: Current max index allowed for physical APIC ID table is 255. */
#define AVIC_PHY_APIC_ID_MAX    0xFE

#define AVIC_UNACCEL_ACCESS_OFFSET_MASK    0xFF0

/*
 * Note:
 * Currently, svm-avic mode is not supported with nested virtualization.
 * Therefore, it is not yet currently enabled by default. Once the support
 * is in-place, this should be enabled by default.
 */
bool svm_avic = false;

static inline const bool svm_is_avic_domain(struct domain *d)
{
    return d->arch.hvm.svm.avic_physical_id_table != 0;
}

static avic_physical_id_entry_t*
avic_get_physical_id_entry(const struct svm_domain *d, unsigned int index)
{
    if ( !d->avic_physical_id_table )
        return NULL;

    /*
    * Note: APIC ID = 0xFF is used for broadcast.
    *       APIC ID > 0xFF is reserved.
    */
    ASSERT(index <= AVIC_PHY_APIC_ID_MAX);

    if ( index > AVIC_PHY_APIC_ID_MAX )
        return NULL;

    return &d->avic_physical_id_table[index];
}

void avic_vcpu_load(struct vcpu *v)
{
    uint32_t apic_id = vlapic_get_reg(vcpu_vlapic(v), APIC_ID);
    avic_physical_id_entry_t *entry;
    unsigned int h_phy_apic_id;

    ASSERT(!test_bit(_VPF_blocked, &v->pause_flags));

    /*
     * Note: APIC ID = 0xff is used for broadcast.
     *       APIC ID > 0xff is reserved.
     */
    h_phy_apic_id = cpu_data[v->processor].apicid;
    ASSERT(h_phy_apic_id < AVIC_PHY_APIC_ID_MAX);

    entry = avic_get_physical_id_entry(&v->domain->arch.hvm.svm,
                                       GET_xAPIC_ID(apic_id));
    entry->host_phy_apic_id = h_phy_apic_id;
    smp_wmb();
    set_bit(IS_RUNNING_BIT, &entry->raw);
}

void avic_vcpu_unload(struct vcpu *v)
{
    uint32_t apic_id = vlapic_get_reg(vcpu_vlapic(v), APIC_ID);
    avic_physical_id_entry_t *entry;

    entry = avic_get_physical_id_entry(&v->domain->arch.hvm.svm,
                                       GET_xAPIC_ID(apic_id));
    clear_bit(IS_RUNNING_BIT, &entry->raw);
}

void avic_vcpu_resume(struct vcpu *v)
{
    uint32_t apic_id = vlapic_get_reg(vcpu_vlapic(v), APIC_ID);
    avic_physical_id_entry_t *entry;

    ASSERT(svm_avic_vcpu_enabled(v));
    ASSERT(!test_bit(_VPF_blocked, &v->pause_flags));

    entry = avic_get_physical_id_entry(&v->domain->arch.hvm.svm,
                                       GET_xAPIC_ID(apic_id));
    set_bit(IS_RUNNING_BIT, &entry->raw);
}

void avic_vcpu_block(struct vcpu *v)
{
    uint32_t apic_id = vlapic_get_reg(vcpu_vlapic(v), APIC_ID);
    avic_physical_id_entry_t *entry;

    ASSERT(svm_avic_vcpu_enabled(v));

    entry = avic_get_physical_id_entry(&v->domain->arch.hvm.svm,
                                       GET_xAPIC_ID(apic_id));
    clear_bit(IS_RUNNING_BIT, &entry->raw);
}

int svm_avic_dom_init(struct domain *d)
{
    int ret = 0;
    struct page_info *pg;

    if ( !svm_avic || !has_vlapic(d) )
        return 0;

    pg = alloc_domheap_page(NULL, MEMF_no_owner);
    if ( !pg )
    {
        ret = -ENOMEM;
        goto err_out;
    }
    clear_domain_page(page_to_mfn(pg));

    /*
     * Note:
     * AVIC hardware walks the nested page table to check permissions,
     * but does not use the SPA address specified in the leaf page
     * table entry since it uses  address in the AVIC_BACKING_PAGE pointer
     * field of the VMCB. Therefore, we set up a dummy page for APIC.
     */
    set_mmio_p2m_entry(d, paddr_to_pfn(APIC_DEFAULT_PHYS_BASE),
                       page_to_mfn(pg), PAGE_ORDER_4K, p2m_access_rw);

    d->arch.hvm.svm.avic_permission_page = __map_domain_page_global(pg);

    /* Init AVIC logical APIC ID table */
    pg = alloc_domheap_page(NULL, MEMF_no_owner);
    if ( !pg )
    {
        ret = -ENOMEM;
        goto err_out;
    }
    clear_domain_page(page_to_mfn(pg));
    d->arch.hvm.svm.avic_logical_id_table = __map_domain_page_global(pg);

    /* Init AVIC physical APIC ID table */
    pg = alloc_domheap_page(NULL, MEMF_no_owner);
    if ( !pg )
    {
        ret = -ENOMEM;
        goto err_out;
    }
    clear_domain_page(page_to_mfn(pg));
    d->arch.hvm.svm.avic_physical_id_table = __map_domain_page_global(pg);

    spin_lock_init(&d->arch.hvm.svm.avic_dfr_mode_lock);

    d->arch.hvm.pi_ops.flags |= PI_CSW_FROM;
    d->arch.hvm.pi_ops.flags |= PI_CSW_TO;
    d->arch.hvm.pi_ops.flags |= PI_CSW_BLOCK;
    d->arch.hvm.pi_ops.flags |= PI_CSW_RESUME;

    return ret;
 err_out:
    svm_avic_dom_destroy(d);
    return ret;
}

void svm_avic_dom_destroy(struct domain *d)
{
    struct svm_domain *s = &d->arch.hvm.svm;
    struct page_info *pg;

    if ( !svm_avic || !has_vlapic(d) )
        return;

    if ( d->arch.hvm.svm.avic_permission_page )
    {
        pg = mfn_to_page(domain_page_map_to_mfn(s->avic_permission_page));
        free_domheap_page(pg);
        unmap_domain_page_global(d->arch.hvm.svm.avic_permission_page);
        d->arch.hvm.svm.avic_permission_page = NULL;
    }

    if ( d->arch.hvm.svm.avic_physical_id_table )
    {
        pg = mfn_to_page(domain_page_map_to_mfn(s->avic_physical_id_table));
        free_domheap_page(pg);
        unmap_domain_page_global(d->arch.hvm.svm.avic_physical_id_table);
        d->arch.hvm.svm.avic_physical_id_table = NULL;
    }

    if ( d->arch.hvm.svm.avic_logical_id_table )
    {
        pg = mfn_to_page(domain_page_map_to_mfn(s->avic_logical_id_table));
        free_domheap_page(pg);
        unmap_domain_page_global(d->arch.hvm.svm.avic_logical_id_table);
        d->arch.hvm.svm.avic_logical_id_table = NULL;
    }
}

bool svm_avic_vcpu_enabled(const struct vcpu *v)
{
    return vmcb_get_vintr(v->arch.hvm.svm.vmcb).fields.avic_enable;
}

int svm_avic_init_vmcb(struct vcpu *v)
{
    struct svm_domain *d = &v->domain->arch.hvm.svm;
    const struct vlapic *vlapic = vcpu_vlapic(v);
    struct svm_vcpu *s = &v->arch.hvm.svm;
    avic_physical_id_entry_t *entry;
    struct vmcb_struct *vmcb = s->vmcb;
    uint32_t apic_id;

    if ( !svm_avic || !has_vlapic(v->domain) )
        return 0;

    if ( !vlapic || !vlapic->regs_page )
        return -EINVAL;

    vmcb->avic_bk_pg_pa = page_to_maddr(vlapic->regs_page);
    vmcb->avic_logical_id_table_pa = mfn_to_maddr(domain_page_map_to_mfn(d->avic_logical_id_table));
    vmcb->avic_physical_id_table_pa = mfn_to_maddr(domain_page_map_to_mfn(d->avic_physical_id_table));

    /* Set Physical ID Table Pointer [7:0] to max apic id of the domain */
    vmcb->avic_physical_id_table_pa |= (v->domain->max_vcpus * 2) & 0xFF;

    apic_id = vlapic_get_reg(vcpu_vlapic(v), APIC_ID);

    entry = avic_get_physical_id_entry(d, GET_xAPIC_ID(apic_id));
    entry->bk_pg_ptr_mfn = mfn_x(maddr_to_mfn(vmcb->avic_bk_pg_pa));
    entry->is_running = 0;
    entry->valid = 1;

    vmcb->avic_vapic_bar = APIC_DEFAULT_PHYS_BASE;
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
    struct vmcb_struct *vmcb = curr->arch.hvm.svm.vmcb;
    uint32_t icrh = vmcb->exitinfo1 >> 32;
    uint32_t icrl = vmcb->exitinfo1;
    uint32_t id = vmcb->exitinfo2 >> 32;
    uint32_t index = vmcb->exitinfo2 && 0xFF;

    curr->arch.hvm.svm.cnt_avic_incomp_ipi++;

    switch ( id )
    {
    case AVIC_INCMP_IPI_ERR_INVALID_INT_TYPE:
        /*
         * AVIC hardware handles the delivery of IPIs when the specified
         * Message Type is Fixed (also known as fixed delivery mode) and
         * the Trigger Mode is edge-triggered. The hardware also supports
         * self and broadcast delivery modes specified via the Destination
         * Shorthand(DSH) field of the ICRL. Logical and physical APIC ID
         * formats are supported. All other IPI types cause a #VMEXIT,
         * which needs to emulated.
         */
        vlapic_reg_write(curr, APIC_ICR2, icrh);
        vlapic_reg_write(curr, APIC_ICR, icrl);
        break;

    case AVIC_INCMP_IPI_ERR_TARGET_NOT_RUN:
    {
        /*
         * At this point, we expect that the AVIC HW has already set the
         * appropriate IRR bits on the valid target vcpus. So, we just
         * need to kick the appropriate vcpu.
         */
        struct vcpu *v;
        uint32_t dest = GET_xAPIC_DEST_FIELD(icrh);
        uint32_t short_hand = icrl & APIC_SHORT_MASK;
        bool dest_mode = icrl & APIC_DEST_MASK;

        for_each_vcpu ( currd,  v )
        {
            if ( v != curr &&
                 vlapic_match_dest(vcpu_vlapic(v), vcpu_vlapic(curr),
                                   short_hand, dest, dest_mode) )
            {
                vcpu_kick(v);
            }
        }
        break;
    }

    case AVIC_INCMP_IPI_ERR_INV_TARGET:
        gprintk(XENLOG_ERR,
                "SVM: Invalid IPI target (icr=0x%08x:%08x, idx=%u)\n",
                icrh, icrl, index);
        domain_crash(currd);
        break;

    case AVIC_INCMP_IPI_ERR_INV_BK_PAGE:
        gprintk(XENLOG_ERR,
                "SVM: Invalid bk page (icr=0x%08x:%08x, idx=%u)\n",
                icrh, icrl, index);
        domain_crash(currd);
        break;

    default:
        gprintk(XENLOG_ERR, "SVM: Unknown IPI interception (%#x)\n", id);
        domain_crash(currd);
    }
}

static avic_logical_id_entry_t *
avic_get_logical_id_entry(struct svm_domain *d, uint32_t ldr, bool flat)
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

        if ( (apic < 0) || (apic > 4) || (cluster >= 0xf) )
            return NULL;
        index = (cluster << 2) + apic;
    }

    return &d->avic_logical_id_table[index];
}

static int avic_ldr_write(struct vcpu *v, u8 g_phy_id, uint32_t ldr, bool valid)
{
    avic_logical_id_entry_t *entry, new_entry;
    uint32_t dfr = vlapic_get_reg(vcpu_vlapic(v), APIC_DFR);

    entry = avic_get_logical_id_entry(&v->domain->arch.hvm.svm,
                                      ldr, (dfr == APIC_DFR_FLAT));
    if ( !entry )
        return -EINVAL;

    new_entry.raw = ACCESS_ONCE(entry->raw);
    new_entry.guest_phy_apic_id = g_phy_id;
    new_entry.valid = valid;
    ACCESS_ONCE(entry->raw) = new_entry.raw;

    return 0;
}

static int avic_handle_ldr_update(struct vcpu *v)
{
    uint32_t ldr = vlapic_get_reg(vcpu_vlapic(v), APIC_LDR);
    uint32_t apic_id = vlapic_get_reg(vcpu_vlapic(v), APIC_ID);
    int ret;

    if ( !ldr )
        return -EINVAL;

    ret = avic_ldr_write(v, GET_xAPIC_ID(apic_id), ldr, true);
    if ( !ret )
    {
        /*
         * Note:
         * In case of failure to update LDR register, we set the guest
         * physical APIC ID to 0, and set the entry logical APID ID entry
         * to invalid (false).
         */
        avic_ldr_write(v, 0, v->arch.hvm.svm.avic_last_ldr, false);
        v->arch.hvm.svm.avic_last_ldr = 0;
    }
    else if (v->arch.hvm.svm.avic_last_ldr)
    {
        /*
         * Note:
         * This saves the last valid LDR so that we know which entry in
         * the local APIC ID to clean up when the LDR is updated.
         */
        v->arch.hvm.svm.avic_last_ldr = ldr;
    }

    return ret;
}

static int avic_handle_dfr_update(struct vcpu *v)
{
    uint32_t mod;
    struct svm_domain *d = &v->domain->arch.hvm.svm;
    uint32_t dfr = vlapic_get_reg(vcpu_vlapic(v), APIC_DFR);

    mod = (dfr >> 28) & 0xFu;

    spin_lock(&d->avic_dfr_mode_lock);
    if ( d->avic_dfr_mode != mod )
    {
        /*
         * We assume that all local APICs are using the same type. If
         * DFR mode changes, we need to flush the domain AVIC logical
         * APIC id table.
         */
        clear_domain_page(domain_page_map_to_mfn(d->avic_logical_id_table));
        d->avic_dfr_mode = mod;
    }
    spin_unlock(&d->avic_dfr_mode_lock);

    if ( v->arch.hvm.svm.avic_last_ldr )
        avic_handle_ldr_update(v);

    return 0;
}

static int avic_unaccel_trap_write(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    uint32_t offset = vmcb->exitinfo1 & AVIC_UNACCEL_ACCESS_OFFSET_MASK;
    uint32_t reg = vlapic_reg_read(v, offset);

    switch ( offset )
    {
    case APIC_ID:
        /*
         * Currently, we do not support APIC_ID update while the vcpus
         * are running, which might require updating AVIC max APIC ID
         * in all VMCBs. This would require synchronize update on all
         * running VCPUs.
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
    }

    vlapic_reg_write(v, offset, reg);

    return X86EMUL_OKAY;
}

static inline bool avic_is_trap(uint32_t offset)
{
    uint32_t pos = offset >> 4;
    static const unsigned long avic_trap[] = {
#define REG(x) (1UL << (APIC_ ## x >> 4))
    REG(ID)   | REG(EOI)     | REG(RRR)   | REG(LDR)  |
    REG(DFR)  | REG(SPIV)    | REG(ESR)   | REG(ICR)  |
    REG(LVTT) | REG(LVTTHMR) | REG(LVTPC) | REG(LVT0) |
    REG(LVT1) | REG(LVTERR)  | REG(TMICT) | REG(TDCR)
#undef REG
    };

    return pos < (sizeof(avic_trap) * 8) && test_bit(pos, avic_trap);
}

/*
 * Note:
 * This function handles the AVIC_NOACCEL #vmexit when AVIC is enabled.
 * The hardware generates this fault when :
 * - A guest access to an APIC register that is not accelerated by
 *   AVIC hardware.
 * - EOI is attempted when the highest priority in-service interrupt
 *   is level-triggered.
 */
void svm_avic_vmexit_do_noaccel(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct vmcb_struct *vmcb = curr->arch.hvm.svm.vmcb;
    uint32_t offset = vmcb->exitinfo1 & 0xFF0;
    bool rw = (vmcb->exitinfo1 >> 32) & 0x1;
    struct hvm_emulate_ctxt ctx;
    int rc;

    curr->arch.hvm.svm.cnt_avic_noaccel++;

    if ( avic_is_trap(offset) )
    {
        /* Handling AVIC Trap (intercept right after the access). */
        if ( !rw )
        {
            /*
             * If a read trap happens, the CPU microcode does not
             * implement the spec.
             */
            gprintk(XENLOG_ERR, "Invalid #VMEXIT due to trap read (%#x)\n",
                    offset);
            domain_crash(curr->domain);
        }
        else if ( avic_unaccel_trap_write(curr) != X86EMUL_OKAY )
        {
            gprintk(XENLOG_ERR, "Failed to handle trap write (%#x)\n",
                    offset);
            domain_crash(curr->domain);
        }
    }
    else
    {
        /* Handling AVIC Fault (intercept before the access). */
        hvm_emulate_init_once(&ctx, x86_insn_is_mem_access,
                              guest_cpu_user_regs());
        rc = hvm_emulate_one(&ctx);

        switch( rc )
        {
        case X86EMUL_UNHANDLEABLE:
        case X86EMUL_UNRECOGNIZED:
            hvm_inject_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC);
            break;

        case X86EMUL_EXCEPTION:
            hvm_inject_event(&ctx.ctxt.event);

        }

        hvm_emulate_writeback(&ctx);
    }
}

void svm_avic_deliver_posted_intr(struct vcpu *v, u8 vec)
{
    struct vlapic *vlapic = vcpu_vlapic(v);

    /* Fallback to use non-AVIC if vcpu is not enabled with AVIC. */
    if ( !svm_avic_vcpu_enabled(v) )
    {
        if ( !vlapic_test_and_set_vector(vec, &vlapic->regs->data[APIC_IRR]) )
            vcpu_kick(v);
        return;
    }

    if ( vlapic_test_and_set_vector(vec, &vlapic->regs->data[APIC_IRR]) )
        return;

    v->arch.hvm.svm.cnt_avic_post_intr++;
    /*
     * If vcpu is running on another cpu, hit the doorbell to signal
     * it to process interrupt. Otherwise, kick it.
     */
    if ( v->is_running && (v != current) )
    {
        wrmsrl(MSR_AMD_AVIC_DOORBELL, cpu_data[v->processor].apicid);
        v->arch.hvm.svm.cnt_avic_doorbell++;
    }
    else {
        vcpu_kick(v);
    }
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
