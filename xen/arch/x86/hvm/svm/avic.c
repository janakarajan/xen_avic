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
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
