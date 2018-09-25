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

/*
 * Note:
 * Currently, svm-avic mode is not supported with nested virtualization.
 * Therefore, it is not yet currently enabled by default. Once the support
 * is in-place, this should be enabled by default.
 */
bool svm_avic = false;

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
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
