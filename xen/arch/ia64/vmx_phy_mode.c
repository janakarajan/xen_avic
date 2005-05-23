/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_phy_mode.c: emulating domain physical mode.
 * Copyright (c) 2005, Intel Corporation.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Arun Sharma (arun.sharma@intel.com)
 * Kun Tian (Kevin Tian) (kevin.tian@intel.com)
 * Xuefei Xu (Anthony Xu) (anthony.xu@intel.com)
 */


#include <asm/processor.h>
#include <asm/gcc_intrin.h>
#include <asm/vmx_phy_mode.h>
#include <xen/sched.h>
#include <asm/pgtable.h>


int valid_mm_mode[8] = {
    GUEST_PHYS, /* (it, dt, rt) -> (0, 0, 0) */
    INV_MODE,
    INV_MODE,
    GUEST_PHYS, /* (it, dt, rt) -> (0, 1, 1) */
    INV_MODE,
    GUEST_PHYS, /* (it, dt, rt) -> (1, 0, 1) */
    INV_MODE,
    GUEST_VIRT, /* (it, dt, rt) -> (1, 1, 1).*/
};

/*
 * Special notes:
 * - Index by it/dt/rt sequence
 * - Only existing mode transitions are allowed in this table
 * - RSE is placed at lazy mode when emulating guest partial mode
 * - If gva happens to be rr0 and rr4, only allowed case is identity
 *   mapping (gva=gpa), or panic! (How?)
 */
int mm_switch_table[8][8] = {
    /*  2004/09/12(Kevin): Allow switch to self */
        /*
         *  (it,dt,rt): (0,0,0) -> (1,1,1)
         *  This kind of transition usually occurs in the very early
     *  stage of Linux boot up procedure. Another case is in efi
     *  and pal calls. (see "arch/ia64/kernel/head.S")
     *
     *  (it,dt,rt): (0,0,0) -> (0,1,1)
     *  This kind of transition is found when OSYa exits efi boot
     *  service. Due to gva = gpa in this case (Same region),
     *  data access can be satisfied though itlb entry for physical
     *  emulation is hit.
         */
    SW_SELF,0,  0,  SW_NOP, 0,  0,  0,  SW_P2V,
    0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,
    /*
     *  (it,dt,rt): (0,1,1) -> (1,1,1)
     *  This kind of transition is found in OSYa.
     *
     *  (it,dt,rt): (0,1,1) -> (0,0,0)
     *  This kind of transition is found in OSYa
     */
    SW_NOP, 0,  0,  SW_SELF,0,  0,  0,  SW_P2V,
    /* (1,0,0)->(1,1,1) */
    0,  0,  0,  0,  0,  0,  0,  SW_P2V,
    /*
         *  (it,dt,rt): (1,0,1) -> (1,1,1)
         *  This kind of transition usually occurs when Linux returns
     *  from the low level TLB miss handlers.
         *  (see "arch/ia64/kernel/ivt.S")
         */
    0,  0,  0,  0,  0,  SW_SELF,0,  SW_P2V,
    0,  0,  0,  0,  0,  0,  0,  0,
    /*
         *  (it,dt,rt): (1,1,1) -> (1,0,1)
         *  This kind of transition usually occurs in Linux low level
     *  TLB miss handler. (see "arch/ia64/kernel/ivt.S")
     *
     *  (it,dt,rt): (1,1,1) -> (0,0,0)
     *  This kind of transition usually occurs in pal and efi calls,
     *  which requires running in physical mode.
     *  (see "arch/ia64/kernel/head.S")
     *  (1,1,1)->(1,0,0)
     */

    SW_V2P, 0,  0,  0,  SW_V2P, SW_V2P, 0,  SW_SELF,
};

void
physical_mode_init(VCPU *vcpu)
{
    UINT64 psr;
    struct domain * d = vcpu->domain;

    vcpu->domain->arch.emul_phy_rr0.rid = XEN_RR7_RID+((d->domain_id)<<3);
    /* FIXME */
#if 0
    vcpu->domain->arch.emul_phy_rr0.ps = 28;  /* set page size to 256M */
#endif
	vcpu->domain->arch.emul_phy_rr0.ps = EMUL_PHY_PAGE_SHIFT;  /* set page size to 4k */
    vcpu->domain->arch.emul_phy_rr0.ve = 1; /* enable VHPT walker on this region */

    vcpu->domain->arch.emul_phy_rr4.rid = XEN_RR7_RID + ((d->domain_id)<<3) + 4;
    vcpu->domain->arch.emul_phy_rr4.ps = EMUL_PHY_PAGE_SHIFT;  /* set page size to 4k */
    vcpu->domain->arch.emul_phy_rr4.ve = 1; /* enable VHPT walker on this region */

    vcpu->arch.old_rsc = 0;
    vcpu->arch.mode_flags = GUEST_IN_PHY;

    psr = ia64_clear_ic();

    ia64_set_rr((VRN0<<VRN_SHIFT), vcpu->domain->arch.emul_phy_rr0.rrval);
    ia64_srlz_d();
    ia64_set_rr((VRN4<<VRN_SHIFT), vcpu->domain->arch.emul_phy_rr4.rrval);
    ia64_srlz_d();
#if 0
    /* FIXME: temp workaround to support guest physical mode */
ia64_itr(0x1, IA64_TEMP_PHYSICAL, dom0_start,
	 pte_val(pfn_pte((dom0_start >> PAGE_SHIFT), PAGE_KERNEL)),
	 28);
ia64_itr(0x2, IA64_TEMP_PHYSICAL, dom0_start,
	 pte_val(pfn_pte((dom0_start >> PAGE_SHIFT), PAGE_KERNEL)),
	 28);
ia64_srlz_i();
#endif
    ia64_set_psr(psr);
    ia64_srlz_i();
    return;
}

extern u64 get_mfn(domid_t domid, u64 gpfn, u64 pages);
void
physical_itlb_miss(VCPU *vcpu, u64 vadr)
{
    u64 psr;
    IA64_PSR vpsr;
    u64 mppn,gppn;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    gppn=(vadr<<1)>>13;
    mppn = get_mfn(DOMID_SELF,gppn,1);
    mppn=(mppn<<12)|(vpsr.cpl<<7)|PHY_PAGE_WB;

    psr=ia64_clear_ic();
    ia64_itc(1,vadr&(~0xfff),mppn,EMUL_PHY_PAGE_SHIFT);
    ia64_set_psr(psr);
    ia64_srlz_i();
    return;
}

void
physical_dtlb_miss(VCPU *vcpu, u64 vadr)
{
    u64 psr;
    IA64_PSR vpsr;
    u64 mppn,gppn;
    vpsr.val=vmx_vcpu_get_psr(vcpu);
    gppn=(vadr<<1)>>13;
    mppn = get_mfn(DOMID_SELF,gppn,1);
    mppn=(mppn<<12)|(vpsr.cpl<<7);
    if(vadr>>63)
        mppn |= PHY_PAGE_UC;
    else
        mppn |= PHY_PAGE_WB;

    psr=ia64_clear_ic();
    ia64_itc(2,vadr&(~0xfff),mppn,EMUL_PHY_PAGE_SHIFT);
    ia64_set_psr(psr);
    ia64_srlz_i();
    return;
}

void
vmx_init_all_rr(VCPU *vcpu)
{
	VMX(vcpu,vrr[VRN0]) = 0x38;
	VMX(vcpu,vrr[VRN1]) = 0x38;
	VMX(vcpu,vrr[VRN2]) = 0x38;
	VMX(vcpu,vrr[VRN3]) = 0x38;
	VMX(vcpu,vrr[VRN4]) = 0x38;
	VMX(vcpu,vrr[VRN5]) = 0x38;
	VMX(vcpu,vrr[VRN6]) = 0x60;
	VMX(vcpu,vrr[VRN7]) = 0x60;

	VMX(vcpu,mrr5) = vmx_vrrtomrr(vcpu, 0x38);
	VMX(vcpu,mrr6) = vmx_vrrtomrr(vcpu, 0x60);
	VMX(vcpu,mrr7) = vmx_vrrtomrr(vcpu, 0x60);
}

void
vmx_load_all_rr(VCPU *vcpu)
{
	unsigned long psr;

	psr = ia64_clear_ic();

	/* WARNING: not allow co-exist of both virtual mode and physical
	 * mode in same region
	 */
	if (is_physical_mode(vcpu)) {
		ia64_set_rr((VRN0 << VRN_SHIFT),
			     vcpu->domain->arch.emul_phy_rr0.rrval);
		ia64_set_rr((VRN4 << VRN_SHIFT),
			     vcpu->domain->arch.emul_phy_rr4.rrval);
	} else {
		ia64_set_rr((VRN0 << VRN_SHIFT),
			     vmx_vrrtomrr(vcpu, VMX(vcpu, vrr[VRN0])));
		ia64_set_rr((VRN4 << VRN_SHIFT),
			     vmx_vrrtomrr(vcpu, VMX(vcpu, vrr[VRN4])));
	}

#if 1
	/* rr567 will be postponed to last point when resuming back to guest */
	ia64_set_rr((VRN1 << VRN_SHIFT),
		     vmx_vrrtomrr(vcpu, VMX(vcpu, vrr[VRN1])));
	ia64_set_rr((VRN2 << VRN_SHIFT),
		     vmx_vrrtomrr(vcpu, VMX(vcpu, vrr[VRN2])));
	ia64_set_rr((VRN3 << VRN_SHIFT),
		     vmx_vrrtomrr(vcpu, VMX(vcpu, vrr[VRN3])));
#endif
	ia64_srlz_d();
	ia64_set_psr(psr);
    ia64_srlz_i();
}

void
switch_to_physical_rid(VCPU *vcpu)
{
    UINT64 psr;

    /* Save original virtual mode rr[0] and rr[4] */

    psr=ia64_clear_ic();
    ia64_set_rr(VRN0<<VRN_SHIFT, vcpu->domain->arch.emul_phy_rr0.rrval);
    ia64_srlz_d();
    ia64_set_rr(VRN4<<VRN_SHIFT, vcpu->domain->arch.emul_phy_rr4.rrval);
    ia64_srlz_d();

    ia64_set_psr(psr);
    ia64_srlz_i();
    return;
}


void
switch_to_virtual_rid(VCPU *vcpu)
{
    UINT64 psr;
    ia64_rr mrr;

    psr=ia64_clear_ic();

    mrr=vmx_vcpu_rr(vcpu,VRN0<<VRN_SHIFT);
    mrr.rid = VRID_2_MRID(vcpu,mrr.rid);
//VRID_2_MRID(vcpu,mrr.rid);
    mrr.ve = 1;
    ia64_set_rr(VRN0<<VRN_SHIFT, mrr.rrval );
    ia64_srlz_d();
    mrr=vmx_vcpu_rr(vcpu,VRN4<<VRN_SHIFT);
    mrr.rid = VRID_2_MRID(vcpu,mrr.rid);
    mrr.ve = 1;
    ia64_set_rr(VRN4<<VRN_SHIFT, mrr.rrval );
    ia64_srlz_d();
    ia64_set_psr(psr);
    ia64_srlz_i();
    return;
}

static int mm_switch_action(IA64_PSR opsr, IA64_PSR npsr)
{
    return mm_switch_table[MODE_IND(opsr)][MODE_IND(npsr)];
}

void
switch_mm_mode(VCPU *vcpu, IA64_PSR old_psr, IA64_PSR new_psr)
{
    int act;
    REGS * regs=vcpu_regs(vcpu);
    act = mm_switch_action(old_psr, new_psr);
    switch (act) {
    case SW_V2P:
        vcpu->arch.old_rsc = regs->ar_rsc;
        switch_to_physical_rid(vcpu);
        /*
         * Set rse to enforced lazy, to prevent active rse save/restor when
         * guest physical mode.
         */
        regs->ar_rsc &= ~(IA64_RSC_MODE);
        vcpu->arch.mode_flags |= GUEST_IN_PHY;
        break;
    case SW_P2V:
        switch_to_virtual_rid(vcpu);
        /*
         * recover old mode which is saved when entering
         * guest physical mode
         */
        regs->ar_rsc = vcpu->arch.old_rsc;
        vcpu->arch.mode_flags &= ~GUEST_IN_PHY;
        break;
    case SW_SELF:
        printf("Switch to self-0x%lx!!! MM mode doesn't change...\n",
            old_psr.val);
        break;
    case SW_NOP:
        printf("No action required for mode transition: (0x%lx -> 0x%lx)\n",
            old_psr.val, new_psr.val);
        break;
    default:
        /* Sanity check */
    printf("old: %lx, new: %lx\n", old_psr.val, new_psr.val);
        panic("Unexpected virtual <--> physical mode transition");
        break;
    }
    return;
}



/*
 * In physical mode, insert tc/tr for region 0 and 4 uses
 * RID[0] and RID[4] which is for physical mode emulation.
 * However what those inserted tc/tr wants is rid for
 * virtual mode. So original virtual rid needs to be restored
 * before insert.
 *
 * Operations which required such switch include:
 *  - insertions (itc.*, itr.*)
 *  - purges (ptc.* and ptr.*)
 *  - tpa
 *  - tak
 *  - thash?, ttag?
 * All above needs actual virtual rid for destination entry.
 */

void
check_mm_mode_switch (VCPU *vcpu,  IA64_PSR old_psr, IA64_PSR new_psr)
{

    if ( (old_psr.dt != new_psr.dt ) ||
         (old_psr.it != new_psr.it ) ||
         (old_psr.rt != new_psr.rt )
         ) {
        switch_mm_mode (vcpu, old_psr, new_psr);
    }

    return 0;
}


/*
 * In physical mode, insert tc/tr for region 0 and 4 uses
 * RID[0] and RID[4] which is for physical mode emulation.
 * However what those inserted tc/tr wants is rid for
 * virtual mode. So original virtual rid needs to be restored
 * before insert.
 *
 * Operations which required such switch include:
 *  - insertions (itc.*, itr.*)
 *  - purges (ptc.* and ptr.*)
 *  - tpa
 *  - tak
 *  - thash?, ttag?
 * All above needs actual virtual rid for destination entry.
 */

void
prepare_if_physical_mode(VCPU *vcpu)
{
    if (is_physical_mode(vcpu))
        switch_to_virtual_rid(vcpu);
    return;
}

/* Recover always follows prepare */
void
recover_if_physical_mode(VCPU *vcpu)
{
    if (is_physical_mode(vcpu))
        switch_to_physical_rid(vcpu);
    return;
}

