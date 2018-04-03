#ifndef _SVM_AVIC_H_
#define _SVM_AVIC_H_

#include <xen/compiler.h>

enum avic_incmp_ipi_err_code {
    AVIC_INCMP_IPI_ERR_INVALID_INT_TYPE,
    AVIC_INCMP_IPI_ERR_TARGET_NOT_RUN,
    AVIC_INCMP_IPI_ERR_INV_TARGET,
    AVIC_INCMP_IPI_ERR_INV_BK_PAGE,
};

struct __packed avic_logical_id_entry {
    u32 guest_phy_apic_id : 8;
    u32 res               : 23;
    u32 valid             : 1;
};

union avic_physical_id_entry {
    u64 raw;
    struct __packed physical_id {
        u64 host_phy_apic_id  : 8;
        u64 res1              : 4;
        u64 bk_pg_ptr_mfn     : 40;
        u64 res2              : 10;
        u64 is_running        : 1;
        u64 valid             : 1;
    } phy_id_entry;
};

extern bool svm_avic;

int svm_avic_dom_init(struct domain *d);
void svm_avic_dom_destroy(struct domain *d);

bool svm_avic_vcpu_enabled(const struct vcpu *v);
int svm_avic_init_vmcb(struct vcpu *v);

void svm_avic_vmexit_do_incomp_ipi(struct cpu_user_regs *regs);
void svm_avic_vmexit_do_noaccel(struct cpu_user_regs *regs);

#endif /* _SVM_AVIC_H_ */
