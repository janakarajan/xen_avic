#ifndef _SVM_AVIC_H_
#define _SVM_AVIC_H_

#include <xen/types.h>

#define IS_RUNNING_BIT 62

/* Values for domains ->arch.hvm.pi_ops.flags */
#define PI_CSW_FROM   (1u << 0)
#define PI_CSW_TO     (1u << 1)
#define PI_CSW_BLOCK  (1u << 2)
#define PI_CSW_RESUME (1u << 3)

enum avic_incmp_ipi_err_code {
    AVIC_INCMP_IPI_ERR_INVALID_INT_TYPE,
    AVIC_INCMP_IPI_ERR_TARGET_NOT_RUN,
    AVIC_INCMP_IPI_ERR_INV_TARGET,
    AVIC_INCMP_IPI_ERR_INV_BK_PAGE,
};

typedef union avic_logical_id_entry {
    uint32_t raw;
    struct __packed {
        uint32_t guest_phy_apic_id : 8;
        uint32_t res               : 23;
        uint32_t valid             : 1;
    };
} avic_logical_id_entry_t;

typedef union avic_physical_id_entry {
    uint64_t raw;
    struct __packed {
        uint64_t host_phy_apic_id  : 8;
        uint64_t res1              : 4;
        uint64_t bk_pg_ptr_mfn     : 40;
        uint64_t res2              : 10;
        uint64_t is_running        : 1;
        uint64_t valid             : 1;
    };
} avic_physical_id_entry_t;

extern bool svm_avic;

int svm_avic_dom_init(struct domain *d);
void svm_avic_dom_destroy(struct domain *d);

bool svm_avic_vcpu_enabled(const struct vcpu *v);
int svm_avic_init_vmcb(struct vcpu *v);

void svm_avic_vmexit_do_incomp_ipi(struct cpu_user_regs *regs);
void svm_avic_vmexit_do_noaccel(struct cpu_user_regs *regs);

void avic_vcpu_unload(struct vcpu *v);
void avic_vcpu_load(struct vcpu *v);
void avic_vcpu_block(struct vcpu *v);
void avic_vcpu_resume(struct vcpu *v);

#endif /* _SVM_AVIC_H_ */
