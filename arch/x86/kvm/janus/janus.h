#ifndef _KVM_X86_JANUS_H
#define _KVM_X86_JANUS_H
#include "mmu.h"
#include <linux/kvm_host.h>
#include "../mmu/mmu_internal.h"

extern bool enable_janus;
static inline bool is_supported_janus(void)
{
	return !!(enable_janus);
}

static inline void set_janus_enable(void)
{
	enable_janus = true;
}

int handle_vmfunc_janus(struct kvm_vcpu *vcpu);
unsigned long janus_hypercall(struct kvm_vcpu *vcpu, unsigned long a0,
				      unsigned long a1, unsigned long a2,
				      unsigned long a3);
int kvm_janus_init_vm(struct kvm *kvm);
void kvm_janus_uninit_vm(struct kvm *kvm);
int kvm_janus_pre_handle_ept_violation(struct kvm_vcpu *vcpu,
				       u64 error_code,
				       gpa_t gpa);

#define janus_debug_fault(fault, ...)			\
	do {						\
		if (!fault->is_janus_map)		\
			break;				\
		pr_info(__VA_ARGS__);			\
	} while(0);

#endif
