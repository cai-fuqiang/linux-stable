#ifndef _KVM_X86_JANUS_H
#define _KVM_X86_JANUS_H
#include "mmu.h"
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
#endif
