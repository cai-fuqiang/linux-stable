#include "janus.h"
#include <linux/kvm_host.h>

bool enable_janus = false;
EXPORT_SYMBOL_GPL(enable_janus);

int handle_vmfunc_janus(struct kvm_vcpu *vcpu)
{
	u32 function = kvm_rax_read(vcpu);
	u32 eptp_index;

	if (function > 63 && !(is_supported_janus())) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	if (function != 0) {

		/*
		 * Intel sdm specifies that invoking an unsupported function
		 * will cause a VM-exit, but it does not define which exception
		 * should be injected if the hypervisor cannot handle it
		 * either.
		 *
		 * Therefore, we simply inject a GP exception here.
		 */
		kvm_queue_exception(vcpu, GP_VECTOR);
		return 1;
	}
	eptp_index = kvm_rcx_read(vcpu) & 0xffff;
	pr_info("DUMMY PRINT: switching EPTP index is %u\n", eptp_index);

	return kvm_skip_emulated_instruction(vcpu);
}
EXPORT_SYMBOL_GPL(handle_vmfunc_janus);
