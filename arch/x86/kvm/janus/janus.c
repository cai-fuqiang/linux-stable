#include "janus.h"
#include <linux/kvm_host.h>
#include <linux/kvm_para.h>
#include <linux/spinlock.h>
#include <asm/kvm_host.h>
#include <linux/list.h>
#include <linux/bitmap.h>

bool enable_janus = false;
EXPORT_SYMBOL_GPL(enable_janus);

#define JANUS_EPTP_INDEX_MAX	512
#define JANUS_EPTP_HASH_NUM	64

struct janus_ept_root {
	unsigned int index;
	struct kvm_mmu_page *root_page;
	struct hlist_node node;
};

struct kvm_janus {
	spinlock_t lock;
	int num;
	DECLARE_BITMAP(eptp_index_unused, JANUS_EPTP_INDEX_MAX);
	struct hlist_head hash_head[JANUS_EPTP_HASH_NUM];
};

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


unsigned long janus_hypercall(struct kvm_vcpu *vcpu, unsigned long a0,
				      unsigned long a1, unsigned long a2,
				      unsigned long a3)
{
	unsigned long function = a0;
	int ret = -KVM_ENOSYS;

	if (!is_supported_janus()) {
		return ret;
	}

	switch(function) {
	case KVM_HC_JANUS_CRAETE:
	case KVM_HC_JANUS_DESTROY:
	case KVM_HC_JANUS_MAP:
	case KVM_HC_JANUS_UNMAP:
	case KVM_HC_JANUS_CHECK:
		ret = 0;
		pr_info("JANUS DUMMY: janus hypercall function %lu\n", function);
		break;
	}

	return ret;
}

int kvm_janus_init_vm(struct kvm *kvm)
{
	struct kvm_janus *kvm_janus;
	struct kvm_arch *kvm_arch = &kvm->arch;
	int i;

	int ret = 0;

	if (!is_supported_janus()) {
		return ret;
	}

	kvm_janus = kmalloc(sizeof(*kvm_janus), GFP_KERNEL);
	if (!kvm_janus) {
		ret = -ENOMEM;
		return ret;
	}

	for (i = 0; i < JANUS_EPTP_HASH_NUM; i++) {
		INIT_HLIST_HEAD(&kvm_janus->hash_head[i]);
	}

	spin_lock_init(&kvm_janus->lock);
	kvm_janus->num = 0;
	bitmap_fill(kvm_janus->eptp_index_unused, JANUS_EPTP_INDEX_MAX);

	kvm_arch->janus = kvm_janus;

	return 0;
}

void kvm_janus_uninit_vm(struct kvm *kvm)
{
	struct kvm_janus *kvm_janus = kvm->arch.janus;
	BUG_ON(kvm_janus->num);

	kfree(kvm_janus);
	kvm->arch.janus = NULL;
}
