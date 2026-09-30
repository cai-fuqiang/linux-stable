#include "janus.h"
#include <linux/kvm_host.h>
#include <linux/kvm_para.h>
#include <linux/spinlock.h>
#include <asm/kvm_host.h>
#include <linux/list.h>
#include <linux/bitmap.h>
#include "../mmu/mmu_internal.h"
#include "../mmu/spte.h"
#include "../mmu/tdp_mmu.h"

bool enable_janus = false;
EXPORT_SYMBOL_GPL(enable_janus);

#define JANUS_EPTP_NUM_MAX	(512)
#define JANUS_EPTP_INDEX_MAX	(JANUS_EPTP_NUM_MAX - 1)

struct kvm_janus {
	DECLARE_BITMAP(eptp_index_unused, JANUS_EPTP_NUM_MAX);
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

static union kvm_mmu_page_role
kvm_calc_janus_mmu_root_page_role(struct kvm_vcpu *vcpu,
				  u16 index)
{
	union kvm_mmu_page_role root_role = {0};

	root_role.access = ACC_ALL;
	root_role.cr0_wp = true;
	root_role.efer_nx = true;
	root_role.smm = 0;
	root_role.guest_mode = false;
	root_role.ad_disabled = !kvm_ad_enabled();
	root_role.level = kvm_mmu_get_tdp_level(vcpu);
	root_role.direct = true;
	root_role.has_4_byte_gpte = false;
	root_role.janus_index = index;
	root_role.janus = true;
	return root_role;
}

static int kvm_janus_mmu_alloc_root(struct kvm_vcpu *vcpu, u16 index)
{
	union kvm_mmu_page_role root_role = kvm_calc_janus_mmu_root_page_role(vcpu, index);
	struct kvm_mmu_page *root_page;
	int ret;

	ret = __kvm_tdp_mmu_alloc_root(vcpu, root_role, &root_page);

	if (ret == 0)
		kvm_tdp_mmu_put_root(vcpu->kvm, root_page);

	return ret;
}


static int kvm_hc_janus_create(struct kvm_vcpu *vcpu)
{
	struct kvm_janus *janus = vcpu->kvm->arch.janus;
	u16 janus_index = 0;
	int ret = -KVM_EINVAL;

	BUG_ON(!janus);

retry:
	janus_index = find_next_bit(janus->eptp_index_unused, JANUS_EPTP_NUM_MAX, 0);

	pr_info("get janus index is %d\n", janus_index);

	if (janus_index == JANUS_EPTP_NUM_MAX)
		return ret;

	if (!test_and_clear_bit(janus_index, janus->eptp_index_unused)) {
		goto retry;
	}

	ret = kvm_janus_mmu_alloc_root(vcpu, janus_index);

	if (ret < 0)
		goto restore_index_bitmap;
	return 0;
restore_index_bitmap:
	set_bit(janus_index, janus->eptp_index_unused);
	return ret;
}

static void kvm_janus_mmu_zap_root(struct kvm_vcpu *vcpu, u16 janus_index)
{

	union kvm_mmu_page_role root_role =
		kvm_calc_janus_mmu_root_page_role(vcpu,janus_index);
	struct kvm *kvm = vcpu->kvm;

	write_lock(&vcpu->kvm->mmu_lock);
	kvm_tdp_mmu_zap_role(kvm, &root_role);
	write_unlock(&vcpu->kvm->mmu_lock);
}

static int kvm_hc_janus_delete(struct kvm_vcpu *vcpu, u16 janus_index)
{
	struct kvm_janus *janus = vcpu->kvm->arch.janus;
	int ret = -KVM_EINVAL;

	if (test_and_set_bit(janus_index, janus->eptp_index_unused)) {
		return ret;
	}

	kvm_janus_mmu_zap_root(vcpu, janus_index);
	return 0;
}
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
	case KVM_HC_JANUS_CREATE:
		ret = kvm_hc_janus_create(vcpu);
		break;
	case KVM_HC_JANUS_DESTROY:
		ret = -KVM_EINVAL;
		if (a1 == 0 || a1 > JANUS_EPTP_INDEX_MAX)
			break;
		ret = kvm_hc_janus_delete(vcpu, a1);
		break;
	case KVM_HC_JANUS_MAP:
		ret = -KVM_EINVAL;
		gfn_t gfn_l1;
		gfn_t gfn_l2;
		u16 janus_index;
		u16 access_mask;

		gfn_l1 = a1 >> 12;
		gfn_l2 = a2 >> 12;
		janus_index = a1 & ((1 << 12) - 1);
		access_mask = a2 & ((1 << 12) - 1);

		if (janus_index == 0 || janus_index > JANUS_EPTP_INDEX_MAX)
			break;
		ret = kvm_hc_map_range(vcpu, gfn_l1, gfn_l2, janus_index, access_mask);
		break;
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
	int ret = 0;

	if (!is_supported_janus()) {
		return ret;
	}

	kvm_janus = kmalloc(sizeof(*kvm_janus), GFP_KERNEL);
	if (!kvm_janus) {
		ret = -ENOMEM;
		return ret;
	}

	bitmap_fill(kvm_janus->eptp_index_unused, JANUS_EPTP_NUM_MAX);

	/* 0 use for L1 eptp */
	clear_bit(0, kvm_janus->eptp_index_unused);

	kvm_arch->janus = kvm_janus;

	return 0;
}

void kvm_janus_uninit_vm(struct kvm *kvm)
{
	struct kvm_janus *kvm_janus = kvm->arch.janus;
	kfree(kvm_janus);
	kvm->arch.janus = NULL;
}
