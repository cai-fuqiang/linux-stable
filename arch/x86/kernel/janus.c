#include <asm/pvm_para.h>
#include <asm/setup.h>
#include <asm/cpuid.h>
#include <asm/kvm_para.h>
#include <asm/cpufeature.h>
#include <asm/janus.h>

void __init janus_early_setup(void)
{
	uint32_t eax, tmp[3];

	cpuid(KVM_CPUID_FEATURES, &eax, &tmp[0], &tmp[1], &tmp[2]);

	if (!(eax & (1 << KVM_FEATURE_JANUS_HYPER))) {
		return;
	}

	setup_force_cpu_cap(X86_FEATURE_KVM_JANUS_HYPER);
	pr_info("JANUS: detect JANUS [HYPER] feature\n");
	return;
}


#ifdef CONFIG_PVM_GUEST
void __init janus_guest_early_setup(void)
{
	uint32_t eax, tmp[3];

	eax = KVM_CPUID_FEATURES;

	tmp[1] = 0;
	pvm_cpuid(&eax, &tmp[0], &tmp[1], &tmp[2]);

	if ((eax & (1 << KVM_FEATURE_JANUS_GUEST)) &&
			boot_cpu_has(X86_FEATURE_KVM_PVM_GUEST)) {
		setup_force_cpu_cap(X86_FEATURE_KVM_JANUS_GUEST);
	}

	pr_info("JANUS: detect JANUS [GUEST] feature\n");
	return;
}
#endif
