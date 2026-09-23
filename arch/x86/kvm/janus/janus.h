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
