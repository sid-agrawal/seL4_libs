/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <autoconf.h>
#include <sel4utils/gen_config.h>
#include <sel4/types.h>
#include <sel4utils/thread.h>
#include <sel4utils/helpers.h>
#include <utils/zf_log.h>
#include <utils/stack.h>
#include <stdbool.h>

int sel4utils_arch_init_context(void *entry_point, void *stack_top, seL4_UserContext *context)
{
    context->pc = (seL4_Word) entry_point;
    context->sp = (seL4_Word) stack_top;
    if (!IS_ALIGNED((uintptr_t)stack_top, STACK_CALL_ALIGNMENT_BITS)) {
        ZF_LOGE("Initial stack pointer must be %d byte aligned", STACK_CALL_ALIGNMENT);
        return -1;
    }
    return 0;
}

int sel4utils_arch_init_context_with_args(sel4utils_thread_entry_fn entry_point,
                                          void *arg0, void *arg1, void *arg2,
                                          bool local_stack, void *stack_top,
                                          seL4_UserContext *context,
                                          vka_t *vka, vspace_t *local_vspace, vspace_t *remote_vspace)
{

    context->x0 = (seL4_Word) arg0;
    context->x1 = (seL4_Word) arg1;
    context->x2 = (seL4_Word) arg2;

    return sel4utils_arch_init_context(entry_point, stack_top, context);
}

int sel4utils_arch_init_context_tls_base(seL4_UserContext *context, void *tls_base)
{
    context->tpidr_el0 = (seL4_Word)tls_base;

    return 0;
}

int sel4utils_arch_init_context_guest(uintptr_t kernel_pc, uintptr_t kernel_dtb, seL4_UserContext *context)
{
    context->x0 = (seL4_Word)kernel_dtb;
    context->spsr = 5; // PMODE_EL1h
    context->pc = (seL4_Word)kernel_pc;

    return 0;
}

int sel4utils_arch_set_context_type(seL4_Word type, seL4_UserContext *context)
{
    context->x1 = type;

    return 0;
}
