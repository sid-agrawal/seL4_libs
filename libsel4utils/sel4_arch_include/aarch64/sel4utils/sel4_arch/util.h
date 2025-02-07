/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>
#include <utils/arith.h>

#define ARCH_SYSCALL_INSTRUCTION_SIZE 4

static inline int
sel4utils_is_read_fault(void)
{
    seL4_Word fsr = seL4_GetMR(seL4_VMFault_FSR);
    return (fsr & (BIT(6))) == 0;
}

static inline void
sel4utils_set_instruction_pointer(seL4_UserContext *regs, seL4_Word value)
{
    regs->pc = value;
}

static inline seL4_Word
sel4utils_get_instruction_pointer(seL4_UserContext regs)
{
    return regs.pc;
}

static inline void
sel4utils_set_stack_pointer(seL4_UserContext *regs, seL4_Word value)
{
    regs->sp = value;
}

static inline void
sel4utils_set_arg0(seL4_UserContext *regs, seL4_Word value)
{
    regs->x0 = value;
}

static inline void
sel4utils_set_arg1(seL4_UserContext *regs, seL4_Word value)
{
    regs->x1 = value;
}

static inline seL4_Word
sel4utils_get_sp(seL4_UserContext regs)
{
    return regs.sp;
}

