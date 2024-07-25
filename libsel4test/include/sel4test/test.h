/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

/* Include Kconfig variables. */
#include <autoconf.h>
#include <sel4test/gen_config.h>

#include <sel4/sel4.h>

#include <utils/attribute.h>
#include <sel4test/testutil.h>
#include <vka/vka.h>
#include <vspace/vspace.h>
#include <sel4platsupport/timer.h>
#include <sync/mutex.h>
#include <sel4utils/elf.h>
#include <sel4rpc/client.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* max test name size */
#define TEST_NAME_MAX (64 - 4 * sizeof(seL4_Word))

#define MAX_REGIONS 4

/* various time units in nanoseconds, for sleep requests */
#define SECOND 1000000000UL

#define MILLISECOND 1000000UL

/* Contains information about the test environment for regular tests, bootstrap tests do
 * not use this environment */
struct env
{
    /* An initialised vka that may be used by the test. */
    vka_t vka;
    /* virtual memory management interface */
    vspace_t vspace;
    /* abstract interface over application init */
    simple_t simple;
    /* notification for timer */
    vka_object_t timer_notification;
    /* RPC client for serial server resource allocation */
    sel4rpc_client_t rpc_client;

    /* caps for the current process */
    seL4_CPtr cspace_root;
    seL4_CPtr page_directory;
    seL4_CPtr endpoint;
    seL4_CPtr tcb;
    seL4_CPtr timer_untyped;
    seL4_CPtr asid_pool;
    seL4_CPtr asid_ctrl;
    seL4_CPtr sched_ctrl;
#ifdef CONFIG_ALLOW_SMC_CALLS
    seL4_CPtr smc;
#endif /* CONFIG_ALLOW_SMC_CALLS */
#ifdef CONFIG_IOMMU
    seL4_CPtr io_space;
#endif /* CONFIG_IOMMU */
#ifdef CONFIG_TK1_SMMU
    seL4_SlotRegion io_space_caps;
#endif
    seL4_Word cores;
    seL4_CPtr domain;
    seL4_CPtr device_frame;

    int priority;
    int cspace_size_bits;
    int num_regions;
    sel4utils_elf_region_t regions[MAX_REGIONS];

    /* irq handler for test process */
    seL4_CPtr irq_handler;

    /* endpoint for OSmosis IPC benchmarks */
    seL4_CPtr ipc_bench_ep;
};
typedef struct env *env_t;

/* Prototype of a test function. Returns false on failure. */
typedef int (*test_fn)(uintptr_t environment);

/* Test type definitions. */
typedef enum test_type_name
{
    BOOTSTRAP = 0,
    BASIC,
    OSM
} test_type_name_t;
typedef struct testcase testcase_t; // Forward type declaration.
typedef struct test_type
{
    /* Represents a single test type. See comment for `struct testcase` for info about ALIGN(32). */
    const char *name;
    test_type_name_t id;
    // Function called before and after all the tests for this test type have been run.
    void (*set_up_test_type)(uintptr_t e);
    void (*tear_down_test_type)(uintptr_t e);
    // Function called before and after each test for this test type.
    void (*set_up)(uintptr_t e);
    void (*tear_down)(uintptr_t e);
    // Run the test. Different tests take different environments
    test_result_t (*run_test)(struct testcase *test, uintptr_t e);
} ALIGN(32) test_type_t;

/* Declare a test type.
 * For now, we put the test types in a separate elf section. */
#define DEFINE_TEST_TYPE(_name, _id, _set_up_test_type, _tear_down_test_type, _set_up, _tear_down, _run_test) \
    __attribute__((used)) __attribute__((section("_test_type"))) struct test_type TEST_TYPE_##_name = {       \
        .name = #_name,                                                                                       \
        .id = _id,                                                                                            \
        .set_up_test_type = _set_up_test_type,                                                                \
        .tear_down_test_type = _tear_down_test_type,                                                          \
        .set_up = _set_up,                                                                                    \
        .tear_down = _tear_down,                                                                              \
        .run_test = _run_test,                                                                                \
    };

/* Represents a single testcase.
 * Because this struct is used to declare variables that get
 * placed into custom sections, that we later treat as an array,
 * we need to make sure the struct is aligned and filled to the
 * nearest power of two to avoid gcc placing arbitrary padding between them.
 *
 * The declaration below ensures that the actual size of
 * the objects in the section is the same as the size reported
 * by sizeof(struct testcase), allowing as to treat the items
 * in the section as an array */
struct testcase
{
    char name[TEST_NAME_MAX];
    const char *description;
    test_fn function;
    seL4_Word test_type;
    seL4_Word enabled;
} PACKED;
typedef struct testcase ALIGN(sizeof(struct testcase)) testcase_t;

/* Declare a testcase.
 * Must be declared using C89 style (#_name, _desc, _func...) instead of
 * C99 style (name = _name, desc = _desc, func = _func...) to make sure
 * that it is accepted by C++ compilers.
 */
#define DEFINE_TEST_WITH_TYPE(_name, _description, _function, _test_type, _enabled)               \
    __attribute__((used)) __attribute__((section("_test_case"))) struct testcase TEST_##_name = { \
        #_name,                                                                                   \
        _description,                                                                             \
        (test_fn)_function,                                                                       \
        _test_type,                                                                               \
        _enabled,                                                                                 \
    };

#define DEFINE_TEST(_name, _description, _function, _enabled) DEFINE_TEST_WITH_TYPE(_name, _description, _function, BASIC, _enabled)

#define DEFINE_TEST_BOOTSTRAP(_name, _description, _function, _enabled) DEFINE_TEST_WITH_TYPE(_name, _description, _function, BOOTSTRAP, _enabled)

#define DEFINE_TEST_OSM(_name, _description, _function, _enabled) DEFINE_TEST_WITH_TYPE(_name, _description, _function, OSM, _enabled)

/* Repeat a testcase 500 times */

#define DEFINE_TEST_WITH_TYPE_MULTIPLE(_name, _description, _function, _type, _enabled) \
DEFINE_TEST_WITH_TYPE(_name##_##001, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##002, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##003, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##004, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##005, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##006, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##007, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##008, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##009, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##010, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##011, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##012, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##013, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##014, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##015, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##016, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##017, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##018, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##019, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##020, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##021, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##022, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##023, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##024, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##025, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##026, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##027, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##028, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##029, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##030, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##031, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##032, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##033, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##034, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##035, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##036, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##037, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##038, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##039, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##040, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##041, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##042, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##043, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##044, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##045, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##046, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##047, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##048, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##049, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##050, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##051, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##052, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##053, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##054, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##055, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##056, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##057, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##058, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##059, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##060, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##061, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##062, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##063, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##064, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##065, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##066, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##067, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##068, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##069, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##070, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##071, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##072, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##073, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##074, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##075, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##076, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##077, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##078, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##079, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##080, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##081, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##082, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##083, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##084, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##085, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##086, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##087, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##088, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##089, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##090, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##091, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##092, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##093, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##094, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##095, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##096, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##097, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##098, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##099, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##100, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##101, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##102, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##103, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##104, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##105, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##106, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##107, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##108, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##109, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##110, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##111, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##112, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##113, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##114, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##115, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##116, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##117, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##118, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##119, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##120, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##121, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##122, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##123, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##124, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##125, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##126, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##127, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##128, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##129, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##130, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##131, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##132, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##133, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##134, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##135, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##136, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##137, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##138, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##139, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##140, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##141, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##142, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##143, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##144, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##145, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##146, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##147, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##148, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##149, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##150, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##151, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##152, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##153, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##154, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##155, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##156, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##157, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##158, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##159, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##160, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##161, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##162, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##163, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##164, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##165, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##166, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##167, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##168, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##169, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##170, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##171, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##172, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##173, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##174, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##175, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##176, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##177, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##178, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##179, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##180, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##181, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##182, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##183, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##184, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##185, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##186, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##187, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##188, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##189, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##190, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##191, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##192, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##193, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##194, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##195, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##196, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##197, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##198, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##199, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##201, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##202, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##203, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##204, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##205, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##206, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##207, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##208, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##209, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##210, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##211, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##212, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##213, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##214, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##215, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##216, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##217, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##218, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##219, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##220, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##221, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##222, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##223, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##224, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##225, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##226, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##227, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##228, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##229, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##230, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##231, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##232, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##233, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##234, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##235, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##236, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##237, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##238, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##239, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##240, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##241, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##242, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##243, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##244, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##245, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##246, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##247, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##248, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##249, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##250, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##251, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##252, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##253, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##254, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##255, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##256, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##257, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##258, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##259, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##260, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##261, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##262, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##263, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##264, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##265, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##266, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##267, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##268, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##269, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##270, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##271, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##272, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##273, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##274, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##275, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##276, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##277, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##278, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##279, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##280, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##281, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##282, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##283, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##284, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##285, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##286, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##287, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##288, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##289, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##290, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##291, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##292, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##293, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##294, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##295, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##296, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##297, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##298, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##299, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##300, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##301, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##302, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##303, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##304, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##305, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##306, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##307, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##308, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##309, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##310, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##311, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##312, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##313, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##314, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##315, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##316, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##317, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##318, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##319, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##320, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##321, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##322, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##323, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##324, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##325, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##326, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##327, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##328, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##329, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##330, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##331, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##332, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##333, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##334, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##335, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##336, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##337, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##338, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##339, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##340, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##341, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##342, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##343, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##344, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##345, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##346, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##347, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##348, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##349, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##350, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##351, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##352, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##353, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##354, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##355, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##356, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##357, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##358, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##359, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##360, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##361, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##362, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##363, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##364, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##365, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##366, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##367, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##368, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##369, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##370, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##371, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##372, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##373, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##374, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##375, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##376, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##377, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##378, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##379, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##380, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##381, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##382, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##383, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##384, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##385, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##386, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##387, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##388, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##389, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##390, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##391, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##392, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##393, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##394, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##395, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##396, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##397, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##398, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##399, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##400, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##401, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##402, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##403, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##404, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##405, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##406, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##407, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##408, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##409, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##410, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##411, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##412, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##413, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##414, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##415, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##416, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##417, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##418, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##419, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##420, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##421, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##422, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##423, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##424, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##425, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##426, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##427, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##428, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##429, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##430, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##431, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##432, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##433, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##434, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##435, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##436, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##437, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##438, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##439, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##440, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##441, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##442, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##443, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##444, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##445, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##446, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##447, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##448, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##449, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##450, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##451, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##452, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##453, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##454, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##455, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##456, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##457, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##458, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##459, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##460, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##461, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##462, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##463, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##464, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##465, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##466, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##467, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##468, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##469, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##470, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##471, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##472, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##473, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##474, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##475, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##476, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##477, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##478, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##479, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##480, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##481, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##482, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##483, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##484, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##485, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##486, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##487, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##488, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##489, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##490, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##491, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##492, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##493, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##494, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##495, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##496, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##497, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##498, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##499, _description, _function, _type, _enabled)      \
    DEFINE_TEST_WITH_TYPE(_name##_##500, _description, _function, _type, _enabled)      \


/**/

/* Definitions so that we can find the test types */
extern struct test_type __start__test_type[];
extern struct test_type __stop__test_type[];

/* Definitions so that we can find the test cases */
extern testcase_t __start__test_case[];
extern testcase_t __stop__test_case[];

static inline int test_type_comparator(const void *a, const void *b)
{
    const struct test_type **ta = (const struct test_type **)a;
    const struct test_type **tb = (const struct test_type **)b;
    if ((*ta)->id > (*tb)->id)
    {
        return 1;
    }
    else if ((*ta)->id < (*tb)->id)
    {
        return -1;
    }

    return 0;
}

static inline int test_comparator(const void *a, const void *b)
{
    const struct testcase **ta = (const struct testcase **)a;
    const struct testcase **tb = (const struct testcase **)b;
    return strcmp((*ta)->name, (*tb)->name);
}

/* Fails a test case, stop running the rest of the test, but keep running other tests. */
static inline test_result_t _test_fail(const char *condition, const char *file, int line)
{
    _sel4test_failure(condition, file, line);
    return FAILURE;
}

/* Fails a test case, keep running the rest of the test, then keep running other tests. */
static inline void _test_error(const char *condition, const char *file, int line)
{

    _sel4test_report_error(condition, file, line);
}

/* Fails a test case, stop everything. */
static inline test_result_t _test_abort(const char *condition, const char *file, int line)
{
    _sel4test_failure(condition, file, line);
    return ABORT;
}

static inline void print_error_in_ipc(seL4_Error e)
{
#ifdef CONFIG_KERNEL_INVOCATION_REPORT_ERROR_IPC
    // If it hasnt been printed already
    if (!seL4_CanPrintError() && e != seL4_NoError)
    {
        printf("%s", seL4_GetDebugError());
    }
#endif
}

#define test_error_eq(e, c)                        \
    if (!((e) == (c)))                             \
    {                                              \
        print_error_in_ipc(e);                     \
        return _test_fail(#e, __FILE__, __LINE__); \
    }
#define test_assert(e) \
    if (!(e))          \
    return _test_fail(#e, __FILE__, __LINE__)
#define test_check(e) \
    if (!(e))         \
    _test_error(#e, __FILE__, __LINE__)
#define test_assert_fatal(e) \
    if (!(e))                \
    return _test_abort(#e, __FILE__, __LINE__)

#define __TEST_BUFFER_SIZE 200
#define test_op_type(a, b, op, t, name_a, name_b, cast)                         \
    do                                                                          \
    {                                                                           \
        if (!(a op b))                                                          \
        {                                                                       \
            int len = snprintf(NULL, 0, "Check %s(" t ") %s %s(" t ") failed.", \
                               #name_a, (cast)a, #op, #name_b, (cast)b) +       \
                      1;                                                        \
            char buffer[len];                                                   \
            snprintf(buffer, len, "Check %s(" t ") %s %s(" t ") failed.",       \
                     #name_a, (cast)a, #op, #name_b, (cast)b);                  \
            _test_error(buffer, __FILE__, __LINE__);                            \
        }                                                                       \
    } while (0)

#define test_op(a, b, op)                                                                                     \
    do                                                                                                        \
    {                                                                                                         \
        typeof(a) _a = (a);                                                                                   \
        typeof(b) _b = (b);                                                                                   \
        if (sizeof(_a) != sizeof(_b))                                                                         \
        {                                                                                                     \
            int len = snprintf(NULL, 0, "%s (size %zu) != %s (size %zu), use of test_eq incorrect", #a,       \
                               sizeof(_a), #b, sizeof(_b)) +                                                  \
                      1;                                                                                      \
            char buffer[len];                                                                                 \
            snprintf(buffer, len, "%s (size %zu) != %s (size %zu), use of test_eq incorrect", #a, sizeof(_a), \
                     #b, sizeof(_b));                                                                         \
            _test_error(buffer, __FILE__, __LINE__);                                                          \
        }                                                                                                     \
        else if (TYPES_COMPATIBLE(typeof(_a), int))                                                           \
        {                                                                                                     \
            test_op_type(_a, _b, op, "%d", a, b, int);                                                        \
        }                                                                                                     \
        else if (TYPES_COMPATIBLE(typeof(_a), long))                                                          \
        {                                                                                                     \
            test_op_type(_a, _b, op, "%ld", a, b, long);                                                      \
        }                                                                                                     \
        else if (TYPES_COMPATIBLE(typeof(_a), long long))                                                     \
        {                                                                                                     \
            test_op_type(_a, _b, op, "%lld", a, b, long long);                                                \
        }                                                                                                     \
        else if (TYPES_COMPATIBLE(typeof(_a), unsigned int))                                                  \
        {                                                                                                     \
            test_op_type(_a, _b, op, "%u", a, b, unsigned int);                                               \
        }                                                                                                     \
        else if (TYPES_COMPATIBLE(typeof(_a), unsigned long))                                                 \
        {                                                                                                     \
            test_op_type(_a, _b, op, "%lu", a, b, unsigned long);                                             \
        }                                                                                                     \
        else if (TYPES_COMPATIBLE(typeof(_a), unsigned long long))                                            \
        {                                                                                                     \
            test_op_type(_a, _b, op, "%llu", a, b, unsigned long long);                                       \
        }                                                                                                     \
        else if (TYPES_COMPATIBLE(typeof(_a), char))                                                          \
        {                                                                                                     \
            test_op_type(_a, _b, op, "%c", a, b, char);                                                       \
        }                                                                                                     \
        else if (TYPES_COMPATIBLE(typeof(_a), uintptr_t))                                                     \
        {                                                                                                     \
            test_op_type(_a, _b, op, "0x%" PRIxPTR, a, b, uintptr_t);                                         \
        }                                                                                                     \
        else                                                                                                  \
        {                                                                                                     \
            _test_error("Cannot use test_op on this type", __FILE__, __LINE__);                               \
        }                                                                                                     \
    } while (0)

/* Pretty printed test_check wrapper macros for basic comparisons on base types,
 * which output the values and variable names to aid debugging */
#define test_eq(a, b) test_op(a, b, ==)
#define test_neq(a, b) test_op(a, b, !=)
#define test_gt(a, b) test_op(a, b, >)
#define test_geq(a, b) test_op(a, b, >=)
#define test_lt(a, b) test_op(a, b, <)
#define test_leq(a, b) test_op(a, b, <=)

#define __TEST_MAX_STRING 50
#define test_strop(a, b, op)                                                                \
    do                                                                                      \
    {                                                                                       \
        if (strnlen(a, __TEST_MAX_STRING) == __TEST_MAX_STRING)                             \
        {                                                                                   \
            _test_error("String " #a " too long for test_str* macros", __FILE__, __LINE__); \
        }                                                                                   \
        else if (strnlen(b, __TEST_MAX_STRING) == __TEST_MAX_STRING)                        \
        {                                                                                   \
            _test_error("String " #b " too long for test_str* macros", __FILE__, __LINE__); \
        }                                                                                   \
        else if (!(strncmp(a, b, __TEST_MAX_STRING))op 0)                                   \
        {                                                                                   \
            char buffer[__TEST_BUFFER_SIZE + 2 * __TEST_MAX_STRING];                        \
            snprintf(buffer, sizeof(buffer),                                                \
                     "Check %s(%s) %s %s(%s) failed.", #a, a, #op, #b, b);                  \
            _test_error(buffer, __FILE__, __LINE__);                                        \
        }                                                                                   \
    } while (0)

/* Pretty printed test_check wrapper macros for basic comparisons on c strings,
 * which output the values and variable names to aid debugging */
#define test_streq(a, b) test_strop(a, b, ==)
#define test_strneq(a, b) test_strop(a, b, !=)
#define test_strge(a, b) test_strop(a, b, >)
#define test_strgeq(a, b) test_strop(a, b, >=)
#define test_strle(a, b) test_strop(a, b, <)
#define test_strleq(a, b) test_strop(a, b, <=)

env_t sel4test_get_env(void);
