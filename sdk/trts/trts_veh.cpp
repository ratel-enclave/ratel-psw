/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


/**
 * File: trts_veh.cpp
 * Description:
 *     This file implements the support of custom exception handling.
 */

#include "sgx_trts_exception.h"
#include <stdlib.h>
#include <string.h>
#include "sgx_trts.h"
#include "xsave.h"
#include "arch.h"
#include "sgx_spinlock.h"
#include "thread_data.h"
#include "global_data.h"
#include "trts_internal.h"
#include "trts_inst.h"
#include "util.h"
#include "trts_util.h"

/* Begin: Added by Pinghai */
#define SIGILL      4
#define SIGABRT     6
#define SIGFPE      8
#define SIGSEGV     11
#define SIGBUS      10
#define SIGSYS      12
#define SIGTRAP     5
/* End: Added by Pinghai */

typedef struct _handler_node_t
{
    uintptr_t callback;
    struct _handler_node_t   *next;
} handler_node_t;

static handler_node_t *g_first_node = NULL;
static sgx_spinlock_t g_handler_lock = SGX_SPINLOCK_INITIALIZER;

static uintptr_t g_veh_cookie = 0;
#define ENC_VEH_POINTER(x)  (uintptr_t)(x) ^ g_veh_cookie
#define DEC_VEH_POINTER(x)  (sgx_exception_handler_t)((x) ^ g_veh_cookie)


// sgx_register_exception_handler()
//      register a custom exception handler
// Parameter
//      is_first_handler - the order in which the handler should be called.
// if the parameter is nonzero, the handler is the first handler to be called.
// if the parameter is zero, the handler is the last handler to be called.
//      exception_handler - a pointer to the handler to be called.
// Return Value
//      handler - success
//         NULL - fail
void *sgx_register_exception_handler(int is_first_handler, sgx_exception_handler_t exception_handler)
{
    // initialize g_veh_cookie for the first time sgx_register_exception_handler is called.
    if(unlikely(g_veh_cookie == 0))
    {
        uintptr_t rand = 0;
        do
        {
            if(SGX_SUCCESS != sgx_read_rand((unsigned char *)&rand, sizeof(rand)))
            {
                return NULL;
            }
        } while(rand == 0);

        sgx_spin_lock(&g_handler_lock);
        if(g_veh_cookie == 0)
        {
            g_veh_cookie = rand;
        }
        sgx_spin_unlock(&g_handler_lock);
    }
    if(!sgx_is_within_enclave((const void*)exception_handler, 0))
    {
        return NULL;
    }
    handler_node_t *node = (handler_node_t *)malloc(sizeof(handler_node_t));
    if(!node)
    {
        return NULL;
    }
    node->callback = ENC_VEH_POINTER(exception_handler);

    // write lock
    sgx_spin_lock(&g_handler_lock);

    if((g_first_node == NULL) || is_first_handler)
    {
        node->next = g_first_node;
        g_first_node = node;
    }
    else
    {
        handler_node_t *tmp = g_first_node;
        while(tmp->next != NULL)
        {
            tmp = tmp->next;
        }
        node->next = NULL;
        tmp->next = node;
    }
    // write unlock
    sgx_spin_unlock(&g_handler_lock);

    return node;
}
// sgx_unregister_exception_handler()
//      unregister a custom exception handler.
// Parameter
//      handler - a handler to the custom exception handler previously
// registered using the sgx_register_exception_handler function.
// Return Value
//      none zero - success
//              0 - fail
int sgx_unregister_exception_handler(void *handler)
{
    if(!handler)
    {
        return 0;
    }

    int status = 0;

    // write lock
    sgx_spin_lock(&g_handler_lock);

    if(g_first_node)
    {
        handler_node_t *node = g_first_node;
        if(node == handler)
        {
            g_first_node = node->next;
            status = 1;
        }
        else
        {
            while(node->next != NULL)
            {
                if(node->next == handler)
                {
                    node->next = node->next->next;
                    status = 1;
                    break;
                }
                node = node->next;
            }
        }
    }
    // write unlock
    sgx_spin_unlock(&g_handler_lock);

    if(status) free(handler);
    return status;
}

// continue_execution(sgx_exception_info_t *info):
//      try to restore the thread context saved in info to current execution context.
extern "C" __attribute__((regparm(1))) void continue_execution(sgx_exception_info_t *info);

// internal_handle_exception(sgx_exception_info_t *info):
//      the 2nd phrase exception handing, which traverse registered exception handlers.
//      if the exception can be handled, then continue execution
//      otherwise, throw abortion, go back to 1st phrase, and call the default handler.
/* Begin: Modified by Pinghai */
/* sgxapp: false -> naive signals like SIGSEGV and SIGKILL; true -> communication signal like SIGALRM and SIGCHLD
 * The formmer is supported by vallina SGXSDK, the latter is introduced by SGX-DBI
 */
extern "C" __attribute__((regparm(1))) void _internal_handle_exception(sgx_exception_info_t *info, bool sgxapp)
{
    int status = EXCEPTION_CONTINUE_SEARCH;
    handler_node_t *node = NULL;
    thread_data_t *thread_data = get_thread_data();
    size_t size = 0;
    uintptr_t *nhead = NULL;
    uintptr_t *ntmp = NULL;
    uintptr_t xsp = 0;
    (void)sgxapp;

    if (thread_data->exception_flag < 0)
        goto failed_end;
    thread_data->exception_flag++;

    // read lock
    sgx_spin_lock(&g_handler_lock);

    node = g_first_node;
    while(node != NULL)
    {
        size += sizeof(uintptr_t);
        node = node->next;
    }

    // There's no exception handler registered
    if (size == 0)
    {
        sgx_spin_unlock(&g_handler_lock);

        //exception cannot be handled
        thread_data->exception_flag = -1;

        //instruction triggering the exception will be executed again.
        continue_execution(info);
    }

    if ((nhead = (uintptr_t *)malloc(size)) == NULL)
    {
        sgx_spin_unlock(&g_handler_lock);
        goto failed_end;
    }
    ntmp = nhead;
    node = g_first_node;
    while(node != NULL)
    {
        *ntmp = node->callback;
        ntmp++;
        node = node->next;
    }

    // read unlock
    sgx_spin_unlock(&g_handler_lock);

    // call exception handler until EXCEPTION_CONTINUE_EXECUTION is returned
    ntmp = nhead;
    while(size > 0)
    {
        sgx_exception_handler_t handler = DEC_VEH_POINTER(*ntmp);
        status = handler(info);
        if(EXCEPTION_CONTINUE_EXECUTION == status)
        {
            break;
        }
        ntmp++;
        size -= sizeof(sgx_exception_handler_t);
    }
    free(nhead);

    /* free the dynamically allocated memory */
    if (info->sigcxt_pkg != NULL)
    {
        free(info->sigcxt_pkg);
        info->sigcxt_pkg = NULL;
    }

    // call default handler
    // ignore invalid return value, treat to EXCEPTION_CONTINUE_SEARCH
    // check SP to be written on SSA is pointing to the trusted stack
    xsp = info->cpu_context.REG(sp);
    if (!is_valid_sp(xsp) && !sgxapp)
    {
        goto failed_end;
    }

    if(EXCEPTION_CONTINUE_EXECUTION == status)
    {
        //exception is handled, decrease the nested exception count
        thread_data->exception_flag--;
    }
    else
    {
        //exception cannot be handled
        thread_data->exception_flag = -1;
    }

    //instruction triggering the exception will be executed again.
    continue_execution(info);

failed_end:
    thread_data->exception_flag = -1; // mark the current exception cannot be handled
    abort();    // throw abortion
}
/* End: Modified by Pinghai */

/* Begin: Added by Pinghai */
/* A package stores all contxt information, compatible with DynamoRIO's sigframe_rt_t */
typedef struct _mcontext_t
{
    long long gregs[23];
    char fpregs[8];
    unsigned long long __reserved1[8];
} mcontext_t;

typedef struct _ucontext_t
{
    unsigned long uc_flags;
    struct _ucontext_t *uc_link;
    char uc_stack[24];
    mcontext_t uc_mcontext;
    char uc_sigmask[128];
    char __fpregs_mem[512];
} ucontext_t;

typedef struct _sigcxt_pkg_t
{
    int signum;
    ucontext_t ctx;
    char info[128];
} sigcxt_pkg_t;

/* refer to struct _kernel_sigcontext_t */
#define SIGCXT_R8 0
#define SIGCXT_R9 1
#define SIGCXT_R10 2
#define SIGCXT_R11 3
#define SIGCXT_R12 4
#define SIGCXT_R13 5
#define SIGCXT_R14 6
#define SIGCXT_R15 7
#define SIGCXT_RDI 8
#define SIGCXT_RSI 9
#define SIGCXT_RBP 10
#define SIGCXT_RBX 11
#define SIGCXT_RDX 12
#define SIGCXT_RAX 13
#define SIGCXT_RCX 14
#define SIGCXT_RSP 15
#define SIGCXT_RIP 16

extern "C" __attribute__((regparm(1))) void internal_handle_exception(sgx_exception_info_t *info)
{
    _internal_handle_exception(info, false);
}

/* Hanlde signals triggerred inside sgx-enclave on behalve of DBI */
extern "C" __attribute__((regparm(1))) void internal_handle_DBI_inside_signal(sgx_exception_info_t *info)
{
    thread_data_t *master_td;

    master_td = get_thread_data();
    info->sigcxt_pkg = master_td->signal_frame;
    master_td->signal_frame = NULL;

    _internal_handle_exception(info, true);
}
/* End: Added by Pinghai */

static int expand_stack_by_pages(void *start_addr, size_t page_count)
{
    int ret = -1;

    if ((start_addr == NULL) || (page_count == 0))
        return -1;

    ret = apply_pages_within_exception(start_addr, page_count);
    return ret;
}

// trts_handle_exception(void *tcs)
//      the entry point for the exceptoin handling
// Parameter
//      the pointer of TCS
// Return Value
//      none zero - success
//              0 - fail
extern "C" sgx_status_t
trts_handle_exception(void *tcs, void *ms)
{
    thread_data_t *thread_data = get_thread_data();
    ssa_gpr_t *ssa_gpr = NULL;
    sgx_exception_info_t *info = NULL;
    uintptr_t sp, *new_sp = NULL;
    size_t size = 0;

    if (tcs == NULL)
        goto default_handler;

    if (check_static_stack_canary(tcs) != 0)
        goto default_handler;

    if(get_enclave_state() != ENCLAVE_INIT_DONE)
        goto default_handler;

    // check if the exception is raised from 2nd phrase
    if(thread_data->exception_flag == -1)
        goto default_handler;

    if ((TD2TCS(thread_data) != tcs)
            || (((thread_data->first_ssa_gpr)&(~0xfff)) - SE_PAGE_SIZE) != (uintptr_t)tcs) {
        goto default_handler;
    }

    // no need to check the result of ssa_gpr because thread_data is always trusted
    ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);

    sp = ssa_gpr->REG(sp);
    if(!is_stack_addr((void*)sp, 0))  // check stack overrun only, alignment will be checked after exception handled
    {
        g_enclave_state = ENCLAVE_CRASHED;
        return SGX_ERROR_STACK_OVERRUN;
    }

    size = 0;
#ifdef SE_GNU64
    size += 128; // x86_64 requires a 128-bytes red zone, which begins directly
    // after the return addr and includes func's arguments
#endif

    // decrease the stack to give space for info
    size += sizeof(sgx_exception_info_t);
    sp -= size;
    sp = sp & ~0xF;

    // check the decreased sp to make sure it is in the trusted stack range
    if(!is_stack_addr((void *)sp, size))
    {
        g_enclave_state = ENCLAVE_CRASHED;
        return SGX_ERROR_STACK_OVERRUN;
    }

    info = (sgx_exception_info_t *)sp;
    // decrease the stack to save the SSA[0]->ip
    size = sizeof(uintptr_t);
    sp -= size;
    if(!is_stack_addr((void *)sp, size))
    {
        g_enclave_state = ENCLAVE_CRASHED;
        return SGX_ERROR_STACK_OVERRUN;
    }

    // sp is within limit_addr and commit_addr, currently only SGX 2.0 under hardware mode will enter this branch.^M
    if((size_t)sp < thread_data->stack_commit_addr)
    {
        int ret = -1;
        size_t page_aligned_delta = 0;
        /* try to allocate memory dynamically */
        page_aligned_delta = ROUND_TO(thread_data->stack_commit_addr - (size_t)sp, SE_PAGE_SIZE);
        if ((thread_data->stack_commit_addr > page_aligned_delta)
                && ((thread_data->stack_commit_addr - page_aligned_delta) >= thread_data->stack_limit_addr))
        {
            ret = expand_stack_by_pages((void *)(thread_data->stack_commit_addr - page_aligned_delta), (page_aligned_delta >> SE_PAGE_SHIFT));
        }
        if (ret == 0)
        {
            thread_data->stack_commit_addr -= page_aligned_delta;
            return SGX_SUCCESS;
        }
        else
        {
            g_enclave_state = ENCLAVE_CRASHED;
            return SGX_ERROR_STACK_OVERRUN;
        }
    }

    /* exception handlers are not allowed:
    A: to call in a non-exception state, and
    B: no additional exception handler */
    if (ssa_gpr->exit_info.valid != 1 && g_first_node == NULL)
    {
        goto default_handler;
    }

    // initialize the info with SSA[0]
    info->exception_vector = (sgx_exception_vector_t)ssa_gpr->exit_info.vector;
    info->exception_type = (sgx_exception_type_t)ssa_gpr->exit_info.exit_type;

    info->cpu_context.REG(ax) = ssa_gpr->REG(ax);
    info->cpu_context.REG(cx) = ssa_gpr->REG(cx);
    info->cpu_context.REG(dx) = ssa_gpr->REG(dx);
    info->cpu_context.REG(bx) = ssa_gpr->REG(bx);
    info->cpu_context.REG(sp) = ssa_gpr->REG(sp);
    info->cpu_context.REG(bp) = ssa_gpr->REG(bp);
    info->cpu_context.REG(si) = ssa_gpr->REG(si);
    info->cpu_context.REG(di) = ssa_gpr->REG(di);
    info->cpu_context.REG(flags) = ssa_gpr->REG(flags);
    info->cpu_context.REG(ip) = ssa_gpr->REG(ip);
#ifdef SE_64
    info->cpu_context.r8  = ssa_gpr->r8;
    info->cpu_context.r9  = ssa_gpr->r9;
    info->cpu_context.r10 = ssa_gpr->r10;
    info->cpu_context.r11 = ssa_gpr->r11;
    info->cpu_context.r12 = ssa_gpr->r12;
    info->cpu_context.r13 = ssa_gpr->r13;
    info->cpu_context.r14 = ssa_gpr->r14;
    info->cpu_context.r15 = ssa_gpr->r15;
#endif
    info->sigcxt_pkg = ms;

    new_sp = (uintptr_t *)sp;
    if (ssa_gpr->exit_info.valid == 1)
    {
        ssa_gpr->REG(ip) = (size_t)internal_handle_exception; // prepare the ip for 2nd phrase handling
    }

    /* Begin: Added by Pinghai */
    /* Give high privilege to SGX-DBI if it has registered signal handlers */
    if (g_first_node != NULL)
    {
        /* create an internal copy of the signal framwork and update it */
        thread_data_t *master_td;
        sigcxt_pkg_t *pkg;

        master_td = get_thread_data();
        pkg = (sigcxt_pkg_t *)malloc(sizeof(sigcxt_pkg_t));
        memcpy(pkg, info->sigcxt_pkg, sizeof(sigcxt_pkg_t));

        memset(&pkg->ctx.uc_mcontext, 0, sizeof(mcontext_t));
        pkg->ctx.uc_mcontext.gregs[SIGCXT_R8] = info->cpu_context.REG(8);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_R9] = info->cpu_context.REG(9);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_R10] = info->cpu_context.REG(10);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_R11] = info->cpu_context.REG(11);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_R12] = info->cpu_context.REG(12);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_R13] = info->cpu_context.REG(13);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_R14] = info->cpu_context.REG(14);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_R15] = info->cpu_context.REG(15);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_RDI] = info->cpu_context.REG(di);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_RSI] = info->cpu_context.REG(si);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_RBP] = info->cpu_context.REG(bp);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_RBX] = info->cpu_context.REG(bx);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_RDX] = info->cpu_context.REG(dx);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_RAX] = info->cpu_context.REG(ax);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_RCX] = info->cpu_context.REG(cx);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_RSP] = info->cpu_context.REG(sp);
        pkg->ctx.uc_mcontext.gregs[SIGCXT_RIP] = info->cpu_context.REG(ip);
        pkg->ctx.uc_link = NULL;

        ssa_gpr->REG(ip) = (size_t)internal_handle_DBI_inside_signal; // The signal is triggered by App's code?

        master_td->signal_frame = pkg;
    }
    /* End: Added by Pinghai */

    ssa_gpr->REG(sp) = (size_t)new_sp;      // new stack for internal_handle_exception
    ssa_gpr->REG(ax) = (size_t)info;        // 1st parameter (info) for LINUX32
    ssa_gpr->REG(di) = (size_t)info;        // 1st parameter (info) for LINUX64, LINUX32 also uses it while restoring the context
    *new_sp = info->cpu_context.REG(ip);    // for debugger to get call trace

    //mark valid to 0 to prevent eenter again
    ssa_gpr->exit_info.valid = 0;

    return SGX_SUCCESS;

default_handler:
    g_enclave_state = ENCLAVE_CRASHED;
    return SGX_ERROR_ENCLAVE_CRASHED;
}

/* Begin: Added by Pinghai */
/* Don't modify the order of RSP */
typedef struct _simu_pt_gregs
{
    ulong r8;
    ulong r9;
    ulong r10;
    ulong r11;
    ulong r12;
    ulong r13;
    ulong r14;
    ulong r15;

    ulong rdi;
    ulong rsi;
    ulong rbp;
    ulong rbx;
    ulong rdx;
    ulong rax;
    ulong rcx;
    ulong rsp;
} simu_pt_gregs;

/* handler signals triggerred outside-sgx enclave */
extern "C"
void internal_handle_DBI_outside_signal(simu_pt_gregs *regs)
{
    sgx_exception_info_t info;
    thread_data_t *master_td;
    sigcxt_pkg_t *pkg;

    master_td = get_thread_data();
    pkg = (sigcxt_pkg_t *)master_td->signal_frame;

    /* update the signal framwork, except rsp and rip */
    pkg->ctx.uc_mcontext.gregs[SIGCXT_R8] = regs->r8;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_R9] = regs->r9;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_R10] = regs->r10;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_R11] = regs->r11;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_R12] = regs->r12;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_R13] = regs->r13;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_R14] = regs->r14;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_R15] = regs->r15;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_RDI] = regs->rdi;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_RSI] = regs->rsi;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_RBP] = regs->rbp;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_RBX] = regs->rbx;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_RDX] = regs->rdx;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_RAX] = regs->rax;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_RCX] = regs->rcx;
    pkg->ctx.uc_link = NULL;


    /* initialize info */
    info.sigcxt_pkg = pkg;
    info.cpu_context.r8 = regs->r8;
    info.cpu_context.r9 = regs->r9;
    info.cpu_context.r10 = regs->r10;
    info.cpu_context.r11 = regs->r11;
    info.cpu_context.r12 = regs->r12;
    info.cpu_context.r13 = regs->r13;
    info.cpu_context.r14 = regs->r14;
    info.cpu_context.r15 = regs->r15;

    info.cpu_context.rax = regs->rax;
    info.cpu_context.rcx = regs->rcx;
    info.cpu_context.rdx = regs->rdx;
    info.cpu_context.rbx = regs->rbx;
    info.cpu_context.rbp = regs->rbp;
    info.cpu_context.rsi = regs->rsi;
    info.cpu_context.rdi = regs->rdi;

    info.cpu_context.REG(sp) = pkg->ctx.uc_mcontext.gregs[SIGCXT_RSP] + 8;    // continue_execution create a return_address
    info.cpu_context.REG(ip) = pkg->ctx.uc_mcontext.gregs[SIGCXT_RIP];

    master_td->signal_frame = NULL;
   _internal_handle_exception(&info, true);
}

extern "C"
void function_container_651(void)
{
    __asm__(
        "callwrapper_internal_handle_DBI_outside_signal:\n\t"
        // "call 1f\n"
        // "1:\n\t"
        "push  %rsp\n\t"
        "push  %rcx\n\t"
        "push  %rax\n\t"
        "push  %rdx\n\t"
        "push  %rbx\n\t"
        "push  %rbp\n\t"
        "push  %rsi\n\t"
        "push  %rdi\n\t"

        "push  %r15\n\t"
        "push  %r14\n\t"
        "push  %r13\n\t"
        "push  %r12\n\t"
        "push  %r11\n\t"
        "push  %r10\n\t"
        "push  %r9\n\t"
        "push  %r8\n\t"

        "mov %rsp, %rdi\n\t"
        "call  internal_handle_DBI_outside_signal\n\t");
}

extern "C" void callwrapper_internal_handle_DBI_outside_signal();
extern "C" void oret_load_slave_tls(void);
/* exception triggered when running out-sgx code */
extern "C" sgx_status_t trts_handle_outside_signal(void *tcs, void *ms)
{
    // Inject a signal framework on dynamorio's signal stack
    // 1. Get dynamorio's signal stack
    // 2. Inject the signal frame in that stack
    // 2. Get the return address of the latest do_ocall
    // 3. Save the return address to TCS
    // 4. Replace the return address with address of function switch_stack_call_dr_signal_handler
    thread_data_t *master_td = get_thread_data();
    ocall_context_t *ocall_cxt;
    uintptr_t *stack_ret;
    sigcxt_pkg_t *pkg;

    if (tcs == NULL)
        goto default_handler;

    if (check_static_stack_canary(tcs) != 0)
        goto default_handler;

    if(get_enclave_state() != ENCLAVE_INIT_DONE)
        goto default_handler;

    if (g_first_node == NULL)
        goto default_handler;

    /* Refer to trts_pic.S::do_ocall, the ocall consums 0x408 bytes on stack */
    ocall_cxt = (ocall_context_t*)master_td->last_sp;
    stack_ret = (uintptr_t*)(ocall_cxt->xbp + sizeof(uintptr_t));

    /* create an internal copy of the signal framwork and update it */
    pkg = (sigcxt_pkg_t *)malloc(sizeof(sigcxt_pkg_t));

    memcpy(pkg, ms, sizeof(sigcxt_pkg_t));

    memset(&pkg->ctx.uc_mcontext, 0, sizeof(mcontext_t));
    pkg->ctx.uc_mcontext.gregs[SIGCXT_RSP] = (long long)stack_ret;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_RIP] = (long long)*stack_ret;
    pkg->ctx.uc_link = NULL;

    *stack_ret = (uintptr_t)callwrapper_internal_handle_DBI_outside_signal;
    master_td->signal_frame = pkg;

    oret_load_slave_tls();

    return SGX_SUCCESS;

default_handler:
    g_enclave_state = ENCLAVE_CRASHED;
    return SGX_ERROR_ENCLAVE_CRASHED;
}
/* End: Added by Pinghai */
