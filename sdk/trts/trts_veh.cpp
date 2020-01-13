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
#include "trts_veh.h"


typedef struct _handler_node_t
{
    uintptr_t callback;
    struct _handler_node_t   *next;
} handler_node_t;

static handler_node_t *g_first_node = NULL;
static sgx_spinlock_t g_handler_lock = SGX_SPINLOCK_INITIALIZER;
// static bool g_setup_DBI;

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
    thread_data_t *thread_data = get_thread_data();
    int status = EXCEPTION_CONTINUE_SEARCH;
    handler_node_t *node = NULL;
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


/* We don't consider nested signal */
extern "C"
void initialize_signal_frame(thread_data_t *td)
{
    sgx_exception_info_t *info = (sgx_exception_info_t *)malloc(sizeof(sgx_exception_info_t));
    sigcxt_pkg_t *pkg = (sigcxt_pkg_t *)malloc(sizeof(sigcxt_pkg_t));

    info->sigcxt_pkg = pkg;
    td->signal_info = info;
}

extern "C"
void finalize_signal_frame(thread_data_t *td)
{
    sgx_exception_info_t *info;

    info = (sgx_exception_info_t*)td->signal_info;
    if (info != NULL)
    {
        if (info->sigcxt_pkg != NULL)
            free(info->sigcxt_pkg);
        info->sigcxt_pkg = NULL;
    }
    free(info);
    td->signal_info = NULL;
}

extern "C" __attribute__((regparm(1))) void internal_handle_exception(void)
{
    thread_data_t *thread_data = get_thread_data();

    _internal_handle_exception((sgx_exception_info_t*)thread_data->signal_info, false);
}

/* Hanlde signals triggerred inside sgx-enclave on behalve of DBI */
extern "C" __attribute__((regparm(1))) void internal_handle_DBI_inside_signal(void)
{
    thread_data_t *thread_data = get_thread_data();

    _internal_handle_exception((sgx_exception_info_t*)thread_data->signal_info, true);
}
/* End: Added by Pinghai */

extern "C" uintptr_t get_sdk_signal_stack(void)
{
    thread_data_t *thread_data = get_thread_data();

    return (thread_data->stack_base_addr + STATIC_STACK_SIZE);
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
    sigcxt_pkg_t *pkg = NULL;
    uintptr_t sp;

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

    /* exception handlers are not allowed:
    A: to call in a non-exception state, and
    B: no additional exception handler */
    if (ssa_gpr->exit_info.valid != 1 && g_first_node == NULL)
    {
        goto default_handler;
    }

    info = (sgx_exception_info_t *)thread_data->signal_info;
    assert(info != NULL);

    // initialize the info with SSA[0]
    info = (sgx_exception_info_t *)thread_data->signal_info;
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


    /* Begin: Added by Pinghai */
    /* Give high privilege to SGX-DBI if it has registered signal handlers */
    if (g_first_node != NULL)
    {
        /* Fill the internal signal framwork */
        pkg = (sigcxt_pkg_t *)info->sigcxt_pkg;
        memcpy(pkg, ms, sizeof(sigcxt_pkg_t));

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
    }
    else if (ssa_gpr->exit_info.valid == 1)
    {
        ssa_gpr->REG(ip) = (size_t)internal_handle_exception; // prepare the ip for 2nd phrase handling
    }

    /* End: Added by Pinghai */
    ssa_gpr->REG(sp) = (size_t)get_sdk_signal_stack();      // Reuse SDK stack for ERESUMEing to internal_handle_exception
    ssa_gpr->REG(ax) = (size_t)info;        // 1st parameter (info) for LINUX32
    ssa_gpr->REG(di) = (size_t)info;        // 1st parameter (info) for LINUX64, LINUX32 also uses it while restoring the context

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
    ulong r8, r9, r10, r11, r12, r13, r14, r15;
    ulong rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp;
} simu_pt_gregs;

/* handler signals triggerred outside-sgx enclave */
extern "C"
void internal_handle_DBI_outside_signal(simu_pt_gregs *regs)
{
    thread_data_t *thread_data = get_thread_data();
    sgx_exception_info_t *info = (sgx_exception_info_t *)thread_data->signal_info;
    sigcxt_pkg_t *pkg = (sigcxt_pkg_t *)info->sigcxt_pkg;

    /* initialize info */
    info->cpu_context.r8 = regs->r8;
    info->cpu_context.r9 = regs->r9;
    info->cpu_context.r10 = regs->r10;
    info->cpu_context.r11 = regs->r11;
    info->cpu_context.r12 = regs->r12;
    info->cpu_context.r13 = regs->r13;
    info->cpu_context.r14 = regs->r14;
    info->cpu_context.r15 = regs->r15;

    info->cpu_context.rax = regs->rax;
    info->cpu_context.rcx = regs->rcx;
    info->cpu_context.rdx = regs->rdx;
    info->cpu_context.rbx = regs->rbx;
    info->cpu_context.rbp = regs->rbp;
    info->cpu_context.rsi = regs->rsi;
    info->cpu_context.rdi = regs->rdi;

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

    // +8 because continue_execution creates a return_address on the stack
    info->cpu_context.REG(sp) = pkg->ctx.uc_mcontext.gregs[SIGCXT_RSP] + 8;
    info->cpu_context.REG(ip) = pkg->ctx.uc_mcontext.gregs[SIGCXT_RIP];

   _internal_handle_exception(info, true);
}

extern "C"
void function_container_651(void)
{
    __asm__(
        "stacK_hook_2_signal_handler:\n\t"
        /* Save current machine context, refer simu_pt_gregs */
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
        "call  get_sdk_signal_stack\n\t"
        /* let internal_handle_DBI_outside_signal works on SDK's signal stack*/
        "xchg  %rsp, %rax\n\t"
        "mov   %rax, %rdi\n\t"
        "call  internal_handle_DBI_outside_signal\n\t");
    // doesn't come to here
}

extern "C" void stacK_hook_2_signal_handler();

/* exception triggered when running out-sgx code */
extern "C" sgx_status_t trts_handle_outside_signal(void *tcs, void *ms)
{
    // Inject a signal-info framework into SGX-XDBI's execution flow
    // 1. Get DBI's execution stack
    // 2. Get the return address of the latest do_ocall
    // 3. Save the return address into the signal-info frame
    // 4. Replace the return address with address of stacK_hook_2_signal_handler
    thread_data_t *thread_data = get_thread_data();
    sgx_exception_info_t *info = (sgx_exception_info_t *)thread_data->signal_info;
    sigcxt_pkg_t *pkg = (sigcxt_pkg_t *)info->sigcxt_pkg;

    ocall_context_t *ocall_cxt = NULL;
    uintptr_t *stack_ret = NULL;


    if (tcs == NULL)
        goto default_handler;

    if (check_static_stack_canary(tcs) != 0)
        goto default_handler;

    if(get_enclave_state() != ENCLAVE_INIT_DONE)
        goto default_handler;

    if (g_first_node == NULL)
        goto default_handler;

    /* Refer to trts_pic.S::do_ocall, the ocall consums 0x408 bytes on stack */
    ocall_cxt = (ocall_context_t*)thread_data->last_sp;
    stack_ret = (uintptr_t*)(ocall_cxt->xbp + sizeof(uintptr_t));

    /* Fill the internal copy of the signal framwork and update it */
    memcpy(pkg, ms, sizeof(sigcxt_pkg_t));

    memset(&pkg->ctx.uc_mcontext, 0, sizeof(mcontext_t));
    pkg->ctx.uc_mcontext.gregs[SIGCXT_RSP] = (long long)stack_ret;
    pkg->ctx.uc_mcontext.gregs[SIGCXT_RIP] = (long long)*stack_ret;
    pkg->ctx.uc_link = NULL;

    *stack_ret = (uintptr_t)stacK_hook_2_signal_handler;

    return SGX_SUCCESS;

default_handler:
    g_enclave_state = ENCLAVE_CRASHED;
    return SGX_ERROR_ENCLAVE_CRASHED;
}
/* End: Added by Pinghai */
