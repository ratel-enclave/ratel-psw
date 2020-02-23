/* **********************************************************
 * Copyright (c) 2018-2020 Ratel Authors.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _TRTS_VEH_H__
#define _TRTS_VEH_H__

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

#ifdef __cplusplus
extern "C" {
#endif

#define SIGILL      4
#define SIGABRT     6
#define SIGFPE      8
#define SIGSEGV     11
#define SIGBUS      10
#define SIGSYS      12
#define SIGTRAP     5

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

/* Begin: Added by ratel authors */

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

/* Stores signal information, compatible with DynamoRIO's sigframe_rt_t */
typedef struct _sigcxt_pkg_t
{
    int signum;
    ucontext_t ctx;
    char info[128];
} sigcxt_pkg_t;


uintptr_t get_sdk_signal_stack(void);

#ifdef __cplusplus
}
#endif

#endif  //_TRTS_VEH_H__