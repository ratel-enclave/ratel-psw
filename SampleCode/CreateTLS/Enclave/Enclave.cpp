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


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
//#include "sgx_intrin.h"

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */

#define TLS_TYPE_UNKNOW     0x1      // Use bit 0
#define TLS_TYPE_TCS_TD     0x2      // Use bit 1
#define TLS_TYPE_DBI_DR     0x4      // Use bit 2
#define TLS_TYPE_DBI_APP    0x8      // Use bit 3

extern "C" {
    struct thread_data_t;
    void init_slave_tls(void *tls_segment);
    void load_segment_fs(void *tls_segment);
    void load_segment_gs(void *tls_segment);
};

unsigned long read_gsbase(void)
{
    unsigned long gsbase;

    asm volatile ( "rdgsbase %0" :"=a" (gsbase));
    return gsbase;
}

void write_gsbase(unsigned long gsbase)
{
    asm volatile ( "rdgsbase %0" :"=a" (gsbase));
}

void sgx_load_fsbase(void)
{
    char buf[4096];

    ///////////////////////////////////////////////////////////////////
    unsigned long fsorg, fsnew, fsval;

    // Read the orginal fs-segment
    asm volatile ( "rdfsbase %0" : "=a" (fsorg));
    snprintf(buf, BUFSIZ, "%s: the original fsbase>>>>%lx\n", __FUNCTION__, fsorg);
    ocall_print_string(buf);


    // Create and load new fs-segment
    unsigned long seg = (unsigned long)malloc(4096*2);
    fsnew = (seg + 4096) & ~(0xFFF);

    snprintf(buf, BUFSIZ, "%s: create new fs-segment>>>>%lx\n", __FUNCTION__, fsnew);
    ocall_print_string(buf);

    init_slave_tls((void*)fsnew);
    load_segment_fs((void*)fsnew);
    asm volatile ( "rdfsbase %0" : "=a" (fsval));
    snprintf(buf, BUFSIZ, "%s: update fsbase to >>>>%lx\n", __FUNCTION__, fsval);
    ocall_print_string(buf);

    // Create and load another new fs-segment
    seg = (unsigned long)malloc(4096*2);
    fsnew = (seg + 4096) & ~(0xFFF);

    snprintf(buf, BUFSIZ, "%s: create another new fs-segment>>>>%lx\n", __FUNCTION__, fsnew);
    ocall_print_string(buf);

    init_slave_tls((void*)fsnew);
    load_segment_fs((void*)fsnew);
    asm volatile ( "rdfsbase %0" : "=a" (fsval));
    snprintf(buf, BUFSIZ, "%s: update fsbase to >>>>%lx\n", __FUNCTION__, fsval);
    ocall_print_string(buf);


    //load the orignal fs-segment
    snprintf(buf, BUFSIZ, "%s: load the original fsbase >>>>%lx\n", __FUNCTION__, fsorg);
    ocall_print_string(buf);

    load_segment_fs((void*)fsorg);
    asm volatile ( "rdfsbase %0" : "=a" (fsval));
    snprintf(buf, BUFSIZ, "%s: update fsbase to >>>>%lx\n", __FUNCTION__, fsval);
    ocall_print_string(buf);
}


void sgx_load_gsbase(void)
{
    char buf[4096];

    ///////////////////////////////////////////////////////////////////
    unsigned long fsorg, fsnew, fsval;

    // Read the orginal fs-segment
    asm volatile ( "rdgsbase %0" : "=a" (fsorg));
    snprintf(buf, BUFSIZ, "%s: the original gsbase>>>>%lx\n", __FUNCTION__, fsorg);
    ocall_print_string(buf);


    // Create and load new fs-segment
    unsigned long seg = (unsigned long)malloc(4096*2);
    fsnew = (seg + 4096) & ~(0xFFF);

    snprintf(buf, BUFSIZ, "%s: create new gs-segment>>>>%lx\n", __FUNCTION__, fsnew);
    ocall_print_string(buf);

    init_slave_tls((void*)fsnew);
    load_segment_gs((void*)fsnew);
    asm volatile ( "rdgsbase %0" : "=a" (fsval));
    snprintf(buf, BUFSIZ, "%s: update gsbase to >>>>%lx\n", __FUNCTION__, fsval);
    ocall_print_string(buf);

    // Create and load another new fs-segment
    seg = (unsigned long)malloc(4096*2);
    fsnew = (seg + 4096) & ~(0xFFF);

    snprintf(buf, BUFSIZ, "%s: create another new gs-segment>>>>%lx\n", __FUNCTION__, fsnew);
    ocall_print_string(buf);

    init_slave_tls((void*)fsnew);
    load_segment_gs((void*)fsnew);
    asm volatile ( "rdgsbase %0" : "=a" (fsval));
    snprintf(buf, BUFSIZ, "%s: update gsbase to >>>>%lx\n", __FUNCTION__, fsval);
    ocall_print_string(buf);


    //load the orignal fs-segment
    snprintf(buf, BUFSIZ, "%s: load the original gsbase >>>>%lx\n", __FUNCTION__, fsorg);
    ocall_print_string(buf);

    load_segment_gs((void*)fsorg);
    asm volatile ( "rdgsbase %0" : "=a" (fsval));
    snprintf(buf, BUFSIZ, "%s: update gsbase to >>>>%lx\n", __FUNCTION__, fsval);
    ocall_print_string(buf);
}

void sgx_fsgs_info(void)
{
    sgx_load_fsbase();
    sgx_load_gsbase();
}
