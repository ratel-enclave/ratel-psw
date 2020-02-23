/*
 * Copyright (c) 2018-2020 Ratel Authors.  All rights reserved.
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

/* Implement functions:
 *         init_stack_guard()
 *         enter_enclave()
 *
 *  The functions in this source file will be called during the stack guard initialization.
 *  They cannot be built with '-fstack-protector-strong'. Otherwise, stack guard check will
 *  be failed before the function returns and 'ud2' will be triggered.
*/

#include "sgx_trts.h"
#include "trts_inst.h"
#include "se_memcpy.h"
#include <string.h>
#include <stdlib.h>
#include "thread_data.h"
#include "global_data.h"
#include "trts_internal.h"
#include "internal/rts.h"

static void init_stack_guard(void *tcs)
{
    thread_data_t *thread_data = get_thread_data();
    if ((NULL == thread_data) /*|| ((thread_data->stack_base_addr == thread_data->last_sp) && (0 != g_global_data.thread_policy))*/)
    {
        thread_data = GET_PTR(thread_data_t, tcs, g_global_data.td_template.self_addr);
    }
    else
    {
        return;
    }

    assert(thread_data != NULL);

    size_t tmp_stack_guard = 0;
    if (SGX_SUCCESS != sgx_read_rand(
                           (unsigned char *)&tmp_stack_guard,
                           sizeof(tmp_stack_guard)))
        abort();

    thread_data->stack_guard = tmp_stack_guard;
}

/* Begin: Added by ratel authors */
#define UPDATE_FS 10
#define UPDATE_GS 20


extern "C"
void load_segment_fs(void *tls_segment)
{
    thread_data_t *td_master = get_thread_data();
    assert (td_master != NULL);

    /* Point to TCS-segment ? */
    if (tls_segment == td_master)
        return;

    /* Different segments */
    thread_data_t *td_new = (thread_data_t*)tls_segment;

    td_new->self_addr = (sys_word_t)tls_segment;
    td_new->master_tls = td_master;
    td_master->cur_fs_seg = tls_segment;

    asm volatile ( "wrfsbase %0" :: "a" (tls_segment) );
}


extern "C"
void load_segment_gs(void *tls_segment)
{
    thread_data_t *td_master = get_thread_data();
    assert (td_master != NULL);

    /* Point to TCS-segment ? */
    if (tls_segment == td_master)
        return;

    /* Different segments */
    thread_data_t *td_new = (thread_data_t*)tls_segment;

    td_new->self_addr = (sys_word_t)tls_segment;
    td_new->master_tls = td_master;
    td_master->cur_gs_seg = tls_segment;
    asm volatile ( "wrgsbase %0" :: "a" (tls_segment) );
}


/* Invoked just after every eenter */
extern "C"
void oret_load_slave_tls(void)
{
    thread_data_t *td_master = get_thread_data();
    assert (td_master != NULL);

    void *td_fs = td_master->cur_fs_seg;
    void *td_gs = td_master->cur_gs_seg;
    assert(td_fs != NULL);
    assert(td_gs != NULL);

    /* Optimized, skipping execute wrfsbase/wrgsbase if possible */
    if (td_fs != td_master)
        asm volatile ( "wrfsbase %0" :: "a" (td_fs) );

    if (td_gs != td_master)
        asm volatile ( "wrgsbase %0" :: "a" (td_gs) );
}

extern "C"
void ecall_reset_tls_reg(void)
{
    thread_data_t *td_master = get_thread_data();
    assert (td_master != NULL);

    void *td_fs = td_master->cur_fs_seg;
    void *td_gs = td_master->cur_gs_seg;
    assert(td_fs != NULL);
    assert(td_gs != NULL);

    if (td_fs != td_master)
        asm volatile ( "wrfsbase %0" :: "a" (td_master) );

    if (td_gs != td_master)
        asm volatile ( "wrgsbase %0" :: "a" (td_master) );
}


/* Invoked just before every eexit, compatible with update_ocall_lastsp */
extern "C" void
eexit_update_lastsp(void *last_sp)
{
    thread_data_t *td_master = get_thread_data();
    assert(td_master != NULL);

    td_master->last_sp = (sys_word_t)last_sp;

    /* Make sure:
    td_master->cur_fs_seg = td_fs &&
    td_master->cur_gs_seg = td_gs
    */
}
/* End: Added by ratel authors */

extern "C"
int enter_enclave(int index, void *ms, void *tcs, int cssa)
{
    if(get_enclave_state() == ENCLAVE_CRASHED)
    {
        return SGX_ERROR_ENCLAVE_CRASHED;
    }

    sgx_status_t error = SGX_ERROR_UNEXPECTED;
    if(cssa == 0)
    {
        if(index >= 0)
        {
            // Initialize stack guard if necessary
            init_stack_guard(tcs);
            error = do_ecall(index, ms, tcs);
        }
        else if(index == ECMD_INIT_ENCLAVE)
        {
            error = do_init_enclave(ms, tcs);
        }
        else if(index == ECMD_ORET)
        {
            error = do_oret(ms);
        }
        else if(index == ECMD_MKTCS)
        {
            // Initialize stack guard if necessary
            init_stack_guard(tcs);
            error = do_ecall_add_thread(ms, tcs);
        }
        else if(index == ECMD_UNINIT_ENCLAVE)
        {
            error = do_uninit_enclave(tcs);
        }
		/* Begin: Added by ratel authors */
        else if (index == ECMD_SIGNAL)
        {
            error = trts_handle_outside_signal(tcs, ms);
        }
		/* End: Added by ratel authors */
    }
    else if((cssa == 1) && (index == ECMD_EXCEPT))
    {
        error = trts_handle_exception(tcs, ms);
        if (check_static_stack_canary(tcs) != 0)
        {
            assert(false && "enter_enclave -->> SGX_ERROR_STACK_OVERRUN!!!\n");
            error = SGX_ERROR_STACK_OVERRUN;
        }
    }

    if(error == SGX_ERROR_UNEXPECTED)
    {
        set_enclave_state(ENCLAVE_CRASHED);
    }
    return error;
}
