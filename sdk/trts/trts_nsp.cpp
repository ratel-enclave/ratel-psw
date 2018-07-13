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
    if( (NULL == thread_data) || ((thread_data->stack_base_addr == thread_data->last_sp) && (0 != g_global_data.thread_policy)))
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
                (unsigned char*)&tmp_stack_guard,
                sizeof(tmp_stack_guard)))
        abort();

    thread_data->stack_guard = tmp_stack_guard;
}



//#if defined(LINUX64)

#define UPDATE_FS 10
#define UPDATE_GS 20

static inline void __propagate_thread_data(thread_data_t* td_new, thread_data_t* td_cur)
{
    assert(td_new != NULL && td_cur != NULL);
    td_new->last_sp = td_cur->last_sp;
    td_new->first_ssa_gpr = td_cur->first_ssa_gpr;
    td_new->last_error = td_cur->last_error;
    td_new->exception_flag = td_cur->exception_flag;
    td_new->stack_commit_addr = td_cur->stack_commit_addr;
}

extern "C" {

void load_fsbase(sys_word_t base)
{
    thread_data_t *td_new = (thread_data_t*)base;
    thread_data_t *td_cur = get_thread_data();

    assert (td_new != NULL && td_cur != NULL);

    //The same td instance?
    if (td_new == td_cur)
        return;

    __propagate_thread_data(td_new, td_cur);

    thread_data_t *td_master = NULL;
    if (td_new->master_tls_segment)
        td_master = td_new;
    else if (td_cur->master_tls_segment)
        td_master = td_cur;
    else
        td_master = td_cur->fsbase;

    assert (td_master != NULL);
    td_master->fsbase = td_new;
    asm volatile ( "wrfsbase %0" :: "a" (td_new) );
}


void load_gsbase(sys_word_t base)
{
    thread_data_t *td_new = (thread_data_t*)base;
    thread_data_t *td_cur = get_thread_data();  /* fs-segmetn */

    assert (td_new != NULL && td_cur != NULL);


    thread_data_t *td_master = NULL;
    if (td_cur->master_tls_segment)
        td_master = td_cur;
    else
        td_master = td_cur->fsbase;
    assert (td_master != NULL);

    thread_data_t *td_gs = td_master->gsbase;

    //The same td instance?
    if (td_new == td_gs)
        return;

    td_master->gsbase = td_new;
    asm volatile ( "wrgsbase %0" :: "a" (td_new) );
}


void _eenter_load_slave_tls(void)
{
    thread_data_t *td_master = get_thread_data();

    /* initialized? */
    if (td_master == NULL)
        return;

    assert(td_master->master_tls_segment == 1);

    thread_data_t *td_fs = td_master->fsbase;
    thread_data_t *td_gs = td_master->gsbase;
    assert(td_fs != NULL);
    assert(td_gs != NULL);

    if (td_fs != td_master)
        asm volatile ( "wrfsbase %0" :: "a" (td_fs) );

    if (td_gs != td_master)
        asm volatile ( "wrgsbase %0" :: "a" (td_gs) );
}


void _eexit_update_master_tls(void)
{
    thread_data_t *td = get_thread_data();
    assert(td != NULL);

    if (td->master_tls_segment) {
        //do nothing
    }
    else {
        //update master tls then load it
        thread_data_t *td_master = td->fsbase;
        assert(td_master != NULL);

        __propagate_thread_data(td_master, td);
    }
}

}
//#endif


extern "C" int enter_enclave(int index, void *ms, void *tcs, int cssa)
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
    }
    else if((cssa == 1) && (index == ECMD_EXCEPT))
    {
        error = trts_handle_exception(tcs);
        if (check_static_stack_canary(tcs) != 0)
        {
            error = SGX_ERROR_STACK_OVERRUN;
        }
    }
    if(error == SGX_ERROR_UNEXPECTED)
    {
        set_enclave_state(ENCLAVE_CRASHED);
    }
    return error;
}
